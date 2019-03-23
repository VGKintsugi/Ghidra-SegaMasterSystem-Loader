/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package smsloader;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.mem.MemoryBlock;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SMSLoaderLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// Name the loader
		return "Sega Master System & Game Gear (SMS/GG)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		// Validate this is a proper SMS/GG file by looking for the header
		
		// The 16-byte SMS/GG header can be found at one these offsets within the file
		long headerOffsets[] = {0x1ff0, 0x3ff0, 0x7ff0};
		long sizeOfHeader = 16;
		String signature = "TMR SEGA";
		
		for(int i = 0; i < headerOffsets.length; i++) {
			
			if(provider.length() < headerOffsets[i] + sizeOfHeader) {
				break;
			}
			
			// the first 8 bytes of header are a signature
			byte sig[] = provider.readBytes(headerOffsets[i], 8);
			if(Arrays.equals(sig, signature.getBytes())) {
				
				// found the SMS/GG header, this is a valid format
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("z80:LE:16:default", "default"), true));
				break;
			}			
		}	
		
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// Load the bytes from 'provider' into the 'program'.
		
		//
		// The Sega Master System/GG Memory Map
		//
		// 0x0000 - 0xbfff: ROM
		// 0xc000 - 0xdfff: RAM
		// 0xe000 - 0xffff: RAM Mirror
		//		
		
		try {			
			
			// 0x0000 - 0xbfff: ROM
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
			MemoryBlock block = program.getMemory().createInitializedBlock("ROM", addr, 0xC000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			
			// TODO: I have no clue how to handle mapping carts???
			long maxLen = provider.length();
			if(maxLen > 0xc000)	{
				maxLen = 0xc000;
			}
			
			// read the ROM bytes and attach them to the Ghidra program
			byte romBytes[] = provider.readBytes(0, maxLen);			
			program.getMemory().setBytes(addr, romBytes);
			
			// execution starts at byte 0
			AddressSet addrSet = new AddressSet(addr); // TODO: no clue how AddressSet works
			program.getFunctionManager().createFunction("Start", addr, addrSet, SourceType.IMPORTED);
						
			// 0xc000 - 0xdfff: RAM
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xc000);
			block = program.getMemory().createInitializedBlock("System RAM", addr, 0x2000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			
			// 0xe000 - 0xffff: RAM Mirror, TODO: no clue how to tell Ghidra that this is a mirror
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xe000);
			block = program.getMemory().createInitializedBlock("System RAM (Mirror)", addr, 0x2000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			
		}catch(Exception e) {
			log.appendException(e);
		}
		
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		return super.validateOptions(provider, loadSpec, options);
	}
}
