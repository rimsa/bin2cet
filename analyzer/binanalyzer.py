#!/usr/bin/env python2

# Copyright (C) 2026 Andrei Rimsa <andrei@cefetmg.br>
# Copyright (C) 2026 Bruno Rocha Ribeiro <brunor.ribeiro96@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import json
import sys
from ghidra.util.task import TaskMonitor
from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.lang import OperandType
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.pcode import PcodeOp

ENDBR64 = [0xf3, 0x0f, 0x1e, 0xfa]
PIE_IMAGE_BASE = 0x100000

sbm = SimpleBlockModel(currentProgram)
memory = currentProgram.getMemory()
listing = currentProgram.getListing()
imgbase = currentProgram.getImageBase()
funmanager = currentProgram.getFunctionManager()

addrs_blacklist = set()

def get_relative_addr(addr):
	return (addr.subtract(imgbase) if imgbase.getOffset() == PIE_IMAGE_BASE else addr.getOffset())

def get_file_offset(addr):
	sourceInfo = currentProgram.getMemory().getAddressSourceInfo(addr)
	return (sourceInfo.getFileOffset() if sourceInfo else -1)

def get_addr_content(addr):
	content = list(listing.getCodeUnitAt(addr).getBytes())
	return [val if val >= 0 else (val + 256) for val in content]

def is_instr_indirect_jump(instr):
	return instr.getMnemonicString() == "JMP" and \
			any(pcode.getOpcode() == PcodeOp.BRANCHIND for pcode in instr.getPcode())

def extract_indirect_jump(instr):
	addr = instr.getAddress()

	section = memory.getBlock(addr)
	if not section:
		return None

	return {
		'addr': hex(get_relative_addr(addr)),
		'patch_type': 'indirect_jump',
		'data': {
			'section': section.getName(),
			'section_offset': addr.subtract(section.getStart()),
			'file_offset': get_file_offset(addr),
			'instruction': {
				'content': get_addr_content(addr),
				'asm': instr.toString()
			}
		}
	}

def extract_function_entry(instr, fun):
	# Ignore if the function is outside of a section.
	entry_addr = instr.getAddress()
	section = memory.getBlock(entry_addr)
	if not section:
		return None

	# Check if the entry address is part of a basic block.
	basic_block = sbm.getCodeBlockAt(entry_addr, monitor)
	if not basic_block:
		return None

	blacklist = set()

	current = instr
	instructions = []
	size = 0
	while size < len(ENDBR64):
		# Constantly check if the address belongs to this basic block.
		addr = current.getAddress()
		if not basic_block.contains(addr):
			return None

		blacklist.add(addr)
		content = get_addr_content(addr)
		instructions.append({
			"content": content,
			"asm": current.toString(),
			"relative": True,
			"indirect": is_instr_indirect_jump(current)
		})
		size += len(content)
		current = current.getNext()

	# The next instruction will be patched too,
	# but there is no need to check if it belongs
	# to the current basic block, since this
	# instruction will be replaced by e9patch.
	addr = current.getAddress()
	blacklist.add(addr)
	instructions.append({
		"content": get_addr_content(addr),
		"asm": current.toString(),
		"relative": True,
		"indirect": is_instr_indirect_jump(current)
	})

	addrs_blacklist.update(blacklist)
	return {
		'addr': hex(get_relative_addr(entry_addr)),
		'patch_type': 'target_address',
		'data': {
			'section': section.getName(),
			'section_offset': entry_addr.subtract(section.getStart()),
			'file_offset': get_file_offset(entry_addr),
			'function': fun.getName(),
			'instructions': instructions
		}
	}

all = []
for instr in listing.getInstructions(True):
	if instr.getAddress() in addrs_blacklist:
		continue

	if is_instr_indirect_jump(instr):
		dump = extract_indirect_jump(instr)
		if dump:
			all.append(dump)
	else:
		fun = funmanager.getFunctionAt(instr.getAddress())
		if fun and instr.getMnemonicString() != "ENDBR64":
			dump = extract_function_entry(instr, fun)
			if dump:
				all.append(dump)
			else:
				print("failed to extract function: %s" % fun.getName())

args = getScriptArgs()
if len(args) >= 2:
	print('Usage: analyzer.py [Output extension]')
	sys.exit(1)
ext = args[0] if len(args) == 1 else 'json'

# Open a file in write mode ('w') and dump the data
outfile = currentProgram.getExecutablePath() + '.' + ext
with open(outfile, "w") as json_file:
    json.dump(all, json_file, indent=2)
