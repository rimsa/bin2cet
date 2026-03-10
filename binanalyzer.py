#!/usr/bin/env python2

# Copyright (C) 2026 Andrei Rimsa <andrei@cefetmg.br>
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

def get_relative_addr(addr):
	return (addr.subtract(imgbase) if imgbase.getOffset() == PIE_IMAGE_BASE else addr.getOffset())

def get_file_offset(addr):
	sourceInfo = currentProgram.getMemory().getAddressSourceInfo(addr)
	return (sourceInfo.getFileOffset() if sourceInfo else -1)

def get_addr_content(addr):
	content = list(listing.getCodeUnitAt(addr).getBytes())
	return [val if val >= 0 else (val + 256) for val in content]

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
	addr = instr.getAddress()

	# Ignore if the function already starts with ENDBR64.
	if instr.getMnemonicString() == "ENDBR64":
		return None

	# Ignore if the function is outside the .text section.
	section = memory.getBlock(addr)
	if not section or section.getName() != ".text":
		return None

	# Check if the entry address is part of a basic block.
	basic_block = sbm.getCodeBlockAt(addr, monitor)
	if not basic_block:
		return None

	current = instr
	instructions = []
	size = 0
	while size < len(ENDBR64):
		# Constantly check if the address belongs to this basic block.
		if not basic_block.contains(current.getAddress()):
			return None

		content = get_addr_content(current.getAddress())
		instructions.append({
			"content": content,
			"asm": current.toString(),
			"relative": True
		})
		size += len(content)
		current = current.getNext()

	# The next instruction will be patched too,
	# So let's check if it also belongs to the basic block.
	if not basic_block.contains(current.getAddress()):
		return None

	instructions.append({
		"content": get_addr_content(current.getAddress()),
		"asm": current.toString(),
		"relative": True
	})

	return {
		'addr': hex(get_relative_addr(addr)),
		'patch_type': 'target_address',
		'data': {
			'section': section.getName(),
			'section_offset': addr.subtract(section.getStart()),
			'file_offset': get_file_offset(addr),
			'function': fun.getName(),
			'instructions': instructions
		}
	}

all = []
for instr in listing.getInstructions(True):
	if instr.getMnemonicString() == "JMP" and \
			any(pcode.getOpcode() == PcodeOp.BRANCHIND for pcode in instr.getPcode()):
		dump = extract_indirect_jump(instr)
		if dump:
			all.append(dump)
		continue

	fun = funmanager.getFunctionAt(instr.getAddress())
	if fun:
		dump = extract_function_entry(instr,fun)
		if dump:
			all.append(dump)
		continue

args = getScriptArgs()
if len(args) >= 2:
	print('Usage: analyzer.py [Output extension]')
ext = args[0] if len(args) == 1 else 'json'

# Open a file in write mode ('w') and dump the data
outfile = currentProgram.getExecutablePath() + '.' + ext
with open(outfile, "w") as json_file:
    json.dump(all, json_file, indent=2)
