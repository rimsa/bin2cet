#!/usr/bin/env python3

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

import argparse
import json
import re
import subprocess

ENDBR64 = [0xf3, 0x0f, 0x1e, 0xfa]

def extract_sections(input):
	cmd = ['objdump', '-h', input]
	result = subprocess.run(cmd, capture_output=True, text=True)

	sections = {}
	for line in result.stdout.splitlines():
		match = re.search(r'^\s*(\d+)\s*(\.[^\s]+)\s*0*([^\s]+)\s*0*([^\s]+)\s*0*([^\s]+)\s*0*([^\s]+)\s*.*$', line)
		if match:
			idx = match.group(1)
			name = match.group(2)
			size = int(match.group(3),16)
			vma = int(match.group(4),16)
			lma = int(match.group(5),16)
			file_offset = int(match.group(6), 16)
			sections[name] = {
				'address': vma,
				'file_offset': file_offset,
				'size': size
			}

	return sections

def extract_instructions(input, sections):
	cmd = ['objdump', '-d', '--insn-width=16', input]
	result = subprocess.run(cmd, capture_output=True, text=True)

	current_section = None
	instructions = None
	for line in result.stdout.splitlines():
		match = re.search(r'^Disassembly of section (\.[^:]+):\s*$', line)
		if match:
			current_section = sections[match.group(1)]
			continue

		if current_section is not None:
			match = re.search(r'^0*([0-9A-Fa-f]+)\s+<([^>]*)>:\s*$', line)
			if match:
				addr = int(match.group(1),16)
				fnname = match.group(2)

				functions = current_section.setdefault('functions', [])
				fn = { 'name': fnname, 'address': addr, 'instructions': [] }
				instructions = fn['instructions']
				functions.append(fn)
				continue

		if instructions is not None:
			match = re.search(r'^\s*([0-9A-Fa-f]+):\s*(([0-9A-Fa-f]{2}\s)+)\s+(.*)$', line)
			if match:
				addr = int(match.group(1),16)
				bytes = [int(n, 16) for n in match.group(2).split()]
				asm = re.sub(' +', ' ', match.group(4))
				indirect = re.search(r'^[^\s]+\s*\*', asm) is not None

				instructions.append({
					'address': addr,
					'bytes': bytes,
					'asm': asm,
					'indirect': indirect
				})
				continue

def dump_json(sections, output):
	def is_instr_direct_divert_flow(asm):
		return re.search(r'^(ret|j\w+|call)', asm) is not None

	patches = []
	stats = {
		'indirect_control_transfers': {
			'jumps': 0,
			'calls': 0,
		},
		'function_entries': {
			'extracted': 0,
			'total': 0
		}
	}

	for sect_name in sections:
		section = sections[sect_name]

		# Ignore sections without functions.
		if 'functions' not in section:
			continue

		sect_start = section['address']
		sect_end = sect_start + section['size']
		sect_fileoffset = section['file_offset']

		for function in section['functions']:
			fn_name = function['name']
			fn_entry = function['address']
			fn_size = sum(len(instr['bytes']) for instr in function['instructions'])
			fn_end = fn_entry + fn_size

			instr_idx = 0
			instr_count = len(function['instructions'])

			# Check if we can have a function entry patch outside of the plt section.
			if 'plt' not in sect_name and \
					function['instructions'][instr_idx]['bytes'] != ENDBR64:

				stats['function_entries']['total'] += 1
				patch = None

				if fn_size > len(ENDBR64):
					block_size = 0
					instructions = []
					while block_size < len(ENDBR64):
						instr = function['instructions'][instr_idx]
						if is_instr_direct_divert_flow(instr['asm']):
							break

						instructions.append({
							'asm': instr['asm'],
							'content': instr['bytes']
						})
						instr_idx += 1
						block_size += len(instr['bytes'])

					# Check if the next instruction is within bounds.
					if block_size >= len(ENDBR64) and \
							instr_idx < instr_count:
						# The next instruction will also be added to be patched.
						instr = function['instructions'][instr_idx]
						instructions.append({
							'asm': instr['asm'],
							'content': instr['bytes']
						})
						instr_idx += 1
						block_size += len(instr['bytes'])

						# Ensure we are still within function bounds.
						if block_size <= fn_size:
							fn_sect_offset = function['address'] - sect_start
							fn_file_offset = sect_fileoffset + fn_sect_offset

							patch = {
								'patch_type': 'indirect_branch_target',
								'addr': hex(fn_entry),
								'data': {
									'function': fn_name,
									'section': sect_name,
									'section_offset': fn_sect_offset,
									'file_offset': fn_file_offset,
									'instructions': instructions
								}
							}
					
				# If a patch was created, added to the list.
				if patch:
					stats['function_entries']['extracted'] += 1
					patches.append(patch)
				# Otherwise, ignore this function and start from scratch.
				else:
					print(f'Failed to extract function: {fn_name}')
					instr_idx = 0

			while instr_idx < instr_count:
				instr = function['instructions'][instr_idx]
				if instr['indirect'] and re.search(r'jmp|call', instr['asm']):
					instr_addr = instr['address']
					fn_sect_offset = instr['address'] - sect_start
					fn_file_offset = sect_fileoffset + fn_sect_offset

					ptype = 'indirect_jump' if 'jmp' in instr['asm'] else 'indirect_call'
					if ptype == 'indirect_jump':
						stats['indirect_control_transfers']['jumps'] += 1
					else:
						stats['indirect_control_transfers']['calls'] += 1

					patch = {
						'patch_type': ptype,
						'addr': hex(instr_addr),
						'data': {
							'function': fn_name,
							'section': sect_name,
							'section_offset': fn_sect_offset,
							'file_offset': fn_file_offset,
							'instruction': {
								'asm': instr['asm'],
								'content': instr['bytes']
							}
						}
					}
					patches.append(patch)
				instr_idx += 1

	with open(output, 'w') as json_file:
		json.dump(patches, json_file, indent=2)

	print('Extracted indirect jumps: %d' % stats['indirect_control_transfers']['jumps'])
	print('Extracted indirect calls: %d' % stats['indirect_control_transfers']['calls'])
	if stats['function_entries']['extracted'] > 0:
		print('Extracted functions: %d/%d (%.02f%%)' % (stats['function_entries']['extracted'], \
			stats['function_entries']['total'], (float(stats['function_entries']['extracted']) / stats['function_entries']['total'] * 100)))
	else:
		print('Extracted functions: none')

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Analyze binary with objdump')
	parser.add_argument('input_binary', metavar='input-binary', help='Input binary')
	parser.add_argument('output_analysis', metavar='output-analysis', help='Output analysis')

	args = parser.parse_args()
	sections = extract_sections(args.input_binary)
	extract_instructions(args.input_binary, sections)
	dump_json(sections, args.output_analysis)
