#!/usr/bin/env python3

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

import argparse
import array
import json
import lief
import os
import re
import subprocess
import sys

ENDBR64 = [0xf3, 0x0f, 0x1e, 0xfa]
NOP = 0x90

pie = False
addr_shift = 0
analysis = []

def apply_lief(input_name, output_name):
    if verbose:
        print("[+] Patching binary with lief")

    binary = lief.parse(input_name)

    if verbose:
        print(f"[+] Adding section to enable CET (IBT and SHSTK)")

    # Add section note to enable CET's IBT and SHSTK.
    propertysec = lief.ELF.Section('.note.gnu.property', lief.ELF.Section.TYPE.NOTE)
    propertysec.add(lief.ELF.Section.FLAGS.ALLOC)
    propertysec.alignment = 8
    propertysec.offset = 0
    propertysec.content = bytearray(b'\x04\x00\x00\x00\x10\x00\x00\x00\x05\x00\x00\x00\x47\x4e\x55\x00\x02\x00\x00\xc0\x04\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00')
    binary.add(propertysec)

    # When adding a new segment to the binary,
    # The text section will be shift by 0x1000
    # which will be corrected when applied e9patch.
    if binary.is_pie:
        global pie, addr_shift
        pie = True
        addr_shift = 0x1000

    section = binary.get_section('.text')
    assert section
    new_text = list(section.content)

    for patch in analysis:
        # Ignore patch type if not a valid strategy.
        if patch['patch_type'] not in strategies:
            continue

        # At this phase, we will only patch function entries.
        if patch['patch_type'] != 'target_address':
            continue

        # Check if we are in the right section and within bounds.
        assert patch['data']['section'] == '.text'
        section_offset = patch['data']['section_offset']
        assert section_offset >= 0 and section_offset < section.size

        instructions = patch['data']['instructions'][:-1]
        assert len(instructions) > 0

        # Check if we are patching the right place.
        content = [byte for instr in instructions for byte in instr['content']]
        size = len(content)
        assert size >= len(ENDBR64)
        data1 = new_text[section_offset:section_offset+size]
        data2 = content
        assert data1 == data2

        if verbose:
            addr = hex(int(re.sub(r'L$', '', patch['addr']),16)+addr_shift)
            asms = ' ; '.join(instr['asm'] for instr in instructions)
            plural = 's' if len(instructions) > 1 else ''
            print(f"[+] Replacing the \"{asms}\" instruction{plural} at {addr} with endbr64")

        # Patch the function entry with ENDB64 and NOPs.
        new_text[section_offset:section_offset+len(ENDBR64)] = ENDBR64
        for idx in range(len(ENDBR64),size):
            new_text[section_offset+idx] = NOP

    # Update the section with the new content and write the binary.
    section.content = new_text

    if verbose:
        print(f"[+] Writing ouput to: {output_name}")

    binary.write(output_name)

def apply_e9patch(input_name, output_rpc, output_name):
    if verbose:
        print('[+] Patching binary with e9patch')
        print(f"[+] Generating rpc file: {output_rpc}")

    id = 0
    trampolin = 0
    patch_count = 0
    with open(output_rpc, 'w') as rpc_file:
        rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"binary\",\"params\":{{\"version\":\"1.0.0\",\"filename\":\"{input_name}\",\"mode\":\"elf.exe\"}},\"id\":{id}}}\n")
        id += 1

        debug = '"--trap-all",' if args.debug else ''
        rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"options\",\"params\":{{\"argv\":[{debug}\"-Oprologue=0\",\"-Oprologue-size=0\",\"-Oepilogue=32\",\"-Oepilogue-size=64\",\"-Oorder=true\",\"-Opeephole=true\",\"-Oscratch-stack=true\",\"--mem-granularity=128\"]}},\"id\":{id}}}\n")
        id += 1

        rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"trampoline\",\"params\":{{\"name\":\"$notrack\",\"template\":[62,\"$instr\"]}},\"id\":{id}}}\n")
        id += 1

        for patch in sorted(analysis, key=lambda x: int(re.sub(r'L$', '', x['addr']),16), reverse=True):
            addr = hex(int(re.sub(r'L$', '', patch['addr']),16)+addr_shift)

            offset = patch['data']['file_offset']
            assert offset >= 0
            offset += addr_shift

            # Ignore patch type if not a valid strategy.
            if patch['patch_type'] not in strategies:
                continue

            match patch['patch_type']:
                # Add the notrack flag to the indirect jump.
                case 'indirect_jump':
                    size = len(patch['data']['instruction']['content'])
                    assert size > 0

                    rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"instruction\",\"params\":{{\"address\":\"{addr}\",\"length\":{size},\"offset\":{offset}}},\"id\":{id}}}\n")
                    id += 1

                    rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"patch\",\"params\":{{\"trampoline\":\"$notrack\",\"offset\":{offset}}},\"id\":{id}}}\n")
                    id += 1
                # Patch the next instruction after the endbr64 (and pads)
                # added by lief.
                case 'target_address':
                    instructions = patch['data']['instructions']
                    last = instructions.pop()

                    content = ''
                    size = 0
                    current_addr = int(re.sub(r'L$', '', patch['addr']),16)+addr_shift
                    for instr in instructions:
                        bytes = str(instr['content']).replace(' ', '')[1:-1]
                        assert len(bytes) > 0

                        if pie and instr['relative']:
                            content += f'{{"reloc":[{bytes}],"addr":"{hex(current_addr)}"}},'
                        else:
                            content += bytes + ','
                        size += len(instr['content'])
                        current_addr += len(instr['content'])
                    assert len(content) > 0

                    last_offset = offset + size
                    last_size = len(last['content'])
                    assert last_size > 0

                    rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"trampoline\",\"params\":{{\"name\":\"$trampolin{trampolin}\",\"template\":[{content}\"$instr\",\"$BREAK\"]}},\"id\":{id}}}\n")
                    id += 1

                    rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"instruction\",\"params\":{{\"address\":\"{hex(current_addr)}\",\"length\":{last_size},\"offset\":{last_offset}}},\"id\":{id}}}\n")
                    id += 1

                    rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"patch\",\"params\":{{\"trampoline\":\"$trampolin{trampolin}\",\"offset\":{last_offset}}},\"id\":{id}}}\n")
                    id += 1
                    trampolin += 1
                case _:
                    raise SystemExit('Invalid patch type')

            patch_count += 1

        rpc_file.write(f"{{\"jsonrpc\":\"2.0\",\"method\":\"emit\",\"params\":{{\"filename\":\"{output_name}\",\"format\":\"binary\"}},\"id\":{id}}}\n")
        id += 1

    if verbose:
        print(f"[+] Executing e9patch with generated {output_rpc}")

    with open(output_rpc, 'r') as rpc_file:
        cmd = ["e9patch"]
        result = subprocess.run(cmd, stdin=rpc_file, capture_output=True, text=True)

        if verbose:
            print('[+] Output of e9patch')
            print(result.stdout)

        match = re.search(rf"num_patched\s*=\s*\d+\s*/\s*{patch_count}\s*\((.*%)\)", result.stdout)
        if not match:
            raise SystemExit('Unable to match patched instructions')

        rate = match.group(1)
        if rate != '100.00%':
            raise SystemExit(f'Patched only {rate} of the instructions')

    if verbose:
        print(f"[+] Writing ouput to: {output_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert binary to CET')
    parser.add_argument('--debug', dest='debug', action='store_true', help='Allow for debugging with GDB')
    parser.add_argument('--keep', dest='keep', action='store_true', help='Keep temporary files')
    parser.add_argument('--verbose', dest='verbose', action='store_true', help='Verbose mode')
    parser.add_argument('--strategies', dest='strategies', type=str, default='target_address,indirect_jump', help='Patching strategies (default: %(default)s)')
    parser.add_argument('input_binary', metavar='input-binary', help='Input binary')
    parser.add_argument('analysis', metavar='analysis', help='Analysis')
    parser.add_argument('output_binary', metavar='output-binary', help='Output binary')

    args = parser.parse_args()
    keep_tmp = args.keep
    verbose = args.verbose

    strategies = [s.strip() for s in args.strategies.split(',')]
    for s in strategies:
        if s not in ['target_address', 'indirect_jump']:
            raise SystemExit(f'Unknown patching strategy: {s}')

    analysis = []
    with open(args.analysis) as json_file:
        analysis = json.load(json_file)

    tmp_file = args.input_binary+'.tmp'
    rpc_file = args.input_binary+'.rpc'

    apply_lief(args.input_binary, tmp_file)
    apply_e9patch(tmp_file, rpc_file, args.output_binary)

    if not keep_tmp:
        if verbose:
            print(f"[+] Removing temporaries")
        os.remove(tmp_file)
        os.remove(rpc_file)

    if verbose:
        print(f"[+] Everything done")
