/**
 *
 * Copyright (C) 2026 Andrei Rimsa <andrei@cefetmg.br>
 * Copyright (C) 2026 Matheus Dias de Souza Barros <mdias2015.md@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "pin.H"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstdio>

static KNOB<BOOL> KnobContinue(KNOB_MODE_WRITEONCE, "pintool", "c", "0", "Continue analysis (Do not abort on first error)");
static KNOB<UINT32> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool", "v", "0", "Verbose level (0-3)");
static KNOB<std::string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "", "specify log file name");

static USIZE no_endbr_count = 0;

#define MAX_X86_INSTR_SIZE     15
#define MAX_X86_ASM_INS_SIZE   64

#define ENDBR_INSTR_SIZE 4
uint8_t endbr32[ENDBR_INSTR_SIZE] = { 0xF3, 0x0F, 0x1E, 0xFB };
uint8_t endbr64[ENDBR_INSTR_SIZE] = { 0xF3, 0x0F, 0x1E, 0xFA };

std::string program = "[program]";

VOID dump_log(const std::string& msg) {
	std::string filename = KnobLogFile.Value();
	if (filename != "") {
		int fd = open(filename.c_str(), O_WRONLY|O_APPEND|O_CREAT, 0644);
		assert(fd > 0);

		write(fd, msg.c_str(), msg.length());
		close(fd);
	}
}

VOID fatal() {
	std::stringstream ss;
	ss << program
		<< " executed "
		<< no_endbr_count
		<< " indirect jumps/calls without endbr."
		<< std::endl;
	PIN_ERROR(ss.str());
}

BOOL is_ins_notrack(INS ins) {
	xed_decoded_inst_t* xedd = INS_XedDec(ins);
	return xed_operand_values_cet_no_track(xedd);
}

BOOL is_addr_endbr(ADDRINT addr) {
	uint8_t buf[ENDBR_INSTR_SIZE];

	if (PIN_SafeCopy(buf, (VOID*) addr, ENDBR_INSTR_SIZE) != ENDBR_INSTR_SIZE)
		return false;

	return (memcmp(buf, endbr32, ENDBR_INSTR_SIZE) == 0 ||
			memcmp(buf, endbr64, ENDBR_INSTR_SIZE) == 0);
}

std::string function_name(ADDRINT addr) {
	PIN_LockClient();

	RTN rtn = RTN_FindByAddress(addr);
	std::string funcName = RTN_Valid(rtn) ?
		PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_COMPLETE) :
		"unknown";

	INT32 line = 0;
	std::string fileName;
	PIN_GetSourceLocation(addr, NULL, &line, &fileName);

	PIN_UnlockClient();

	std::stringstream ss;
	ss << funcName;
	if (line > 0)
		ss << "{" << fileName << ":" << line << "}";

	return ss.str();
}

std::string disassemble_address(ADDRINT addr) {
	uint8_t buf[MAX_X86_INSTR_SIZE];
	char disasm[MAX_X86_ASM_INS_SIZE];
	xed_decoded_inst_t xed;

	size_t size = PIN_SafeCopy(buf, (VOID*) addr, MAX_X86_INSTR_SIZE);
	ASSERT(size == MAX_X86_INSTR_SIZE, "Unable to copy instruction");

	xed_decoded_inst_zero(&xed);
	xed_decoded_inst_set_mode(&xed, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

	xed_error_enum_t err = xed_decode(&xed, buf, MAX_X86_INSTR_SIZE);
	ASSERT(err == XED_ERROR_NONE, "Unable to decode instruction");

	xed_bool_t okay = xed_format_context(XED_SYNTAX_INTEL, &xed, disasm, sizeof(disasm), addr, nullptr, nullptr);
	ASSERT(okay, "Unable to disassemble instruction");

	return std::string(disasm);
}

VOID check_endbr(ADDRINT srcAddr, ADDRINT dstAddr) {
	if (!is_addr_endbr(dstAddr)) {
		no_endbr_count++;

		if (KnobVerbose.Value() >= 1) {
			std::stringstream ss;
			ss << std::hex
				<< "indirect target without endbr: 0x"
				<< srcAddr;
			if (KnobVerbose.Value() >= 2) {
				ss << " (" << disassemble_address(srcAddr);
				if (KnobVerbose.Value() >= 3)
					ss << " @" << function_name(srcAddr);
				ss << ")";
			}
			ss << " -> 0x" << dstAddr;
			if (KnobVerbose.Value() >= 2) {
				ss << " (" << disassemble_address(dstAddr);
				if (KnobVerbose.Value() >= 3)
					ss << " @" << function_name(dstAddr);
				ss << ")";
			}
			ss << std::endl;

			std::cerr << "*** " << ss.str();
			dump_log(ss.str());
		}

		if (!KnobContinue.Value())
			fatal();
	}
}

VOID ImageLoad(IMG img, VOID* v) {
	if (IMG_IsMainExecutable(img))
		program = IMG_Name(img);
}

VOID Instrument(INS ins, VOID *v) {
	// Ignore instructions that are not indirect calls/jumps
	// or are not marked with notrack.
	if (!(INS_IsIndirectControlFlow(ins) && !is_ins_notrack(ins) &&
			(INS_IsCall(ins) || INS_IsBranch(ins))))
		return;

	// Add the instrumentation.
	INS_InsertCall(
		ins,
		IPOINT_TAKEN_BRANCH,
		(AFUNPTR) check_endbr,
		IARG_ADDRINT, INS_Address(ins),	// source address
		IARG_BRANCH_TARGET_ADDR,		// destination address
		IARG_END);
}

VOID Fini(INT32 code, VOID* v) {
	if (no_endbr_count > 0)
		fatal();
}

int main(int argc, char *argv[]) {
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) {
		std::cerr << "Unable to initialize PIN" << std::endl;
		return 1;
	}

	PIN_AddFiniFunction(Fini, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);
	INS_AddInstrumentFunction(Instrument, 0);

	PIN_StartProgram();
	return 0;
}
