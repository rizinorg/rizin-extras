// SPDX-FileCopyrightText: 2016 saucec0de
// SPDX-License-Identifier: LGPL-3.0-only

// zpu plugin by saucec0de at 2016

#include <rz_asm.h>
#include <rz_lib.h>

#define asmprintf(...) rz_strbuf_setf(&op->buf_asm, ##__VA_ARGS__)

static int disassemble (RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	char arg[100];
	ut8 instr = buf[0];

	op->size = 1;

	// 000x xxxx
	if ( (instr & 0xe0) == 0x00 ) {
		switch ( instr & 0x1f ) {
			case 0x0: asmprintf ("BRK");     break;
			case 0x1: asmprintf ("unknown"); break;
			case 0x2: asmprintf ("PUSHSP");  break;
			case 0x3: asmprintf ("unknown"); break;
			case 0x4: asmprintf ("POPPC");   break;
			case 0x5: asmprintf ("ADD");     break;
			case 0x6: asmprintf ("AND");     break;
			case 0x7: asmprintf ("OR");      break;
			case 0x8: asmprintf ("LOAD");    break;
			case 0x9: asmprintf ("NOT");     break;
			case 0xa: asmprintf ("FLIP");    break;
			case 0xb: asmprintf ("NOP");     break;
			case 0xc: asmprintf ("STORE");   break;
			case 0xd: asmprintf ("POPSP");   break;
			case 0xe: asmprintf ("unknown"); break;
			case 0xf: asmprintf ("unknown"); break;
			default:
		asmprintf ("ADDTOP");
		sprintf (arg, "%d", instr & 0x0f);
		asmprintf (arg);
		break;
		}
		return 1;
	}
	// 001x xxxx
	if ( (instr & 0xe0) == 0x20 ) {
		asmprintf ("EMULATE");
		sprintf (arg, "%d", instr & 0x1f);
		asmprintf (arg);
		return 1;
	}
	// 010x xxxx
	if ( (instr & 0xe0) == 0x40 ) {
		int val = instr & 0x1f;
		val ^= 0x10;
		if (val == 0) {
			asmprintf ("POP");
			return 1;
		}
		if (val == 1) {
			asmprintf ("POPDOWN");
			return 1;
		}
		asmprintf ("STORESP");
		sprintf (arg, "%d", val);
		asmprintf (arg);
		return 1;
	}
	// 011x xxxx
	if ( (instr & 0xe0) == 0x40 ) {
		int val = instr & 0x1f;
		val ^= 0x10;
		if (val == 0) {
			asmprintf ("DUP");
			return 1;
		}
		if (val == 1) {
			asmprintf ("DUPSTACKB");
			return 1;
		}
		asmprintf ("LOADSP");
		sprintf (arg, "%d", val);
		asmprintf (arg);
		return 1;
	}
	asmprintf ("IM");
	sprintf (arg, "%d", instr & 0x7f);
	asmprintf (arg);
	return 1;
}

RzAsmPlugin rz_asm_plugin_zpu = {
	.name = "zpu",
	.arch = "zpu",
	.license = "LGPL3",
	.bits = 32,
	.desc = "ZPU disassembler",
	.disassemble = &disassemble,
};

#ifndef CORELIB
RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_zpu
};
#endif
