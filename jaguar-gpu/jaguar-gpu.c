// SPDX-FileCopyrightText: 2018 Sebastien Alaiwan
// SPDX-License-Identifier: LGPL-3.0-only

//  Disassembler for the Jaguar GPU/DSP

#include <rz_asm.h>
#include <rz_lib.h>

static int read16_BE(const ut8 **b) {
	int val = ((*b)[0] << 8) | ((*b)[1] << 0);
	(*b) += 2;
	return val;
}

#define asmprintf(fmt, ...) rz_strbuf_setf(&op->buf_asm, fmt, ##__VA_ARGS__)

static const char *condition(int code) {
	switch (code) {
	case 0:
		return "mp"; /* always */
	case 1:
		return "nz";
	case 2:
		return "z";
	case 4:
		return "nc";
	case 5:
		return "nc/nz";
	case 6:
		return "nc/z";
	case 8:
		return "c";
	case 9:
		return "c/nz";
	case 10:
		return "c/z";
	case 20:
		return "nn";
	case 21:
		return "nn/nz";
	case 22:
		return "nn/z";
	case 24:
		return "n";
	case 25:
		return "n/nz";
	case 26:
		return "n/z";
	case 31:
		return "never";
	default:
		return "?";
	}
};

static int notZero(int val) {
	return val == 0 ? 32 : val;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	const ut8 *p = buf; /* read pointer */

	const uint word = read16_BE(&p);
	const uint opCode = (word >> 10) & 63;
	const uint reg1 = (word >> 5) & 31;
	const uint reg2 = (word >> 0) & 31;

	uint pc = a->pc;

	pc += 2;
	switch (opCode) {
	case 0:
		asmprintf("add     r%d, r%d", reg1, reg2);
		break;
	case 1:
		asmprintf("addc    r%d, r%d", reg1, reg2);
		break;
	case 2:
		asmprintf("addq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 3:
		asmprintf("addqt   0x%x, r%d", notZero(reg1), reg2);
		break;
	case 4:
		asmprintf("sub     r%d, r%d", reg1, reg2);
		break;
	case 5:
		asmprintf("subc    r%d, r%d", reg1, reg2);
		break;
	case 6:
		asmprintf("subq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 7:
		asmprintf("subqt   0x%x, r%d", notZero(reg1), reg2);
		break;
	case 8:
		asmprintf("neg     r%d", reg2);
		break;
	case 9:
		asmprintf("and     r%d, r%d", reg1, reg2);
		break;
	case 10:
		asmprintf("or      r%d, r%d", reg1, reg2);
		break;
	case 11:
		asmprintf("xor     r%d, r%d", reg1, reg2);
		break;
	case 12:
		asmprintf("not     r%d", reg2);
		break;
	case 13:
		asmprintf("btst    0x%x, r%d", reg1, reg2);
		break;
	case 14:
		asmprintf("bset    0x%x, r%d", reg1, reg2);
		break;
	case 15:
		asmprintf("bclr    0x%x, r%d", reg1, reg2);
		break;
	case 16:
		asmprintf("mult    r%d, r%d", reg1, reg2);
		break;
	case 17:
		asmprintf("imult   r%d, r%d", reg1, reg2);
		break;
	case 18:
		asmprintf("imultn  r%d, r%d", reg1, reg2);
		break;
	case 19:
		asmprintf("resmac  r%d", reg2);
		break;
	case 20:
		asmprintf("imacn   r%d, r%d", reg1, reg2);
		break;
	case 21:
		asmprintf("div     r%d, r%d", reg1, reg2);
		break;
	case 22:
		asmprintf("abs     r%d", reg2);
		break;
	case 23:
		asmprintf("sh      r%d, r%d", reg1, reg2);
		break;
	case 24:
		asmprintf("shlq    0x%x, r%d", 32 - notZero(reg1), reg2);
		break;
	case 25:
		asmprintf("shrq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 26:
		asmprintf("sha     r%d, r%d", reg1, reg2);
		break;
	case 27:
		asmprintf("sharq   0x%x, r%d", notZero(reg1), reg2);
		break;
	case 28:
		asmprintf("ror     r%d, r%d", reg1, reg2);
		break;
	case 29:
		asmprintf("rorq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 30:
		asmprintf("cmp     r%d, r%d", reg1, reg2);
		break;
	case 31:
		asmprintf("cmpq    0x%x, r%d", reg1, reg2);
		break;
	case 32:
		asmprintf("sat8    r%d", reg2);
		break;
	case 33:
		asmprintf("sat16   r%d", reg2);
		break;
	case 34:
		asmprintf("move    r%d, r%d", reg1, reg2);
		break;
	case 35:
		asmprintf("moveq   0x%x, r%d", reg1, reg2);
		break;
	case 36:
		asmprintf("moveta  r%d, r%d", reg1, reg2);
		break;
	case 37:
		asmprintf("movefa  r%d, r%d", reg1, reg2);
		break;
	case 38: {
		uint low = read16_BE(&p);
		uint high = read16_BE(&p);
		asmprintf("movei   0x%x, r%d", low | (high << 16), reg2);
		break;
	}
	case 39:
		asmprintf("loadb   [r%d], r%d", reg1, reg2);
		break;
	case 40:
		asmprintf("loadw   [r%d], r%d", reg1, reg2);
		break;
	case 41:
		asmprintf("load    [r%d], r%d", reg1, reg2);
		break;
	case 42:
		asmprintf("loadp   [r%d], r%d", reg1, reg2);
		break;
	case 43:
		asmprintf("load    [r14+0x%x], r%d", notZero(reg1) * 4, reg2);
		break;
	case 44:
		asmprintf("load    [r15+0x%x], r%d", notZero(reg1) * 4, reg2);
		break;
	case 45:
		asmprintf("storeb  r%d, [r%d]", reg2, reg1);
		break;
	case 46:
		asmprintf("storew  r%d, [r%d]", reg2, reg1);
		break;
	case 47:
		asmprintf("store   r%d, [r%d]", reg2, reg1);
		break;
	case 48:
		asmprintf("storep  r%d, [r%d]", reg2, reg1);
		break;
	case 49:
		asmprintf("store   r%d, [r14+0x%x]", reg2, notZero(reg1) * 4);
		break;
	case 50:
		asmprintf("store   r%d, [r15+0x%x]", reg2, notZero(reg1) * 4);
		break;
	case 51:
		asmprintf("move    pc, r%d", reg2);
		break;
	case 52:
		asmprintf("j%s     [r%d]", condition(reg2), reg1);
		break;
	case 53:
		asmprintf("j%s     0x%.8X", condition(reg2), pc + ((int8_t)(reg1 << 3) >> 2));
		break;
	case 54:
		asmprintf("mmult   r%d, r%d", reg1, reg2);
		break;
	case 55:
		asmprintf("mtoi    r%d, r%d", reg1, reg2);
		break;
	case 56:
		asmprintf("normi   r%d, r%d", reg1, reg2);
		break;
	case 57:
		asmprintf("nop");
		break;
	case 58:
		asmprintf("load    [r14+r%d], r%d", reg1, reg2);
		break;
	case 59:
		asmprintf("load    [r15+r%d], r%d", reg1, reg2);
		break;
	case 60:
		asmprintf("store   r%d, [r14+r%d]", reg2, reg1);
		break;
	case 61:
		asmprintf("store   r%d, [r15+r%d]", reg2, reg1);
		break;
	case 62:
		asmprintf("sat24   r%d", reg2);
		break;
	case 63: {
		if (reg1 == 0)
			asmprintf("pack    r%d", reg2);
		else if (reg1 == 1)
			asmprintf("unpack    r%d", reg2);
		else
			asmprintf("invalid");
		break;
	}
	}

	op->size = p - buf;
	rz_strbuf_setbin(&op->buf, buf, op->size);

	return op->size;
}

RzAsmPlugin rz_asm_plugin_jaguar_gpu = {
	.name = "jaguar-gpu",
	.arch = "jaguar-gpu",
	.author = "Sebastien Alaiwan",
	.bits = 32,
	.desc = "Disassembler for the Jaguar GPU",
	.license = "LGPL3",
	.disassemble = &disassemble,
};

#ifndef CORELIB
RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_jaguar_gpu
};
#endif
