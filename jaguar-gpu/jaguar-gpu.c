/*
 * Disassembler for the Jaguar GPU/DSP
 * SPDX-FileCopyrightText: 2018 Sebastien Alaiwan
 */

#include <rz_asm.h>
#include <rz_lib.h>

static int read16_BE(const ut8 **b) {
	int val = ((*b)[0] << 8) | ((*b)[1] << 0);
	(*b) += 2;
	return val;
}

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
		rz_strbuf_setf(&op->buf_asm, "add     r%d, r%d", reg1, reg2);
		break;
	case 1:
		rz_strbuf_setf(&op->buf_asm, "addc    r%d, r%d", reg1, reg2);
		break;
	case 2:
		rz_strbuf_setf(&op->buf_asm, "addq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 3:
		rz_strbuf_setf(&op->buf_asm, "addqt   0x%x, r%d", notZero(reg1), reg2);
		break;
	case 4:
		rz_strbuf_setf(&op->buf_asm, "sub     r%d, r%d", reg1, reg2);
		break;
	case 5:
		rz_strbuf_setf(&op->buf_asm, "subc    r%d, r%d", reg1, reg2);
		break;
	case 6:
		rz_strbuf_setf(&op->buf_asm, "subq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 7:
		rz_strbuf_setf(&op->buf_asm, "subqt   0x%x, r%d", notZero(reg1), reg2);
		break;
	case 8:
		rz_strbuf_setf(&op->buf_asm, "neg     r%d", reg2);
		break;
	case 9:
		rz_strbuf_setf(&op->buf_asm, "and     r%d, r%d", reg1, reg2);
		break;
	case 10:
		rz_strbuf_setf(&op->buf_asm, "or      r%d, r%d", reg1, reg2);
		break;
	case 11:
		rz_strbuf_setf(&op->buf_asm, "xor     r%d, r%d", reg1, reg2);
		break;
	case 12:
		rz_strbuf_setf(&op->buf_asm, "not     r%d", reg2);
		break;
	case 13:
		rz_strbuf_setf(&op->buf_asm, "btst    0x%x, r%d", reg1, reg2);
		break;
	case 14:
		rz_strbuf_setf(&op->buf_asm, "bset    0x%x, r%d", reg1, reg2);
		break;
	case 15:
		rz_strbuf_setf(&op->buf_asm, "bclr    0x%x, r%d", reg1, reg2);
		break;
	case 16:
		rz_strbuf_setf(&op->buf_asm, "mult    r%d, r%d", reg1, reg2);
		break;
	case 17:
		rz_strbuf_setf(&op->buf_asm, "imult   r%d, r%d", reg1, reg2);
		break;
	case 18:
		rz_strbuf_setf(&op->buf_asm, "imultn  r%d, r%d", reg1, reg2);
		break;
	case 19:
		rz_strbuf_setf(&op->buf_asm, "resmac  r%d", reg2);
		break;
	case 20:
		rz_strbuf_setf(&op->buf_asm, "imacn   r%d, r%d", reg1, reg2);
		break;
	case 21:
		rz_strbuf_setf(&op->buf_asm, "div     r%d, r%d", reg1, reg2);
		break;
	case 22:
		rz_strbuf_setf(&op->buf_asm, "abs     r%d", reg2);
		break;
	case 23:
		rz_strbuf_setf(&op->buf_asm, "sh      r%d, r%d", reg1, reg2);
		break;
	case 24:
		rz_strbuf_setf(&op->buf_asm, "shlq    0x%x, r%d", 32 - notZero(reg1), reg2);
		break;
	case 25:
		rz_strbuf_setf(&op->buf_asm, "shrq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 26:
		rz_strbuf_setf(&op->buf_asm, "sha     r%d, r%d", reg1, reg2);
		break;
	case 27:
		rz_strbuf_setf(&op->buf_asm, "sharq   0x%x, r%d", notZero(reg1), reg2);
		break;
	case 28:
		rz_strbuf_setf(&op->buf_asm, "ror     r%d, r%d", reg1, reg2);
		break;
	case 29:
		rz_strbuf_setf(&op->buf_asm, "rorq    0x%x, r%d", notZero(reg1), reg2);
		break;
	case 30:
		rz_strbuf_setf(&op->buf_asm, "cmp     r%d, r%d", reg1, reg2);
		break;
	case 31:
		rz_strbuf_setf(&op->buf_asm, "cmpq    0x%x, r%d", reg1, reg2);
		break;
	case 32:
		rz_strbuf_setf(&op->buf_asm, "sat8    r%d", reg2);
		break;
	case 33:
		rz_strbuf_setf(&op->buf_asm, "sat16   r%d", reg2);
		break;
	case 34:
		rz_strbuf_setf(&op->buf_asm, "move    r%d, r%d", reg1, reg2);
		break;
	case 35:
		rz_strbuf_setf(&op->buf_asm, "moveq   0x%x, r%d", reg1, reg2);
		break;
	case 36:
		rz_strbuf_setf(&op->buf_asm, "moveta  r%d, r%d", reg1, reg2);
		break;
	case 37:
		rz_strbuf_setf(&op->buf_asm, "movefa  r%d, r%d", reg1, reg2);
		break;
	case 38: {
		uint low = read16_BE(&p);
		uint high = read16_BE(&p);
		rz_strbuf_setf(&op->buf_asm, "movei   0x%x, r%d", low | (high << 16), reg2);
		break;
	}
	case 39:
		rz_strbuf_setf(&op->buf_asm, "loadb   [r%d], r%d", reg1, reg2);
		break;
	case 40:
		rz_strbuf_setf(&op->buf_asm, "loadw   [r%d], r%d", reg1, reg2);
		break;
	case 41:
		rz_strbuf_setf(&op->buf_asm, "load    [r%d], r%d", reg1, reg2);
		break;
	case 42:
		rz_strbuf_setf(&op->buf_asm, "loadp   [r%d], r%d", reg1, reg2);
		break;
	case 43:
		rz_strbuf_setf(&op->buf_asm, "load    [r14+0x%x], r%d", notZero(reg1) * 4, reg2);
		break;
	case 44:
		rz_strbuf_setf(&op->buf_asm, "load    [r15+0x%x], r%d", notZero(reg1) * 4, reg2);
		break;
	case 45:
		rz_strbuf_setf(&op->buf_asm, "storeb  r%d, [r%d]", reg2, reg1);
		break;
	case 46:
		rz_strbuf_setf(&op->buf_asm, "storew  r%d, [r%d]", reg2, reg1);
		break;
	case 47:
		rz_strbuf_setf(&op->buf_asm, "store   r%d, [r%d]", reg2, reg1);
		break;
	case 48:
		rz_strbuf_setf(&op->buf_asm, "storep  r%d, [r%d]", reg2, reg1);
		break;
	case 49:
		rz_strbuf_setf(&op->buf_asm, "store   r%d, [r14+0x%x]", reg2, notZero(reg1) * 4);
		break;
	case 50:
		rz_strbuf_setf(&op->buf_asm, "store   r%d, [r15+0x%x]", reg2, notZero(reg1) * 4);
		break;
	case 51:
		rz_strbuf_setf(&op->buf_asm, "move    pc, r%d", reg2);
		break;
	case 52:
		rz_strbuf_setf(&op->buf_asm, "j%s     [r%d]", condition(reg2), reg1);
		break;
	case 53:
		rz_strbuf_setf(&op->buf_asm, "j%s     0x%.8X", condition(reg2), pc + ((int8_t)(reg1 << 3) >> 2));
		break;
	case 54:
		rz_strbuf_setf(&op->buf_asm, "mmult   r%d, r%d", reg1, reg2);
		break;
	case 55:
		rz_strbuf_setf(&op->buf_asm, "mtoi    r%d, r%d", reg1, reg2);
		break;
	case 56:
		rz_strbuf_setf(&op->buf_asm, "normi   r%d, r%d", reg1, reg2);
		break;
	case 57:
		rz_strbuf_setf(&op->buf_asm, "nop");
		break;
	case 58:
		rz_strbuf_setf(&op->buf_asm, "load    [r14+r%d], r%d", reg1, reg2);
		break;
	case 59:
		rz_strbuf_setf(&op->buf_asm, "load    [r15+r%d], r%d", reg1, reg2);
		break;
	case 60:
		rz_strbuf_setf(&op->buf_asm, "store   r%d, [r14+r%d]", reg2, reg1);
		break;
	case 61:
		rz_strbuf_setf(&op->buf_asm, "store   r%d, [r15+r%d]", reg2, reg1);
		break;
	case 62:
		rz_strbuf_setf(&op->buf_asm, "sat24   r%d", reg2);
		break;
	case 63: {
		if (reg1 == 0)
			rz_strbuf_setf(&op->buf_asm, "pack    r%d", reg2);
		else if (reg1 == 1)
			rz_strbuf_setf(&op->buf_asm, "unpack    r%d", reg2);
		else
			rz_strbuf_setf(&op->buf_asm, "invalid");
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
