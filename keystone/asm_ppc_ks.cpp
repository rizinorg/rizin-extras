/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/ppc.h>
#include "keystone_priv.h"

static void swap_endianness(RzAsmOp *ao) {
	ut8 copy[4];
	ut8 *buf = rz_asm_op_get_buf(ao);
	copy[0] = buf[3];
	copy[1] = buf[2];
	copy[2] = buf[1];
	copy[3] = buf[0];
	rz_asm_op_set_buf(ao, copy, 4);
}

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	bool mnem = true;
	char buffer[128] = { 0 };
	size_t i, j, buffer_max = sizeof(buffer) - 1;
	ks_mode mode = (ks_mode)0;
	switch (a->bits) {
	case 32:
		mode = (ks_mode)((int)KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN);
		break;
	case 64:
		mode = (ks_mode)KS_MODE_PPC64;
		if (a->big_endian) {
			mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
		}
		break;
	default:
		RZ_LOG_ERROR("invalid arch bits.\n");
		return -1;
	}

	// for some reasons keystone on ppc does not accept r0, r1, etc..
	// but accepts directly the register number: r0 = 0x0, r27 = 0x1B, etc..
	// example: addis R7, r31, 0x0011 -> addis 0x7, 0x1F, 0x0011
	// for whatever reason keystone for ppc uses hexadecimal registers..
	for (i = 0, j = 0; i < strlen(str) && j < buffer_max;) {
		if (mnem && IS_WHITESPACE(str[i])) {
			mnem = false;
		} else if (!mnem && (str[i] == 'R' || str[i] == 'r')) {
			if ((IS_WHITESPACE(str[i - 1]) || str[i - 1] == '(' || str[i - 1] == ',')) {
				int reg;
				sscanf(str + i, str[i] == 'R' ? "R%d" : "r%d", &reg);
				j += snprintf(buffer + j, buffer_max - j, "0x%02x", reg);
				i += reg > 9 ? 3 : 2; // R10-R31 : R0-R9
				continue;
			}
		}
		buffer[j] = str[i];
		i++;
		j++;
	}
	int size = keystone_assemble(a, ao, buffer, KS_ARCH_PPC, mode);
	if (size > 0 && !a->big_endian && a->bits == 32) {
		// keystone does not support LE on ppc when 32 bit is set.
		// so we manually swap the 4 bytes.
		swap_endianness(ao);
	}
	return size;
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_ppc_ks = {
	.name = "ppc.ks",
	.arch = "ppc",
	.author = nullptr,
	.version = nullptr,
	.cpus = nullptr,
	.desc = "PowerPC keystone assembler",
	.license = "GPL",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = nullptr,
	.fini = nullptr,
	.disassemble = nullptr,
	.assemble = &assemble,
	.mnemonics = nullptr,
	.features = nullptr,
	.platforms = nullptr,
};

#ifndef CORELIB
struct rz_lib_struct_t rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_ppc_ks,
	.version = RZ_VERSION,
	.free = nullptr,
};
#endif

#ifdef __cplusplus
}
#endif
