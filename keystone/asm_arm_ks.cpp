/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/arm.h>
#include "keystone_priv.h"

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ks_arch arch = KS_ARCH_ARM;
	ks_mode mode = KS_MODE_ARM;
	switch (a->bits) {
	case 16:
		mode = KS_MODE_THUMB;
		break;
	case 32:
		break;
	case 64:
		arch = KS_ARCH_ARM64;
		mode = KS_MODE_LITTLE_ENDIAN;
		a->big_endian = false;
		break;
	default:
		RZ_LOG_ERROR("invalid arch bits.\n");
		return -1;
	}
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble(a, ao, str, arch, mode);
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_arm_ks = {
	.name = "arm.ks",
	.arch = "arm",
	.author = nullptr,
	.version = nullptr,
	.cpus = nullptr,
	.desc = "ARM keystone assembler",
	.license = "GPL",
	.bits = 16 | 32 | 64,
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
RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_arm_ks,
	.version = RZ_VERSION,
	.free = nullptr,
};
#endif

#ifdef __cplusplus
}
#endif
