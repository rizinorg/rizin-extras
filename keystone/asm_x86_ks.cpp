/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/x86.h>
#include "keystone_priv.h"

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	switch (a->bits) {
	case 16:
		mode = KS_MODE_16;
		break;
	case 32:
		mode = KS_MODE_32;
		break;
	case 64:
		mode = KS_MODE_64;
		break;
	default:
		RZ_LOG_ERROR("invalid arch bits.\n");
		return -1;
	}
	return keystone_assemble(a, ao, str, KS_ARCH_X86, mode);
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_x86_ks = {
	.name = "x86.ks",
	.arch = "x86",
	.author = nullptr,
	.version = nullptr,
	.cpus = nullptr,
	.desc = "x86 keystone assembler",
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
struct rz_lib_struct_t rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_ks,
	.version = RZ_VERSION,
	.free = nullptr,
};
#endif

#ifdef __cplusplus
}
#endif
