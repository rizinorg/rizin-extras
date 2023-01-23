/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/sparc.h>
#include "keystone_priv.h"

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	switch (a->bits) {
	case 32:
		mode = KS_MODE_SPARC32;
		break;
	case 64:
		mode = KS_MODE_SPARC64;
		break;
	default:
		RZ_LOG_ERROR("invalid arch bits.\n");
		return -1;
	}
	if (a->big_endian || a->bits == 64) {
		// sparc64 is only BE
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble(a, ao, str, KS_ARCH_SPARC, mode);
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_sparc_ks = {
	.name = "sparc.ks",
	.arch = "sparc",
	.author = nullptr,
	.version = nullptr,
	.cpus = nullptr,
	.desc = "SPARC keystone assembler",
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
	.data = &rz_asm_plugin_sparc_ks,
	.version = RZ_VERSION,
	.free = nullptr,
	.pkgname = nullptr,
};
#endif

#ifdef __cplusplus
}
#endif
