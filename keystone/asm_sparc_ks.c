/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/sparc.h>

#include "keystone.c"
static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	switch (a->bits) {
	case 32:
		mode = KS_MODE_SPARC32;
		break;
	case 64:
		mode = KS_MODE_SPARC64;
		break;
	}
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, KS_ARCH_SPARC, mode);
}

RzAsmPlugin rz_asm_plugin_sparc_ks = {
	.name = "sparc.ks",
	.desc = "sparc keystone assembler",
	.license = "GPL",
	.arch = "sparc",
	.bits = 32|64,
	.assemble = &assemble,
};

#ifndef CORELIB
struct rz_lib_struct_t rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_sparc_ks,
	.version = RZ_VERSION
};
#endif
