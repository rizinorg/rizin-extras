/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/hexagon.h>
#include "keystone_priv.h"

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble(a, ao, str, KS_ARCH_HEXAGON, mode);
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_hexagon_ks = {
	.name = "hexagon.ks",
	.arch = "hexagon",
	.author = nullptr,
	.version = nullptr,
	.cpus = nullptr,
	.desc = "Hexagon keystone assembler",
	.license = "GPL",
	.bits = 32,
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
	.data = &rz_asm_plugin_hexagon_ks,
	.version = RZ_VERSION,
	.free = nullptr,
	.pkgname = nullptr,
};
#endif

#ifdef __cplusplus
}
#endif
