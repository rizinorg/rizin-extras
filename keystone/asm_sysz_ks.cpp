/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>
#include <keystone/systemz.h>
#include "keystone_priv.h"

static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	ks_mode mode = (ks_mode)0;
	if (a->big_endian) {
		mode = (ks_mode)((int)mode | KS_MODE_BIG_ENDIAN);
	}
	return keystone_assemble (a, ao, str, KS_ARCH_SYSTEMZ, mode);
}

#ifdef __cplusplus
extern "C" {
#endif

RzAsmPlugin rz_asm_plugin_sysz_ks = {
	.name = "sysz.ks",
	.arch = "sysz",
	.author = nullptr,
	.version = nullptr,
	.cpus = nullptr,
	.desc = "SystemZ keystone assembler (S390X)",
	.license = "GPL",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = nullptr,
	.fini = nullptr,
	.disassemble = nullptr,
	.assemble = &assemble,
	.modify = nullptr,
	.mnemonics = nullptr,
	.features = nullptr,
	.platforms = nullptr,
};

#ifndef CORELIB
struct rz_lib_struct_t rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_sysz_ks,
	.version = RZ_VERSION
};
#endif

#ifdef __cplusplus
}
#endif
