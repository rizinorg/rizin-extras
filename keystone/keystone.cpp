/* radare2-keystone - GPL - Copyright 2016 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <keystone/keystone.h>

static void *oldcur = nullptr;
static ks_engine *ks = nullptr;
static int oldbit = 0;

RZ_IPI int keystone_assemble(RzAsm *a, RzAsmOp *ao, const char *str, ks_arch arch, ks_mode mode) {
	ks_err err = KS_ERR_ARCH;
	bool must_init = false;
	size_t count, size;
	ut8 *insn = nullptr;

	if (!ks_arch_supported(arch)) {
		return -1;
	}

	must_init = true; //! oldcur || (a->cur != oldcur || oldbit != a->bits);
	oldcur = a->cur;
	oldbit = a->bits;

	if (must_init) {
		if (ks) {
			ks_close(ks);
			ks = nullptr;
		}
		err = ks_open(arch, mode, &ks);
		if (err != KS_ERR_OK || !ks) {
			RZ_LOG_ERROR("Cannot initialize keystone %s\n", ks_strerror(err));
			ks_free(insn);
			if (ks) {
				ks_close(ks);
				ks = nullptr;
			}
			return -1;
		}
	}

	if (!ks) {
		ks_free(insn);
		if (ks) {
			ks_close(ks);
			ks = nullptr;
		}
		return -1;
	}
	if (a->syntax == RZ_ASM_SYNTAX_ATT) {
		ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
	} else {
		ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
	}
	int rc = ks_asm(ks, str, a->pc, &insn, &size, &count);
	if (rc) {
		RZ_LOG_ERROR("ks_asm: (%s) %s\n", str, ks_strerror((ks_err)ks_errno(ks)));
		ks_free(insn);
		if (ks) {
			ks_close(ks);
			ks = nullptr;
		}
		return -1;
	}
	rz_asm_op_set_buf(ao, insn, size);
	ks_free(insn);
	if (ks) {
		ks_close(ks);
		ks = nullptr;
	}
	return size;
}
