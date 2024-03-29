#!/bin/sed -nf
# SPDX-FileCopyrightText: 2022 Jules Maselbas <jmaselbas@kalray.eu>
# SPDX-License-Identifier: LGPL-3.0-only
# Expect opcodes/kv3-opc.c from binutils as input

/^kv3opc_t kv3_v1_optab/,/Number of instructions/{
	/^kv3opc_t kv3_v1_optab/d;
	/Number of instructions/d;
	/{"/{
		N;
		s/ "",//;
		/1, 32,/{
			s/.*{\(".*"\),.*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*{\(&kv3.*\)0}.*\(".*"\).*/{ \1, \5, 1, { \3 }, { \2 }, { \4}, .type = 0, .cond = 0 },/
			s/.*{\(".*"\),.*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*{0}.*\(".*"\).*/{ \1, \4, 1, { \3 }, { \2 }, { kvx_decode_none }, .type = 0, .cond = 0 },/
		};
		/2, 64,/{
			s/.*{\(".*"\),.*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*{\(&kv3.*\)0}.*\(".*"\).*/{ \1, \7, 2, { \3, \5 }, { \2, \4 }, { \6}, .type = 0, .cond = 0 },/
		};
		/3, 96,/{
			s/.*{\(".*"\),.*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*\(0x[0-9a-f]\+\).*{\(&kv3.*\)0}.*\(".*"\).*/{ \1, \9, 3, { \3, \5, \7 }, { \2, \4, \6 }, { \8}, .type = 0, .cond = 0 },/
		};
		p;
	}
};
