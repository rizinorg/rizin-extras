#include <rz_analysis.h>
#include <rz_cmd.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yxml.h>

#define XMLBUFSIZE 4096

typedef struct ta_iter {
	uint8_t yxml_buf[4096];
	yxml_t x;

	const char *start;
	const char *ptr;
	const char *end;

	char regname[10];
	char groupName[10];
	char bitoffset[4];
	char bitwidth[20];
} ta_iter;

static void strcpytrunc(char *dst, const char *src, size_t dstsize) {
	size_t to_copy = strlen(src);
	if (to_copy >= dstsize)
		to_copy = dstsize - 1;
	memcpy(dst, src, to_copy);
	dst[to_copy] = '\0';
}

static const RzCmdDescArg cmd_svd_args[] = {
	{
		.name = "svd file",
		.type = RZ_CMD_ARG_TYPE_STRING,

	},
	{ 0 },
};

static const RzCmdDescHelp svd_usage = {
	.summary = "SVD Plugin for Rizin",
	.args = cmd_svd_args,
};

static inline int ta_iter_done(ta_iter *ta) {
	return *ta->ptr == 0 || ta->ptr >= ta->end;
}

static ta_iter *ta_iter_next(ta_iter *ta) {
	char *tmp;
	yxml_ret_t r = YXML_OK;
	yxml_t ta_x;

	int level = 0;
	char *cur = NULL;
	char value[2048];
	const char *ta_start;
	enum { REGNAME,
		BITWIDTH,
		BITOFFSET } elem_type;

	cur = value;
	value[0] = 0;

	if (!ta->groupName[0]) {
		while (!ta_iter_done(ta) &&
			(yxml_parse(&ta->x, *ta->ptr) != YXML_ELEMSTART ||
				strcasecmp(ta->x.elem, "peripherals"))) {
			ta->ptr++;
		}
		if (ta_iter_done(ta))
			return NULL;
		ta_start = ta->ptr;
		ta_x = ta->x;

		level = 0;
		while (!ta_iter_done(ta) && !ta->groupName[0]) {
			switch ((r = yxml_parse(&ta->x, *ta->ptr))) {
			case YXML_ELEMSTART:
				level += 1;
				if (level == 1 && strcasecmp(ta->x.elem, "groupName") == 0) {
					cur = value;
					*cur = 0;
				}
				break;

			case YXML_ELEMEND:
				level -= 1;
				if (level < 0) {
					return ta_iter_next(ta);
				} else if (level == 1 && cur) {
					strcpytrunc(ta->groupName, value, sizeof(ta->groupName));
					cur = NULL;
					ta->ptr = ta_start;
					ta->x = ta_x;
				}
				break;

			case YXML_CONTENT:
				if (!cur || level != 2) {
					break;
				}
				tmp = ta->x.data;
				while (*tmp && cur < value + sizeof(value)) {
					*cur++ = *tmp++;
				}
				if (cur >= value + sizeof(value)) {
					cur = NULL;
				} else {
					*cur = 0;
				}
				break;
			default:
				break;
			}
			ta->ptr++;
		}
		if (ta_iter_done(ta))
			return NULL;
	}
	assert(ta->groupName[0]);

	level = 0;
	while (!ta_iter_done(ta)) {
		r = yxml_parse(&ta->x, *ta->ptr);

		if (r == YXML_ELEMSTART) {
			level += 1;
			if (level == 3 &&
				strcasecmp(ta->x.elem, "register") == 0) {
				break;
			}

		} else if (r == YXML_ELEMEND) {
			level -= 1;
			if (level < 0) {
				ta->groupName[0] = 0;
				return ta_iter_next(ta);
			}
		}
		ta->ptr++;
	}
	if (ta_iter_done(ta)) {
		return NULL;
	}

	assert(r == YXML_ELEMSTART);

	cur = NULL;
	value[0] = 0;
	elem_type = -1;

	*ta->bitoffset = *ta->regname = *ta->bitwidth = 0;

	for (;;) {
		switch (r) {
		case YXML_ELEMSTART:
			level += 1;
			if (level != 7)
				break;
			else if (strcasecmp(ta->x.elem, "name") == 0) {
				elem_type = REGNAME;
			} else if (strcasecmp(ta->x.elem, "bitWidth") == 0) {
				elem_type = BITWIDTH;
			} else if (strcasecmp(ta->x.elem, "bitOffset") == 0) {
				elem_type = BITOFFSET;
			} else {
				break;
			}
			cur = value;
			*cur = 0;
			break;

		case YXML_ELEMEND:
			level -= 1;
			if (level < 0) {
				ta->groupName[0] = 0;
				return ta_iter_next(ta);
			} else if (level != 6 || !cur) {
				break;
			}
		
			cur = NULL;
			switch (elem_type) {
			case BITOFFSET:
				strcpytrunc(ta->bitoffset, value, sizeof(ta->bitoffset));
				break;
			case BITWIDTH:
				strcpytrunc(ta->bitwidth, value, sizeof(ta->bitwidth));
				break;
			case REGNAME:
				strcpytrunc(ta->regname, value, sizeof(ta->regname));
				break;
			}
			break;

		case YXML_CONTENT:
			if (!cur) {
				break;
			}
			tmp = ta->x.data;
			while (*tmp && cur < value + sizeof(value))
				*cur++ = *tmp++;
			if (cur >= value + sizeof(value))
				cur = NULL;
			else
				*cur = 0;
			break;

		default:
			break;
		}
		if (level == 0) {
			break;
		}
		ta->ptr++;
		if (ta_iter_done(ta)) {
			return NULL;
		}
		r = yxml_parse(&ta->x, *ta->ptr);
	}
	return ta->bitoffset && *ta->regname && *ta->groupName && *ta->bitwidth ? ta : ta_iter_next(ta);
}

static ta_iter *ta_iter_init(ta_iter *ta, const char *file) {
	char *doc = rz_file_slurp(file, NULL);
	int doc_len = rz_file_size(file);

	ta->ptr = ta->start = doc;
	ta->end = ta->start + doc_len;
	yxml_init(&ta->x, ta->yxml_buf, sizeof(ta->yxml_buf));
	ta->groupName[0] = 0;
	return ta_iter_next(ta);
}

static int parse_svd(RzCore *core, const char *file) {
	ta_iter ta_spc, *ta;

	for (ta = ta_iter_init(&ta_spc, file); ta; ta = ta_iter_next(ta)) {
		rz_core_cmdf(core, "f %s.%s %s @ %s", ta->groupName, ta->regname, ta->bitwidth, ta->bitoffset);
	}
	return 1;
}

RZ_IPI RzCmdStatus rz_cmd_svd_handler(RzCore *core, int argc,
	const char **argv) {
	if (argc < 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	parse_svd(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

static bool rz_cmd_svd_init(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		rz_warn_if_reached();
		return false;
	}

	RzCmdDesc *svd = rz_cmd_desc_argv_new(rcmd, root_cd, "svd",
		rz_cmd_svd_handler, &svd_usage);
	if (!svd) {
		rz_warn_if_reached();
		return false;
	}

	return true;
}

RzCorePlugin rz_core_plugin_svd = {
	.name = "rz-svd",
	.desc = "SVD Plugin for Rizin",
	.license = "LGPL3",
	.author = "officialcjunior",
	.init = rz_cmd_svd_init,
};

#ifndef CORELIB
RZ_API RzLibStruct rizin_plugin = { .type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_svd,
	.version = RZ_VERSION,
	.pkgname = "rz-svd" };
#endif