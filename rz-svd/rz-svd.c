#include <rz_core.h>
#include <yxml.h>

#define XMLBUFSIZE 4096
#define VALUESIZE  2048

typedef struct ta_iter {
	uint8_t yxml_buf[XMLBUFSIZE];
	yxml_t x;

	const char *start;
	const char *ptr;
	const char *end;

	char regname[50];
	char baseaddress[50];
	char bitoffset[10];
	char bitwidth[20];
	char description[200];
} ta_iter;

enum { REGISTER_NAME,
	REGISTER_SIZE,
	REGISTER_OFFSET,
	REGISTER_DESCRIPTION,
	PERIPHERAL_BASEADDRESS } elem_type;

static const RzCmdDescArg cmd_svd_args[] = {
	{
		.name = "Path to the SVD file",
		.type = RZ_CMD_ARG_TYPE_FILE,
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

static ta_iter *ta_iter_return(ta_iter *ta, RzCore *core);
static ta_iter *ta_iter_init_vars(ta_iter *ta);
static inline int ta_iter_find_register(ta_iter *ta);
static inline int ta_iter_parse_register(ta_iter *ta, RzCore *core);
static inline int ta_iter_find_baseaddress(ta_iter *ta);

static ta_iter *ta_iter_next(ta_iter *ta, RzCore *core) {
	int ret;

	if (!ta->baseaddress[0]) {
		ta_iter_done(ta);
	}
	while (!ta_iter_done(ta) &&
		(yxml_parse(&ta->x, *ta->ptr) != YXML_ELEMSTART ||
			strcasecmp(ta->x.elem, "peripherals"))) {
		ta->ptr++;
	}
	if (ta_iter_done(ta)) {
		return NULL;
	}

	ret = ta_iter_find_baseaddress(ta);
	if (ret == 1) {
		return ta_iter_next(ta, core);
	}
	if (ta_iter_done(ta)) {
		return NULL;
	}

	if (ta_iter_find_register(ta)) {
		return ta_iter_next(ta, core);
	}
	if (ta_iter_done(ta)) {
		return NULL;
	}

	ta_iter_init_vars(ta);

	ret = ta_iter_parse_register(ta, core);
	if (ret == 1) {
		return ta_iter_next(ta, core);
	} else if (ret == -1) {
		return NULL;
	}

	return ta_iter_return(ta, core);
}

static inline int ta_iter_find_baseaddress(ta_iter *ta) {
	int level = 0;
	yxml_ret_t r = YXML_OK;
	char *cur, *tmp;
	char value[VALUESIZE];
	cur = value;
	value[0] = 0;

	while (!ta_iter_done(ta) && !ta->baseaddress[0]) {
		switch ((r = yxml_parse(&ta->x, *ta->ptr))) {
		case YXML_ELEMSTART:
			level += 1;
			if (level == 2 && strcasecmp(ta->x.elem, "baseAddress") == 0) {
				cur = value;
				*cur = 0;
			}
			break;

		case YXML_ELEMEND:
			level -= 1;
			if (level < 0) {
				return 1;
			} else if (level == 2 && cur) {
				rz_str_ncpy(ta->baseaddress, value, sizeof(ta->baseaddress));
				cur = NULL;
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
	return 0;
}

static inline int ta_iter_parse_register(ta_iter *ta, RzCore *core) {
	int level = 3;
	int address;
	char *cur = NULL, *tmp;
	char value[VALUESIZE];
	value[0] = 0;
	elem_type = -1;
	yxml_ret_t r = YXML_OK;

	for (;;) {
		switch (r) {
		case YXML_ELEMSTART:
			level += 1;
			if (strcmp(ta->x.elem, "baseAddress") == 0 && level == 2) {
				elem_type = PERIPHERAL_BASEADDRESS;
				cur = value;
				*cur = 0;
			}
			if (level != 4) {
				break;
			}
			if (strcasecmp(ta->x.elem, "displayName") == 0) {
				elem_type = REGISTER_NAME;
			} else if (strcasecmp(ta->x.elem, "description") == 0) {
				elem_type = REGISTER_DESCRIPTION;
			} else if (strcasecmp(ta->x.elem, "addressOffset") == 0) {
				elem_type = REGISTER_OFFSET;
			} else if (strcasecmp(ta->x.elem, "size") == 0) {
				elem_type = REGISTER_SIZE;
			} else {
				break;
			}
			cur = value;
			*cur = 0;
			break;

		case YXML_ELEMEND:
			level -= 1;
			if (elem_type == PERIPHERAL_BASEADDRESS) {
				rz_str_ncpy(ta->baseaddress, value, sizeof(ta->baseaddress));
				cur = NULL;
				break;
			}
			if (level < 0) {
				ta->baseaddress[0] = 0;
				return 1;
			} else if (level != 3 || !cur) {
				break;
			}
			cur = NULL;
			switch (elem_type) {
			case REGISTER_OFFSET:
				rz_str_ncpy(ta->bitoffset, value, sizeof(ta->bitoffset));
				break;
			case REGISTER_SIZE:
				rz_str_ncpy(ta->bitwidth, value, sizeof(ta->bitwidth));
				address = rz_num_math(NULL, ta->bitoffset) + rz_num_math(NULL, ta->baseaddress);
				rz_flag_set(core->flags, ta->regname, address, rz_num_math(NULL, ta->bitwidth));
				rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, address, ta->description);
				break;
			case REGISTER_NAME:
				rz_str_ncpy(ta->regname, value, sizeof(ta->regname));
				break;
			case REGISTER_DESCRIPTION:
				rz_str_replace_char(value, '\n', ' ');
				rz_str_ncpy(ta->description, value, sizeof(ta->description));
				break;
			default:
				break;
			}
			break;

		case YXML_CONTENT:
			if (!cur) {
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
		if (level == -1) {
			break;
		}
		ta->ptr++;
		if (ta_iter_done(ta)) {
			return -1;
		}
		r = yxml_parse(&ta->x, *ta->ptr);
	}
	return 0;
}

static inline int ta_iter_find_register(ta_iter *ta) {
	yxml_ret_t r = YXML_OK;
	int level = 0;
	while (!ta_iter_done(ta)) {
		r = yxml_parse(&ta->x, *ta->ptr);

		if (r == YXML_ELEMSTART) {
			level += 1;
			if (level == 1 &&
				strcasecmp(ta->x.elem, "register") == 0) {
				break;
			}

		} else if (r == YXML_ELEMEND) {
			level -= 1;
			if (level < -1) {
				ta->baseaddress[0] = 0;
				return 1;
			}
		}
		ta->ptr++;
	}
	return 0;
}

static ta_iter *ta_iter_return(ta_iter *ta, RzCore *core) {
	if (!ta) {
		return NULL;
	}
	return *ta->bitoffset && *ta->regname && *ta->baseaddress && *ta->bitwidth && *ta->description ? ta : ta_iter_next(ta, core);
}

static ta_iter *ta_iter_init_vars(ta_iter *ta) {
	if (!ta) {
		return NULL;
	}
	*ta->bitoffset = *ta->regname = *ta->bitwidth = *ta->description = 0;
	return ta;
}

static ta_iter *ta_iter_init(ta_iter *ta, const char *file) {
	char *doc = rz_file_slurp(file, NULL);
	if (!doc) {
		eprintf("Failed to open file \"%s\"\n", file);
		return NULL;
	}
	int doc_len = rz_file_size(file);
	if (!doc_len) {
		eprintf("Failed to read the file size \"%s\"\n", file);
		return NULL;
	}
	ta->ptr = ta->start = doc;
	ta->end = ta->start + doc_len;
	yxml_init(&ta->x, ta->yxml_buf, sizeof(ta->yxml_buf));
	ta->baseaddress[0] = 0;
	return ta;
}

static int parse_svd(RzCore *core, const char *file) {
	ta_iter ta_spc, *ta;
	ta = ta_iter_init(&ta_spc, file);
	ta = ta_iter_next(ta, core);
	while (ta) {
		ta = ta_iter_next(ta, core);
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
	.version = "0.1.0",
	.author = "officialcjunior",
	.init = rz_cmd_svd_init,
};

#ifndef CORELIB
RZ_API RzLibStruct rizin_plugin = { .type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_svd,
	.version = RZ_VERSION,
	.pkgname = "rz-svd" };
#endif
