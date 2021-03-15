#include <yxml.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <rz_analysis.h>

#define XMLBUFSIZE 4096

//for debugging
FILE *fp2;

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

int parse_svd(const char *file) {
	void *xml_buf = malloc(XMLBUFSIZE);
	yxml_t x;
	yxml_init(&x, xml_buf, XMLBUFSIZE);

	char namebuf[64], *namecur = NULL;
	char descbuf[64], *desccur = NULL;
	char bitoffbuf[64], *bitoffcurr = NULL;

	fp2 = fopen("/home/cjunior/file", "w+");

	char *doc = rz_file_slurp(file, NULL);
	for (; *doc; doc++) {
		if (!doc) {
			break;
		}
		yxml_ret_t r = yxml_parse(&x, *doc);
		if (r < 0) {
			eprintf("Parsing error at :%" PRIu32 ":%" PRIu64 " byte offset %" PRIu64 "\n",
				x.line, x.byte, x.total);
		}

		switch (r) {
		case YXML_ELEMSTART:
			if (!strcmp(x.elem, "name"))
				namecur = namebuf;
			if (!strcmp(x.elem, "description"))
				desccur = descbuf;
			if (!strcmp(x.elem, "bitOffset"))
				bitoffcurr = bitoffbuf;
			break;
		case YXML_CONTENT:
			if (!strcmp(x.elem, "name"))
				strcat(namebuf, x.data);
			if (!strcmp(x.elem, "description"))
				strcat(descbuf, x.data);
			if (!strcmp(x.elem, "bitOffset"))
				strcat(bitoffbuf, x.data);
			break;
		case YXML_ATTREND:
			if (namecur)
				namecur = NULL;
			if (descbuf)
				desccur = NULL;
			if (bitoffbuf)
				bitoffcurr = NULL;
			break;
		}
		fprintf(fp2, "%s %s %s \n", namebuf, descbuf, bitoffbuf);
	}
}

RZ_IPI RzCmdStatus rz_cmd_svd_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	parse_svd(argv[1]);
	return RZ_CMD_STATUS_OK;
}

static bool rz_cmd_svd_init(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		rz_warn_if_reached();
		return false;
	}

	RzCmdDesc *svd = rz_cmd_desc_argv_new(rcmd, root_cd, "svd", rz_cmd_svd_handler, &svd_usage);
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
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_svd,
	.version = RZ_VERSION,
	.pkgname = "rz-svd"
};
#endif
