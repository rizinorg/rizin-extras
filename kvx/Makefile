# SPDX-FileCopyrightText: 2022 Jules Maselbas <jmaselbas@kalray.eu>
# SPDX-License-Identifier: LGPL-3.0-only

NAME=kvx
RZ_PLUGIN_PATH=$(shell rizin -H RZ_LIBR_PLUGINS)
CFLAGS=-g -fPIC $(shell pkg-config --cflags rz_asm rz_analysis)
LDFLAGS=-shared $(shell pkg-config --libs rz_asm rz_analysis)
SO_EXT=$(shell uname | grep -q Darwin && echo dylib || echo so)
OBJS=kvx-reg.o kvx-dis.o
LIBS=$(NAME)_asm.$(SO_EXT) $(NAME)_analysis.$(SO_EXT)

all: $(LIBS)

%.$(SO_EXT): %.o $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(LIBS) $(OBJS) *.o

install:
	mkdir -p $(RZ_PLUGIN_PATH)
	cp -f $(LIBS) $(RZ_PLUGIN_PATH)

uninstall:
	rm -f $(addprefix $(RZ_PLUGIN_PATH)/, $(LIBS))

.PHONY: all clean install uninstall
