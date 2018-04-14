NAME = rpmcpio
SONAME = lib$(NAME).so.0

all: lib$(NAME).so example
lib$(NAME).so: $(SONAME)
	ln -sf $< $@
clean:
	rm -f lib$(NAME).so $(SONAME) example zreader

SRC = rpmcpio.c header.c zreader.c reada.c
HDR = rpmcpio.h header.h zreader.h reada.h errexit.h

RPM_OPT_FLAGS ?= -O2 -g -Wall
STD = -std=gnu11 -D_GNU_SOURCE
LFS = $(shell getconf LFS_CFLAGS)
LTO = -flto
COMPILE = $(CC) $(RPM_OPT_FLAGS) $(STD) $(LFS) $(LTO)

SHARED = -fpic -shared -Wl,-soname=$(SONAME) -Wl,--no-undefined
LIBS = -lz -llzma

$(SONAME): $(SRC) $(HDR)
	$(COMPILE) -o $@ $(SHARED) $(SRC) $(LIBS)
example: example.c rpmcpio.h lib$(NAME).so
	$(COMPILE) -o $@ -I. $< -L. -l$(NAME) -Wl,-rpath,$$PWD

zreader: zreader.c zreader.h reada.c reada.h
	$(COMPILE) -o $@ -DZREADER_MAIN zreader.c reada.c $(LIBS)

check: zreader
	: simple decompression
	for zprog in gzip lzma xz; do \
	out=`echo foo |$$zprog |./zreader $$zprog` && \
		[ "$$out" = foo ] || exit 1; done
	: concatenated streams
	for zprog in gzip xz; do \
	out=`(echo -n foo |$$zprog && echo bar |$$zprog) |./zreader $$zprog` && \
		[ "$$out" = foobar ] || exit 1; done
	: FAILURES EXPECTED: non-concatenatable streams
	for zprog in lzma; do \
	out=`(echo -n foo |$$zprog && echo bar |$$zprog) |./zreader $$zprog` && \
		exit 1 || :; done
	: FAILURES EXPECTED: no trailing garbage
	for zprog in gzip lzma xz; do \
	out=`(echo foo |$$zprog && echo bar) |./zreader $$zprog` && \
		exit 1 || :; done
