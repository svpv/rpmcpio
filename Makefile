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
SHARED = -fpic -shared -Wl,-soname=$(SONAME) -Wl,--no-undefined
LTO = -flto
LIBS = -lz -llzma
DEFS =

$(SONAME): $(SRC) $(HDR)
	$(CC) $(RPM_OPT_FLAGS) $(LTO) $(DEFS) $(SHARED) -o $@ $(SRC) $(LIBS)
example: example.c rpmcpio.h lib$(NAME).so
	$(CC) $(RPM_OPT_FLAGS) -o $@ -I. $< -L. -l$(NAME) -Wl,-rpath,$$PWD

zreader: zreader.c zreader.h reada.c reada.h
	$(CC) $(RPM_OPT_FLAGS) $(DEFS) -DZREADER_MAIN -o $@ zreader.c reada.c $(LIBS)

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
