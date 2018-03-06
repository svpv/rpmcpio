NAME = rpmcpio
SONAME = lib$(NAME).so.0

all: lib$(NAME).so example
lib$(NAME).so: $(SONAME)
	ln -sf $< $@
clean:
	rm -f lib$(NAME).so $(SONAME) example

SRC = rpmcpio.c
HDR = rpmcpio.h errexit.h

RPM_OPT_FLAGS ?= -O2 -g -Wall
SHARED = -fpic -shared -Wl,-soname=$(SONAME) -Wl,--no-undefined
LTO = -flto
LIBS = -lrpm -lrpmio
DEFS =

$(SONAME): $(SRC) $(HDR)
	$(CC) $(RPM_OPT_FLAGS) $(LTO) $(DEFS) $(SHARED) -o $@ $(SRC) $(LIBS)
example: example.c rpmcpio.h lib$(NAME).so
	$(CC) $(RPM_OPT_FLAGS) -o $@ -I. $< -L. -l$(NAME) -Wl,-rpath,$$PWD
