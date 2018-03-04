NAME = rpmcpio
SONAME = lib$(NAME).so.0

all: lib$(NAME).so
lib$(NAME).so: $(SONAME)
	ln -sf $< $@
clean:
	rm -f lib$(NAME).so $(SONAME)

SRC = rpmcpio.c
HDR = rpmcpio.h errexit.h

RPM_OPT_FLAGS ?= -O2 -g -Wall
SHARED = -fpic -shared -Wl,--no-undefined
LTO = -flto
LIBS = -lrpm -lrpmio
DEFS =

$(SONAME): $(SRC) $(HDR)
	$(CC) $(RPM_OPT_FLAGS) $(LTO) $(DEFS) $(SHARED) -o $@ $(SRC) $(LIBS)
