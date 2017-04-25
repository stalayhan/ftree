#
# ftree
#
# See LICENSE file for copyright and license details.

CC ?= gcc
LD ?= $(CC)
MIN_GCC_VERSION = "4.9"
# Warn if gcc version is lower than 4.9 (-fstack-protector-strong was introduced in this version)
GCC_VERSION := "`gcc -dumpversion`"
IS_GCC_ABOVE_MIN_VERSION := $(shell expr "$(GCC_VERSION)" ">=" "$(MIN_GCC_VERSION)")
ifeq "$(IS_GCC_ABOVE_MIN_VERSION)" "1"
    CFLAGS = -O2 -pipe -MMD -I. -fPIC -fstack-protector-strong -Wall -Wextra -std=c11 -pedantic-errors -D_XOPEN_SOURCE=500
else
    CFLAGS = -O2 -pipe -MMD -I. -fPIC -fstack-protector -Wall -Wextra -std=c11 -pedantic-errors -D_XOPEN_SOURCE=500
endif

PREFIX ?= $(DESTDIR)/usr/local
LDFLAGS = -Wl,-O1,--sort-common,--as-needed,-z,relro -Wl,-z,now
# LDLIBS = $(shell pkg-config --cflags --libs tap)
TESTS = $(patsubst %.c, %, $(wildcard t/*.c))
HDR = $(wildcard *.h)
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, %.o,$(wildcard *.c))
TOBJ = $(patsubst %, %.o, $(TESTS))

TARGET = "ftree"

%:
	$(CC) $(LDFLAGS) $(TARGET_ARCH) $(filter %.o, $^) $(LDLIBS) -o $@

%.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c $(filter %.c, $^) $(LDLIBS) -o $@

all: $(TARGET) tests

$(TARGET): $(OBJ)

$(OBJ): %.o: %.c $(HDR)

tests: $(TESTS)

$(TESTS): %: %.o $(OBJ)

$(TOBJ): %.o: %.c $(HDR)

install: $(TARGET)
	@printf "\n\t%s\n\n" "installing"
	mkdir -p $(PREFIX)/bin
	install -c $(TARGET) $(prefix)/bin

uninstall:
	rm $(PREFIX)/bin/$(TARGET)

dist: clean
	@printf "\n\t%s\n\n" "creating dist tarball"
	mkdir -p $(TARGET)
	cp -R LICENSE Makefile README.md ${HDR} ${SRC} $(TARGET)
	tar -czf $(TARGET).tar.gz $(TARGET)
	rm -f $(TARGET)

check test: all
	./t/test

clean:
	@printf "\n\t%s\n\n" "cleaning"
	rm -f $(TARGET) $(OBJ) $(TOBJ) $(TESTS) ftree.tar.gz $(wildcard *.d)

-include $(wildcard *.d)
.PHONY: all clean install uninstall dist check test tests
