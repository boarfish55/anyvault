CC := gcc
PROGNAME = anyvault
VERSION = 2.1.0
DESTDIR ?=
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

# Project-mandatory flags. We *append* to CPPFLAGS/CFLAGS/LDFLAGS so that any
# flags supplied through the environment (notably dpkg-buildflags under Debian:
# hardening, -O2, -D_FORTIFY_SOURCE, -ffile-prefix-map, ...) are preserved
# instead of being clobbered.
#
# Optimization is safe here: every sensitive buffer is cleared through
# wipe_mem()/explicit_bzero(), which the compiler is not permitted to optimize
# away. (An earlier scheme overwrote buffers with random bytes via a plain
# store, which dead-store elimination could legally drop -- hence the old
# caution against -O2. explicit_bzero() removes that hazard.)
CPPFLAGS += -DPROGNAME=\"$(PROGNAME)\" -DVERSION=\"$(VERSION)\" -D_GNU_SOURCE
CFLAGS += -Wall -g -O2 $(shell pkg-config --cflags 'jansson >= 2.9' x11 xtst)
LDFLAGS += -Wl,-z,relro -Wl,-z,now
LDLIBS += $(shell pkg-config --libs 'jansson >= 2.9' x11 xtst) -lreadline

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $(PROGNAME) $(PROGNAME).c \
		$(LDFLAGS) $(LDLIBS)

$(PROGNAME)-static: $(PROGNAME).c
	gcc -static -DPROGNAME=\"$(PROGNAME)\" \
		-DVERSION=\"$(VERSION)\" \
		-D_GNU_SOURCE \
		$(PROGNAME).c -g -O2 \
		-o $(PROGNAME)-static \
		-lreadline -lncurses -ltinfo -pthread \
		`pkg-config --static --libs 'jansson >= 2.9' x11 xtst` \
		-Wall -Wl,-z,relro -Wl,-z,now

install: $(PROGNAME)
	install -D -m 0755 $(PROGNAME) $(DESTDIR)$(BINDIR)/$(PROGNAME)

clean:
	rm -f $(PROGNAME) $(PROGNAME)-static *.o
