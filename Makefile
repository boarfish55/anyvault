PROGNAME=anyvault
VERSION=2.0.0
DESTDIR=
prefix=~

all: $(PROGNAME)

# Be careful with optimization options. We must make sure nothing will try
# to elimitate the memory wiping code, since the buffer is freed shortly
# after.

$(PROGNAME): $(PROGNAME).c
	gcc -DPROGNAME=\"$(PROGNAME)\" \
		-DVERSION=\"$(VERSION)\" \
		-D_GNU_SOURCE \
		$(PROGNAME).c -g -o $(PROGNAME) \
		`pkg-config --libs 'jansson >= 2.9' x11 xtst` \
		-lreadline \
		-Wall -Wl,-z,relro -Wl,-z,now

$(PROGNAME)-static: $(PROGNAME).c
	gcc -static -DPROGNAME=\"$(PROGNAME)\" \
		-DVERSION=\"$(VERSION)\" \
		-D_GNU_SOURCE \
		$(PROGNAME).c -g \
		-o $(PROGNAME)-static \
		-lreadline -lncurses -ltinfo -pthread \
		`pkg-config --static --libs 'jansson >= 2.9' x11 xtst` \
		-Wall -Wl,-z,relro -Wl,-z,now

install: $(PROGNAME)
	install -D -m 0755 -s $(PROGNAME) $(DESTDIR)$(prefix)/bin/$(PROGNAME)

clean:
	rm -f $(PROGNAME) $(PROGNAME)-static *.o
