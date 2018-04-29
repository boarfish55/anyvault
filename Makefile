PROGNAME=ckrts
VERSION=1.1.3

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).c
	gcc -DPROGNAME=\"$(PROGNAME)\" \
		-DVERSION=\"$(VERSION)\" \
		-D_GNU_SOURCE \
		$(PROGNAME).c -g -o $(PROGNAME) \
		`pkg-config --libs 'jansson >= 2.9'` \
		-lreadline \
		-Wall

$(PROGNAME)-static: $(PROGNAME).c
	gcc -static -DPROGNAME=\"$(PROGNAME)\" \
		-DVERSION=\"$(VERSION)\" \
		-D_GNU_SOURCE \
		$(PROGNAME).c -g \
		-o $(PROGNAME)-static \
		-lreadline -lncurses -ltinfo \
		`pkg-config --static --libs 'jansson >= 2.9'` \
		-Wall

clean:
	rm -f $(PROGNAME) $(PROGNAME)-static *.o
