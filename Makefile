PROGNAME=ckrts
VERSION=1.0

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).c
	gcc -DPROGNAME=\"$(PROGNAME)\" \
		-DVERSION=\"$(VERSION)\" \
		$(PROGNAME).c -g -o $(PROGNAME) \
		`pkg-config --libs 'jansson >= 2.9'` \
		-lreadline \
		-Wall

clean:
	rm -f $(PROGNAME) *.o
