PROGNAME=secrets
VERSION=1.0

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).c
	gcc -DPROGNAME=\"$(PROGNAME)\" \
		-DVERSION=\"$(VERSION)\" \
		$(PROGNAME).c -g -o $(PROGNAME) \
		`pkg-config --libs 'json-c >= 0.12.1'` \
		-lreadline \
		-Wall

clean:
	rm -f $(PROGNAME) *.o
