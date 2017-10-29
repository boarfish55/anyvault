all: secrets

secrets: secrets.c
	gcc secrets.c -g -o secrets \
		`pkg-config --libs 'json-c >= 0.12.1'` \
		-lreadline \
		-Wall

clean:
	rm -f secrets *.o
