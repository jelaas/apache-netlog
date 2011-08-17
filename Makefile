CC=gcc
CFLAGS=-Wall -Os
LDFLAGS=-static
LDLIBS=-lcurl -lidn  -lrtmp -lssl -lcrypto -lz -ldl -lrt
all:	apache-netlog apache-netlog-unpack aes
aes:	aes.o rijndael.o
apache-netlog:	apache-netlog.o rijndael.o jelopt.o strbase64.o jelist.o http.o
apache-netlog-unpack:	apache-netlog-unpack.o rijndael.o jelopt.o strbase64.o
clean:
	rm -f *.o apache-netlog apache-netlog-unpack aes
install:	all
	mkdir -p $(DESTDIR)/usr/bin
	cp apache-netlog apache-netlog-unpack $(DESTDIR)/usr/bin
