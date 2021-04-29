# $(CC) $(CFLAGS) -o client client.o dispatcher.o crypto.o mbedtls/libmbedcrypto.a mbedtls/libmbedtls.a mbedtls/libmbedx509.a 

CC = g++
CFLAGS = -Wall -g
CPPFLAGS = -I../../include

.PHONY: build clean

build: dispatcher.o crypto.o
dispatcher.o: dispatcher.h crypto.h
crypto.o: crypto.h

clean:
	rm -f *.o *.pem client