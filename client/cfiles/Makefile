CC = g++
CFLAGS = -Wall -g
CPPFLAGS = -I../../include

.PHONY: main clean run

main: client.o dispatcher.o crypto.o
	$(CC) $(CFLAGS) -o client client.o dispatcher.o crypto.o mbedtls/libmbedcrypto.a mbedtls/libmbedtls.a mbedtls/libmbedx509.a 
client.o: client.cpp dispatcher.h crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c client.cpp
dispatcher.o: dispatcher.h crypto.h
 
crypto.o: crypto.h

clean:
	rm -f *.o *.pem client

run:
	./client