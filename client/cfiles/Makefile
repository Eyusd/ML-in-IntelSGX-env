CC = g++
CFLAGS = -Wall -g
CPPFLAGS = -I../../include

main: client.o dispatcher.o crypto.o
	$(CC) $(CFLAGS) -o client client.o dispatcher.o crypto.o
client.o: client.cpp dispatcher.h crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c client.cpp
dispatcher.o: dispatcher.h crypto.h
 
crypto.o: crypto.h