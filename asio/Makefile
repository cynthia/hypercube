CC=gcc
CCFLAGS=-Wall -Werror -ggdb #-pg

all: asio.o $(AKEPOLLOBJ)
asio.o: asio.c asio.h $(AKEPOLLHDR)
	$(CC) $(CCFLAGS) $(AKEPOLLDEF) -c asio.c
AKepoll.o: AKepoll.s asio.h AKepoll.h
	$(CC) $(CCFLAGS) -c AKepoll.s
