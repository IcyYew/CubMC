CC=gcc
CFLAGS= -Wall -Wextra

rcon: rcon.o
	$(CC) -o rcon rcon.o

rcon.o: rcon.c
	$(CC) $(CFLAGS) -c rcon.c -o rcon.o


clean:
	rm -f rcon rcon.o
