CC=gcc
CFLAGS=-Wextra -Wall

rcon: rcon.o
	$(CC) -o rcon rcon.o $(CFLAGS)


clean:
	rm -f rcon rcon.o
