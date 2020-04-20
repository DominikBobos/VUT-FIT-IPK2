CC=gcc
CFLAGS= -std=c99 -pedantic -Wall -Wextra

all: ipk-sniffer
	$(CC) $(CFLAGS) -o ipk-sniffer ipk-sniffer.c

run:
	./ipk-sniffer

clean:
	rm -f ipk-sniffer