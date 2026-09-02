CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror
LDFLAGS ?= -static

.PHONY: all clean

all: dirtyfrag-exploit

dirtyfrag-exploit: dirtyfrag-exploit.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lutil

clean:
	rm -f dirtyfrag-exploit
