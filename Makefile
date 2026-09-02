CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror

.PHONY: all clean

all: dirtyfrag-poc run-as-1000

dirtyfrag-poc: dirtyfrag-poc.c
	$(CC) $(CFLAGS) -static -o $@ $<

run-as-1000: run_as_1000.c
	$(CC) $(CFLAGS) -static -o $@ $<

clean:
	rm -f dirtyfrag-poc run-as-1000
