#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <program> [args...]\n", argv[0]);
		return 2;
	}

	if (getuid() != 0) {
		fprintf(stderr, "%s must be started by the guest root shell\n", argv[0]);
		return 1;
	}

	if (setgroups(0, NULL) < 0 ||
	    setresgid(1000, 1000, 1000) < 0 ||
	    setresuid(1000, 1000, 1000) < 0) {
		fprintf(stderr, "drop privileges: %s\n", strerror(errno));
		return 1;
	}

	execvp(argv[1], &argv[1]);
	fprintf(stderr, "execvp(%s): %s\n", argv[1], strerror(errno));
	return 127;
}
