#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include "util.h"

void gethex(char d[], const char s[], int n, const char name[])
{
	size_t l = strlen(s);
	int i;

	if (l % 2 != 0) {
		fprintf(stderr, "%s: incorrect byte HEX length", name);
		exit(1);
	} if (l < n * 2) {
		fprintf(stderr, "%s: byte HEX too short, padded with 0 to match %d bytes\n", name, n);
	} else if (l > n * 2) {
		fprintf(stderr, "%s: byte HEX too ong, truncated to %d bytes\n", name, n);
	}

	i = sscanf(optarg, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7]);
	if (i * 2 != l) {
		fprintf(stderr, "%s: byte HEX conversion failed at position %d\n", name, i);
		exit(1);
	}
}

void genhex(char d[], int n, const char name[])
{
	int i;

	RAND_bytes((unsigned char *)d, n);
	fprintf(stderr, "%s: ", name);
	for (i = 0; i < n; ++i)
		fprintf(stderr, "%02hhX", d[i]);
	fprintf(stderr, "\n");
}
