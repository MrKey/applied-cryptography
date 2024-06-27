#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mode.h"
#include "getbits.h"

#define KEYSIZE 8
#define KEYBITS (KEYSIZE*8)
#define BLOCKSIZE 8
#define BLOCKBITS (BLOCKSIZE*8)
#define UNITSIZE 8
#define EDFLAG_ENCRYPT 0
#define EDFLAG_DECRYPT 1

void chain(char enc[], const char buf[], int n);
void shiftreg(char reg[], int n);
void move(char reg[], const char buf[], int n);

int main(int argc, char *argv[])
{
	int i, n, flag;

	char buf[UNITSIZE], output[UNITSIZE], reg[BLOCKSIZE], enc[BLOCKSIZE];
	char blockbits[BLOCKBITS], keybits[KEYBITS];
	char *key, *iv;
	int mode = MODE_ENCRYPT;
	int unit = UNITSIZE;

	// Get options
	int ch;
	while ((ch = getopt(argc, argv, "edi:k:u:")) != -1) {
		switch (ch) {
			case 'u': // encription unit size, like openssl's des-cfb, des-cfb1, des-cfb8
				if (strcmp(optarg, "1") == 0) {
					unit = 1;
				} else if (strcmp(optarg, "2") == 0) {
					unit = 2;
				} else if (strcmp(optarg, "4") == 0) {
					unit = 4;
				} else if (strcmp(optarg, "8") == 0) {
					unit = 8;
				} else {
					fprintf(stderr, "Invalid unit size");
					exit(1);
				}
				break;
			case 'd': // decrypt
				mode = mode | MODE_DECRYPT;
				break;
			case 'e': // encrypt
				mode = mode & ~MODE_DECRYPT;
				break;
			case 'i': // initialization vector value
				iv = optarg;
				break;
			case 'k': // key value
				key = optarg;
				break;
		}
	}

	getbits(key, keybits, KEYSIZE);
	setkey(keybits);

	switch (mode) {
		case MODE_ENCRYPT:
			memset(reg, 0, BLOCKSIZE);									// initialization vector
			while ((n = read(0, buf, unit)) > 0) {
				// TODO: Padding for UNITSIZE > 1
				getbits(reg, blockbits, BLOCKSIZE);
				encrypt(blockbits, EDFLAG_ENCRYPT);
				getbytes(blockbits, enc, BLOCKSIZE);
				chain(enc, buf, n);
				shiftreg(reg, unit);
				move(reg, enc, n);
				write(1, enc, n);
			}
			break;
		case MODE_DECRYPT:
			memset(reg, 0, BLOCKSIZE);									// initialization vector
			while ((n = read(0, buf, unit)) > 0) {
				// TODO: Padding for UNITSIZE > 1
				getbits(reg, blockbits, BLOCKSIZE);
				encrypt(blockbits, EDFLAG_ENCRYPT);
				getbytes(blockbits, enc, BLOCKSIZE);
				chain(enc, buf, n);
				shiftreg(reg, unit);
				move(reg, buf, n);
				write(1, enc, n);
			}
			break;
	}
}

void chain(char enc[], const char buf[], int n)
{
	for (int i = 0; i < n; ++i)
		enc[i] ^= buf[i];
}

void shiftreg(char reg[], int n)
{
	for (int i = 0; i < BLOCKSIZE - n; ++i)
		reg[i] = reg[i + n];
}

void move(char reg[], const char buf[], int n)
{
	for (int i = 0; i < n; ++i)
		reg[BLOCKSIZE - n + i] = buf[i];
}

