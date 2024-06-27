#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mode.h"
#include "getbits.h"
#include "util.h"

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

void usage(char *cmd);

int main(int argc, char *argv[])
{
	int i, n;

	char buf[UNITSIZE], reg[BLOCKSIZE], enc[BLOCKSIZE];
	char blockbits[BLOCKBITS], keybits[KEYBITS];
	char key[BLOCKSIZE], iv[BLOCKSIZE];
	int _key = 0, _iv = 0;

	int mode = MODE_ENCRYPT;
	int unit = UNITSIZE;

	memset(key, 0, BLOCKSIZE);
	memset(iv, 0, BLOCKSIZE);

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
			case 'i': // initialization vector HEX
				_iv = 1;
				gethex(iv, optarg, BLOCKSIZE, "IV");
				break;
			case 'k': // key HEX
				_key = 1;
				gethex(key, optarg, BLOCKSIZE, "Key");
				break;
			default:
				usage(argv[0]);
				return 1;
		}
	}

	// Generate random values if not provided
	if (_key == 0) {
		genhex(key, BLOCKSIZE, "Key");
	}
	if (_iv == 0) {
		genhex(iv, BLOCKSIZE, "IV");
	}

	getbits(key, keybits, KEYSIZE);
	setkey(keybits);

	switch (mode) {
		case MODE_ENCRYPT:
			memcpy(reg, iv, BLOCKSIZE);									// initialization vector
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
			memcpy(reg, iv, BLOCKSIZE);									// initialization vector
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

void usage(char *cmd)
{
	printf("Encrypts/decrypts content in DES-CFB mode.\n");
	printf("usage: %s [-ed] [-i HEX] [-k HEX] [-u N] [< infile] [> outfile]\n", cmd);
	printf("\nOptions:\n"
		   "  -d      Decrypt.\n"
		   "  -e      Encrypt (default).\n"
		   "  -k HEX  Secret key in hexadecimal notation. If not provided, generates a random key and outputs to stderr prefixed with 'Key: '.\n"
		   "  -i HEX  Secret initialization vector in hexadecimal notation. If not provided, generates a random value and outputs to stderr prefixed with 'IV: '.\n"
		   "  -u N    CFB shift unit size (in bytes), similar to des-cfb1, des-cfb8. Possible values: 1, 2, 4, 8. Default is 8 to match des-cfb.\n"
		   "\nInput/output:\n"
		   "  < FILE  Retrieve file content to encrypt via STDIN.\n"
		   "  > FILE  Store encrypted content into a file via STDOUT.\n");
}
