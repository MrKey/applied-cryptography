#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define KEYSIZE 8
#define KEYBITS KEYSIZE*8
#define BLOCKSIZE 8
#define BLOCKBITS BLOCKSIZE*8
#define EDFLAG_ENCRYPT 0
#define EDFLAG_DECRYPT 1

typedef struct bytebits {
	unsigned int bit7 : 1;
	unsigned int bit6 : 1;
	unsigned int bit5 : 1;
	unsigned int bit4 : 1;
	unsigned int bit3 : 1;
	unsigned int bit2 : 1;
	unsigned int bit1 : 1;
	unsigned int bit0 : 1;
} Bytebits;

void getbits(const char *bytes, char *bits, int n);
void getbytes(const char *bits, char *bytes, int n);
void chain(char buf[], const char cph[], int n);

int main(int argc, char *argv[])
{
	int i, n;
	char buf[BLOCKSIZE], cph[BLOCKSIZE], buf1[BLOCKSIZE];

	const char key[] = "12345678";
	char keybits[KEYBITS];
	char blockbits[BLOCKBITS];

	getbits(key, keybits, KEYSIZE);

#ifdef _DEBUG
	for (i = 0; i < KEYBITS; i++) {
		printf("%d", keybits[i]);
		if ((i+1)%8 == 0) printf(" ");
	}
	printf("\n");
#endif

	setkey(keybits);

	i = 0;
	while ((n = read(0, buf, BLOCKSIZE)) > 0) {
		if (n == BLOCKSIZE) {
			getbits(buf, blockbits, n);
			encrypt(blockbits, EDFLAG_DECRYPT);
			getbytes(blockbits, cph, n);
			if (i > 0) {
				chain(cph, buf1, n);
			}
			memcpy(buf1, buf, n);
			write(1, cph, n);
		} else {
			// nopadding - no stealing (xor last part)
			// encrypt the last ciphertext again, and xor the leftmost bits with the buffer
			getbits(buf1, blockbits, BLOCKSIZE);
			encrypt(blockbits, EDFLAG_ENCRYPT);
			getbytes(blockbits, cph, n);
			chain(buf, cph, n);
			write(1, buf, n);
		}
		++i;
	}
}

/**
 * Get bits for bytes, each bit is a byte with value 0 or 1
 */
void getbits(const char bytes[], char bits[], int n)
{
	Bytebits *bytebits;
	int i, j;

	for (i = 0, j = 0; i < n; ++i, j += 8) {
		bytebits = (Bytebits *) &bytes[i];
	
		bits[0 + j] = (*bytebits).bit0;
		bits[1 + j] = (*bytebits).bit1;
		bits[2 + j] = (*bytebits).bit2;
		bits[3 + j] = (*bytebits).bit3;
		bits[4 + j] = (*bytebits).bit4;
		bits[5 + j] = (*bytebits).bit5;
		bits[6 + j] = (*bytebits).bit6;
		bits[7 + j] = (*bytebits).bit7;
	}
}

void getbytes(const char bits[], char bytes[], int n)
{
	Bytebits *bytebits;
	int i, j;

	for (i = 0, j = 0; i < n; ++i, j += 8) {
		bytebits = (Bytebits *) &bytes[i];

		(*bytebits).bit0 = bits[0 + j];
		(*bytebits).bit1 = bits[1 + j];
		(*bytebits).bit2 = bits[2 + j];
		(*bytebits).bit3 = bits[3 + j];
		(*bytebits).bit4 = bits[4 + j];
		(*bytebits).bit5 = bits[5 + j];
		(*bytebits).bit6 = bits[6 + j];
		(*bytebits).bit7 = bits[7 + j];
	}
}

void chain(char buf[], const char cph[], int n)
{
	for (int i = 0; i < n; ++i)
		buf[i] ^= cph[i];
}

