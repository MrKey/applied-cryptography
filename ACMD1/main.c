#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define BLOCKSIZE 8

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

// void block_encrypt(const unsigned char *input, unsigned char *output);
// void string_to_keybits(const char str[], char keybits[]); 

char *getbits(const char byte);

int main(int argc, char *argv[])
{
	/*
	int n;
	char buf[BLOCKSIZE],
		chiper[BLOCKSIZE];

	setkey("12345678");

	while ((n = read(0, buf, BLOCKSIZE)) > 0) {
		if (n == 8) {
			encrypt(buf, 0);
			write(1, buf, n);
		} else {
			write(1, buf, n);
		}
	}
	*/

	char a = 'a';
	char *b;

	b = getbits(a);

	for (int i = 0; i < 8; i++) {
		printf("%d", b[i]);
	}
	printf("\n");
}

void block_encrypt(const unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < BLOCKSIZE; i++)
		output[i] = input[BLOCKSIZE - 1 - i];
}

/**
 * Converts each byte to eight bits
 *
 * Resulting array must be 8 times bigger than input
 */
void bytes_to_bits(const char str[], char keybits[])
{
	
}

/**
 * Return array of 8 bytes with bit values, each byte value is 0 or 1
 */
char *getbits(const char byte)
{
	Bytebits *bytebits = (Bytebits *) &byte;
	char *bits;

	bits = (char *) malloc(sizeof(char) * 8);

	bits[0] = (*bytebits).bit0;
	bits[1] = (*bytebits).bit1;
	bits[2] = (*bytebits).bit2;
	bits[3] = (*bytebits).bit3;
	bits[4] = (*bytebits).bit4;
	bits[5] = (*bytebits).bit5;
	bits[6] = (*bytebits).bit6;
	bits[7] = (*bytebits).bit7;

	return bits;
}

