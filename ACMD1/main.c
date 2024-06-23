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
#define OP_ENCRYPT 0
#define OP_DECRYPT 1

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

	char plain[BLOCKSIZE], cipher[BLOCKSIZE], cipher1[BLOCKSIZE];
	char keybits[KEYBITS];
	char blockbits[BLOCKBITS];

	const char key[] = "12345678";
	const int op = 1;

	getbits(key, keybits, KEYSIZE);
	setkey(keybits);

#ifdef _DEBUG
	for (i = 0; i < KEYBITS; i++) {
		printf("%d", keybits[i]);
		if ((i+1)%8 == 0) printf(" ");
	}
	printf("\n");
#endif

	memset(cipher, 0, BLOCKSIZE);										// For the first block, use 0 for the XOR operation instead of using a counter together with a conditional expression
	switch (op) {
		case OP_DECRYPT:
			// here 'cipher1' is the current read ciphertext block, 'cipher' is the previous block
			while ((n = read(0, cipher1, BLOCKSIZE)) > 0) {
				if (n == BLOCKSIZE) {
					// CBC full block chaining - P_i = C_i-1 ^ D_k(C_i)
					// DES decrypt the current ciphertext block and XOR with the previous ciphertext block
					getbits(cipher1, blockbits, n);
					encrypt(blockbits, EDFLAG_DECRYPT);
					getbytes(blockbits, plain, n);						// Actually, it is not yet a plaintext, the plaintext is retrieved in the next step
					chain(plain, cipher, n);							// Here 'plain' contains the plaintext
					memcpy(cipher, cipher1, n);
					write(1, plain, n);
				} else {
					// nopadding - no stealing (xor last part)
					// encrypt the last ciphertext again, and xor the leftmost bits with the buffer
					getbits(cipher, blockbits, BLOCKSIZE);
					encrypt(blockbits, EDFLAG_ENCRYPT);
					getbytes(blockbits, plain, n);						// Actually, it is not yet a plaintext, the plaintext is retrieved in the next step
					chain(plain, cipher1, n);							// Here 'plain' contains the plaintext
					write(1, plain, n);
				}
			}
			break;
		case OP_ENCRYPT:
		default:
			// here 'cipher' is reused, the current ciphertext block also can be used as the previous block in the beginning of the next iteration
			while ((n = read(0, plain, BLOCKSIZE)) > 0) {
				if (n == BLOCKSIZE) {
					// CBC full block chaining -- C_i = E_k(P_i ^ C_i-1)
					// XOR the current plaintext block with the previous block ciphertext, DES encrypt the result
					chain(plain, cipher, n);
					getbits(plain, blockbits, n);
					encrypt(blockbits, EDFLAG_ENCRYPT);
					getbytes(blockbits, cipher, n);
					write(1, cipher, n);
				} else {
					// CBC trailing block with no padding (same length) using the XOR approach - encrypt the last full block again, then XOR with the trailing bytes
					encrypt(blockbits, EDFLAG_ENCRYPT);
					getbytes(blockbits, cipher, n);
					chain(cipher, plain, n);
					write(1, cipher, n);
				}
			}
			break;
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

