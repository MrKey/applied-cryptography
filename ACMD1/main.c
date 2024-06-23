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

	char plain[BLOCKSIZE], cipher[BLOCKSIZE], plain1[BLOCKSIZE], cipher1[BLOCKSIZE];
	char keybits[KEYBITS];
	char blockbits[BLOCKBITS];

	char *key;
	int op = OP_ENCRYPT, nopad = 1;
	int firstblock;

	// Get options
	int ch;
	while ((ch = getopt(argc, argv, "dek:p")) != -1) {
		switch (ch) {
			case 'd':
				op = OP_DECRYPT;
				break;
			case 'e':
				op = OP_ENCRYPT;
				break;
			case 'k':
				key = optarg;
				break;
			case 'p':
				nopad = 0;
				break;
		}
	}

	getbits(key, keybits, KEYSIZE);
	setkey(keybits);

#ifdef _DEBUG
	for (i = 0; i < KEYBITS; i++) {
		printf("%d", keybits[i]);
		if ((i+1)%8 == 0) printf(" ");
	}
	printf("\n");
#endif

	switch (op) {
		case OP_DECRYPT:
			// here 'cipher', 'plain' is the current read ciphertext block / decrypted plaintext block, 'cipher1', 'plain1' is the previous block
			memset(cipher1, 0, BLOCKSIZE);								// For the first block use 0 in place of the previous block value
			if (!nopad) firstblock = 1;
			while ((n = read(0, cipher, BLOCKSIZE)) > 0) {
				if (n == BLOCKSIZE) {
					// CBC full block chaining - P_i = C_i-1 ^ D_k(C_i)
					// DES decrypt the current ciphertext block and XOR with the previous ciphertext block
					getbits(cipher, blockbits, n);
					encrypt(blockbits, EDFLAG_DECRYPT);
					getbytes(blockbits, plain, n);						// Actually, it is not yet a plaintext, the plaintext is retrieved in the next step
					chain(plain, cipher1, n);							// Here 'plain' contains the plaintext
					memcpy(cipher1, cipher, n);
					if (nopad) {
						write(1, plain, n);
					} else {
						// Padding in use, the current block might be the last and contain padding bytes. The previous block is certain to contain no padding bytes
						if (!firstblock) {
							write(1, plain1, n);
						} else {
							firstblock = 0;
						}
						memcpy(plain1, plain, n);
					}
				} else {
					// nopadding - no stealing (xor last part)
					// encrypt the last ciphertext again, and xor the leftmost bits with the buffer
					getbits(cipher1, blockbits, BLOCKSIZE);
					encrypt(blockbits, EDFLAG_ENCRYPT);
					getbytes(blockbits, plain, n);						// Actually, it is not yet a plaintext, the plaintext is retrieved in the next step
					chain(plain, cipher, n);							// Here 'plain' contains the plaintext
					write(1, plain, n);
				}
				// TODO (n != BLOCKSIZE && padding) -> Error! (invalid block size)
			}
			// Detect and skip padding bytes from output
			if (!nopad) {
				write(1, plain, BLOCKSIZE - *(plain + BLOCKSIZE - 1));
				// TODO (plain[BLOCKSIZE-n] > BLOCKSIZE) -> Error! (invalid padding specification)
			}
			break;
		case OP_ENCRYPT:
		default:
			// here 'cipher' is reused, the current ciphertext block also can be used as the previous block in the beginning of the next iteration
			memset(cipher, 0, BLOCKSIZE);								// For the first block use 0 in place of the previous block value
			while ((n = read(0, plain, BLOCKSIZE)) > 0 || !nopad) {
				if (n == BLOCKSIZE || !nopad) {
					// Padding necessary
					if (n < BLOCKSIZE) {
						// Padding with PKCS#5 (standard block padding)
						memset(plain + n, BLOCKSIZE - n, BLOCKSIZE - n);
						n = BLOCKSIZE;
						nopad = 1;
					}
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

