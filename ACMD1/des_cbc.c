#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "mode.h"
#include "getbits.h"

#define KEYSIZE 8
#define KEYBITS KEYSIZE*8
#define BLOCKSIZE 8
#define BLOCKBITS BLOCKSIZE*8
#define EDFLAG_ENCRYPT 0
#define EDFLAG_DECRYPT 1

void chain(char buf[], const char cph[], int n);

int main(int argc, char *argv[])
{
	int i, n, flag;

	char plain[BLOCKSIZE], cipher[BLOCKSIZE], plain_prev[BLOCKSIZE], cipher_prev[BLOCKSIZE];
	char keybits[KEYBITS];
	char blockbits[BLOCKBITS];
	char *key;
	int mode = MODE_ENCRYPT + MODE_NOPAD + MODE_NOPAD_XOR;

	// Get options
	int ch;
	while ((ch = getopt(argc, argv, "dek:ps")) != -1) {
		switch (ch) {
			case 'd': // decrypt
				mode = mode | MODE_DECRYPT;
				break;
			case 'e': // encrypt
				mode = mode & ~MODE_DECRYPT;
				break;
			case 'k': // key value
				key = optarg;
				break;
			case 'p': // pad
				mode = mode & ~MODE_NOPAD | MODE_PAD;
				break;
			case 's': // nopad with stealing
				mode = mode & ~MODE_PAD | MODE_NOPAD_STEAL;
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

	switch (mode) {
		case MODE_ENCRYPT + MODE_PAD:
			// 'cipher' is used both for the previous and current block value as it can be reused in this flow
			memset(cipher, 0, BLOCKSIZE);								// initialization vector
			flag = 0;													// set when padding done for the last block
			while ((n = read(0, plain, BLOCKSIZE)) > 0 || !flag) {
				if (n < BLOCKSIZE) {
					// Pad using PKCS#5 (standard block padding); if (n == 0) then a full block with padding bytes
					memset(plain + n, BLOCKSIZE - n, BLOCKSIZE - n);
					n = BLOCKSIZE;
					flag = 1;
				}
				// CBC full block chaining: C_i = E_k(P_i ^ C_i-1)
				// XOR the current plaintext block with the previous block ciphertext, DES encrypt the result
				chain(plain, cipher, n);								// plain:		`P_i ^ C_i-1`
				getbits(plain, blockbits, n);
				encrypt(blockbits, EDFLAG_ENCRYPT);						// blockbits:	`E_k(P_i ^ C_i-1)`
				getbytes(blockbits, cipher, n);							// cipher:		`C_i = E_k(P_i ^ C_i-1)`
				write(1, cipher, n);
			}
			break;
		case MODE_DECRYPT + MODE_PAD:
			memset(cipher_prev, 0, BLOCKSIZE);							// initialization vector
			flag = 0;													// set after the 1st block
			while ((n = read(0, cipher, BLOCKSIZE)) > 0) {
				// TODO: (n != BLOCKSIZE && padding) -> Error! (invalid block size)
				// CBC full block chaining: P_i = C_i-1 ^ D_k(C_i)
				// Decrypt the current ciphertext block and XOR with the previous ciphertext block to get the plaintext
				getbits(cipher, blockbits, n);							// blockbits: `C_i`
				encrypt(blockbits, EDFLAG_DECRYPT);
				getbytes(blockbits, plain, n);							// plain': `D_k(C_i)`
				chain(plain, cipher_prev, n);							// plain: `P_i = C_i-1 ^ D_k(C_i)`
				memcpy(cipher_prev, cipher, n);
				// It is not yet known whether the current block is not the last one containing padding bytes, thus delay output by one block
				if (flag) {
					write(1, plain_prev, n);
				} else {
					flag = 1;
				}
				memcpy(plain_prev, plain, n);
			}
			// The last block, remove padding bytes from output
			write(1, plain, BLOCKSIZE - *(plain + BLOCKSIZE - 1));
			// TODO: (plain[BLOCKSIZE-n] > BLOCKSIZE) -> Error! (invalid padding specification)
			break;
		case MODE_ENCRYPT + MODE_NOPAD + MODE_NOPAD_XOR:
			// 'cipher' is used both for the previous and current block value as it can be reused in this flow
			memset(cipher, 0, BLOCKSIZE);								// initialization vector
			while ((n = read(0, plain, BLOCKSIZE)) > 0) {
				if (n == BLOCKSIZE) {
					// CBC full block chaining: C_i = E_k(P_i ^ C_i-1)
					// XOR the current plaintext block with the previous block ciphertext, DES encrypt the result
					chain(plain, cipher, n);							// cipher:		`P_i ^ C_i-1`
					getbits(plain, blockbits, n);
					encrypt(blockbits, EDFLAG_ENCRYPT);					// blockbits:	`E_k(P_i ^ C_i-1)`
					getbytes(blockbits, cipher, n);						// cipher:		`C_i = E_k(P_i ^ C_i-1)`
					write(1, cipher, n);
				} else {
					// CBC no padding XOR approach - encrypt the last full block again, then XOR with the trailing bytes
					encrypt(blockbits, EDFLAG_ENCRYPT);					// blockbits:	`E_k(C_i-1)`
					getbytes(blockbits, cipher, n);						// cipher':		`C_i = E_k(C_i-1)`
					chain(cipher, plain, n);							// cipher:		`C_i = P_i ^ E_k(C_i-1)`
					write(1, cipher, n);
				}
			}
			break;
		case MODE_DECRYPT + MODE_NOPAD + MODE_NOPAD_XOR:
			memset(cipher_prev, 0, BLOCKSIZE);							// initialization vector
			while ((n = read(0, cipher, BLOCKSIZE)) > 0) {
				if (n == BLOCKSIZE) {
					// CBC full block chaining: P_i = C_i-1 ^ D_k(C_i)
					// DES decrypt the current ciphertext block and XOR with the previous ciphertext block
					getbits(cipher, blockbits, n);						// cipher:		`C_i`
					encrypt(blockbits, EDFLAG_DECRYPT);
					getbytes(blockbits, plain, n);						// plain':		`D_k(C_i)`
					chain(plain, cipher_prev, n);						// plain:		`P_i = C_i-1 ^ D_k(C_i)`
					memcpy(cipher_prev, cipher, n);
					write(1, plain, n);
				} else {
					// CBC no padding XOR approach - encrypt the last full block again, then XOR with the trailing bytes
					getbits(cipher_prev, blockbits, BLOCKSIZE);
					encrypt(blockbits, EDFLAG_ENCRYPT);					// blockbits:	`E_k(C_i-1)`
					getbytes(blockbits, plain, n);						// plain':		`E_k(C_i-1)`
					chain(plain, cipher, n);							// plain:		`E_k(C_i-1) ^ C_i`
					write(1, plain, n);
				}
			}
			break;
		case MODE_ENCRYPT + MODE_NOPAD + MODE_NOPAD_STEAL:
			break;
		case MODE_DECRYPT + MODE_NOPAD + MODE_NOPAD_STEAL:
			break;
	}
}

void chain(char buf[], const char cph[], int n)
{
	for (int i = 0; i < n; ++i)
		buf[i] ^= cph[i];
}

