#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "getbits.h"
#include "util.h"

#define KEYSIZE 8
#define KEYBITS (KEYSIZE*8)
#define BLOCKSIZE 8
#define BLOCKBITS (BLOCKSIZE*8)
#define EDFLAG_ENCRYPT 0
#define EDFLAG_DECRYPT 1
#define MACSIZE 8
#define CMAC_R "\x00\x00\x00\x00\x00\x00\x00\x1b" // CMAC constant string for subkey generation, R64 = 0..11011

void chain(char buf[], const char cph[], int n);
void lshift_bits(char bits[], int n);
void usage(char *cmd);

int main(int argc, char *argv[])
{
	int i, n, n1, flag;

	char buf[BLOCKSIZE], buf1[BLOCKSIZE], cph[BLOCKSIZE], k1[BLOCKSIZE], k2[BLOCKSIZE];
	char keybits[KEYBITS];
	char blockbits[BLOCKBITS];
	char key[BLOCKBITS];
	int _key = 0;

	memset(key, 0, BLOCKSIZE);

	// Get options
	int ch;
	while ((ch = getopt(argc, argv, "k:?")) != -1) {
		switch (ch) {
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

	getbits(key, keybits, KEYSIZE);
	setkey(keybits);

	// Subkey Generation
    memset(buf, 0, BLOCKSIZE);
    getbits(buf, blockbits, BLOCKSIZE);
    encrypt(blockbits, EDFLAG_ENCRYPT);
    getbytes(blockbits, cph, BLOCKSIZE);					// Let L = CIPHK(0b).

	lshift_bits(blockbits, 1);								// k1 <<= 1
	getbytes(blockbits, k1, BLOCKSIZE);						// If MSB1(L) = 0, then K1 = L << 1;
    if (cph[0] >> 7 == 1) {
		chain(k1, CMAC_R, BLOCKSIZE);						// Else K1 = (L << 1) ^ Rb; see Sec. 5.3 for the definition of Rb.
	}

	memcpy(k2, k1, BLOCKSIZE);
	getbits(k2, blockbits, BLOCKSIZE);
	lshift_bits(blockbits, 1);								// k2 <<= 1
	getbytes(blockbits, k2, BLOCKSIZE);						// If MSB1(K1) = 0, then K2 = K1 << 1;
	if (k1[0] >> 7 == 1) {
        chain(k2, CMAC_R, BLOCKSIZE);						// Else K2 = (K1 << 1) ^ Rb.
    }

	// 'cph' is used both for the previous and current block value as it can be reused in this flow
	memset(cph, 0, BLOCKSIZE);								// Let C0 = 0b.
	flag = 0;												// set when the last block is processed
	n = read(0, buf, BLOCKSIZE);
	while ((n1 = read(0, buf1, BLOCKSIZE)) > 0 || !flag) {	// Read one block ahead to detect Mn is a full block
		if (n1 == 0 && n == BLOCKSIZE) {					// If Mn* is a complete block, let Mn = K1 ^ Mn*;
			chain(buf, k1, n);
			flag = 1;
		} else if (n < BLOCKSIZE) {							// else, let Mn = K2 ^ (Mn*||10j), where j = nb-Mlen-1.
			// Pad using bits 10..0, since we use bytes it is 1000 000  0000 0000  ..  0000 0000
			memset(buf + n, 0x80, 1);
			memset(buf + n + 1, 0, BLOCKSIZE - n - 1);
			n = BLOCKSIZE;
			flag = 1;
			chain(buf, k2, n);
		}
		// CBC full block chaining: C_i = E_k(P_i ^ C_i-1)
		// XOR the current plaintext block with the previous block ciphertext, DES encrypt the result
		chain(buf, cph, n);							// For i = 1 to n, let Ci = CIPHK(Ci-1 ^ Mi).
		getbits(buf, blockbits, n);
		encrypt(blockbits, EDFLAG_ENCRYPT);
		getbytes(blockbits, cph, n);

		n = n1;
		memcpy(buf, buf1, n1);
	}

	for (i = 0; i < MACSIZE; ++i) {
		printf("%02hhX", cph[i]);
	}
	printf("\n");
}

void chain(char buf[], const char cph[], int n)
{
	for (int i = 0; i < n; ++i)
		buf[i] ^= cph[i];
}

void lshift_bits(char bits[], int n)
{
	int i;
	for (i = 0; i < BLOCKBITS - n; ++i)
		bits[i] = bits[i + n];
	for (i = BLOCKBITS - n; i < BLOCKBITS; ++i)
		bits[i] = 0;
}

void usage(char *cmd)
{
	printf("Calculates MAC using CMAC algorithm with DES-CBC mode.\n");
	printf("usage: %s [-k HEX] [< FILE] [> FILE]\n", cmd);
	printf("\nOptions:\n"
		   "  -k HEX  Secret key in hexadecimal notation. If not provided, generates a random key and outputs to stderr using a 'Key: ' prefix.\n"
		   "\nInput/output:\n"
		   "  < FILE  Retrieve file content for MAC via STDIN.\n"
		   "  > FILE  Store resulting MAC hex string into a file via STDOUT.\n");
}
