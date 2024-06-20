#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define BLOCKSIZE 8

void block_encrypt(const unsigned char *input, unsigned char *output);

int main(int argc, char *argv[])
{
	int n;
	unsigned char buf[BLOCKSIZE],
		chiper[BLOCKSIZE];

	while ((n = read(0, buf, BLOCKSIZE)) > 0) {
		if (n == 8) {
			block_encrypt(buf, chiper);
			write(1, chiper, n);
		} else {
			write(1, buf, n);
		}
	}
}

void block_encrypt(const unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < BLOCKSIZE; i++)
		output[i] = input[BLOCKSIZE - 1 - i];
}

