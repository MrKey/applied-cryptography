#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define BLOCKSIZE 8

int main(int argc, char *argv[])
{
	int n;
	char buf[BLOCKSIZE];

	while ((n = read(0, buf, BLOCKSIZE)) > 0) {
		write(1, buf, n);
	}
}

