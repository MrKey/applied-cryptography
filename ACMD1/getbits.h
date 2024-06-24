#ifndef _GETBITS_H
#define _GETBITS_H

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

#endif
