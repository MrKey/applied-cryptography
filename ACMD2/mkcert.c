#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

void readcnf(const char *filename, char **C, char **O, char **OU, char **CN);

int main()
{
	// Read configuration from file mkcert.cnf
	char *x509_field_C = NULL, *x509_field_O = NULL, *x509_field_OU = NULL, *x509_field_CN = NULL;
	readcnf("mkcert.cnf", &x509_field_C, &x509_field_O, &x509_field_OU, &x509_field_CN);

	// This is deprecated use. Use single EVP_RSA_gen() instead!
	/*
	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		perror("EVP_PKEY_new");
		exit(1);
	}

	RSA *rsa;
	rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	if (rsa == NULL) {
		perror("RSA_generate_key");
		exit(1);
	}

	EVP_PKEY_assign_RSA(pkey, rsa);
	*/

	EVP_PKEY *pkey;
	pkey = EVP_RSA_gen(2048);

	X509 *x509;
	x509 = X509_new();

	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); //  Some open-source HTTP servers refuse to accept a certificate with a serial number of '0', which is the default.

	X509_gmtime_adj(X509_get_notBefore(x509), 0); // now
	X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L); // 365 days

	X509_set_pubkey(x509, pkey);

	// Set name and issuer to yourself
	X509_NAME *name;
	name = X509_get_subject_name(x509);

	if (x509_field_C != NULL)
		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)x509_field_C, -1, -1, 0);
	if (x509_field_O != NULL)
		X509_NAME_add_entry_by_txt(name, "0", MBSTRING_ASC, (unsigned char *)x509_field_O, -1, -1, 0);
	if (x509_field_OU != NULL)
		X509_NAME_add_entry_by_txt(name, "0U", MBSTRING_ASC, (unsigned char *)x509_field_OU, -1, -1, 0);
	if (x509_field_CN != NULL)
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)x509_field_CN, -1, -1, 0);

	X509_set_issuer_name(x509, name);
	X509_set_subject_name(x509, name); // Root certificate's issuer and subject fields are the same, and its signature can be validated with its own public key.

	X509_sign(x509, pkey, EVP_sha3_256());

	// Write out to files
	FILE *f = fopen("key.pem", "wb");
	PEM_write_PrivateKey(f, pkey, EVP_aes_128_cbc(), NULL, 0, NULL, "");
	fclose(f);
	f = fopen("cert.pem", "wb");
	PEM_write_X509(f, x509);
	fclose(f);

	X509_free(x509);
	EVP_PKEY_free(pkey);

	exit(0);
}

void readcnf(const char *filename, char **C, char **O, char **OU, char **CN)
{
	size_t l;
	FILE *f = fopen(filename, "r");
	char buf[256], *s;
	while (fgets(buf, 256, f)) {
		if (strncmp(buf, "C:", 2) == 0) {
			s = malloc(l = strlen((buf+2)));
			strcpy(s, buf+2);
			if (s[l-1] == 0x0a) s[l-1] = 0; // Trim retained newline
			*C = s;
			// puts(s);
		}
		if (strncmp(buf, "O:", 2) == 0) {
			s = malloc(l = strlen(buf+2));
			strcpy(s, buf+2);
			if (s[l-1] == 0x0a) s[l-1] = 0; // Trim retained newline
			*O = s;
			// puts(s);
		}
		if (strncmp(buf, "OU:", 3) == 0) {
			s = malloc(l = strlen(buf+3));
			strcpy(s, buf+3);
			if (s[l-1] == 0x0a) s[l-1] = 0; // Trim retained newline
			*OU = s;
			// puts(s);
		}
		if (strncmp(buf, "CN:", 3) == 0) {
			s = malloc(l = strlen(buf+3));
			strcpy(s, buf+3);
			if (s[l-1] == 0x0a) s[l-1] = 0; // Trim retained newline
			*CN = s;
			// puts(s);
		}
	}
	fclose(f);
}
