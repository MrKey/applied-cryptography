#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int main(int argc, char *argv[])
{
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

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"LV", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "0", MBSTRING_ASC, (unsigned char *)"Martins Ketners", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "0U", MBSTRING_ASC, (unsigned char *)"Root CA", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"ACMD2", -1, -1, 0);

	X509_set_issuer_name(x509, name);
	X509_set_subject_name(x509, name); // Root certificate's issuer and subject fields are the same, and its signature can be validated with its own public key.

	X509_sign(x509, pkey, EVP_sha3_256());

	// Write out to files
	FILE *f;
	f = fopen("key.pem", "wb");
	PEM_write_PrivateKey(f, pkey, EVP_aes_128_cbc(), NULL, 9, NULL, "");
	fclose(f);
	f = fopen("cert.pem", "wb");
	PEM_write_X509(f, x509);
	fclose(f);

	X509_free(x509);
	EVP_PKEY_free(pkey);

	exit(0);
}
