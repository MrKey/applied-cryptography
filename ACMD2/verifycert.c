#include <stdio.h>

#include <openssl/x509v3.h>
#include <openssl/pem.h>

int main()
{
	const char cert_file[] = "cert.pem";

	X509 *x509;
	x509 = X509_new();

	FILE *f = fopen(cert_file, "r");
	PEM_read_X509(f, &x509, NULL, "");
	fclose(f);

	// check whether certificate issuer and subject are the same
	X509_NAME *issuer_name, *subject_name;
	issuer_name = X509_get_issuer_name(x509);
	subject_name = X509_get_subject_name(x509);

	if (X509_NAME_cmp(issuer_name, subject_name) != 0) {
		fprintf(stderr, "Root Certificate verification failed, issuer does not match subject\n");
		exit(1);
	}

	// check whether a digital signature of the issuer matches the subject’s public key
	EVP_PKEY *pkey;
	pkey = X509_get_pubkey(x509);
	if (X509_verify(x509, pkey) != 1) {
		fprintf(stderr, "Signature validation failed\n");
		exit(1);
	}

	X509_free(x509);
	EVP_PKEY_free(pkey);

	exit(0);
}
