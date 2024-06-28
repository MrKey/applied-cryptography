### Build

Note: OpenSSL paths should be updated in the `Makefile` with local values. For example, `-lssl -lcrypto` might work.

```sh
make mkcert
make verifycert
```

### Usage

Use `mkcert.cnf` file for x.509 certificate fields. Generated certificate file is stored in file `cert.pem`. The related private key is stored in file `key.pem`.

To create a self-signed root certificate:
```sh
mkcert
```

To verify a self-signed root certificate `cert.pem`:

```sh
verifycert
```
