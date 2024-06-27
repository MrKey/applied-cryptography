### Build

Note: OpenSSL paths should be updated in the `Makefile` with local values.

```sh
make des_cbc
make des_cfb
make mac_des_cbc
```

### Usage

Use STDIN, STDOUT and STDERR redirections, for example:

```sh
des_cbc -e -k 0011223344556677 -i 0000000000000000 < plain.txt > encrypted.bin
```

```sh
des_cbc --help
des_cfb --help
mac_des_cbc --help
```
