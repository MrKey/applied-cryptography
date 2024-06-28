mkcert: mkcert.c
	gcc -o mkcert mkcert.c -lssl -lcrypto
verifycert: verifycert.c
	gcc -o verifycert verifycert.c -lssl -lcrypto
_mkcert: mkcert.c
	gcc -o mkcert mkcert.c -I/opt/homebrew/Cellar/openssl@3/3.2.0_1/include -L/opt/homebrew/Cellar/openssl@3/3.2.0_1/lib -lcrypto
_verifycert: verifycert.c
	gcc -o verifycert verifycert.c -I/opt/homebrew/Cellar/openssl@3/3.2.0_1/include -L/opt/homebrew/Cellar/openssl@3/3.2.0_1/lib -lcrypto