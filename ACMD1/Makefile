des_cbc: des_cbc.c mode.h getbits.h getbits.c
	gcc -o des_cbc des_cbc.c getbits.c util.c -lssl -lcrypto
des_cfb: des_cfb.c mode.h getbits.h getbits.c
	gcc -o des_cfb des_cfb.c getbits.c util.c -lssl -lcrypto
mac_des_cbc: mac_des_cbc.c getbits.h getbits.c
	gcc -o mac_des_cbc mac_des_cbc.c getbits.c util.c -lssl -lcrypto
_des_cbc: des_cbc.c mode.h getbits.h getbits.c
	gcc -o des_cbc des_cbc.c getbits.c util.c -I/opt/homebrew/Cellar/openssl@3/3.2.0_1/include -L/opt/homebrew/Cellar/openssl@3/3.2.0_1/lib -lcrypto
_des_cfb: des_cfb.c mode.h getbits.h getbits.c
	gcc -o des_cfb des_cfb.c getbits.c util.c -I/opt/homebrew/Cellar/openssl@3/3.2.0_1/include -L/opt/homebrew/Cellar/openssl@3/3.2.0_1/lib -lcrypto
_mac_des_cbc: mac_des_cbc.c getbits.h getbits.c
	gcc -o mac_des_cbc mac_des_cbc.c getbits.c util.c -I/opt/homebrew/Cellar/openssl@3/3.2.0_1/include -L/opt/homebrew/Cellar/openssl@3/3.2.0_1/lib -lcrypto
