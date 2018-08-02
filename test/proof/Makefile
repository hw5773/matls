all:
	gcc -o proof_test proof_test.c proof_func.c -I../../openssl-matls-lib/include -L../../openssl-matls-lib/lib -lssl -lcrypto -ldl

verify:
	gcc -o proof_verify proof_verify.c proof_func.c -I../../openssl-matls-lib/include -L../../openssl-matls-lib/lib -lssl -lcrypto -ldl
