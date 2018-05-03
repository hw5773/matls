CERT_FILE=matls_cert.crt
CA_CERT_FILE=ca_alice.pem
KEY_FILE=matls_priv.pem
FORWARD_FILE=forward.txt

SERVER=mb_matls
GCC=gcc
CFLAGS=-DDEBUG -o
SERVER_SRC=mb_server.c mssl.c table.c common.c
SERVER_OBJ=mb_server.o mssl.o table.o common.o
#FLAGS=-I../../openssl-matls-lib/include -L../../openssl-matls-lib/lib
FLAGS=-I/home/hwlee/openssl-matls-lib/include -L/home/hwlee/openssl-matls-lib/lib
#FLAGS=-I/home/hwlee/openssl_lib/include -L/home/hwlee/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=5555
NUM_OF_THREADS=1

default: mb_server

mb_server:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

sstart:
	./${SERVER} ${PORT} ${CERT_FILE} ${KEY_FILE} ${CA_CERT_FILE} ${FORWARD_FILE}

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${SERVER}
