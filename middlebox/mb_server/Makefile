CERT_FILE=matls_cert.crt
CA_CERT_FILE=ca_alice.pem
KEY_FILE=matls_priv.pem

SERVER=mb_server
GCC=gcc
CFLAGS=-DDEBUG -o
SERVER_SRC=mb_server.c
SERVER_OBJ=mb_server.o
FLAGS=-I/home/hwlee/openssl-splittls-lib/include -L/home/hwlee/openssl-splittls-lib/lib
#FLAGS=-I/home/hwlee/openssl_lib/include -L/home/hwlee/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=5678
NUM_OF_THREADS=1

default: server

server:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

sstart:
	./${SERVER} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE}

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${SERVER}
