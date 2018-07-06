CERT_FILE=matls_cert.crt
CA_CERT_FILE=ca_carol.pem
KEY_FILE=matls_priv.pem

CLIENT=client
SERVER=server
GCC=gcc
#CFLAGS=-DMB_DEBUG -DDEBUG -o 
CFLAGS=-o 
CLIENT_SRC=client.c
SERVER_SRC=server.c
FLAGS=-I/home/versatile/openssl-matls-lib/include -L/home/versatile/openssl-matls-lib/lib
#FLAGS=-I/home/versatile/openssl_lib/include -L/home/versatile/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=5017
NUM_OF_THREADS=1

default: matls

matls:
	${GCC} -DMATLS ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

split:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

sstart:
	./${SERVER} ${PORT} ${CERT_FILE} ${KEY_FILE}

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${SERVER}
