CERT_FILE=new_carol.crt
CA_CERT_FILE=ca_carol.pem
KEY_FILE=carol_priv.key

CLIENT=client
SERVER=server
GCC=gcc
CFLAGS=-DMB_DEBUG -DDEBUG -o 
#CFLAGS=-o 
CLIENT_SRC=client.c
SERVER_SRC=server.c
FLAGS=-I/home/hwlee/openssl-matls-lib/include -L/home/hwlee/openssl-matls-lib/lib
#FLAGS=-I/home/hwlee/openssl_lib/include -L/home/hwlee/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=5500
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
