CERT_FILE=carol_cert.pem
CA_CERT_FILE=ca_carol.pem
KEY_FILE=carol_priv.key

CLIENT=client
SERVER=server
GCC=gcc
CFLAGS=-o
CLIENT_SRC=client.c
SERVER_SRC=server.c
FLAGS=-I/home/hwlee/openssl_lib/include -L/home/hwlee/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=443
NUM_OF_THREADS=1

all: client server

client:
	${GCC} ${CFLAGS} ${CLIENT} ${CLIENT_SRC} ${FLAGS} ${LDFLAGS}

server:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

cstart:
	./${CLIENT} ${HOST} ${PORT} ${NUM_OF_THREADS}

sstart:
	./${SERVER} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE}

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${CLIENT} ${SERVER}
