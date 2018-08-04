CERT_FILE=matls_cert.crt
CA_CERT_FILE=ca_carol.pem
KEY_FILE=matls_priv.pem

CLIENT=client
SERVER=server
GCC=gcc
#CFLAGS=-DMB_DEBUG -DDEBUG -o 
#CFLAGS=-DDEBUG -DLOGGER -o 
CFLAGS=-DLOGGER -o 
CLIENT_SRC=client.c
SERVER_SRC=server.c
TCP_SERVER_SRC=tcp_server.c
TCP_CLIENT_SRC=tcp_client.c
FLAGS=-I../openssl-matls-lib/include -L../openssl-matls-lib/lib
#FLAGS=-I/home/hwlee/openssl-matls-lib/include -L/home/hwlee/openssl-matls-lib/lib
#FLAGS=-I/home/hwlee/openssl_lib/include -L/home/hwlee/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=www.matls.com
PORT=5017
NUM_OF_THREADS=1

default: matls

matls:
	${GCC} -DMATLS ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${CLIENT} ${CLIENT_SRC} ${FLAGS} ${LDFLAGS}

split:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${CLIENT} ${CLIENT_SRC} ${FLAGS} ${LDFLAGS}

tcp:
	${GCC} ${CFLAGS} ${SERVER} ${TCP_SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${CLIENT} ${TCP_CLIENT_SRC} ${FLAGS} ${LDFLAGS}

sstart:
	./${SERVER} ${PORT} ${CERT_FILE} ${KEY_FILE} ${LOG_FILE}

cstart:
	./${CLIENT} ${HOST} ${PORT} 1 ${LOG_FILE}

tcp_sstart:
	./${SERVER} ${PORT}

tcp_cstart:
	./${CLIENT} ${HOST} ${PORT} 1 ${LOG_FILE}


debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${SERVER} ${CLIENT}
