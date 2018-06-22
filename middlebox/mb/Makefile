CERT_FILE=matls_cert.crt
CA_CERT_FILE=ca_alice.pem
KEY_FILE=matls_priv.pem
FORWARD_FILE=forward.txt

SERVER=mb
GCC=gcc
CFLAGS=-DDEBUG -o
#CFLAGS=-o
SERVER_SRC=mb.c mssl.c table.c common.c
SERVER_OBJ=mb.o mssl.o table.o common.o
FLAGS=-I../../openssl-matls-lib/include -L../../openssl-matls-lib/lib
#FLAGS=-I/home/mb2/openssl-matls-lib/include -L/home/mb2/openssl-matls-lib/lib
#FLAGS=-I/home/mb2/openssl_lib/include -L/home/mb2/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=443
NUM_OF_THREADS=1

SERVER_1=mb1
SERVER_2=mb2
SERVER_3=mb3
PORT_1=443
PORT_2=5555
PORT_3=443
FORWARD_FILE_1=forward_1.txt
FORWARD_FILE_2=forward_2.txt
FORWARD_FILE_3=forward_3.txt

default: matls

matls:
	${GCC} -DMATLS ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_1} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_2} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_3} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

split:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_1} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_2} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_3} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

mstart:
	sudo ./${SERVER} ${PORT} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE} 0 0

read:
	./${SERVER_1} ${PORT_1} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE_1} 0 0

write:
	./${SERVER_2} ${PORT_2} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE_2} 0 1

mstart3:
	./${SERVER_3} ${PORT_3} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE_3} 0 0

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${SERVER} ${SERVER_1} ${SERVER_2} ${SERVER_3}
