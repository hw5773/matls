CERT_FILE=matls_cert.crt
CA_CERT_FILE=ca_alice.pem
KEY_FILE=matls_priv.pem
FORWARD_FILE=forward.txt

SERVER=mb
GCC=gcc
#CFLAGS=-DDEBUG -o
CFLAGS=-DLOGGER -o
SERVER_SRC=mb.c mssl.c table.c common.c logger.c
SRC=mssl.c table.c common.c logger.c
SERVER_OBJ=mb.o mssl.o table.o common.o logger.o
#FLAGS=-I../../openssl-matls-lib/include -L../../openssl-matls-lib/lib
FLAGS=-I/home/dist/openssl-matls-lib/include -L/home/dist/openssl-matls-lib/lib
#FLAGS=-I/home/mb2/openssl_lib/include -L/home/mb2/openssl_lib/lib
#FLAGS=-I/usr/local/include -L/usr/local/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=5555
NUM_OF_THREADS=1

SERVER_1=mb1
SERVER_2=mb2
SERVER_3=mb3
SERVER_4=mb4
SERVER_5=mb5
SERVER_6=mb6
SERVER_7=mb7
SERVER_8=mb8
SERVER_9=mb9
SERVER_10=mb10
SERVER_11=mb11
SERVER_12=mb12
SERVER_13=mb13
SERVER_14=mb14
SERVER_15=mb15
SERVER_16=mb16
PORT_1=5001
PORT_2=5002
PORT_3=5003
PORT_4=5004
PORT_5=5005
PORT_6=5006
PORT_7=5007
PORT_8=5008
PORT_9=5009
PORT_10=5010
PORT_11=5011
PORT_12=5012
PORT_13=5013
PORT_14=5014
PORT_15=5015
PORT_16=5016
FORWARD_FILE_1=forward_1.txt
FORWARD_FILE_2=forward_2.txt
FORWARD_FILE_3=forward_3.txt
FORWARD_FILE_4=forward_4.txt
FORWARD_FILE_5=forward_5.txt
FORWARD_FILE_6=forward_6.txt
FORWARD_FILE_7=forward_7.txt
FORWARD_FILE_8=forward_8.txt
FORWARD_FILE_9=forward_9.txt
FORWARD_FILE_10=forward_10.txt
FORWARD_FILE_11=forward_11.txt
FORWARD_FILE_12=forward_12.txt
FORWARD_FILE_13=forward_13.txt
FORWARD_FILE_14=forward_14.txt
FORWARD_FILE_15=forward_15.txt
FORWARD_FILE_16=forward_16.txt

default: matls

matls:
	${GCC} -DMATLS ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_1} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_2} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_3} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_4} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_5} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_6} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_7} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_8} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_9} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_10} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_11} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_12} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_13} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_14} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_15} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SERVER_16} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

split:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_1} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_2} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_3} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_4} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_5} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_6} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_7} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_8} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_9} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_10} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_11} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_12} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_13} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_14} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_15} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SERVER_16} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

mstart:
	sudo ./${SERVER} ${PORT} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE} 0 0

read:
	./${SERVER_1} ${PORT_1} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE_1} 0 0

write:
	./${SERVER_2} ${PORT_2} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE_2} 0 1

mstart1:
	./${SERVER_1} ${PORT_1} 1.pem 1.key ${FORWARD_FILE_1} 0 0

mstart2:
	./${SERVER_2} ${PORT_2} 2.pem 2.key ${FORWARD_FILE_2} 0 0

mstart3:
	./${SERVER_3} ${PORT_3} 3.pem 3.key ${FORWARD_FILE_3} 0 0

mstart4:
	./${SERVER_4} ${PORT_4} 4.pem 4.key ${FORWARD_FILE_4} 0 0

mstart5:
	./${SERVER_5} ${PORT_5} 5.pem 5.key ${FORWARD_FILE_5} 0 0

mstart6:
	./${SERVER_6} ${PORT_6} 6.pem 6.key ${FORWARD_FILE_6} 0 0

mstart7:
	./${SERVER_7} ${PORT_7} 7.pem 7.key ${FORWARD_FILE_7} 0 0

mstart8:
	./${SERVER_8} ${PORT_8} 8.pem 8.key ${FORWARD_FILE_8} 0 0

mstart9:
	./${SERVER_9} ${PORT_9} 9.pem 9.key ${FORWARD_FILE_9} 0 0

mstart10:
	./${SERVER_10} ${PORT_10} 10.pem 10.key ${FORWARD_FILE_10} 0 0

mstart11:
	./${SERVER_11} ${PORT_11} 11.pem 11.key ${FORWARD_FILE_11} 0 0

mstart12:
	./${SERVER_12} ${PORT_12} 12.pem 12.key ${FORWARD_FILE_12} 0 0

mstart13:
	./${SERVER_13} ${PORT_13} 13.pem 13.key ${FORWARD_FILE_13} 0 0

mstart14:
	./${SERVER_14} ${PORT_14} 14.pem 14.key ${FORWARD_FILE_14} 0 0

mstart15:
	./${SERVER_15} ${PORT_15} 15.pem 15.key ${FORWARD_FILE_15} 0 0

mstart16:
	./${SERVER_16} ${PORT_16} 16.pem 16.key ${FORWARD_FILE_16} 0 0

mstart1w:
	./${SERVER_1} ${PORT_1} 1.pem 1.key ${FORWARD_FILE_1} 0 1

mstart2w:
	./${SERVER_2} ${PORT_2} 2.pem 2.key ${FORWARD_FILE_2} 0 2

mstart3w:
	./${SERVER_3} ${PORT_3} 3.pem 3.key ${FORWARD_FILE_3} 0 3

mstart4w:
	./${SERVER_4} ${PORT_4} 4.pem 4.key ${FORWARD_FILE_4} 0 4

mstart5w:
	./${SERVER_5} ${PORT_5} 5.pem 5.key ${FORWARD_FILE_5} 0 5

mstart6w:
	./${SERVER_6} ${PORT_6} 6.pem 6.key ${FORWARD_FILE_6} 0 6

mstart7w:
	./${SERVER_7} ${PORT_7} 7.pem 7.key ${FORWARD_FILE_7} 0 7

mstart8w:
	./${SERVER_8} ${PORT_8} 8.pem 8.key ${FORWARD_FILE_8} 0 8

mstart9w:
	./${SERVER_9} ${PORT_9} 9.pem 9.key ${FORWARD_FILE_9} 0 9

mstart10w:
	./${SERVER_10} ${PORT_10} 10.pem 10.key ${FORWARD_FILE_10} 0 10

mstart11w:
	./${SERVER_11} ${PORT_11} 11.pem 11.key ${FORWARD_FILE_11} 0 11

mstart12w:
	./${SERVER_12} ${PORT_12} 12.pem 12.key ${FORWARD_FILE_12} 0 12

mstart13w:
	./${SERVER_13} ${PORT_13} 13.pem 13.key ${FORWARD_FILE_13} 0 13

mstart14w:
	./${SERVER_14} ${PORT_14} 14.pem 14.key ${FORWARD_FILE_14} 0 14

mstart15w:
	./${SERVER_15} ${PORT_15} 15.pem 15.key ${FORWARD_FILE_15} 0 15

mstart16w:
	./${SERVER_16} ${PORT_16} 16.pem 16.key ${FORWARD_FILE_16} 0 16

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${SERVER} ${SERVER_1} ${SERVER_2} ${SERVER_3} ${SERVER_4} ${SERVER_5} ${SERVER_6} ${SERVER_7} ${SERVER_8} ${SERVER_9} ${SERVER_10} ${SERVER_11} ${SERVER_12} ${SERVER_13} ${SERVER_14} ${SERVER_15} ${SERVER_16}
