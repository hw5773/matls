##
## Makefile for Modification Record

CC=gcc
RM=rm
CFLAGS=-DDEBUG -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl

OUT=test_record
SRC=test_record.c record.c
OBJ=test_record.o record.o

all: $(OBJ)
	$(CC) -o $(OUT) $(OBJ) $(LDFLAGS)

clean:
	$(RM) $(OBJ)

test_record.o: test_record.c
	$(CC) $(CFLAGS) -o $@ -c $<

record.o: record.c
	$(CC) $(CFLAGS) -o $@ -c $<
