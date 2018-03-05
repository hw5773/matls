##
## Makefile for Modification Record

CC=gcc
RM=rm
CFLAGS=-DDEBUG -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl

RECORD=test_record
PRF=test_prf
SRC=test_record.c record.c logs.c
ROBJ=test_record.o record.o logs.o
POBJ=test_prf.o prf.o logs.o

all: record prf

record: test_record.o record.o logs.o
	$(CC) -o $(RECORD) $(ROBJ) $(LDFLAGS)

prf: test_prf.o prf.o logs.o
	$(CC) -o $(PRF) $(POBJ) $(LDFLAGS)

clean:
	$(RM) *.o $(PRF) $(RECORD)

test_record.o: test_record.c
	$(CC) $(CFLAGS) -o $@ -c $<

test_prf.o: test_prf.c
	$(CC) $(CFLAGS) -o $@ -c $<

record.o: record.c
	$(CC) $(CFLAGS) -o $@ -c $<

prf.o: prf.c
	$(CC) $(CFLAGS) -o $@ -c $<

logs.o: logs.c
	$(CC) $(CFLAGS) -o $@ -c $<
