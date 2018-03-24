CC = gcc
LD = gcc
CFLAGS=-O -DDEBUG -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl -lmssl

TARGETS = test
OBJS = test.o
SRCS = test.c

all: test

test: $(OBJS)
	$(LD) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) $(TARGETS)
