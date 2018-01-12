.SUFFIXES= .c .o

CC=gcc
LD=gcc
RM=rm
CFLAGS=-O -DDEBUG
LDFLAGS=

TARGETS=middlebox

OBJS=middlebox.o \
		ip.o \
		tcp.o \
		udp.o \
		etc.o

SRCS = middlebox.c \
			 ip.c \
			 tcp.c \
			 udp.c \
			 etc.c

all: middlebox

middlebox: $(OBJS)
	$(LD) -o $@ $?

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) $(TARGETS)

middlebox.o: middlebox.h middlebox.c
ip.o: ip.c
tcp.o: tcp.c
udp.o: udp.c
etc.o: etc.c
