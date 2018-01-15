.SUFFIXES= .c .o

CC=gcc
LD=gcc
RM=rm
CFLAGS=-O -DDEBUG
LDFLAGS=

TARGETS=middlebox

OBJS=middlebox.o \
		packet.o \
		hash_function.o \
		hash_table.o \
		etc.o \
		pair_repo.o

SRCS = middlebox.c \
			 packet.c \
			 hash_function.c \
			 hash_table.c \
			 etc.c \
			 pair_repo.c

all: middlebox

middlebox: $(OBJS)
	$(LD) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) $(TARGETS)

middlebox.o: middlebox.h middlebox.c
ip.o: ip.c
tcp.o: tcp.c
udp.o: udp.c
etc.o: etc.c
pair_repo.o: pair_repo.c
