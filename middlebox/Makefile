.SUFFIXES= .c .o

CC=gcc
LD=gcc
RM=rm
CFLAGS=-O -DDEBUG
LDFLAGS=

TARGETS=middlebox

OBJS=middlebox.o \
		packet.o \
		hash_table.o \
		hash_function.o \
		etc.o \
		pair_repo.o

SRCS = middlebox.c \
			 packet.c \
			 hash_table.c \
			 hash_function.c \
			 etc.c \
			 pair_repo.c

all: middlebox

middlebox: $(OBJS)
	$(LD) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) $(TARGETS)


