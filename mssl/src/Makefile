CC = cc
RM = rm
CFLAGS=-O -DDEBUG -I/usr/local/include -Wall

OBJS = logs.o \
			 cpu.o \
			 config.o \
			 util.o \
			 sock_module.o \
			 eth_in.o \
			 core.o

SRCS = logs.c \
			 cpu.c \
			 config.c \
			 util.c \
			 sock_module.c \
			 eth_in.c \
			 core.c

default: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS)
