CC = cc
RM = rm
CFLAGS=-O -DDEBUG -I/usr/local/include -Wall

OBJS = logs.o \
			 cpu.o \
			 config.o \
			 util.o \
			 sock_module.o \
			 arp.o \
			 eth_in.o \
			 eth_out.o \
			 ip_in.o \
			 ip_out.o \
			 core.o

SRCS = logs.c \
			 cpu.c \
			 config.c \
			 util.c \
			 sock_module.c \
			 arp.c \
			 eth_in.c \
			 eth_out.c \
			 ip_in.c \
			 ip_out.c \
			 core.c

default: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS)
