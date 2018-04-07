CC = cc
RM = rm
CFLAGS=-O -DDEBUG -I/usr/local/include -Wall

OBJS = core.o tcp_stream.o config.o api.o socket.o \
			 tcp_util.o eth_in.o ip_in.o tcp.o tcp_in.o eth_out.o ip_out.o tcp_out.o logs.o \
			 arp.o timer.o cpu.o util.o fhash.o memory_mgt.o

SRC = core.c tcp_stream.c config.c api.c socket.c \
			tcp_util.c eth_in.c ip_in.c tcp.c tcp_in.c eth_out.c ip_out.c tcp_out.c logs.c \
			arp.c timer.c cpu.c util.c fhash.c memory_mgt.c \
			tcp_rb.c sock_module.c

default: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS)
