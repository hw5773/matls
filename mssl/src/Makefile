CC = cc
RM = rm
CFLAGS=-O -DDEBUG -I/usr/local/include

OBJS = core.o \
			 logs.o

SRCS = core.c \
			 logs.c

default: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS)
