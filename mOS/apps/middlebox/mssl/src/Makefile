.PHONY: clean

MSSL_LIB_DIR = ../lib
MSSL_LIB = libmssl.a
MSSL_TARGET = $(MSSL_LIB_DIR)/$(MSSL_LIB)

MSSL_HDR_DIR =../include
MSSL_HDR = record_header.h sp.h

GCC = gcc
RM = rm
ARFLAGS =
AR = ar $(ARFLAGS) r
RANLIB = ranlib

SRCS = record_header.c func.c
OBJS = $(patsubst %.c,%.o,$(SRCS))
DEPS = $(patsubst %.c,.%.d,$(SRCS))


default: $(OBJS)
	$(AR) $(MSSL_TARGET) $?
	$(RANLIB) $(MSSL_TARGET)

$(OBJS): %.o: %.c Makefile
	$(GCC) -I$(MSSL_HDR_DIR) -c $< -o $@

$(DEPS): .%.d: %.c Makefile
	$(GCC) -I$(MSSL_HDR_DIR) -MM $< > $@

clean:
	$(RM) $(OBJS) $(DEPS) $(MSSL_TARGET)
