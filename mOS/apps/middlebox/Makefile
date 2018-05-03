TARGET = middlebox

######################################################################
# GCC and compilation options
######################################################################
GCC = $(CC)
GCC_OPT = -m64 -Wall -Werror -fgnu89-inline
GCC_OPT += -DNDEBUG -O3 -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR
GCC_OPT += $(DBG_OPT)
ifeq ($V,) # no echo
    export MSG=@echo
    export HIDE=@
else
    export MSG=@\#
    export HIDE=
endif

######################################################################
# LIBRARIES AND INCLUDES
######################################################################
MTCP_FLD    = ../../core
MTCP_INC    =-I$(MTCP_FLD)/include
MTCP_TARGET = $(MTCP_FLD)/lib/libmtcp.a
LIBS        += -lmtcp -lssl -lcrypto -lnuma -lpthread -lrt
LIB_DIR     += -L$(MTCP_FLD)/lib
CMN_DIR     = ../common
CMN_INC     = -I$(CMN_DIR)
UTIL_INC    = -I../../util/include

# I/O library parameter (PSIO or DPDK)
GCC_OPT += -D__thread="" -DBE_RESILIENT_TO_PACKET_DROP
INC += -DENABLE_PCAP
LIBS += -lpcap

######################################################################
# MSSL (Middlebox SSL)
######################################################################
MSSL_FLD		=	mssl
MSSL_INC		= -I$(MSSL_FLD)/src/include
MSSL_TARGET	=	$(MSSL_FLD)/lib/libmssl.a
LIBS				+= -lmssl
LIB_DIR			+= -L$(MSSL_FLD)/lib

######################################################################

default: $(TARGET)

$(MTCP_TARGET):
	@echo "Compile MTCP targets"
	cd $(MTCP_FLD)/src && make	

$(MSSL_TARGET):
	@echo "Compile MSSL-related source codes"
	cd $(MSSL_FLD)/src && make

$(TARGET): $(MTCP_TARGET) $(MSSL_TARGET) $(TARGET).c $(CMN_DIR)/*.c $(OBJ)
	$(MSG) "   CC $<"
	$(HIDE) $(GCC) $(GCC_OPT) -o $@ $^ $(MTCP_INC) $(MSSL_INC) $(CMN_INC) $(UTIL_INC) $(LIB_DIR) $(LIBS)

clean:
	rm -rf *~ *.o $(TARGET) logs/*
	cd $(MSSL_FLD)/src && make clean

cleanall: clean
	rm -rf Makefile

func.o: func.c
	$(GCC) -c $^
