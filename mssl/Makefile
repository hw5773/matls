##
## Makefile for Flex Socket

PLATFORM=dist

VERSION=1.0
SHLIB_VERSION_NUMBER=1.0
SHLIB_MAJOR=1
SHLIB_MONOR=0

LIBS=libmssl.a
INSTALLTOP=/usr/local
INSTALL_LIBS=libmssl.a
LIBDIR=lib

APPDIR=apps
LIBRPATH=$(INSTALLTOP)/$(LIBDIR)

CC= cc
CFLAGS=-O -DDEBUG -I/usr/local/include -Wall
LDFLAGS= -L/usr/local/lib -lssl -lcrypto -ldl

ARFLAGS=
AR=ar $(ARFLAGS) r
RANLIB=ranlib

SRCDIR=`pwd`
DESTDIR=
RM= rm -f
RMDIR= rmdir
BASENAME= mssl
NAME= $(BASENAME)-$(VERSION)

PCS=libmssl.pc

OBJ = src/logs.o \
			src/cpu.o \
			src/config.o \
			src/util.o \
			src/core.o

all: objs libmssl.a libmssl.pc

install: all install_lib

install_lib:
	@[ -n "$(INSTALLTOP)" ] || (echo INSTALLTOP should not be empty; exit 1)
	@echo "*** Installing development files"
	@$(SRCDIR)/util/mkdir-p.pl $(INSTALLTOP)/include/mssl
	@ :
	@set -e; for i in $(SRCDIR)/include/mssl/*.h; do \
		fn=`basename $$i`; \
		echo "install $$i -> $(INSTALLTOP)/include/mssl/$$fn"; \
		cp $$i $(INSTALLTOP)/include/mssl/$$fn; \
		chmod 644 $(INSTALLTOP)/include/mssl/$$fn; \
	done
	@$(SRCDIR)/util/mkdir-p.pl $(INSTALLTOP)/$(LIBDIR)
	@set -e; for l in $(INSTALL_LIBS); do \
		fn=`basename $$l`; \
		echo "install $$l -> $(INSTALLTOP)/$(LIBDIR)/$$fn"; \
		cp $$l $(INSTALLTOP)/$(LIBDIR)/$$fn.new; \
		$(RANLIB) $(INSTALLTOP)/$(LIBDIR)/$$fn.new; \
		chmod 644 $(INSTALLTOP)/$(LIBDIR)/$$fn.new; \
		mv -f $(INSTALLTOP)/$(LIBDIR)/$$fn.new \
					$(INSTALLTOP)/$(LIBDIR)/$$fn; \
	done
	@ :
	@$(SRCDIR)/util/mkdir-p.pl $(INSTALLTOP)/$(LIBDIR)/pkgconfig
	@echo "install libmssl.pc -> $(INSTALLTOP)/$(LIBDIR)/pkgconfig/libmssl.pc"
	@cp libmssl.pc $(INSTALLTOP)/$(LIBDIR)/pkgconfig
	@chmod 644 $(INSTALLTOP)/$(LIBDIR)/pkgconfig/libmssl.pc

uninstall: uninstall_lib

uninstall_lib:
	@echo "*** Uninstalling development files"
	@ :
	@set -e; for i in $(SRCDIR)/include/mssl/*.h; do \
		fn=`basename $$i`; \
		echo "$(RM) $(INSTALLTOP)/include/mssl/$$fn"; \
		$(RM) $(INSTALLTOP)/include/mssl/$$fn; \
	done
	-$(RMDIR) $(INSTALLTOP)/include/mssl
	@set -e; for l in $(INSTALL_LIBS); do \
		fn=`basename $$l`; \
		echo "$(RM) $(INSTALLTOP)/$(LIBDIR)/$$fn"; \
		$(RM) $(INSTALLTOP)/$(LIBDIR)/$$fn; \
	done
	@ :
	$(RM) $(INSTALLTOP)/$(LIBDIR)/pkgconfig/libmssl.pc

libclean:
	@set -e; for s in $(SHLIB_INFO); do\
		s1=`echo "$$s" | cut -f1 -d";"`; \
		s2=`echo "$$s" | cut -f2 -d";"`; \
		echo $(RM) $$s1; \
		$(RM) $$s1; \
		if [ "$$s1" != "$$s2" ]; then \
			echo $(RM) $$s2; \
			$(RM) $$s2; \
		fi; \
	done
	$(RM) $(LIBS)
	$(RM) *.map

clean: libclean
	$(RM) $(OBJ) $(PCS)
	-$(RM) `find . -name '*.o' -a \! -path "./.git*"`

libmssl.pc:
	@ ( echo 'prefix=$(INSTALLTOP)'; \
		 	echo 'exec_prefix=$${prefix}'; \
			echo 'libdir=$${exec_prefix}/$(LIBDIR)'; \
			echo 'includedif=$${prefix}/include'; \
			echo ''; \
			echo 'Name: Flex-libmssl'; \
			echo 'Description: mssl library'; \
			echo 'Version: '$(VERSION); \
			echo 'Libs: -L$${libdir} -lmssl'; \
			echo 'Cflags: -I$${includedir}' ) > libmssl.pc

libmssl.a: $(OBJ)
	$(AR) $@ $?
	$(RANLIB) $@

objs:
	@echo "Compile the source codes"
	(cd src; make;)
