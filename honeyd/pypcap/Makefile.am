# $Id: Makefile.am,v 1.1 2005/10/31 04:23:07 provos Exp $

#CONFIG_ARGS = --with-pcap=$(HOME)/build/libpcap-0.8.3

# PYTHON = C:\\Python23\\python.exe
# CONFIG_ARGS = --with-pcap=..\\wpdpack

all: pcap.c
	$(PATH_PYTHON) setup.py config $(CONFIG_ARGS)
	$(PATH_PYTHON) setup.py build

pcap.c: pcap.pyx
	pyrexc pcap.pyx

install:
	$(PATH_PYTHON) setup.py install

test:
	$(PATH_PYTHON) test.py

pkg_win32:
	$(PATH_PYTHON) setup.py bdist_wininst

pkg_osx:
	bdist_mpkg --readme=README --license=LICENSE

clean:
	$(PATH_PYTHON) setup.py clean
	rm -rf build dist

cleandir distclean: clean
	$(PATH_PYTHON) setup.py clean -a
	rm -f config.h *~

distdir:
	@echo "Nothing"
