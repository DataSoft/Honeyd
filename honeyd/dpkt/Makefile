# $Id: Makefile,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

all:
	python setup.py build

install:
	python setup.py install

test:
	python test.py

clean:
	rm -rf build

cleandir distclean: clean
	rm -f *.pyc *~ */*.pyc */*~

distdir:
	# we are dumb
