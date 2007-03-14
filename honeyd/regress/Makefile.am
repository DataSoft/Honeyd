# Honeyd Regression Test Suite
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.

if COND_PYDPKT
  PATH_PYDPKT=:../dpkt
endif
if COND_PYPCAP
  PATH_PYPCAP=:../pypcap
endif
PYTHONPATH=.$(PATH_PYDPKT)$(PATH_PYPCAP)

all: 
	@echo "To run the regression tests: cd regress && make test"

test: check 
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) general.py
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) detect.py
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) routing.py
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) nmap.py

check:
	@[ "`id -u`" -eq 0 ] || { echo "Need to run the test suite as root!"; exit 1; }
	@[ -n "`which python`" ] || { echo "No python interpreter, tests will not work"; exit 1; }

# Generate output for all tests
# (Note: nmap.py does not have output associated)
generate: check
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) general.py -g
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) detect.py -g
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) routing.py -g

# Run tests in debug mode
debug: check 
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) general.py -d
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) detect.py -d
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) routing.py -d
	@PYTHONPATH=$(PYTHONPATH) $(PATH_PYTHON) nmap.py -d

# Clean out auto-generated files 
clean:
	rm -f config.nmap nmap.log *~  

EXTRA_DIST = config.1 config.2 detect.py general.py nmap.py \
	regress.py routing.py detect.output.1 detect.output.2 \
	detect.output.3	detect.output.4 \
	gen.output.1 gen.output.2 route.output.1
