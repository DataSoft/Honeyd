#!/usr/bin/python

import sys
import os
import urllib2
import socket
import argparse
import binascii
from ipp import *

if __name__ == "__main__" :
  # get requisite SNMP data here
  
  # parse for parameters we need
  snmplength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  requestidarg = int(binascii.hexlify(sys.stdin.read(16)[15]), 16)
  oidlength = int(binascii.hexlify(sys.stdin.read(12)[11]), 16)
  oid = str(binascii.hexlify(sys.stdin.read(oidlength)))
  
  
  # give paramaters to IPPResponseUDP constructor
  req = IPPResponseUDP(reqoid=oid,requestid=requestidarg)
  print binascii.a2b_hex(req.generateResponse())