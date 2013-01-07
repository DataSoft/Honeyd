#!/usr/bin/python

import sys
import os
import urllib2
import socket
import argparse
import binascii
from ipp import *

if __name__ == "__main__" :
  for i in range(0, 7) :
    parse = raw_input()
  statuscode = "0x0506"
  requestid = raw_input()[4:8] # bytes of chars 5-8 in IPP header section are request_id
  req = IPPResponseUDP(status_code=statuscode, request_id=requestid, printattr=True)
  print binascii.a2b_hex(req.generateResponse())