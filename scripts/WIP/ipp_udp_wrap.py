#!/usr/bin/python

import sys
import os
import urllib2
import socket
import argparse
import binascii
from ipp import *

if __name__ == "__main__" :
  # get requisite SNMP data here by
  # parsing stdin for parameters we need
  snmpmessagelength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmpversionlength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmpversion = int(binascii.hexlify(sys.stdin.read(snmpversionlength)))
  snmpcommunitystringlength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmpcommunitystring = str(sys.stdin.read(snmpcommunitystringlength))
  snmppdumetadata = sys.stdin.read(2)
  snmppdutype = binascii.hexlify(snmppdumetadata[0])
  snmppdulength = int(binascii.hexlify(snmppdumetadata[1]), 16)
  snmpreqidlength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmpreqid = int(binascii.hexlify(sys.stdin.read(snmpreqidlength)), 16)
  snmperrorlength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmperror = int(binascii.hexlify(sys.stdin.read(snmperrorlength)), 16)
  snmperrindexlength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmperrindex = int(binascii.hexlify(sys.stdin.read(snmperrindexlength)), 16)
  snmpvarbindlistlength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmpvarbindlength = int(binascii.hexlify(sys.stdin.read(2)[1]), 16)
  snmpvaluetype = int(binascii.hexlify(sys.stdin.read(1)), 16) 
  snmpvaluelength = int(binascii.hexlify(sys.stdin.read(1)), 16)
  snmpoid = str(binascii.hexlify(sys.stdin.read(snmpvaluelength)))
  
  """
    sys.stderr.write("snmpmessagelength: " + str(snmpmessagelength) + "\n")
    sys.stderr.write("snmpversionlength: " + str(snmpversionlength) + "\n")
    sys.stderr.write("snmpversion: " + str(snmpversion) + "\n")
    sys.stderr.write("snmpcommunitystringlength: " + str(snmpcommunitystringlength) + "\n")
    sys.stderr.write("snmpcommunitystring: " + str(snmpcommunitystring) + "\n")
    sys.stderr.write("snmppdutype: " + str(snmppdutype) + "\n")
    sys.stderr.write("snmppdulength: " + str(snmppdulength) + "\n")
    sys.stderr.write("snmpreqidlength: " + str(snmpreqidlength) + "\n")
    sys.stderr.write("snmpreqid: " + str(snmpreqid) + "\n")
    sys.stderr.write("snmperrorlength: " + str(snmperrorlength) + "\n")
    sys.stderr.write("snmperror: " + str(snmperror) + "\n")
    sys.stderr.write("snmperrindexlength: " + str(snmperrindexlength) + "\n")
    sys.stderr.write("snmperrindex: " + str(snmperrindex) + "\n")
    sys.stderr.write("snmpvarbindlistlength: " + str(snmpvarbindlistlength) + "\n")
    sys.stderr.write("snmpvarbindlength: " + str(snmpvarbindlength) + "\n")
    sys.stderr.write("snmpvaluetype: " + str(snmpvaluetype) + "\n")
    sys.stderr.write("snmpvaluelength: " + str(snmpvaluelength) + "\n")
    sys.stderr.write("snmpoid: " + str(snmpoid) + "\n")
  """
  
  # give paramaters to IPPResponseUDP constructor
  req = IPPResponseUDP(reqoid=snmpoid,
                       requestid=snmpreqid,
                       requestidlength=snmpreqidlength,
                       pdutype=snmppdutype,
                       version=snmpversion)
  response = req.generateResponse()
  print binascii.a2b_hex(response)