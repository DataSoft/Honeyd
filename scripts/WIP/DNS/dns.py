#!/usr/bin/python

import sys
from socket import *
from binascii import hexlify, a2b_hex
from re import match
from random import seed, randint

def get_ns_list():
  f = open('/etc/resolv.conf', 'r')
  nameservers = []
  lines = f.readlines()
  for i in lines:
    if match('nameserver', i):
      nameservers.append(i.split(' ')[1].rstrip('\n'))
  return nameservers

def getEncodedDomain():
  ret = ''
  binary = ''
  while 1:
    binvalue = sys.stdin.read(1)
    binary += binvalue
    traverse = int(hexlify(binvalue), 10)
    if traverse != 0:
      binvalue = sys.stdin.read(traverse)
      binary += binvalue
      ret += binvalue + '.'
    else:
      break
  return [ret[:-1], binary]

if __name__ == "__main__":
  if len(sys.argv) != 2:
    sys.exit(1)
  seed()
  DNS_HEADER = 12
  Q_TYPE = 2
  Q_CLASS = 2
  dstip = sys.argv[1]
  save = sys.stdin.read(DNS_HEADER)
  domain_pair = getEncodedDomain() 
  domain = domain_pair[0]
  save += domain_pair[1]
  save += sys.stdin.read(Q_TYPE + Q_CLASS)
  port = randint(49152, 65535)
  address_recv = ('localhost', port)
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
  sock.bind(address_recv)
  ns = (get_ns_list()[0], 53)
  sock.sendto(save, ns)
  
  data, addr = sock.recvfrom(4096)
  sys.stdout.write(data)
  