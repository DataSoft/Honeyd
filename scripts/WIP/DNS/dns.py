#!/usr/bin/python

from socket import *
import sys
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

def findDNSBoundaries(start):
  ret = start
  while 1:
    traverse = int(hexlify(sys.stdin.read(1)), 10)
    ret += 1
    if traverse == 0:
      break
    ret += traverse
  ret += 3
  return ret

if __name__ == "__main__":
  if len(sys.argv) != 2:
    sys.exit(1)
  seed()
  dstip = sys.argv[1]
  save = sys.stdin.read(12)
  domain_pair = getEncodedDomain()
  domain = domain_pair[0]
  save += domain_pair[1]
  save += sys.stdin.read(5)
  port = randint(49152, 65535)
  address_recv = (dstip, port)
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
  sock.bind(address_recv)
  ns = (get_ns_list()[0], 53)
  sock.sendto(save, ns)
  
  data, addr = sock.recvfrom(4096)
  print data
  