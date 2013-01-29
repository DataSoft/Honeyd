#!/usr/bin/python

from socket import *
import sys
from binascii import hexlify, a2b_hex
from random import seed, randint

def compressDname(domain):
  ret = ''
  for sub in domain:
    test_len = '{0:02X}'.format(len(sub))
    ret += a2b_hex(test_len)
    ret += a2b_hex(hexlify(sub))
  return ret

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print 'dns_req.py DOMAIN_NAME'
    sys.exit(1)
  dname = sys.argv[1].split('.')
  seed()
  payload = ''
  rando = '{0:04X}'.format(randint(0, 65535))
  for i in range(0, len(rando), 2):
    payload += a2b_hex(rando[i:i + 2])
  payload += '\x01\x00'
  payload += '\x00\x01'
  payload += '\x00\x00'
  payload += '\x00\x00'
  payload += '\x00\x00'
  payload += compressDname(dname)
  payload += '\x00'
  payload += '\x00\x01'
  payload += '\x00\x01'
  sys.stdout.write(payload)