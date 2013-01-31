#!/usr/bin/python

import sys
import socket
from binascii import hexlify

def generateSMBHeader():
  # Protocol portion of SMB header
  ret = '\xff\x53\x4d\x42'
  # Command portion; this is for a Negotiate Protocol
  #  Response
  ret += '\x72'
  # Status; this means Status OK
  ret += '\x00' * 4
  # Flags. \x88 means this packet is a reply, and pathnames
  #  are case insensitive
  ret += '\x88'
  # Flags2: These flags combined mean the following:
  #  Strings are Unicode
  #  Error Codes are NT Error Codes
  #  Extended Security Negotiation is supported
  #  Long Names Allowed
  ret += '\0xc801'
  # Combination of many \x00 bytes; explanations to follow.
  #  First two bytes are PIDHigh, i.e. represent the high-order
  #    bits of a process identifier
  #  Bytes 2-9 are Security Features. All set to 0, as security 
  #    features are not supported
  #  Bytes 10 and 11 represent a reserved field, set to 0
  #  Bytes 12 and 13 represent a Tree Identifier (TID)
  ret += '\x00' * 14
  # This is PIDLow, the low-order bits of a PID
  ret += ''
  # This is UID
  ret += '\x00' * 2
  # Multiplex ID
  ret += '\x01\x00'
  return ''

if __name__ == "__main__":
  types = {'session-message':'\x00',
           'session-request':'\x81',
           'positive-ack':'\x82',
           'negative-ack':'\x83',
           'retarget-ack':'\x84',
           'keep-alive':'\x85'}
  while 1:
    type = '\\' + 'x' + hexlify(sys.stdin.read(1))
    sys.stderr.write('type == ' + type + '\n')
    flags = hexlify(sys.stdin.read(1))
    length = int(hexlify(sys.stdin.read(2)), 16)
    
    if type == '\\x00':
      dontneedyet = hexlify(sys.stdin.read(26))
      sys.stderr.write('dontneedyet: ' + dontneedyet + '\n')
      pid = hexlify(sys.stdin.read(2))
      sys.stderr.write('pid: ' + str(pid) + '\n')
      reversepid = pid[2:] + pid[:2]
      sys.stderr.write('reversepid: ' + reversepid + '\n')
      pid = int(reversepid, 16)
      sys.stderr.write('pid: ' + str(pid) + '\n')
      response = types['session-message']
      response += '\x00'
      break
    
    #sys.stderr.write('type: ' + types[type] + '\n')
    #sys.stderr.write('flags: ' + flags + '\n')
    #sys.stderr.write('length: ' + str(length) + '\n')
    elif type == '\\x81':
      sys.stdin.read(length)
      sys.stderr.write('doooooop' + '\n')
      # Response type (1 byte, hex. Codes are in the types array
      response = types['positive-ack']
      
      # Response flags (bits 0-6 are reserved, set to 0. bit 7 is length
      # extensions, not used here
      response += '\x00'
      
      # Response trailer length; contains the data within the packet.
      # For a positive ack, length is \x00 and there's no data
      # For a negative ack, length is \x01 and the packet contains a 1-byte 
      #  error code
      # For a retarget ack, length is \x06 and the packet contains a 4-byte
      #  retarget-ip-address and a two byte port value
      # For a session message, length is variable and the packet contains 
      #  user-data
      # For a keep-alive, length is also \x00 and there's no data
      response += '\x00\x00'
      
      # The response data. As we're using a canned negative ack for now,
      #  this contains the error code 'Not listening on called name'
      #response += '\x80'
      
      #response += generateSMBHeader()
    
      sys.stdout.write(response)
      sys.stdout.flush()
  
  sys.stderr.write('end\n')