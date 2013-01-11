#!/usr/bin/python

import binascii
import sys
import os
import re
import subprocess
from struct import pack, unpack

def openrdwr(filename, *args, **kwargs) :
  fd = os.open(filename, os.O_RDWR | os.O_CREAT)
  return os.fdopen(fd, *args, **kwargs)
  pass

def modtype(type, line) :
  retType = ''
  if type == 'STRING' or type == 'Hex-STRING':
    retType = 'octet-string'
  elif type == 'INTEGER' :
    retType = 'integer'
  elif type == 'IpAddress' :
    retType = 'ip-address'
  elif type == 'OID' :
    retType = 'object-identifier'
  elif type == 'Gauge32' :
    """
      The Gauge32 and Counter32 variable types are the SNMP v2
      versions of Gauge and Counter. Currently, the two sets are 
      in different dictionaries within ipp.py, but until I can
      find a device that responds to v2c or v3 requests with the v2c+ 
      variable types, both are going to return the SNMP v1 types.
    """
    retType = 'gauge'
  elif type == 'Gauge' :
    retType = 'gauge'
  elif type == 'Counter32' :
    retType = 'counter'
  elif type == 'Counter' :
    retType = 'counter'
  elif type == 'Timeticks' :
    retType = 'timeticks'
  else :
    retType = 'null'
    
  return line.replace(type, retType)

if __name__ == '__main__' :
  if len(sys.argv) < 2 :
    sys.exit(1)

  ip = sys.argv[1]
  path = 'temp.' + ip + '.txt'
  f = open(path,'a+')
  f.seek(0)
  f.write(subprocess.check_output(['snmpwalk','-Cc','-Os','-c','public','-v','1',str(ip)],
                          stderr=subprocess.STDOUT))
  f.seek(0)
  restructure = f.readlines()
  replf = ip + '.txt'
  replacement = open(replf, 'w')
  for line in restructure :
    writeline = line.replace('iso', '1.3')
    writeline = writeline.replace('=', ':')
    splitline = writeline.split(':')
    for i in range(0, len(splitline)) :
      splitline[i] = splitline[i].strip()
    writeline = ':'.join(splitline) + '\n'
    writeline = modtype(splitline[1], writeline)
    replacement.write(writeline)
    
  f.close()
  replacement.close()
  os.remove(path)
  
  
  