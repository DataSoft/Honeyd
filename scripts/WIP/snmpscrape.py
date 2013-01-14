#!/usr/bin/python

import binascii
import sys
import os
import re
import subprocess

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
    '''
      The Gauge32 and Counter32 variable types are the SNMP v2
      versions of Gauge and Counter. Currently, the two sets are 
      in different dictionaries within ipp.py, but until I can
      find a device that responds to v2c or v3 requests with the v2c+ 
      variable types, both are going to return the SNMP v1 types.
    '''
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

def getLongFormEncoding(value) :
  retlist = []
  i = 1
  while (2 ** (7 * i)) < value :
    i += 1
  bytenum = i
  for i in reversed(range(0, bytenum)) :
    test = 0x00
    mult = 128 * i if i > 0 else 1
    while True :
      test += 0x01
      if (test * mult) > value :
        test -= 0x01
        break
    add = 0x80 if i > 0 else 0x00
    retlist.append('{0:02X}'.format(int(hex(test), 16) + add))
    value -= test * mult
  return ''.join(retlist)

def convertDotsToHex(oid) :
  oidBER = []
  oidBER.append('{0:02X}'.format(0x2B))
  split = oid.split('.')
  for j in range(2, len(split)) :
    if int(split[j], 10) > 255 :
      oidBER.append(getLongFormEncoding(int(split[j], 10)))
    else :
      oidBER.append('{0:02X}'.format(int(split[j], 16)))
  return ''.join(oidBER)

if __name__ == '__main__' :
  if len(sys.argv) < 2 :
    sys.exit(1)

  ip = sys.argv[1]
  path = 'temp.' + ip + '.txt'
  f = open(path,'w+')
  f.write(subprocess.check_output(['snmpwalk','-Cc','-Os','-c','public','-v','1',str(ip)],
                          stderr=subprocess.STDOUT))
  f.close()
  f = open(path, 'r')
  restructure = f.readlines()
  fileappend = 0
  # search for a printer#*.txt that isn't taken, then write to it
  while True :
    try :
      replf = 'printer' + str(fileappend) + '.txt'
      replacement = open(replf, 'r')
      fileappend += 1
    except IOError :
      replacement = open(replf, 'w')
      break
  # In this block, we're restructuring the lines returned from snmpwalk 
  # to be consistent with the values and names used in the ipp.py script
  for line in restructure :
    writeline = line.replace('iso', '1')
    writeline = writeline.replace('=', ':')
    splitline = writeline.split(':')
    for i in range(0, len(splitline)) :
      splitline[i] = splitline[i].strip()
      
    splitline[0] = convertDotsToHex(splitline[0])
    # Timeticks has a special format in the returned info for snmpwalk.
    # Something like (#########) Date Conversion
    # However, the only information being sent within the packet is 
    # the value within the parens.
    if splitline[1] == 'Timeticks' :
      split = splitline[2].split(' ')
      splitline[2] = split[0].replace('(', '').replace(')', '')
      while len(splitline) > 3 :
        del splitline[-1]
      splitline[2] = hex(int(splitline[2], 10))
      hexrange = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
                  'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b', 'c', 'd', 'e', 'f']
      if splitline[2][-1] not in hexrange :
        splitline[2] = splitline[2][0:-1]
    # Since OID BER encoding is a bit mathematically heavy-handed,
    # do it here. This will take an OID in the format 1.3.6.1.{...}
    # and turn it into a hex string of 2B{...}.
    elif splitline[1] == 'OID' :
      if splitline[2] == 'ccitt.0' :
        splitline[2] = '00'
      else :
        splitline[2] = convertDotsToHex(splitline[2])
    # We want to convert an IpAddress in dot-decimal format into
    # four hex pairs in one string
    elif splitline[1] == 'IpAddress' :
      split = splitline[2].split('.')
      ipBER = []
      for i in range(0, len(split)) :
        ipBER.append('{0:02X}'.format(int(hex(int(split[i], 10)), 16)))
      splitline[2] = ''.join(ipBER)
    # STRINGs take the form "some-string", we want to take the value
    # inside the quotes and encode it into hex.
    elif splitline[1] == 'STRING' :
      split = splitline[2].split('"')
      splitline[2] = split[1].encode('hex')
    # For hex strings, the values are going to be stored
    # as a string representation of the hex. Just need to use 
    # binascii.a2b_hex(hexstring) to get the binary values for
    # the response packet
    elif splitline[1] == 'Hex-STRING' :
      split = ''.join(splitline[2].split(' '))
      splitline[2] = split
    # There are some OIDs that return nothing, shown in the 
    # snmpwalk return text as "". For this return value, wireshark
    # shows the packet as having a varbind id of 0x04 (octet-string)
    # and a length of 0x00. 
    elif splitline[1] == "" :
      splitline[1] = 'octet-string'
      splitline[2] = ' '
    writeline = ':'.join(splitline) + '\n'
    writeline = modtype(splitline[1], writeline)
    replacement.write(writeline)
    
  f.close()
  replacement.close()
  #os.remove(path)
  
  
  