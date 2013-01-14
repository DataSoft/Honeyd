#!/usr/bin/python

import socket
import sys
import binascii

ids = {'integer':0x02, 
       'bit-string':0x03,
       'octet-string':0x04, 
       'null':0x05, 
       'object-identifier':0x06,
       'sequence':0x30, 
       'ip-address':0x40,
       'counter':0x41,
       'gauge':0x42,
       'timeticks':0x43,
       'opaque':0x44,
       'nsap-address':0x45,
       'get-request':0xA0,
       'get-next-request':0xA1, 
       'get-response':0xA2, 
       'set-request':0xA3,
       'trap-pdu':0xA4}

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

def constructRequest() :
  snmpmessage = []
  snmpmessage.append('{0:02X}'.format(ids['sequence']))
  snmpversion = []
  snmpversion.append('{0:02X}'.format(ids['integer']))
  snmpversion.append('{0:02X}'.format(int('1', 16)))
  snmpversion.append('{0:02X}'.format(int('0', 16)))
  snmpcomm = []
  snmpcomm.append('{0:02X}'.format(ids['octet-string']))
  snmpcomm.append('{0:02X}'.format(int(hex(len('public')), 16)))
  snmpcomm.append('public'.encode('hex'))
  snmphead = ''.join(''.join(snmpversion) + ''.join(snmpcomm))
  snmppdu = constructPDU()
  snmpmessage.append('{0:02X}'.format(int(hex((len(snmphead) + len(snmppdu)) / 2), 16)))
  snmpmessage.append(snmphead)
  snmpmessage.append(snmppdu)
  return ''.join(snmpmessage)

def constructPDU() :
  pdu = []
  pdu.append('{0:02X}'.format(ids['get-request']))
  reqid = []
  reqid.append('{0:02X}'.format(ids['integer']))
  reqid.append('{0:02X}'.format(int('1', 16)))
  reqid.append('{0:02X}'.format(int('1', 16)))
  reqid = ''.join(reqid)
  error = []
  error.append('{0:02X}'.format(ids['integer']))
  error.append('{0:02X}'.format(int('1', 16)))
  error.append('{0:02X}'.format(int('0', 16)))
  error = ''.join(error)
  errindex = []
  errindex.append('{0:02X}'.format(ids['integer']))
  errindex.append('{0:02X}'.format(int('1', 16)))
  errindex.append('{0:02X}'.format(int('0', 16)))
  errindex = ''.join(errindex)
  varbindlist = constructVarbindList()
  pdu.append('{0:02X}'.format(int(hex((len(reqid) + len(error) + len(errindex) + len(varbindlist)) / 2), 16)))
  pdu.append(reqid)
  pdu.append(error)
  pdu.append(errindex)
  pdu.append(varbindlist) 
  return ''.join(pdu)

def constructVarbindList() :
  vblist = []
  vblist.append('{0:02X}'.format(ids['sequence']))
  vb = constructVarbind()
  vblist.append('{0:02x}'.format(int(hex(len(vb) / 2), 16)))
  vblist.append(vb)
  return ''.join(vblist)

def constructVarbind() :
  vb = []
  vboid = []
  vboid.append('{0:02X}'.format(ids['object-identifier']))
  vboid.append('{0:02X}'.format(int(hex(len(OID) / 2), 16)))
  vboid.append(OID)
  vboid.append('{0:02X}'.format(ids['null']))
  vboid.append('{0:02X}'.format(int('0', 16)))
  vboid = ''.join(vboid)
  vb.append('{0:02X}'.format(ids['sequence']))
  vb.append('{0:02X}'.format(int(hex(len(vboid) / 2), 16)))
  vb.append(vboid)
  return ''.join(vb)

if __name__ == "__main__" :
  if len(sys.argv) != 4 :
    print 'args: IPADDR SPORT DPORT OID'
    sys.exit(1)
  IPADDR = sys.argv[1]
  DPORT = int(sys.argv[2], 10)
  OID = convertDotsToHex(sys.argv[3])
  
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

  s.connect((IPADDR, DPORT))
  
  PACKETDATA = constructRequest()
  
  s.send(binascii.a2b_hex(PACKETDATA))

  while 1 :
    data = s.recv(1024)
    print data
    break
    
  s.close()
