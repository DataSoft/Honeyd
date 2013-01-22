#!/usr/bin/python

import sys
import binascii
from socket import *
from ipp import *

if __name__ == "__main__":
  mib = sys.argv[1] + '.txt'
  address = ('10.10.1.2', 161)
  listen_socket = socket(AF_INET, SOCK_DGRAM)
  listen_socket.bind(address)
  
  while(1):
    recv_data, addr = listen_socket.recvfrom(4096)
    # use addr arg for return send
    parse = binascii.hexlify(recv_data)
    i = 2
    snmpmessagelength = int(parse[i:i + 2], 16)
    i += 4
    snmpversionlength = int(parse[i: i + 2], 16)
    snmpversion = int(parse[i:i + snmpversionlength], 16)
    i += snmpversionlength * 2 + 4
    snmpcommunitystringlength = int(parse[i:i + 2], 16)
    i += 2
    snmpcommunitystring = binascii.unhexlify(parse[i:i + snmpcommunitystringlength * 2])
    i += snmpcommunitystringlength * 2
    snmppdumetadata = []
    temp= parse[i:i + 4]
    snmppdumetadata.append(temp[0:len(temp)/2])
    snmppdumetadata.append(temp[len(temp)/2:])
    i += 6
    snmppdutype = snmppdumetadata[0]
    snmppdulength = int(snmppdumetadata[1], 16)
    snmpreqidlength = int(parse[i:i + 2], 16)
    i += 2
    snmpreqid = int(parse[i:i + snmpreqidlength * 2], 16)
    i += snmpreqidlength * 2 + 2
    snmperrorlength = int(parse[i:i + 2], 16)
    i += 2
    snmperror = int(parse[i:i + snmperrorlength * 2], 16)
    i += snmperrorlength * 2 + 2
    snmperrindexlength = int(parse[i:i + 2], 16)
    i += 2
    snmperrindex = int(parse[i:i + snmperrindexlength * 2], 16)
    i += snmperrindexlength * 2 + 2
    snmpvarbindlistlength = int(parse[i:i + 2], 16)
    i += 4
    snmpoid = []
    togo = 0
    while togo < snmpvarbindlistlength:
      snmpvarbindlength = int(parse[i:i + 2], 16)
      i += 2
      snmpvaluetype = int(parse[i:i + 2], 16)
      i += 2 
      snmpvaluelength = int(parse[i:i + 2], 16)
      i += 2
      snmpoid.append(parse[i:i + snmpvaluelength * 2])
      i += snmpvaluelength * 10 + 4
      togo += 6 + snmpvaluelength 
    
    if len(snmpoid) == 1:
      snmpoid = ''.join(snmpoid)
  
    if type(snmpoid) is list:
      for i in range(0, len(snmpoid)):
        test = list(snmpoid[i])
        for j in range(0, len(test)):
          test[j] = test[j].upper()
        snmpoid[i] = ''.join(test)
    else:
      test = list(snmpoid)
      for i in range(0, len(test)):
        test[i] = test[i].upper()
      snmpoid = ''.join(test)
    
    req = IPPResponseUDP(reqoid=snmpoid,
                         requestid=snmpreqid,
                         requestidlength=snmpreqidlength,
                         pdutype=snmppdutype,
                         version=snmpversion,
                         mibfile=mib)
    response = req.generateResponse()
    clean = list(response)
    hexrange = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
                'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b', 'c', 'd', 
                'e', 'f']
    for c in range(0, len(clean)):
      if clean[c] not in hexrange:
        del clean[c]
  
    response = ''.join(clean)
    listen_socket.sendto(binascii.a2b_hex(response), addr)