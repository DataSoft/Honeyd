import os
import sys
import socket
import struct
import binascii

from pprint import pprint

import dns


# TODO read in name from config file
hostname = "foo.local"
honeypotIp = os.getenv("HONEYD_IP_DST")

sys.stderr.write("Our ip was " + honeypotIp + "\n")

def reply(requestPacket):
	replyPacket = dns.DNSHeader()
	replyPacket.transactionID = requestPacket.transactionID
	replyPacket.flags = int("8400", 16)
	
	rr = dns.DNSResourceRecord()
	rr.name = hostname
	rr.type = 1
	rr.dataclass = int("8001", 16)
	rr.ttl = 120
	rr.rdlength = 4
	rr.rdata = socket.inet_aton(honeypotIp)

	replyPacket.answers.append(rr)

	replyPacket.writePacket(sys.stdout)
	sys.stderr.write("REPLIED!\n")



packet = dns.DNSHeader()
packet.readPacket(sys.stdin)

# Only interested if this is a query
if (packet.qr != dns.QR_QUERY):
	sys.exit()

# Only interested if there are questions
if (packet.qdcount == 0):
	sys.exit()


pprint(vars(packet), sys.stderr)
for question in packet.questions:
	pprint(vars(question), sys.stderr)
	
	if (question.qname == hostname):
		
		reply(packet)

