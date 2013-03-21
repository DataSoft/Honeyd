import os
import sys
import socket
import struct
import binascii

from pprint import pprint

sys.path.append("/usr/share/honeyd/scripts/lib/")
from names import GetAllocatedName, IsAllocated, AddNameAllocation

import dns


# TODO read in name from config file
honeypotIp = os.getenv("HONEYD_TEMPLATE_NAME")

honeyd_home = ""
if("HONEYD_HOME" in os.environ):
	honeyd_home = os.getenv("HONEYD_HOME")

fd = open(sys.argv[2])
names_file = fd.readline().split(" ", 1)[1].rstrip("\n")
names_path = honeyd_home + names_file

our_name = GetAllocatedName(names_path, honeypotIp).upper()
if(our_name == ""):
	our_name = AddNameAllocation(names_path, honeypotIp).upper()
	if(our_name == ""):
		sys.stderr.write("Unable to get mdns name")
		sys.exit(0)
hostname = our_name + ".local"


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


packet = dns.DNSHeader()
packet.readPacket(sys.stdin)

# Only interested if this is a query
if (packet.qr != dns.QR_QUERY):
	sys.exit()

# Only interested if there are questions
if (packet.qdcount == 0):
	sys.exit()


#pprint(vars(packet), sys.stderr)
for question in packet.questions:
	#pprint(vars(question), sys.stderr)
	
	if (question.qname.upper() == hostname):
		
		reply(packet)

