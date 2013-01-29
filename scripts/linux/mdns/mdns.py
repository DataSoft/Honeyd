import sys
import struct
import binascii

from pprint import pprint

import dns


def reply(requestPacket):
	replyPacket = dns.DNSHeader()
	replyPacket.transactionID = requestPacket.transactionID
	replyPacket.flags = 
	replyPacket.writePacket(sys.stdout)
	sys.stderr.write("REPLIED!\n")



# TODO read in name from config file
hostname = "foo.local"


packet = dns.DNSHeader()
packet.readPacket(sys.stdin)

# Only interested if this is a query
if (packet.qr != dns.QR_QUERY):
	sys.exit()

# Only interested if there are questions
if (packet.qdcount == 0):
	sys.exit()


for question in packet.questions:
	pprint(vars(question), sys.stderr)
	
	if (question.qname == hostname):
		
		reply(packet)

