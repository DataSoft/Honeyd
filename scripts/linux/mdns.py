import sys
import struct
import binascii
from pprint import pprint

# From RFC1035, meant to be & with m_flags[0]
BITMASK_QR = 1 << 7
BITMASK_OPCODE = 0xF << 3
BITMASK_AA = 1 << 2
BITMASK_TC = 1 << 1
BITMASK_RD = 1 << 0

# From RFC1035, meant to be & with m_flags[1]
BITMASK_RA = 1 << 7
BITMASK_RCODE = 0x7 << 4
BITMASK_Z = 0x0F

QR_QUERY = 0
QR_RESPONSE = 1

OPCODE_QUERY = 0
OPCODE_IQUERY = 1
OPCODE_STATUS = 2

RCODE_NO_ERROR = 0
RCODE_FORMAT_ERROR = 1
RCODE_SERVER_FAILURE = 2
RCODE_NAME_ERROR = 3
RCODE_REFUSED = 4

class DNSHeader:
	def __init__(self, stream):
		self.transactionID = stream.read(2)
		self.flags = stream.read(2)

		self.qr = int(ord(self.flags[0]) & BITMASK_QR != 0)
		self.opcode = int(ord(self.flags[0]) & BITMASK_OPCODE)
		self.aa = int(ord(self.flags[0]) & BITMASK_AA != 0)
		self.tc = int(ord(self.flags[0]) & BITMASK_TC != 0)
		self.rd = int(ord(self.flags[0]) & BITMASK_RD != 0)
		
		self.ra = int(ord(self.flags[1]) & BITMASK_RA != 0)
		self.rcode = int(ord(self.flags[1]) & BITMASK_RCODE)
		self.z = int(ord(self.flags[1]) & BITMASK_Z)

		self.qdcount, self.ancount, self.nscount, self.arcount = struct.unpack('!HHHH', stream.read(8))

		self.questions = []

		for i in range(0,self.qdcount):
			question = DNSQuestion()
			
			labelLength = 1
			
			while (labelLength != 0):
				labelLength = ord(stream.read(1))
				question.qname += stream.read(labelLength)
				question.qname += "."
			
			self.questions.append(question)

class DNSQuestion:
	def __init__(self):
		self.qname = ""
		self.qtype = ""
		self.qcode = ""


packet = DNSHeader(sys.stdin)

if (packet.qdcount != 0):
	pprint(vars(packet), sys.stderr)
