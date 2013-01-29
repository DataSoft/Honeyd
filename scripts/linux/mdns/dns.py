import sys
import struct
import binascii

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

class DNSHeader(object):
	def __init__(self):
		self.questions = []
		self.answers = []
	
	@property
	def flags(self):
		return self._flags

	@flags.setter
	def flags(self, value):
		self._flags = value
	
	@property
	def qr(self):
		return int(ord(self._flags[0]) & BITMASK_QR != 0)

	@property
	def opcode(self):
		return int(ord(self._flags[0]) & BITMASK_OPCODE)

	@property
	def aa(self):
		return int(ord(self._flags[0]) & BITMASK_AA != 0)

	@property
	def tc(self):
		return int(ord(self._flags[0]) & BITMASK_TC != 0)
	
	@property
	def rd(self):
		return int(ord(self._flags[0]) & BITMASK_RD != 0)
	
	@property
	def ra(self):
		return int(ord(self._flags[1]) & BITMASK_RA != 0)
	
	@property
	def rcode(self):
		return int(ord(self._flags[1]) & BITMASK_RCODE)
	

	def readPacket(self, stream):
		self.transactionID = stream.read(2)
		self.flags = stream.read(2)

		self.qdcount, self.ancount, self.nscount, self.arcount = struct.unpack('!HHHH', stream.read(8))

		# Extract the question section
		for i in range(0,self.qdcount):
			question = DNSQuestion()
			
			labelLength = 1
		
			local = 0
			while (labelLength != 0):
				labelLength = ord(stream.read(1))
				if (labelLength > 0):
					if (local > 0):
						question.qname += "."
					question.qname += stream.read(labelLength)
				local += 1
			
			question.qtype = stream.read(2)
			question.qclass = stream.read(2)
			self.questions.append(question)

	def writePacket(self, stream):
		stream.write(struct.pack('!HHHHHH', self.transactionID, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount))

class DNSQuestion:
	def __init__(self):
		self.qname = ""
		self.qtype = ""
		self.qclass = ""

class DNSResourceRecord:
	def __init(self):
		self.name = ""
		self.type = ""
		self.dataclass = ""
		self.ttl = ""
		self.rdlength = ""
		self.rdata = ""
