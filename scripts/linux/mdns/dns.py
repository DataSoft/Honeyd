import sys
import struct
import binascii

# From RFC1035, meant to be & with m_flags
BITMASK_QR = 1 << 7
BITMASK_OPCODE = 0xF << 3
BITMASK_AA = 1 << 2
BITMASK_TC = 1 << 1
BITMASK_RD = 1 << 0

BITMASK_RA = 1 << 15
BITMASK_RCODE = 0x7 << 12

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
		self.qdcount = 0
		self.ancount = 0
		self.nscount = 0
		self.arcount = 0
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
		return int(self._flags & BITMASK_QR != 0)

	@property
	def opcode(self):
		return int(self._flags & BITMASK_OPCODE)

	@property
	def aa(self):
		return int(self._flags & BITMASK_AA != 0)

	@property
	def tc(self):
		return int(self._flags & BITMASK_TC != 0)
	
	@property
	def rd(self):
		return int(self._flags & BITMASK_RD != 0)
	
	@property
	def ra(self):
		return int(self._flags & BITMASK_RA != 0)
	
	@property
	def rcode(self):
		return int(self._flags & BITMASK_RCODE)
	

	def readPacket(self, stream):
		self.transactionID, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount = struct.unpack('!HHHHHH', stream.read(12))

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
		self.qdcount = len(self.questions)
		self.ancount = len(self.answers)
		stream.write(struct.pack('!HHHHHH', self.transactionID, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount))
		for answer in self.answers:
			stream.write(answer.packedString())
		

class DNSQuestion:
	def __init__(self):
		self.qname = ""
		self.qtype = ""
		self.qclass = ""

class DNSResourceRecord:
	def __init(self):
		self.name = ""
		self.type = 0
		self.dataclass = 0
		self.ttl = 0
		self.rdlength = 0
		self.rdata = ""

	def packedString(self):
		returnString = ""

		locals = self.name.split(".")
		for local in locals:
			returnString += struct.pack('!B', len(local))
			returnString += struct.pack('!' + str(len(local)) + 's', local)
		returnString += struct.pack('!B', 0)

		returnString += struct.pack('!H', self.type)
		returnString += struct.pack('!H', self.dataclass)
		returnString += struct.pack('!I', self.ttl)
		returnString += struct.pack('!H', self.rdlength)
		returnString += struct.pack('!' + str(self.rdlength) + 's', self.rdata)

		return returnString
		

