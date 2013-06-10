import sys
import struct
import binascii

class PreLoginToken:
	def __init__(self):
		self.type = 0
		self.position = 0
		self.length = 0

class PreLoginMessage:
	def __init__(self):
		self.type = 12
		self.tokens = []

	def readPacket(self, stream):
		self.type = struct.unpack("!B", stream.read(1))[0]
		
		if self.type != 18:
			return False

		self.status = struct.unpack("!B", stream.read(1))[0]
		self.length = struct.unpack("!H", stream.read(2))[0]
		self.chan = struct.unpack("!H", stream.read(2))[0]
		self.packet = struct.unpack("!B", stream.read(1))[0]
		self.window = struct.unpack("!B", stream.read(1))[0]

		bytesRead = 8
		while bytesRead < self.length:
			# Read a token
			token = PreLoginToken()
			token.type = struct.unpack("!B", stream.read(1))[0]
			bytesRead += 1
		
			if (token.type == 255):
				self.tokens.append(token)
				break

			token.position = struct.unpack("!H", stream.read(2))[0]
			bytesRead += 2
			token.length = struct.unpack("!H", stream.read(2))[0]
			bytesRead += 2

			self.tokens.append(token)

		if bytesRead < self.length:
			self.payload = stream.read(self.length - bytesRead)

		return True
		
	def toString(self):
		returnString = ""
		returnString += "Type: " + str(self.type) + "\n"
		returnString += "Status: " + str(self.status) + "\n"
		returnString += "Length: " + str(self.length) + "\n"
		returnString += "Channel: " + str(self.chan) + "\n"
		returnString += "Packet: " + str(self.packet) + "\n"
		returnString += "Window: " + str(self.window) + "\n"

		for token in self.tokens:
			returnString += "Token: " + str(token.type) + "\n"
			returnString += "Position: " + str(token.position) + "\n"
			returnString += "Length: " + str(token.length) + "\n\n"
			#returnString += "Value: " + str(self.payload[token.position:(token.position + token.length)]) + "\n\n"

		return returnString

class LoginError:
	def __init__(self):
		self.tdstype = 4
		self.status = 1
		self.tlength = 94
		self.channel = 51
		self.number = 1
		self.window = 0
		
		self.token = 0xaa
		self.length = 74
		self.error = 18456
		self.state = 1
		self.level = 14
		self.errorLength = 36
		self.errorMsg = "Login failed for user 'MSSQLSERVER'."
		self.serverNameLength = 26
		self.serverName = "PHERRICOXIDE-PC\\SQLEXPRESS"
		self.processNameLength = 0
		self.lineNumber = 1

		self.doneToken = 0xfd
		self.statusFlags = 2
		self.op = 0
		self.rows = 0


	def packedString(self):
		returnString = ""

		returnString += struct.pack('!B', self.tdstype)
		returnString += struct.pack('!B', self.status)
		returnString += struct.pack('!H', self.tlength)
		returnString += struct.pack('!H', self.channel)
		returnString += struct.pack('!B', self.number)
		returnString += struct.pack('!B', self.window)
		
		returnString += struct.pack('!B', self.token)
		returnString += struct.pack('!B', self.length)
		returnString += struct.pack('!B', 0)
		returnString += struct.pack('<I', self.error)
		returnString += struct.pack('!B', self.state)
		returnString += struct.pack('!B', self.level)
		returnString += struct.pack('!B', self.errorLength)
		returnString += struct.pack('!B', 0)
		returnString += struct.pack(str(len(self.errorMsg)) + 's', self.errorMsg)
		returnString += struct.pack('!B', self.serverNameLength)
		returnString += struct.pack(str(len(self.serverName)) + 's', self.serverName)
		returnString += struct.pack('!B', self.processNameLength)
		returnString += struct.pack('<H', self.lineNumber)
		returnString += struct.pack('!B', self.doneToken)
		returnString += struct.pack('<H', self.statusFlags)
		returnString += struct.pack('!H', self.op)
		returnString += struct.pack('!I', self.rows)


		return returnString


tds = PreLoginMessage()
if tds.readPacket(sys.stdin):
	sys.stderr.write(tds.toString())
else:
	sys.stderr.write("Message not a pre-login message!\n")


#answer = LoginError()
#sys.stdout.write(answer.packedString())

