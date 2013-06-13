import sys
import os
import struct
import binascii
import time

class PreLoginToken:
	def __init__(self):
		self.tokenPosition = 0
		self.type = 0
		self.position = 0
		self.length = 0

class TDSPacket:
	def __init__(self):
		self.type = 12
		self.tokens = []

	# Returns string version of the packet
	def writePacket(self):
		ret = "";
		ret += struct.pack("!B", self.type)
		ret += struct.pack("!B", self.status)
		ret += struct.pack("!H", self.length)
		ret += struct.pack("!H", self.chan)
		ret += struct.pack("!B", self.packet)
		ret += struct.pack("!B", self.window)

		for token in self.tokens:
			ret += struct.pack("!B", token.type)
			
			if (token.type != 255):
				ret += struct.pack("!H", token.position)
				ret += struct.pack("!H", token.length)

		ret += struct.pack(str(len(self.payload)) + "s", self.payload)

		return ret

	# Reads in a TDS packet. Really only parses pre-login packets.
	def readPacket(self, stream):
		self.type = struct.unpack("!B", stream.read(1))[0]
		
		self.status = struct.unpack("!B", stream.read(1))[0]
		self.length = struct.unpack("!H", stream.read(2))[0]
		self.chan = struct.unpack("!H", stream.read(2))[0]
		self.packet = struct.unpack("!B", stream.read(1))[0]
		self.window = struct.unpack("!B", stream.read(1))[0]

		bytesRead = 8
		
		if self.type == 18:
			while bytesRead < self.length:
				# Read a token
				token = PreLoginToken()
				token.tokenPosition = bytesRead

				token.type = struct.unpack("!B", stream.read(1))[0]
				bytesRead += 1
		
				if (token.type == 255):
					self.tokens.append(token)
					break

				token.position = struct.unpack("!H", stream.read(2))[0]
				bytesRead += 2
				token.length = struct.unpack("!H", stream.read(2))[0]
				bytesRead += 2
			
				if token.type == 0:
					self.tokenOffset = token.position

				self.tokens.append(token)


			self.payloadStart = bytesRead + 1
			if bytesRead < self.length:
				self.payload = struct.unpack(str(self.length - bytesRead) + "s", stream.read(self.length - bytesRead))[0]
		else:
			self.payload = struct.unpack(str(self.length - bytesRead) + "s", stream.read(self.length - bytesRead))[0]

		return True
	
	# Just for debugging, gives a human readable version of the packet	
	def toString(self):
		ret = ""
		ret += "Type: " + str(self.type) + "\n"
		ret += "Status: " + str(self.status) + "\n"
		ret += "Length: " + str(self.length) + "\n"
		ret += "Channel: " + str(self.chan) + "\n"
		ret += "Packet: " + str(self.packet) + "\n"
		ret += "Window: " + str(self.window) + "\n\n"

		ret += "Payload: ";
		ret += ":".join("{0:x}".format(ord(c)) for c in self.payload)
		ret += "\n"

		ret += "First byte is " + str(ord(self.payload[0])) + "\n"

		for token in self.tokens:
			ret += "Token: " + str(token.type) + "\n"
			ret += "Token Position: " + str(token.tokenPosition) + "\n"
			ret += "Position: " + str(token.position) + "\n"
			ret += "Length: " + str(token.length) + "\n"
			ret += "Value: "
			foo = str(self.payload[token.position - (self.tokenOffset):(token.position + token.length - (self.tokenOffset))])
			for char in foo:
				ret += str(ord(char)) + " "
			ret += "\n\n"

		ret += "Payload size: " + str(len(self.payload))

		return ret

# Creates a generic login error response packet
class LoginError:
	def __init__(self):
		self.tdstype = 4
		self.status = 1
		self.channel = 51
		self.number = 1
		self.window = 0
		
		self.token = 0xaa
		self.error = 18456
		self.state = 1
		self.level = 14
		self.errorMsg = "Login failed for user."
		self.errorLength = len(self.errorMsg)
		self.serverName = os.getenv("HONEYD_IP_DST")
		self.serverNameLength = len(self.serverName)
		self.processNameLength = 0
		self.lineNumber = 1
		self.length = 14 + 2*self.serverNameLength + 2*self.errorLength
		self.tlength = 38 + 2*self.serverNameLength + 2*self.errorLength

		self.doneToken = 0xfd
		self.statusFlags = 2
		self.op = 0
		self.rows = 0


	# Returns string version of the packet
	def writePacket(self):
		ret = ""

		ret += struct.pack('!B', self.tdstype)
		ret += struct.pack('!B', self.status)
		ret += struct.pack('!H', self.tlength)
		
		ret += struct.pack('!H', self.channel)
		ret += struct.pack('!B', self.number)

		ret += struct.pack('!B', self.window)
		
		ret += struct.pack('!B', self.token)
		ret += struct.pack('!B', self.length)
		ret += struct.pack('!B', 0)
		ret += struct.pack('<I', self.error)
		ret += struct.pack('!B', self.state)
		ret += struct.pack('!B', self.level)

		ret += struct.pack('!B', self.errorLength)
		ret += struct.pack('!B', 0)
		for char in self.errorMsg:
			ret += struct.pack("<H", ord(char))

		ret += struct.pack('!B', self.serverNameLength)
		for char in self.serverName:
			ret += struct.pack("<H", ord(char))

		ret += struct.pack('!B', self.processNameLength)
		ret += struct.pack('<H', self.lineNumber)

		ret += struct.pack('!B', 0)
		ret += struct.pack('!B', 0)

		ret += struct.pack('!B', self.doneToken)
		ret += struct.pack('<H', self.statusFlags)
		ret += struct.pack('!H', self.op)
		ret += struct.pack('!I', self.rows)
		
		ret += struct.pack('!I', 0)

		return ret

while True:
	tds = TDSPacket()
	tds.readPacket(sys.stdin)
	# Type 18 is the pre-login handshake packet
	if tds.type == 18:
		# Modify the packet
		tds.type = 4
		for token in tds.tokens:
			# Force encryption off
			if (token.type == 1):
				tds.payload = tds.payload[:token.position - tds.tokenOffset] + chr(2) + tds.payload[token.position - tds.tokenOffset + 1:]
			# Zero the thread ID
			if (token.type == 3):
				tds.payload = tds.payload[:token.position - tds.tokenOffset] + chr(0) + chr(0) + chr(0) + chr(0) + tds.payload[token.position - tds.tokenOffset + 4:]

		sys.stdout.write(tds.writePacket())
		sys.stdout.flush()
	# Types 16 and 23 are login attempts
	elif (tds.type == 16 or tds.type == 23):
		answer = LoginError()
		sys.stdout.write(answer.writePacket())
		sys.stdout.flush()
		os.system('createNovaScriptAlert.py "' + os.getenv("HONEYD_IP_SRC") + '" "' + os.getenv("HONEYD_INTERFACE") + '" "mssql" "Mssql database login attempt"') 
		sys.exit(0)

