import sys
import struct
import binascii

class LoginError:
	def __init(self):
		self.type = 4
		self.status = 1
		self.length = 75
		self.channel = 51
		self.number = 1
		self.window = 0
		
		self.token = 0xaa
		self.length = 55
		self.error = 18456
		self.state = 1
		self.level = 14
		self.errorLength = 36
		self.error = "Login failed for user 'MSSQLSERVER'."
		self.serverNameLength = 7
		self.serverName = "AZUREUS"
		self.processNameLength = 0
		self.lineNumber = 1

		self.doneToken = 0xfd
		self.statusFlags = 2
		self.op = 0
		self.rows = 0


	def packedString(self):
		returnString = ""

		returnString += struct.pack('!B', self.type)
		returnString += struct.pack('!B', self.status)
		returnString += struct.pack('!H', self.length)
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
		returnString += struct.pack('!s', self.error)
		returnString += struct.pack('!B', self.serverNameLength)
		returnString += struct.pack('!s', self.serverName)
		returnString += struct.pack('!B', self.processNameLength)
		returnString += struct.pack('<H', self.lineNumber)
		returnString += struct.pack('!B', self.doneToken)
		returnString += struct.pack('<H', self.statusFlags)
		returnString += struct.pack('!H', self.op)
		returnString += struct.pack('!I', self.rows)


		return returnString

answer = LoginError()
sys.stdout.write(answer.packedString())

