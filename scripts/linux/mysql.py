# ============================================================================
#  Name        : mysql.py
#  Copyright   : DataSoft Corporation 2011-2013
# 	Nova is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
# 
#    Nova is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
# 
#    You should have received a copy of the GNU General Public License
#    along with Nova.  If not, see <http://www.gnu.org/licenses/>.
#  Description : Trivial mysql script for honeyd
# ============================================================================

import sys
import struct


class ErrorGreeting:
	def __init__(self):
		self.length = 54
		self.packetNumber = 0
		
		self.errorCode = 1130
		self.message = "Host is not allowed to connect to this MySQL server"

	def packedString(self):
		returnString = ""

		# First 3 bytes are packet length, 4th byte is packet number
		firstBytes = (self.packetNumber << 24) | (self.length);
	
		# Padding? Not really sure what this is for, reverse engineered from packet caps in wireshark
		ff = 0xff

		returnString += struct.pack('<I', firstBytes)
		returnString += struct.pack('!B', ff)
		returnString += struct.pack('<H', self.errorCode)
		returnString += struct.pack(str(len(self.message)) + 's', self.message)

		return returnString




e = ErrorGreeting()

sys.stdout.write(e.packedString())
