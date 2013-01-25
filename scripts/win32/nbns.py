import sys
import binascii
import socket

our_IP = sys.argv[1]

#Parse the NBNS header

#Read Transaction ID -> 2 bytes
trans_ID = sys.stdin.read(2)

#Read Flags > 2 bytes
flags = sys.stdin.read(2)

#Number of questions > 2 bytes
questions = sys.stdin.read(2)

#Number of answers > 2 bytes
answers = sys.stdin.read(2)

#Number of Authority Resource Records -> 2 bytes
authorities = sys.stdin.read(2)

#Number of Additional Resource Records -> 2 bytes
additionals = sys.stdin.read(2)


#We only respond to questions. Throw anything else out
if (int(binascii.hexlify(questions)) <= 0) or (int(binascii.hexlify(answers)) > 0):
	sys.exit(0)


#Parse the Question

#The first byte has to be x20
name_start = sys.stdin.read(1)
if name_start != '\x20':
	sys.exit(0)

#Netbios name
#	First level encoded
i = 'a'
name = ""
while i != '\x00':
	i = sys.stdin.read(1)
	name += i

#Type
query_type = sys.stdin.read(2)

#class
query_class = sys.stdin.read(2)


#If this is a forward request
if query_type == '\x00\x20':
	#Begin forging a response
	reponse_packet = trans_ID
	#flags
	reponse_packet += '\x85\x80'
	#number of questions
	reponse_packet += '\x00\x00'
	#number of answers
	reponse_packet += '\x00\x01'
	#authority RRs
	reponse_packet += '\x00\x00'
	#additional RRs
	reponse_packet += '\x00\x00'
	#netbios name (parroted back)
	reponse_packet += name_start + name
	#type == NB
	reponse_packet += '\x00\x20'
	#class == IN
	reponse_packet += '\x00\x01'
	#TTL = 3 days
	reponse_packet += '\x00\x03\xf4\x80'
	#data length = 6
	reponse_packet += '\x00\x06'
	#flags
	reponse_packet += '\x00\x00'
	#Our address
	reponse_packet += socket.inet_aton(our_IP)
	sys.stdout.write(reponse_packet)
	sys.exit(0)

#If this is a reverse request
if query_type == '\x00\x21':
	#Begin forging a response
	reponse_packet = trans_ID
	#flags
	reponse_packet += '\x84\x00'
	#number of questions
	reponse_packet += '\x00\x00'
	#number of answers
	reponse_packet += '\x00\x01'
	#authority RRs
	reponse_packet += '\x00\x00'
	#additional RRs
	reponse_packet += '\x00\x00'	
	#netbios name (parroted back)
	reponse_packet += name_start + name
	#Type == NBSTAT
	reponse_packet += '\x00\x21'
	#class == IN
	reponse_packet += '\x00\x01'
	#TTL == 0
	reponse_packet += '\x00\x00\x00\x00'
	#Data Length (65 bytes -> 0x41)
	reponse_packet += '\x00\x41'
	#Number of names == 1
	reponse_packet += '\x01'
	#Name (ascii) (16 bytes) TODO
	reponse_packet += "WOOT           " + '\x00'
	#name flags
	reponse_packet += '\x04\x00'
	#Empty fields at end (46 bytes)
	reponse_packet += '\x00' * 46
	sys.stdout.write(reponse_packet)
	sys.exit(0)

sys.exit(0)

