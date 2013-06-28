#!/usr/bin/python

import sys
import binascii

native_os = ""
primary_domain = ""
time_zone = 0
lan_manager = ""

def GetRequest():
    #Get netBIOS Session Service header
    sys.stdin.read(4)
    #Server component must be "0xffSMB"
    server_component = sys.stdin.read(4)
    if(server_component != "\xffSMB"):
        return False
    
    ### SMB Header ###
    smb_command = sys.stdin.read(1)     #SMB command
    nt_status = sys.stdin.read(4)       #NT status 
    flags1 = sys.stdin.read(1)          #Flags 1
    flags2 = sys.stdin.read(2)          #Flags 2
    pid_high = sys.stdin.read(2)        #PID high
    signature = sys.stdin.read(8)       #Signature
    pid_high = sys.stdin.read(2)        #Reserved
    tree_id = sys.stdin.read(2)         #Tree ID
    pid = sys.stdin.read(2)             #pid
    uid = sys.stdin.read(2)             #User id
    mid = sys.stdin.read(2)             #Multiplex id

    ### Supported Request Types ###

    #Negotiate Protocol Request
    if(smb_command == "\x72"):
        return HandleNegotiateProtocolRequest(pid, mid)

    #Session Setup AndX Request (authenticate)
    if(smb_command == "\x73"):
        return HandleSessionSetupRequest(pid, mid)

    #Tree Connect AndX Request
    if(smb_command == "\x75"):
        return HandleTreeConnectRequest(pid, mid)

    #Tree Disconnect AndX Request
    if(smb_command == "\x71"):
        return HandleDisconnectRequest(pid, mid)

    SendError("\x72", "\x00\x00\x00\x00", pid, mid)
    return True

#pid = the Process ID that needs to be parroted back
#mid = the Message ID that needs to be parroted back
def HandleNegotiateProtocolRequest(pid, mid):
    #Word Count
    word_count = sys.stdin.read(1)
    #Byte Count
    byte_count = sys.stdin.read(2)
    #convert to integer, read in that many bytes (reverse byte order)
    remaining_bytes = ord(byte_count[0]) + ( 256 * ord(byte_count[1]))
    requested_dialects = sys.stdin.read(remaining_bytes)
    dialects = requested_dialects.split("\x00")
    chosen_dialect = -1
    for i in range(0, len(dialects)-1):
        #Shave off the 1st byte, as it is the Buffer Format
        #sys.stderr.write(dialects[i][1:] + "\n")
        if(dialects[i][1:] == "NT LM 0.12"):
            chosen_dialect = i
            break

    if chosen_dialect == -1:
        SendError('\x72', "\x00\x00\x00\x00", pid, mid)
        return

    ### SMB Header ###
    response = "\xffSMB" 
    response += "\x72"              #SMB command
    response += "\x00\x00\x00\x00"  #NT status 
    response += "\x88"              #Flags 1
    response += "\xc8\x41"          #Flags 2
    response += "\x00\x00"          #PID high
    response += "\x00\x00\x00\x00\x00\x00\x00\x00" #Signature
    response += "\x00\x00"          #Reserved
    response += "\x00\x00"          #Tree ID
    response += pid                 #pid
    response += "\x00\x00"          #User id
    response += mid                 #Multiplex id

    ### Response ###
    #SMB Message Parameters
    response += "\x11" #34 byte header (value x2)
    response += chr(chosen_dialect) + "\x00"
    response += "\x08" #most security off
    response += "\x32\x00"
    response += "\x01\x00"
    response += "\x04\x41\x00\x00"
    response += "\x00\x00\x01\x00"
    response += "\x00\x00\x00\x00"
    response += "\xf9\xf3\x01\x00" #capabilties (no extra security)
    response += "\xa9\xbb\x01\x95\x73\x56\xce\x01" #TODO get system time
    #Convert integer length to hex string in reverse byte order
    response += chr(time_zone % 256) + chr(time_zone / 256) #Server time zone
    response += "\x00"

    byte_size = len(primary_domain) + 1
    #Convert integer length to hex string in reverse byte order
    response += chr(byte_size % 256) + chr(byte_size/256)
    response += primary_domain + "\x00"
    sys.stdout.write("\x00\x00\x00" + chr(len(response)) + response)
    sys.stdout.flush()
    return True

def HandleSessionSetupRequest(pid, mid):
    ### Read Request Contents ###

    #Word Count
    word_count = sys.stdin.read(1)
    remaining_bytes = ord(word_count) * 2
    options = sys.stdin.read(remaining_bytes)

    #Byte Count
    byte_count = sys.stdin.read(2)
    #convert to integer, read in that many bytes (reverse byte order)
    remaining_bytes = ord(byte_count[0]) + ( 256 * ord(byte_count[1]))
    rest = sys.stdin.read(remaining_bytes)

    ### Create SMB Header ###
    response = "\xffSMB"   
    response += "\x73"      #SMB command
    response += "\x00\x00\x00\x00" #NT status SUCCESS
    response += "\x88"      #Flags 1
    response += "\xc8\x41"  #Flags 2
    response += "\x00\x00"  #PID high
    response += "\x00\x00\x00\x00\x00\x00\x00\x00" #Signature 
    response += "\x00\x00"  #Reserved
    response += "\x00\x00"  #Tree ID
    response += pid         #pid
    response += "\x00\x00"  #User id
    response += mid         #Multiplex id

    ### Create Response ###

    #SMB Message Parameters
    response += "\x03" #6 byte start (value x2)
    response += "\xff" #no further commands
    response += "\x00" #reserved
    response += "\xc7\x00" #AndXOffset
    response += "\x00\x00" #Action: not logged in as GUEST

    byte_size = len(native_os) + len(lan_manager) + len(primary_domain) + 3
    #Convert integer length to hex string in reverse byte order
    server_info = chr(byte_size % 256) + chr(byte_size/256)
    server_info += native_os + "\x00" #Native OS
    server_info += lan_manager + "\x00" #Native LAN manager
    server_info += primary_domain + "\x00" #Primary Domain
    response += server_info

    #Prepend packet with NetBios Session Service header
    sys.stdout.write("\x00\x00\x00" + chr(len(response)) + response)
    sys.stdout.flush()
    return True

def HandleTreeConnectRequest(pid, mid):
    #Word Count
    word_count = sys.stdin.read(1)
    remaining_bytes = ord(word_count) * 2
    options = sys.stdin.read(remaining_bytes)

    #Byte Count
    byte_count = sys.stdin.read(2)
    #convert to integer, read in that many bytes (reverse byte order)
    remaining_bytes = ord(byte_count[0]) + ( 256 * ord(byte_count[1]))
    rest = sys.stdin.read(remaining_bytes)

    ### Create SMB Header ###
    response = "\xffSMB"    
    response += "\x75"      #SMB command
    response += "\x22\x00\x00\xc0" #NT status 
    response += "\x88"      #Flags 1
    response += "\xc8\x41"  #Flags 2
    response += "\x00\x00"  #PID high
    response += "\x00\x00\x00\x00\x00\x00\x00\x00" #Signature 
    response += "\x00\x00"  #Reserved
    response += "\x00\x00"  #Tree ID
    response += pid         #pid
    response += "\x00\x00"  #User id
    response += mid         #Multiplex id

    ### Create Response ###

    response += "\x00\x00\x00"

    #Prepend packet with NetBios Session Service header
    sys.stdout.write("\x00\x00\x00" + chr(len(response)) + response)
    sys.stdout.flush()
    return True

def HandleDisconnectRequest(pid, mid):
    #Word Count
    word_count = sys.stdin.read(1)
    remaining_bytes = ord(word_count) * 2
    options = sys.stdin.read(remaining_bytes)

    #Byte Count
    byte_count = sys.stdin.read(2)
    #convert to integer, read in that many bytes (reverse byte order)
    remaining_bytes = ord(byte_count[0]) + ( 256 * ord(byte_count[1]))
    rest = sys.stdin.read(remaining_bytes)

    ### Create SMB Header ###
    response = "\xffSMB"    
    response += "\x71"      #SMB command
    response += "\x00\x00\x00\x00" #NT status 
    response += "\x88"      #Flags 1
    response += "\xc8\x01"  #Flags 2
    response += "\x00\x00"  #PID high
    response += "\x00\x00\x00\x00\x00\x00\x00\x00" #Signature 
    response += "\x00\x00"  #Reserved
    response += "\x00\x00"  #Tree ID
    response += pid         #pid
    response += "\x00\x00"  #User id
    response += mid         #Multiplex id

    ### Create Response ###

    response += "\x00\x00\x00"

    #Prepend packet with NetBios Session Service header
    sys.stdout.write("\x00\x00\x00" + chr(len(response)) + response)
    sys.stdout.flush()
    return True
   

#error_code = 1 byte SMB Command
#status = 4 byte NT status code
#pid = the Process ID that needs to be parroted back
#mid = the Message ID that needs to be parroted back
def SendError(error_code, status, pid, mid):
    ### SMB Header ###
    error_message = "\xffSMB"
    error_message += error_code
    error_message += status
    error_message += "\x88"
    error_message += "\xc8\x41"
    error_message += "\x00\x00"
    error_message += "\x00\x00\x00\x00\x00\x00\x00\x00"
    error_message += "\x00\x00\x00\x00"
    error_message += "\x00\x00"
    error_message += pid
    error_message += "\x00\x00"
    error_message += mid

    ### Response ###
    error_message += "\x00\x00\x00"

    sys.stdout.write(error_message)
    sys.stdout.flush()
    return True


#Read Arguments
for line in open(sys.argv[2],'r'):
    if(line.split(' ', 1)[0] == "NATIVE_OS"):
        native_os = line.split(' ', 1)[1].rstrip()
    if(line.split(' ', 1)[0] == "PRIMARY_DOMAIN"):
        primary_domain = line.split(' ', 1)[1].rstrip()
    if(line.split(' ', 1)[0] == "TIME_ZONE"):
        time_zone = int(line.split(' ', 1)[1].rstrip())
    if(line.split(' ', 1)[0] == "LAN_MANAGER"):
        lan_manager = line.split(' ', 1)[1].rstrip()


#Main Loop. Keep accepting requests until one comes back bad
keep_going = True
while keep_going == True:
    keep_going = GetRequest()    

