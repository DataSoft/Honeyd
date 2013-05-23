#!/usr/bin/python

import sys
import binascii

def GetRequest():
    #Server component must be "0xffSMB"
    server_component = sys.stdin.read(4)
    if(server_component != "\xffSMB"):
        return
    
    ### SMB Header ###

    #SMB command
    smb_command = sys.stdin.read(1)
    #NT status 
    nt_status = sys.stdin.read(4)
    #Flags 1
    flags1 = sys.stdin.read(1)
    #Flags 2
    flags2 = sys.stdin.read(2)
    #PID high
    pid_high = sys.stdin.read(2)
    #Signature
    signature = sys.stdin.read(8)
    #Reserved
    pid_high = sys.stdin.read(2)
    #Tree ID
    tree_id = sys.stdin.read(2)
    #pid
    pid = sys.stdin.read(2)
    #User id
    user_id = sys.stdin.read(2)
    #Multiplex id
    user_id = sys.stdin.read(2)

    ### Supported Request Types ###

    #Negotiate Protocol Request
    if(smb_command == "\x72"):
        HandleNegotiateProtocolRequest(pid, mid)
        return

    #Session Setup AndX Request (authenticate)
    if(smb_command == "\x73"):
        HandleSessionSetupRequest()
        return

    #Tree Connect AndX Request
    if(smb_command == "\x75"):
        HandleTreeConnectRequest()
        return

    #Tree Disconnect AndX Request
    if(smb_command == "\x71"):
        HandleDisconnectRequest()
        return

    SendError(error_code, status, pid, mid)
    return

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
        #TODO Check against known good list of dialects
        if(dialects[i][1:] == "NT LM 0.12"):
            chosen_dialect = i
            break

    #Craft Response#
    ### SMB Header ###
    response = "\xffSMB"
    response += "\x72"
    response += "\x00\x00\x00\x00"
    response += "\x88"
    response += "\xc8\x01"
    response += "\x00\x00"
    response += "\x00\x00\x00\x00\x00\x00\x00\x00"
    response += "\x00\x00\x00\x00"
    response += "\x00\x00"
    response += pid
    response += "\x00\x00"
    response += mid

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
    response += "\x7d\xf3\x01\x80" #capabilties (no extra security)
    response += "\xa9\xbb\x01\x95\x73\x56\xce\x01" #TODO get system time
    response += "\xa4\x01"  #TODO get server time
    response += "\x00"
    response += "\x10" #length onward
    #TODO generate GUID
    response += "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"



def HandleSessionSetupRequest():
    return

def HandleTreeConnectRequest():
    return

def HandleDisconnectRequest():
    return
   

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
    error_message += "\xc8\x01"
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



GetRequest()



