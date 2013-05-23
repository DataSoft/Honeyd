#!/usr/bin/python

import sys
import binascii

def GetRequest(encoded_str):
    #Server component must be "0xffSMB"
    server_component = sys.stdin.read(4)
    if(server_component != "0xffSMB"):
        SendError("0xfe")
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

    ### Negotiate Protocol Request ###

    #Word Count
    word_count = sys.stdin.read(1)
    #Byte Count
    byte_count = sys.stdin.read(2)
    #convert to integer, read in that many bytes
    remaining_bytes = (256 * ord(byte_count[0])) + ord(byte_count[1])
    requested_dialects = sys.stdin.read(remaining_bytes)

    
    

def SendError(error_code):
    error_message = "0xffSMB"
    error_message += error_code
    error_message += 


    sys.stdout.write(error_message)







