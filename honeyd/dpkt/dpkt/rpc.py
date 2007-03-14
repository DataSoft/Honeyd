# $Id: rpc.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import struct
from dpkt import Packet

# RPC.dir
CALL = 0
REPLY = 1

# RPC.Auth.flavor
AUTH_NONE = AUTH_NULL = 0
AUTH_UNIX = 1
AUTH_SHORT = 2
AUTH_DES = 3

# RPC.Reply.stat
MSG_ACCEPTED = 0
MSG_DENIED = 1

# RPC.Reply.Accept.stat
SUCCESS = 0
PROG_UNAVAIL = 1
PROG_MISMATCH = 2
PROC_UNAVAIL = 3
GARBAGE_ARGS = 4
SYSTEM_ERR = 5

# RPC.Reply.Reject.stat
RPC_MISMATCH = 0
AUTH_ERROR = 1

class RPC(Packet):
    """Remote Procedure Call."""
    __hdr__ = (
        ('xid', 'I', 0),
        ('dir', 'I', CALL)
        )
    class Auth(Packet):
        __hdr__ = (('flavor', 'I', AUTH_NONE), )
        def unpack(self, buf):
            Packet.unpack(self, buf)
            n = struct.unpack('>I', self.data[:4])[0]
            self.data = self.data[4:4+n]
        def __len__(self):
            return 8 + len(self.data)
        def __str__(self):
            return self.pack_hdr() + struct.pack('>I', len(self.data)) + \
                   self.data
    
    class Call(Packet):
        __hdr__ = (
            ('rpcvers', 'I', 2),
            ('prog', 'I', 0),
            ('vers', 'I', 0),
            ('proc', 'I', 0)
            )
        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.cred = RPC.Auth(self.data)
            self.verf = RPC.Auth(self.data[len(self.cred):])
            self.data = self.data[len(self.cred) + len(self.verf):]

    class Reply(Packet):
        __hdr__ = (('stat', 'I', MSG_ACCEPTED), )

        class Accept(Packet):
            __hdr__ = (('stat', 'I', SUCCESS), )
            def unpack(self, buf):
                self.verf = RPC.Auth(buf)
                buf = buf[len(self.verf):]
                self.stat = struct.unpack('>I', buf[:4])[0]
                if self.stat == SUCCESS:
                    self.data = buf[4:]
                elif self.stat == PROG_MISMATCH:
                    self.low, self.high = struct.unpack('>II', buf[4:12])
                    self.data = buf[12:]
            def __len__(self):
                if self.stat == PROG_MISMATCH: n = 8
                else: n = 0
                return len(self.verf) + 4 + n + len(self.data)
            def __str__(self):
                if self.stat == PROG_MISMATCH:
                    return str(self.verf) + struct.pack('>III', self.stat,
                        self.low, self.high) + self.data
                return str(self.verf) + Packet.__str__(self)
        
        class Reject(Packet):
            __hdr__ = (('stat', 'I', AUTH_ERROR), )
            def unpack(self, buf):
                Packet.unpack(self, buf)
                if self.stat == RPC_MISMATCH:
                    self.low, self.high = struct.unpack('>II', self.data[:8])
                    self.data = self.data[8:]
                elif self.stat == AUTH_ERROR:
                    self.why = struct.unpack('>I', self.data[:4])[0]
                    self.data = self.data[4:]
            def __len__(self):
                if self.stat == RPC_MISMATCH: n = 8
                elif self.stat == AUTH_ERROR: n =4
                else: n = 0
                return 4 + n + len(self.data)
            def __str__(self):
                if self.stat == RPC_MISMATCH:
                    return struct.pack('>III', self.stat, self.low,
                                       self.high) + self.data
                elif self.stat == AUTH_ERROR:
                    return struct.pack('>II', self.stat, self.why) + self.data
                return Packet.__str__(self)
        
        def unpack(self, buf):
            Packet.unpack(self, buf)
            if self.stat == MSG_ACCEPTED:
                self.data = self.accept = self.Accept(self.data)
            elif self.status == MSG_DENIED:
                self.data = self.reject = self.Reject(self.data)
        
    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.dir == CALL:
            self.data = self.call = self.Call(self.data)
        elif self.dir == REPLY:
            self.data = self.reply = self.Reply(self.data)
