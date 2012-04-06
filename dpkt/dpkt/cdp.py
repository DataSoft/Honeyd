# $Id: cdp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import struct
from dpkt import Packet, in_cksum as _cdp_cksum

CDP_DEVID        = 1
CDP_ADDRESS      = 2
CDP_PORTID       = 3
CDP_CAPABILITIES = 4
CDP_VERSION      = 5
CDP_PLATFORM     = 6
CDP_IPPREFIX     = 7

class CDP(Packet):
    """Cisco Discovery Protocol."""
    __hdr__ = (
        ('version', 'B', 2),
        ('ttl', 'B', 180),
        ('sum', 'H', 0)
        )
    class Address(Packet):
        # XXX - only handle NLPID/IP for now
        __hdr__ = (
            ('ptype', 'B', 1),	# protocol type (NLPID)
            ('plen', 'B', 1),	# protocol length
            ('p', 'B', 0xcc),	# IP
            ('alen', 'H', 4)	# address length
            )
        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.data = self.data[:self.alen]
            
    class TLV(Packet):
        __hdr__ = (
            ('type', 'H', 0),
            ('len', 'H', 4)
            )
        def unpack(self, buf):
            Packet.unpack(self, buf)
            self.data = self.data[:self.len - 4]
            if self.type == CDP_ADDRESS:
                n = struct.unpack('>I', self.data[:4])[0]
                buf = self.data[4:]
                l = []
                for i in range(n):
                    a = CDP.Address(buf)
                    l.append(a)
                    buf = buf[len(a):]
                self.data = l

        def __len__(self):
            if self.type == CDP_ADDRESS:
                n = 4 + sum(map(len, self.data))
            else:
                n = len(self.data)
            return self.__hdr_len__ + n
        
        def __str__(self):
            self.len = len(self)
            if self.type == CDP_ADDRESS:
                s = struct.pack('>I', len(self.data)) + \
                    ''.join(map(str, self.data))
            else:
                s = self.data
            return self.pack_hdr() + s

    def unpack(self, buf):
        Packet.unpack(self, buf)
        buf = self.data
        l = []
        while buf:
            tlv = self.TLV(buf)
            l.append(tlv)
            buf = buf[len(tlv):]
        self.data = l

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __str__(self):
        data = ''.join(map(str, self.data))
        if not self.sum:
            self.sum = _cdp_cksum(self.pack_hdr() + data)
        return self.pack_hdr() + data

