#
# Dynamic Trunking Protocol
#
# from Ethereal's DTP dissector.
#
# Copyright (c) 2004 Dug Song <dugsong@monkey.org>
#
# $Id: dtp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import struct
import dpkt

class DTP(dpkt.Packet):
    __hdr__ = (
        ('v', 'B', 0),
        ) # rest is TLVs
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        buf = self.data
        tvs = []
        while buf:
            t, l = struct.unpack('>HH', buf[:4])
            v, buf = buf[4:4+l], buf[4+l:]
            tvs.append((t, v))
        self.data = tvs

TRUNK_NAME = 0x01
MAC_ADDR = 0x04
