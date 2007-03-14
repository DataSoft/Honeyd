# $Id: ah.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet
import ip

class AH(Packet):
    """Authentication Header."""
    __hdr__ = (
        ('nxt', 'B', 0),
        ('len', 'B', 0),	# payload length
        ('rsvd', 'H', 0),
        ('spi', 'I', 0),
        ('seq', 'I', 0)
        )
    auth = ''
    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.auth = self.data[:self.plen]
        buf = self.data[self.plen:]
        try:
            self.data = ip.IP._protosw[self.nxt](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except:
            self.data = buf

    def __len__(self):
        return self.__hdr_len__ + len(self.auth) + len(self.data)

    def __str__(self):
        return self.pack_hdr() + str(self.auth) + str(self.data)

