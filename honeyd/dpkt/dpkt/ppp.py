# $Id: ppp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from struct import unpack as st_unpack
from dpkt import Packet
import ip

# XXX - finish later

# http://www.iana.org/assignments/ppp-numbers
PPP_IP	= 0x21	# Internet Protocol

# Protocol field compression
PFC_BIT	= 0x01

class PPP(Packet):
    """Point-to-Point Protocol."""
    __hdr__ = (
        ('p', 'B', PPP_IP),
        )
    _protosw = {
        PPP_IP:ip.IP,
        }
    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.p & PFC_BIT == 0:
            self.p = _st_unpack('>H', buf)
            self.data = self.data[1:]
        try:
            self.data = self._protosw[self.p](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except:
            pass

