# $Id: pim.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet, in_cksum as _pim_cksum

class PIM(Packet):
    """Protocol Independent Multicast."""
    __hdr__ = (
        ('v_type', 'B', 0x20),
        ('rsvd', 'B', 0),
        ('sum', 'H', 0)
        )
    def _get_v(self): return self.v_type >> 4
    def _set_v(self, v): self.v_type = (v << 4) | (self.v_type & 0xf)
    v = property(_get_v, _set_v)
    
    def _get_type(self): return self.v_type & 0xf
    def _set_type(self, type): self.v_type = (self.v_type & 0xf0) | type
    type = property(_get_type, _set_type)

    def __str__(self):
        if not self.sum:
            self.sum = _pim_cksum(Packet.__str__(self))
        return Packet.__str__(self)
