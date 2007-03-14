# $Id: igmp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet, in_cksum as _igmp_cksum

class IGMP(Packet):
    """Internet Group Management Protocol."""
    __hdr__ = (
        ('type', 'B', 0),
        ('maxresp', 'B', 0),
        ('sum', 'H', 0),
        ('group', 'I', 0)
        )
    def __str__(self):
        if not self.sum:
            self.sum = _igmp_cksum(Packet.__str__(self))
        return Packet.__str__(self)

