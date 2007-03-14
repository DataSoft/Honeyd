# $Id: ospf.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet, in_cksum as _ospf_cksum

AUTH_NONE = 0
AUTH_PASSWORD = 1
AUTH_CRYPTO = 2

class OSPF(Packet):
    """Open Shortest Path First."""
    __hdr__ = (
        ('v', 'B', 0),
        ('type', 'B', 0),
        ('len', 'H', 0),
        ('router', 'I', 0),
        ('area', 'I', 0),
        ('sum', 'H', 0),
        ('atype', 'H', 0),
        ('auth', '8s', '')
        )
    def __str__(self):
        if not self.sum:
            self.sum = _ospf_cksum(Packet.__str__(self))
        return Packet.__str__(self)
