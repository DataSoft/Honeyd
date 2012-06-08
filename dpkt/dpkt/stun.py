# $Id: stun.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet

class STUN(Packet):
    """Simple Traversal of UDP through NAT."""
    __hdr__ = (
        ('type', 'H', 0),
        ('len', 'H', 0),
        ('xid', 'H', 0)
        )

