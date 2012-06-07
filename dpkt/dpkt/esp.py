# $Id: esp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet

class ESP(Packet):
    """Encapsulated Security Protocol."""
    __hdr__ = (
        ('spi', 'I', 0),
        ('seq', 'I', 0)
        )

