# $Id: udp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import dpkt

UDP_PORT_MAX	= 65535

class UDP(dpkt.Packet):
    """User Datagram Protocol."""
    __hdr__ = (
        ('sport', 'H', 0xdead),
        ('dport', 'H', 0),
        ('ulen', 'H', 8),
        ('sum', 'H', 0)
        )

