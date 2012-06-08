# $Id: ipx.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet

IPX_HDR_LEN = 30

class IPX(Packet):
    """Internetwork Packet Exchange."""
    __hdr__ = (
        ('sum', 'H', 0xffff),
        ('len', 'H', IPX_HDR_LEN),
        ('tc', 'B', 0),
        ('pt', 'B', 0),
        ('dst', '12s', ''),
        ('src', '12s', '')
        )
