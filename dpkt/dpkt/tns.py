# $Id: tns.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import dpkt

class TNS(dpkt.Packet):
    __hdr__ = [
    ('length', 'H', 0),
    ('pktsum', 'H', 0),
    ('type', 'B', 0),
    ('rsvd', 'B', 0),
    ('hdrsum', 'H', 0)
    ]

