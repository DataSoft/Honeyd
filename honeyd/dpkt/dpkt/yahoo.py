# $Id: yahoo.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import dpkt

class YHOO(dpkt.Packet):
    __hdr__ = [
        ('version', '8s', ' ' * 8),
        ('length', 'I', 0),
        ('service', 'I', 0),
        ('connid', 'I', 0),
        ('magic', 'I', 0),
        ('unknown', 'I', 0),
        ('type', 'I', 0),
        ('nick1', '36s', ' ' * 36),
        ('nick2', '36s', ' ' * 36)
    ]
    __byte_order__ = '<'

class YMSG(dpkt.Packet):
    __hdr__ =  [
        ('version', '8s', ' ' * 8),
        ('length', 'H', 0),
        ('type', 'H', 0),
        ('unknown1', 'I', 0),
        ('unknown2', 'I', 0)
    ]
    
