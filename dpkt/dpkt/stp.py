# $Id: stp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet

class STP(Packet):
    """Spanning Tree Protocol."""
    __hdr__ = (
        ('proto_id', 'H', 0),
        ('v', 'B', 0),
        ('type', 'B', 0),
        ('flags', 'B', 0),
        ('root_id', '8s', ''),
        ('root_path', 'I', 0),
        ('bridge_id', '8s', ''),
        ('port_id', 'H', 0),
        ('age', 'H', 0),
        ('max_age', 'H', 0),
        ('hello', 'H', 0),
        ('fd', 'H', 0)
        )
