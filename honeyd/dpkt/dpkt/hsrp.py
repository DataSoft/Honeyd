# $Id: hsrp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import dpkt

# Opcodes
HELLO = 0
COUP = 1
RESIGN = 2

# States
INITIAL = 0x00
LEARN = 0x01
LISTEN = 0x02
SPEAK = 0x04
STANDBY = 0x08
ACTIVE = 0x10

class HSRP(dpkt.Packet):
    """Cisco Hot Standby Router Protocol."""
    __hdr__ = (
        ('version', 'B', 0),
        ('opcode', 'B', 0),
        ('state', 'B', 0),
        ('hello', 'B', 0),
        ('hold', 'B', 0),
        ('priority', 'B', 0),
        ('group', 'B', 0),
        ('rsvd', 'B', 0),
        ('auth', '8s', 'cisco'),
        ('vip', '4s', '')
    )
