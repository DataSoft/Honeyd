# $Id: dhcp.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet
import arp

DHCP_OP_REQUEST = 1
DHCP_OP_REPLY = 2

DHCP_MAGIC = 0x63825363

# DHCP option codes
DHCP_OPT_NETMASK = 1	# I: subnet mask
DHCP_OPT_ROUTER = 3	# s: list of router IPs
DHCP_OPT_DNS_SVRS = 6	# s: list of DNS servers
DHCP_OPT_HOSTNAME = 12	# s: client hostname
DHCP_OPT_DOMAIN = 15	# s: domain name
DHCP_OPT_REQ_IP = 50	# I: IP address
DHCP_OPT_LEASE_SEC = 51	# I: lease seconds
DHCP_OPT_MSGTYPE = 53	# B: message type
DHCP_OPT_SERVER_ID = 54	# I: server IP address
DHCP_OPT_PARAM_REQ = 55	# s: list of option codes
DHCP_OPT_VENDOR_ID = 60	# s: vendor string
DHCP_OPT_CLIENT_ID = 61	# Bs: idtype, id (idtype 0: FQDN, idtype 1: MAC)

# DHCP message type values
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

class DHCP(Packet):
    """Dynamic Host Configuration Protocol."""
    __hdr__ = (
        ('op', 'B', DHCP_OP_REQUEST),
        ('hrd', 'B', arp.ARP_HRD_ETH),  # just like ARP.hrd
        ('hln', 'B', 6),		# and ARP.hln
        ('hops', 'B', 0),
        ('xid', 'I', 0xdeadbeefL),
        ('secs', 'H', 0),
        ('flags', 'H', 0),
        ('ciaddr', 'I', 0),
        ('yiaddr', 'I', 0),
        ('siaddr', 'I', 0),
        ('giaddr', 'I', 0),
        ('chaddr', '16s', 16 * '\x00'),
        ('sname', '64s', 64 * '\x00'),
        ('file', '128s', 128 * '\x00'),
        ('magic', 'I', DHCP_MAGIC),
        )
    opts = ()	# list of (type, data) tuples

    def __len__(self):
        return self.__hdr_len__ + \
               sum([ 2 + len(o[1]) for o in self.opts ]) + len(self.data)

    def __str__(self):
        return self.pack_hdr() + self.pack_opts() + self.data
    
    def pack_opts(self):
        """Return packed options string."""
        if not self.opts:
            return ''
        l = []
        for t, data in self.opts:
            l.append('%s%s%s' % (chr(t), chr(len(data)), data))
        l.append('\xff')
        return ''.join(l)
    
    def unpack(self, buf):
        Packet.unpack(self, buf)
        self.chaddr = self.chaddr[:self.hln]
        buf = self.data
        l = []
        while buf:
            t = ord(buf[0])
            if t == 0xff:
                buf = buf[1:]
                break
            elif t == 0:
                buf = buf[1:]
            else:
                n = ord(buf[1])
                l.append((t, buf[2:2+n]))
                buf = buf[2+n:]
        self.opts = l
        self.data = buf

if __name__ == '__main__':
    import unittest

    class DHCPTestCast(unittest.TestCase):
        def test_DHCP(self):
            s = '\x01\x01\x06\x00\xadS\xc8c\xb8\x87\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02U\x82\xf3\xa6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x01\xfb\x01\x01=\x07\x01\x00\x02U\x82\xf3\xa62\x04\n\x00\x01e\x0c\tGuinevere<\x08MSFT 5.07\n\x01\x0f\x03\x06,./\x1f!+\xff\x00\x00\x00\x00\x00'
            dhcp = DHCP(s)
            self.failUnless(s == str(dhcp))

    unittest.main()

