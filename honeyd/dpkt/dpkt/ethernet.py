# $Id: ethernet.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from struct import unpack as st_unpack
from dpkt import Packet
import arp, cdp, dtp, ip, ip6, ipx, ppp, stp

ETH_CRC_LEN	= 4
ETH_HDR_LEN	= 14

ETH_LEN_MIN	= 64		# minimum frame length with CRC
ETH_LEN_MAX	= 1518		# maximum frame length with CRC

ETH_MTU		= (ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
ETH_MIN		= (ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_PUP	= 0x0200		# PUP protocol
ETH_TYPE_IP	= 0x0800		# IP protocol
ETH_TYPE_ARP	= 0x0806		# address resolution protocol
ETH_TYPE_CDP	= 0x2000		# Cisco Discovery Protocol
ETH_TYPE_DTP	= 0x2004		# Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP	= 0x8035		# reverse addr resolution protocol
ETH_TYPE_8021Q	= 0x8100		# IEEE 802.1Q VLAN tagging
ETH_TYPE_IPX	= 0x8137		# Internetwork Packet Exchange
ETH_TYPE_IP6	= 0x86DD		# IPv6 protocol
ETH_TYPE_PPP	= 0x880B		# PPP
ETH_TYPE_MPLS	= 0x8847		# MPLS
ETH_TYPE_MPLS_MCAST	= 0x8848	# MPLS Multicast
ETH_TYPE_PPPOEDISC	= 0x8863	# PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPOE		= 0x8864	# PPP Over Ethernet Session Stage
ETH_TYPE_LOOPBACK	= 0x9000	# used to test interfaces

class Ethernet(Packet):
    """Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
    with automatic 802.1q, MPLS, and Cisco ISL decapsulation."""
    __hdr__ = (
        ('dst', '6s', ''),
        ('src', '6s', ''),
        ('type', 'H', ETH_TYPE_IP)
        )
    _typesw = {
        ETH_TYPE_ARP:arp.ARP,
        ETH_TYPE_CDP:cdp.CDP,
        ETH_TYPE_DTP:dtp.DTP,
        ETH_TYPE_IP:ip.IP,
        ETH_TYPE_IP6:ip6.IP6,
        ETH_TYPE_IPX:ipx.IPX,
        ETH_TYPE_PPP:ppp.PPP,
        }
    def _unpack_data(self, buf):
        if self.type == ETH_TYPE_8021Q:
            self.tag, self.type = st_unpack('>HH', buf[:4])
            buf = buf[4:]
        elif self.type == ETH_TYPE_MPLS or \
             self.type == ETH_TYPE_MPLS_MCAST:
            # XXX - skip labels
            for i in range(24):
                if st_unpack('>I', buf[i:i+4])[0] & 0x0100: # MPLS_STACK_BOTTOM
                    break
            self.type = ETH_TYPE_IP
            buf = buf[(i + 1) * 4:]
        try:
            self.data = self._typesw[self.type](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except:
            self.data = buf
    
    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.type > 1500:
            # Ethernet II
            self._unpack_data(self.data)
        elif self.dst.startswith('\x01\x00\x0c\x00\x00') or \
             self.dst.startswith('\x03\x00\x0c\x00\x00'):
            # Cisco ISL
            #self.vlan = st_unpack('>H', self.data[6:8])[0]
            self.unpack(self.data[12:])
        elif self.data.startswith('\xff\xff'):
            # Novell "raw" 802.3
            self.type = ETH_TYPE_IPX
            self.data = self.ipx = ipx.IPX(self.data[2:])
        else:
            # 802.2 LLC
            #self.dsap, self.ssap, self.ctl = st_unpack('BBB', self.data[:3])
            if self.data.startswith('\xaa\xaa'):
                # SNAP
                self.type = st_unpack('>H', self.data[6:8])[0]
                self._unpack_data(self.data[8:])
            else:
                # non-SNAP
                dsap = ord(self.data[0])
                if dsap == 0x06: # SAP_IP
                    self.data = self.ip = ip.IP(self.data[3:])
                elif dsap == 0x10 or dsap == 0xe0: # SAP_NETWARE{1,2}
                    self.data = self.ipx = ipx.IPX(self.data[3:])
                elif dsap == 0x42: # SAP_STP
                    self.data = self.stp = stp.STP(self.data[3:])
