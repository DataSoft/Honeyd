# $Id: pcap.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

import time
import dpkt

TCPDUMP_MAGIC = 0xa1b2c3d4L
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

class PcapFileHdr(dpkt.Packet):
    """pcap file header."""
    __hdr__ = (
        ('magic', 'I', TCPDUMP_MAGIC),
        ('v_major', 'H', PCAP_VERSION_MAJOR),
        ('v_minor', 'H', PCAP_VERSION_MINOR),
        ('thiszone', 'I', 0),
        ('sigfigs', 'I', 0),
        ('snaplen', 'I', 1500),
        ('linktype', 'I', 1),
        )
    __byte_order__ = '@'

class PcapPktHdr(dpkt.Packet):
    """pcap packet header."""
    __hdr__ = (
        ('tv_sec', 'I', 0),
        ('tv_usec', 'I', 0),
        ('caplen', 'I', 0),
        ('len', 'I', 0),
        )
    __byte_order__ = '@'

class PcapDumper(object):
    def __init__(self, filename, snaplen=1500, linktype=1):
        self.f = open(filename, 'w')
        fh = PcapFileHdr(snaplen=snaplen, linktype=linktype)
        self.f.write(str(fh))

    def append(self, pkt, ts=None):
        if ts is None:
            ts = time.time()
        s = str(pkt)
        n = len(s)
        ph = PcapPktHdr(tv_sec=int(ts),
                        tv_usec=int((int(ts) - float(ts)) * 1000000.0),
                        caplen=n, len=n)
        self.f.write(str(ph))
        self.f.write(s)

    def close(self):
        f.close()
