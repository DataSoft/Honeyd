# $Id: ip6.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from dpkt import Packet, in_cksum_add as _ip_cksum_add, \
     in_cksum_done as _ip_cksum_done
import ip

class IP6(Packet):
    """Internet Protocol, version 6."""
    __hdr__ = (
        ('v_fc_flow', 'I', 0x60000000L),
        ('plen', 'H', 0),	# payload length (not including header)
        ('nxt', 'B', 0),	# next header protocol
        ('hlim', 'B', 0),	# hop limit
        ('src', '16s', ''),
        ('dst', '16s', '')
        )
    _protosw = ip.IP._protosw
    
    def _get_v(self):
        return self.v_fc_flow >> 28
    def _set_v(self, v):
        self.v_fc_flow = (self.v_fc_flow & ~0xf0000000L) | (v << 28)
    v = property(_get_v, _set_v)

    def _get_fc(self):
        return (self.v_fc_flow >> 20) & 0xff
    def _set_fc(self, v):
        self.v_fc_flow = (self.v_fc_flow & ~0xff00000L) | (v << 20)
    fc = property(_get_fc, _set_fc)

    def _get_flow(self):
        return self.v_fc_flow & 0xfffff
    def _set_flow(self, v):
        self.v_fc_flow = (self.v_fc_flow & ~0xfffff) | (v & 0xfffff)
    flow = property(_get_flow, _set_flow)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        buf = self.data[:self.plen]
        try:
            self.data = self._protosw[self.nxt](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except:
            self.data = buf

    def __str__(self):
        if self.nxt == 6 or self.nxt == 17 or self.nxt == 58:
            # XXX - set TCP, UDP, and ICMPv6 checksums
            p = str(self.data)
            s = _ip_cksum_add(0, self.src + self.dst)
            s = _ip_cksum_add(s, p)
            try: self.data.sum = _ip_cksum_done(s + self.p + len(p))
            except AttributeError: pass
        return Packet.__str__(self)

