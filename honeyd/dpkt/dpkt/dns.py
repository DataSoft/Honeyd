# $Id: dns.py,v 1.1.1.1 2005/10/29 18:20:48 provos Exp $

from struct import pack as _st_pack, unpack as _st_unpack
from dpkt import Packet

DNS_Q = 0
DNS_R = 1

# Opcodes
DNS_QUERY = 0
DNS_IQUERY = 1
DNS_STATUS = 2
DNS_NOTIFY = 4
DNS_UPDATE = 5

# Flags
DNS_CD = 0x0010	# checking disabled
DNS_AD = 0x0020	# authenticated data
DNS_Z =  0x0040	# unused
DNS_RA = 0x0080	# recursion available
DNS_RD = 0x0100	# recursion desired
DNS_TC = 0x0200	# truncated
DNS_AA = 0x0400	# authoritative answer

# Response codes
DNS_RCODE_NOERR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5
DNS_RCODE_YXDOMAIN = 6
DNS_RCODE_YXRRSET = 7
DNS_RCODE_NXRRSET = 8
DNS_RCODE_NOTAUTH = 9
DNS_RCODE_NOTZONE = 10

# RR types
DNS_A = 1
DNS_NS = 2
DNS_CNAME = 5
DNS_SOA = 6
DNS_PTR = 12
DNS_HINFO = 13
DNS_MX = 15
DNS_TXT = 16
DNS_AAAA = 28
DNS_SRV = 33

# RR classes
DNS_IN = 1
DNS_CHAOS = 3
DNS_HESIOD = 4
DNS_ANY = 255

def unpack_name(buf, off):
    name = ''
    saved_off = 0
    for i in range(100): # XXX
        n = ord(buf[off])
        if n == 0:
            off += 1
            break
        elif (n & 0xc0) == 0xc0:
            ptr = _st_unpack('>H', buf[off:off+2])[0] & 0x3fff
            off += 2
            if not saved_off:
                saved_off = off
            # XXX - don't use recursion!@#$
            name = name + unpack_name(buf, ptr)[0] + '.'
            break
        else:
            off += 1
            name = name + buf[off:off+n] + '.'
            if len(name) > 255:
                raise ValueError, 'name longer than 255 bytes'
            off += n
    return name.strip('.'), off

class DNS(Packet):
    """Domain Name System."""
    __hdr__ = (
        ('id', 'H', 0),
        ('op', 'H', DNS_RD),	# recursive query
        # XXX - lists of query, RR objects
        ('qd', 'H', []),
        ('an', 'H', []),
        ('ns', 'H', []),
        ('ar', 'H', [])
        )
    def get_qr(self):
        return int((self.op & 0x8000) == 0x8000)
    def set_qr(self, v):
        if v: self.op |= 0x8000
        else: self.op &= ~0x8000
    qr = property(get_qr, set_qr)

    def get_opcode(self):
        return (self.op >> 11) & 0xf
    def set_opcode(self, v):
        self.op = (self.op & ~0x7800) | ((v & 0xf) << 11)
    opcode = property(get_opcode, set_opcode)

    def get_rcode(self):
        return self.op & 0xf
    def set_rcode(self, v):
        self.op = (self.op & ~0xf) | (v & 0xf)
    rcode = property(get_rcode, set_rcode)
    
    class Q(Packet):
        """DNS question."""
        __hdr__ = (
            ('name', '1025s', ''),
            ('type', 'H', DNS_A),
            ('cls', 'H', DNS_IN)
            )
        def __len__(self):
            raise NotImplementedError
        __str__ = __len__
        def unpack(self, buf):
            raise NotImplementedError

    class RR(Q):
        """DNS resource record."""
        __hdr__ = (
            ('name', '1025s', ''),
            ('type', 'H', DNS_A),
            ('cls', 'H', DNS_IN),
            ('ttl', 'I', 0),
            ('rlen', 'H', 4),
            ('rdata', 's', '')
            )
        def unpack_rdata(self, buf, off):
            if self.type == DNS_A:
                self.ip = self.rdata
            elif self.type == DNS_NS or self.type == DNS_CNAME or \
                 self.type == DNS_PTR:
                self.name, off = unpack_name(buf, off)
            elif self.type == DNS_SOA:
                self.mname, off = unpack_name(buf, off)
                self.rname, off = unpack_name(buf, off)
                self.serial, self.refresh, self.retry, self.expire, \
                    self.minimum = _st_unpack('>IIIII', buf[off:off+20])
            elif self.type == DNS_MX:
                self.preference = _st_unpack('>H', self.rdata[:2])
                self.exchange, off = unpack_name(buf, off+2)
            elif self.type == DNS_TXT or self.type == DNS_HINFO:
                self.text = []
                buf = self.rdata
                while buf:
                    n = ord(buf[0])
                    self.text.append(buf[1:1+n])
                    buf = buf[1+n:]
            elif self.type == DNS_AAAA:
                self.ip6 = self.rdata
            elif self.type == DNS_SRV:
                self.priority, self.weight, self.port = \
                    _st_unpack('>HHH', self.rdata[:6])
                self.target, off = unpack_name(buf, off+6)
    
    def pack_name(self, buf, name):
        """Append compressed DNS name and return buf."""
        labels = name.split('.')
        labels.append('')
        for i, label in enumerate(labels):
            key = '.'.join(labels[i:]).upper()
            ptr = self.index.get(key, None)
            if not ptr:
                if len(key) > 1:
                    ptr = len(buf)
                    if ptr < 0xc000:
                        self.index[key] = ptr
                i = len(label)
                buf += chr(i) + label
            else:
                buf += _st_pack('>H', (0xc000 | ptr))
                break
        return buf
    
    def unpack_name(self, buf, off):
        """Return DNS name and new offset."""
        return unpack_name(buf, off)
    
    def pack_q(self, buf, q):
        """Append packed DNS question and return buf."""
        buf = self.pack_name(buf, q.name)
        buf += _st_pack('>HH', q.type, q.cls)
        return buf

    def unpack_qd(self, buf, off):
        """Return DNS question and new offset."""
        q = self.Q()
        q.name, off = self.unpack_name(buf, off)
        q.type, q.cls = _st_unpack('>HH', buf[off:off+4])
        off += 4
        return q, off

    def pack_rr(self, buf, rr):
        """Append packed DNS RR and return buf."""
        buf = self.pack_name(buf, rr.name)
        buf += _st_pack('>HHIH', rr.type, rr.cls, rr.ttl, len(rr.rdata))
        buf += rr.rdata
        return buf
    
    def unpack_rr(self, buf, off):
        """Return DNS RR and new offset."""
        rr = self.RR()
        rr.name, off = self.unpack_name(buf, off)
        rr.type, rr.cls, rr.ttl, rdlen = _st_unpack('>HHIH', buf[off:off+10])
        off += 10
        rr.rdata = buf[off:off+rdlen]
        rr.unpack_rdata(buf, off)
        off += rdlen
        return rr, off
    
    def unpack(self, buf):
        Packet.unpack(self, buf)
        off = self.__hdr_len__
        cnt = self.qd
        self.qd = []
        for i in range(cnt):
            qd, off = self.unpack_qd(buf, off)
            self.qd.append(qd)
        for x in ('an', 'ns', 'ar'):
            cnt = getattr(self, x, 0)
            setattr(self, x, [])
            for i in range(cnt):
                rr, off = self.unpack_rr(buf, off)
                getattr(self, x).append(rr)
        self.data = ''

    def __len__(self):
        # XXX - cop out
        return len(str(self))

    def __str__(self):
        # XXX - compress names on the fly
        self.index = {}
        buf = _st_pack(self.__hdr_fmt__, self.id, self.op,
                      len(self.qd), len(self.an), len(self.ns), len(self.ar))
        for q in self.qd:
            buf = self.pack_q(buf, q)
        for x in ('an', 'ns', 'ar'):
            for rr in getattr(self, x):
                buf = self.pack_rr(buf, rr)
        del self.index
        return buf

if __name__ == '__main__':
    import unittest
    from ip import IP

    class DNSTestCase(unittest.TestCase):
        def test_DNS(self):
            s = 'E\x00\x02\x08\xc15\x00\x00\x80\x11\x92aBk0\x01Bk0w\x005\xc07\x01\xf4\xda\xc2d\xd2\x81\x80\x00\x01\x00\x03\x00\x0b\x00\x0b\x03www\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x03V\x00\x17\x03www\x06google\x06akadns\x03net\x00\xc0,\x00\x01\x00\x01\x00\x00\x01\xa3\x00\x04@\xe9\xabh\xc0,\x00\x01\x00\x01\x00\x00\x01\xa3\x00\x04@\xe9\xabc\xc07\x00\x02\x00\x01\x00\x00KG\x00\x0c\x04usw5\x04akam\xc0>\xc07\x00\x02\x00\x01\x00\x00KG\x00\x07\x04usw6\xc0t\xc07\x00\x02\x00\x01\x00\x00KG\x00\x07\x04usw7\xc0t\xc07\x00\x02\x00\x01\x00\x00KG\x00\x08\x05asia3\xc0t\xc07\x00\x02\x00\x01\x00\x00KG\x00\x05\x02za\xc07\xc07\x00\x02\x00\x01\x00\x00KG\x00\x0f\x02zc\x06akadns\x03org\x00\xc07\x00\x02\x00\x01\x00\x00KG\x00\x05\x02zf\xc07\xc07\x00\x02\x00\x01\x00\x00KG\x00\x05\x02zh\xc0\xd5\xc07\x00\x02\x00\x01\x00\x00KG\x00\x07\x04eur3\xc0t\xc07\x00\x02\x00\x01\x00\x00KG\x00\x07\x04use2\xc0t\xc07\x00\x02\x00\x01\x00\x00KG\x00\x07\x04use4\xc0t\xc0\xc1\x00\x01\x00\x01\x00\x00\xfb4\x00\x04\xd0\xb9\x84\xb0\xc0\xd2\x00\x01\x00\x01\x00\x001\x0c\x00\x04?\xf1\xc76\xc0\xed\x00\x01\x00\x01\x00\x00\xfb4\x00\x04?\xd7\xc6S\xc0\xfe\x00\x01\x00\x01\x00\x001\x0c\x00\x04?\xd00.\xc1\x0f\x00\x01\x00\x01\x00\x00\n\xdf\x00\x04\xc1-\x01g\xc1"\x00\x01\x00\x01\x00\x00\x101\x00\x04?\xd1\xaa\x88\xc15\x00\x01\x00\x01\x00\x00\r\x1a\x00\x04PCC\xb6\xc0o\x00\x01\x00\x01\x00\x00\x10\x7f\x00\x04?\xf1I\xd6\xc0\x87\x00\x01\x00\x01\x00\x00\n\xdf\x00\x04\xce\x84dl\xc0\x9a\x00\x01\x00\x01\x00\x00\n\xdf\x00\x04A\xcb\xea\x1b\xc0\xad\x00\x01\x00\x01\x00\x00\x0b)\x00\x04\xc1l\x9a\t'
            ip = IP(s)
            dns = DNS(ip.udp.data)
            self.failUnless(dns.qd[0].name == 'www.google.com' and
                            dns.an[1].name == 'www.google.akadns.net')
            s = '\x05\xf5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x03cnn\x03com\x00\x00\x01\x00\x01'
            dns = DNS(s)
            self.failUnless(s == str(dns))

    unittest.main()

        
