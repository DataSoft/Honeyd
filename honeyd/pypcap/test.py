#!/usr/bin/env python

import glob, sys, unittest
sys.path.insert(0, glob.glob('build/lib.*')[0])
import pcap

class PcapTestCase(unittest.TestCase):
    def test_pcap_iter(self):
        l = [ (x[0], len(x[1])) for x in pcap.pcap('test.pcap') ]
        assert l == [(1092256609.9265549, 62), (1092256609.9265759, 54), (1092256610.332396, 62), (1092256610.3324161, 54), (1092256610.8330729, 62), (1092256610.8330951, 54)], 'pcap iter'

    def test_pcap_properties(self):
        p = pcap.pcap('test.pcap')
        assert (p.name, p.snaplen, p.dloff, p.filter) == ('test.pcap', 2000, 14, ''), 'pcap properties'

    def test_pcap_errors(self):
        p = pcap.pcap('test.pcap')
        try:
            print p.stats()
        except OSError:
            pass
        assert p.geterr() != '', 'pcap_geterr'

    def test_pcap_dispatch(self):
        def __cnt_handler(ts, pkt, d):
            d['cnt'] += 1
        p = pcap.pcap('test.pcap')
        d = { 'cnt':0 }
        n = p.dispatch(-1, __cnt_handler, d)
        assert n == 0
        assert d['cnt'] == 6
        
        def __bad_handler(ts, pkt):
            raise NotImplementedError
        p = pcap.pcap('test.pcap')
        try:
            p.dispatch(-1, __bad_handler)
        except NotImplementedError:
            pass

    def test_pcap_readpkts(self):
        assert len(pcap.pcap('test.pcap').readpkts()) == 6

if __name__ == '__main__':
    unittest.main()
