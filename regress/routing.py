#!/usr/bin/env python
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
import os
import sys
import getopt
import regress
import time
import dnet
from dpkt.ip import IP
from dpkt.icmp import ICMP
from dpkt.tcp import TCP

class RouteOne(regress.Test):
    def Setup(self):
        self.name = "Routing to Open Port"
        self.expect = "route.output.1"

        # Packet 1
        payload = TCP(sport=555, dport=80, seq=10000,
                      flags=dnet.TH_SYN)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.3.10"),
                id=8143, ttl=1,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 2
        payload = TCP(sport=555, dport=80, seq=10000,
                      flags=dnet.TH_SYN)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.3.10"),
                id=8144, ttl=2,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 3
        payload = TCP(sport=555, dport=80, seq=10000,
                      flags=dnet.TH_SYN)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.3.10"),
                id=8145, ttl=3,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

# Main
def usage():
    print "Usage: %s [-dg]" % sys.argv[0]

try:
    opts, args = getopt.getopt(sys.argv[1:],"dg", ["debug", "generate"])
except getopt.GetoptError:
    usage()
    sys.exit(2)

debug = 0
generate = 0
for o, a in opts:
    if o in ("-d", "--debug"):
	    debug = 1
    if o in ("-g", "--generate"):
	    generate = 1
    if o in ("-h", "--help"):
            usage()
            sys.exit(1)

reg = regress.regress("routing behavior", "../honeyd", "config.2", debug)
reg.generate = generate
reg.run(RouteOne())
reg.finish()
