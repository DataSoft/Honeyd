#!/usr/bin/env python
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
import os
import getopt
import sys
import regress
import time
import dnet
from dpkt.ip import IP
from dpkt.icmp import ICMP
from dpkt.tcp import TCP

class Ping(regress.Test):
    def Setup(self):
        self.name = "Ping"
        self.expect = "gen.output.1"

        payload = ICMP(type = 8, data=ICMP.Echo(id=123, seq=1, data="12345690"))
        ip = IP(src=dnet.ip_aton("192.0.2.254"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5624,
                p=dnet.IP_PROTO_ICMP)

        ip.data = payload
        ip.len += len(ip.data)

        self.packets.append(ip)

class TCPOpen(regress.Test):
    def Setup(self):
        self.name = "Connection to open port"
        self.expect = "gen.output.2"

        # Packet 1
        payload = TCP(sport=555, dport=80, seq=10000, flags=dnet.TH_SYN)
        ip = IP(src=dnet.ip_aton("192.0.2.254"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5624,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 2
        payload = TCP(sport=555, dport=80,
                      seq=10001, ack=194595108,
                      flags=dnet.TH_ACK)
        ip = IP(src=dnet.ip_aton("192.0.2.254"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5625, p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 3
        payload = TCP(sport=555, dport=80,
                      seq=10001, ack=194595108,
                      flags=dnet.TH_ACK)
        payload.data = 'Honeyd fools you'
        ip = IP(src=dnet.ip_aton("192.0.2.254"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5625, p=dnet.IP_PROTO_TCP)
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
reg = regress.regress("general networking tests", "../honeyd", "config.1", debug)
reg.generate = generate
reg.run(Ping())
reg.run(TCPOpen())
reg.finish()
