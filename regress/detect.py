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

class DetectSFSROpen(regress.Test):
    def Setup(self):
        self.name = "SF|SR Probe to Open Port"
        self.expect = "detect.output.1"

        # Packet 1
        payload = TCP(sport=555, dport=80, seq=10000,
                      flags=dnet.TH_SYN|dnet.TH_RST)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5624,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 2
        payload = TCP(sport=556, dport=80, seq=10000,
                      flags=dnet.TH_SYN|dnet.TH_FIN)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5625,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

class DetectSAAROpen(regress.Test):
    def Setup(self):
        self.name = "SA|AR Probe to Open Port"
        self.expect = "detect.output.2"

        # Packet 1
        payload = TCP(sport=555, dport=80, seq=10000,
                      flags=dnet.TH_SYN|dnet.TH_ACK)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5624,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 2
        payload = TCP(sport=556, dport=80, seq=10000,
                      flags=dnet.TH_ACK|dnet.TH_RST)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5625,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

class DetectSAARClose(regress.Test):
    def Setup(self):
        self.name = "SA|AR Probe to Closed Port"
        self.expect = "detect.output.3"

        # Packet 1
        payload = TCP(sport=555, dport=79, seq=10000,
                      flags=dnet.TH_SYN|dnet.TH_ACK)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5624,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 2
        payload = TCP(sport=556, dport=79, seq=10000,
                      flags=dnet.TH_ACK|dnet.TH_RST)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5625,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

class DetectSFSRClose(regress.Test):
    def Setup(self):
        self.name = "SF|SR Probe to Closed Port"
        self.expect = "detect.output.4"

        # Packet 1
        payload = TCP(sport=555, dport=79, seq=10000,
                      flags=dnet.TH_SYN|dnet.TH_RST)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5624,
                p=dnet.IP_PROTO_TCP)
        ip.data = payload
        ip.len += len(ip.data)
        self.packets.append(ip)

        # Packet 2
        payload = TCP(sport=556, dport=79, seq=10000,
                      flags=dnet.TH_SYN|dnet.TH_FIN)
        ip = IP(src=dnet.ip_aton("192.0.2.1"),
                dst=dnet.ip_aton("192.18.0.10"),
                id=5625,
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

reg = regress.regress("detect probe", "../honeyd", "config.1", debug)
reg.generate = generate
reg.run(DetectSFSROpen())
reg.run(DetectSAAROpen())
reg.run(DetectSAARClose())
reg.run(DetectSFSRClose())
reg.finish()
