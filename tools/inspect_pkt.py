#!/usr/bin/env python

'''
Copyright (c) 2014, 2016 Andrew McConachie <smutt@depht.com>
All rights reserved.
Code originally based on https://github.com/hexcap/hexcap/blob/master/hexcap/cp.py
'''

# This is a test script for futzing with dpkt edge cases, it will change a lot
# ARG1 is pcap file to load
# ARG2 is packet to inspect, one-based

import sys
sys.path.insert(0, sys.path[0] + '/../dpkt/')
import dpkt
from inspect import getmembers
from pprint import pprint

ii = 1
pcIn = dpkt.pcap.Reader(open(sys.argv[1]))
for ts, pkt in pcIn:
  if str(ii) == sys.argv[2]:
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    tcp = ip.data
    tls = dpkt.ssl.TLS(tcp.data)

    print repr(tls)
  ii += 1
