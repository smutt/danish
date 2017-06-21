#!/usr/bin/env python

'''
Copyright (c) 2014, 2017 Andrew McConachie <smutt@depht.com>
All rights reserved.
Code originally based on https://github.com/hexcap/hexcap/blob/master/hexcap/cp.py
'''

# This is a test script for printing IPv6 header values
# ARG1 is pcap file to load
# ARG2 is packet to inspect, one-based

import sys
sys.path.insert(0, sys.path[0] + '/../dpkt/')
import dpkt
from inspect import getmembers
from pprint import pprint


# Change dpkt character bytes to padded hex string without leading 0x
def pcapToHexStr(val, delim=":", l=1):
  rv = ''
  ii = 1
  for v in val:
    rv += hex(ord(v)).split("0x")[1].rjust(2, "0")
    if ii % l == 0:
      rv += delim
    ii += 1
  return rv.strip(":")



ii = 1
pcIn = dpkt.pcap.Reader(open(sys.argv[1]))
for ts, pkt in pcIn:
  if str(ii) == sys.argv[2]:
    eth = dpkt.ethernet.Ethernet(pkt)
    ip6 = eth.data
    print pcapToHexStr(ip6.src, ':', 2)

  ii += 1
