#!/usr/bin/env python

import os
import pcapy as pcap
import dns


# Initializes a pcap capture object
# Returns a string on failure and pcapy.Reader on success
def initRx(iface, filt):
  if(os.getuid() or os.geteuid()):
    return "Error:Requires root access"
  
  if(not iface in pcap.findalldevs()):
    return "Error:Bad interface " + iface

  pr = pcap.open_live(iface, 65536, True, 10)
  if(pr.datalink() != pcap.DLT_EN10MB):
    return "Error:Interface not Ethernet " + iface

  try:
    pr.setfilter(filt)
  except pcap.PcapError:
    return "Error:Bad capture filter"

  return pr

# Prints a packet
def printPkt(hdr, pkt):
  # Print timestamps  
  tAbs, tRel = hdr.getts()
  print "tAbs>" + str(tAbs) + " tRel>" + str(tRel) + " " 

  s = []
  for c in pkt:
    s.append(hex(ord(c)).lstrip("0x").zfill(2))

  # Print Linklayer
  dst = ':'.join(s[:6])
  src = ':'.join(s[6:12])
  etype = ':'.join(s[12:14])
  print "dst>" + dst + " src>" + src + " etype>" + etype

  # Print rest of packet
  print ':'.join(s[14:]) + "\n"

  
pr = initRx('br-lan', "icmp")
while True:
  pkt = pr.dispatch(1, printPkt)



 
print "Finished Execution"
