#!/usr/bin/env python

import pcapy as pcap
import os
import dns


# Initializes a pcap capture object
# Returns a string on failure and ifCap reference on success
def initRx(iface, filt):
  if(os.getuid() or os.geteuid()):
    return "Error:Requires root access"
  
  if(not iface in pcap.findalldevs()):
    return "Error:Bad interface " + self.ifName

  ifCap = pcap.open_live(iface, 65536, True, 10)
  if(ifCap.datalink() != pcap.DLT_EN10MB):
    return "Error:Interface not Ethernet " + iface

  try:
    ifCap.setfilter(filt)
  except pcap.PcapError:
    return "Error:Bad capture filter"

  return ifCap


print initRx('br-lan', "udp")
print "Finished Execution"
