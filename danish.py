#!/usr/bin/env python

import sys
sys.path.insert(0, sys.path[0] + '/dpkt/')
import os
import pcapy as pcap
import dpkt
#import dns



# Initializes a pcap capture object
# Prints a string on failure and returns pcapy.Reader on success
def initRx(iface, filt):
  if(os.getuid() or os.geteuid()):
    print "Error:Requires root access"
    return
    
  if(not iface in pcap.findalldevs()):
    print "Error:Bad interface " + iface
    return
    
  pr = pcap.open_live(iface, 65536, True, 10)
  if(pr.datalink() != pcap.DLT_EN10MB):
    print "Error:Interface not Ethernet " + iface
    return
    
  try:
    pr.setfilter(filt)
  except pcap.PcapError:
    print "Error:Bad capture filter"
    return
    
  return pr

# Takes a list of character nibbles
# Prints them in pretty hex format
def printHex(chars):
  ii = 1
  outStr = "0000 | "
  outAsc = ""
  for c in chars:
    outStr += c
    if(int(c, 16) > 32 and int(c, 16) < 127):
      outAsc += chr(int(c, 16))
    else:
      outAsc += "."

    if(ii % 4 == 0):
      outStr += " "
    
    if(ii % 16 == 0):
      print outStr + " | " + outAsc
      outStr = str(ii).zfill(4) + " | "
      outAsc = ""
    ii += 1
  
# Prints a packet
def printPkt(hdr, pkt):
  # Print timestamps  
  tAbs, tRel = hdr.getts()
  print "\ntAbs>" + str(tAbs) + " tRel>" + str(tRel) + " " 

  s = []
  for c in pkt:
    s.append(hex(ord(c)).lstrip("0x").zfill(2))

  # Print Linklayer
  dst = ':'.join(s[:6])
  src = ':'.join(s[6:12])
  etype = ':'.join(s[12:14])
  print "dst>" + dst + " src>" + src + " etype>" + etype

  printHex(s[14:])
  
# Parses a TLS ClientHello packet using dpkt
def parseClientHello(hdr, pkt):
  printPkt(hdr, pkt)
  eth = dpkt.ethernet.Ethernet(pkt)
  if(eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.Ethernet.ETH_TYPE_IP6):
    ip = eth.data
    tcp = ip.data
    tls = dpkt.ssl.TLSHandshake(tcp.data)
  else:
    print "Error:Unsupported ethertype " + eth.type
    
###################
# BEGIN EXECUTION #
###################

# http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
BPF_HELLO = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
BPF_REPLY = ""

#pr = initRx('br-lan', "icmp")
pr = initRx('br-lan', BPF_HELLO)

while True:
  pkt = pr.dispatch(1, parseClientHello)

print "Finished Execution"
