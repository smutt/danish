#!/usr/bin/env python

import sys
sys.path.insert(0, sys.path[0] + '/dpkt/')
import os
import pcapy as pcap
import dpkt
import struct
#import dns

# Print string then die
def death(errStr):
  print errStr
  sys.exit(1)
  
# Initializes a pcap capture object
# Prints a string on failure and returns pcapy.Reader on success
def initRx(iface, filt):
  if(os.getuid() or os.geteuid()):
    death("Error:Requires root access")
    
  if(not iface in pcap.findalldevs()):
    death("Error:Bad interface " + iface)
    
  pr = pcap.open_live(iface, 65536, True, 10)
  if(pr.datalink() != pcap.DLT_EN10MB):
    death("Error:Interface not Ethernet " + iface)
    
  try:
    pr.setfilter(filt)
  except pcap.PcapError:
    death("Error:Bad capture filter")
    
  return pr

# Converts pcap data to Nibble String List
def dpktDataToNibStrList(data):
  s = []
  for c in data:
    s.append(hex(ord(c)).lstrip("0x").zfill(2))
  return s

# Takes a list of character nibbles
# Prints them in pretty nibble hex format
def printNibbles(chars):
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

  s = dpktDataToNibStrList(pkt)
  
  # Print Linklayer
  dst = ':'.join(s[:6])
  src = ':'.join(s[6:12])
  etype = ':'.join(s[12:14])
  print "dst>" + dst + " src>" + src + " etype>" + etype

  printNibbles(s[14:])
  
# Parses a TLS ClientHello packet using dpkt
def parseClientHello(hdr, pkt):
  eth = dpkt.ethernet.Ethernet(pkt)
  if(eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.Ethernet.ETH_TYPE_IP6):
    death("Error:Unsupported ethertype " + eth.type)

  ip = eth.data
  tcp = ip.data

  tlsRecord = dpkt.ssl.TLSRecord(tcp.data)

  if(dpkt.ssl.RECORD_TYPES[tlsRecord.type].__name__ != 'TLSHandshake'):
    death("Error:TLS Packet captured not TLSHandshake")

  tlsHandshake = dpkt.ssl.RECORD_TYPES[tlsRecord.type](tlsRecord.data)
  tlsClientHello = tlsHandshake.data
  if(0 not in tlsClientHello.extensions):
    death("Error:SNI not found in TLS Client Hello")
  
  #printNibbles(dpktDataToNibStrList(tlsClientHello.data))
  sni = tlsClientHello.extensions[0]

  if(struct.unpack("!B", sni[2:3])[0] != 0):
    death("Error:SNI not a DNS name")

  domain = sni[5:struct.unpack("!H", sni[3:5])[0]+5]

  print "Client SNI:" + domain


def parseServerReply(hdr, pkt):
  printPkt(hdr, pkt)


  
###################
# BEGIN EXECUTION #
###################

# http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
BPF_HELLO = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
BPF_REPLY = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x0b) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)"

#pr = initRx('br-lan', "icmp")
helloPR = initRx('br-lan', BPF_HELLO)
replyPR = initRx('br-lan', BPF_REPLY)

while True:
  helloPR.dispatch(1, parseClientHello)
  replyPR.dispatch(1, parseServerReply)


  
print "Finished Execution"
