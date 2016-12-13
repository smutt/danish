#!/usr/bin/env python

import sys
sys.path.insert(0, sys.path[0] + '/dpkt/')
import os
import pcapy as pcap
import dpkt
import struct
#import dns

# Print string then die
def death(errStr=''):
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

    
# Writes a packet to /tmp/danish.pcap
def dumpPkt(hdr, pkt):
  fh = open('/tmp/danish.pcap', 'wb')
  df = dpkt.pcap.Writer(fh)
  df.writepkt(pkt)
  df.close()

  
# Prints a packet for debugging, can assume it's always TCP
def printPkt(hdr, pkt):
  # Print timestamps  
  tAbs, tRel = hdr.getts()
  print "\ntAbs>" + str(tAbs) + " tRel>" + str(tRel) + " " 

  s = dpktDataToNibStrList(pkt)
  
  # Print Linklayer
  dst2 = ':'.join(s[:6])
  src2 = ':'.join(s[6:12])
  etype = ':'.join(s[12:14])
  print "L2 dst>" + dst2 + " src>" + src2 + " etype>" + etype

  # Print IPv4/IPv6
  if etype == '08:00':
    #ver = 'IPv4'
    #ln = ':'.join(s[16:18])
    frag = ':'.join(s[20:22])
    #type4 = ':'.join(s[23])
    src3 = ':'.join(s[26:30])
    dst3 = ':'.join(s[30:34])
    print "L3 dst>" + dst3 + " src>" + src3 + " frag>" + frag
    printNibbles(s[34:])
    
  elif etype == '86:dd':
    #ver = 'IPv6'
    #ln = ':'.join(s[18:20])
    #type4 = ':'.join(s[20])
    src3 = ':'.join(s[22:38])
    dst3 = ':'.join(s[38:54])
    print "L3 dst>" + dst3 + " src>" + src3
    printNibbles(s[54:])
    
  else:
    printNibbles(s[14:])
    

# Takes pcapy packet and returns 3 layers
def parseTCP(pkt):
  eth = dpkt.ethernet.Ethernet(pkt)
  if len(eth) < 140: # Sometimes pcapy gives us buffer leftovers
    return

  if(eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.Ethernet.ETH_TYPE_IP6):
    death("Error:Unsupported ethertype " + eth.type)

  ip = eth.data
  return eth, ip, ip.data

  
# Parses a TLS ClientHello packet
def parseClientHello(hdr, pkt):
  print "Entered parseClientHello"
  eth, ip, tcp = parseTCP(pkt)

  tlsRecord = dpkt.ssl.TLSRecord(tcp.data)
  if dpkt.ssl.RECORD_TYPES[tlsRecord.type].__name__ != 'TLSHandshake':
    death("Error:TLS Packet captured not TLSHandshake")

  tlsHandshake = dpkt.ssl.RECORD_TYPES[tlsRecord.type](tlsRecord.data)
  if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ClientHello':
    death("Error:TLSHandshake captured not ClientHello")

  tlsClientHello = tlsHandshake.data
  if(0 not in dict(tlsClientHello.extensions)):
    death("Error:SNI not found in TLS ClientHello")

  sni = dict(tlsClientHello.extensions)[0]
  if(struct.unpack("!B", sni[2:3])[0] != 0):
    death("Error:SNI not a DNS name")
  domain = sni[5:struct.unpack("!H", sni[3:5])[0]+5]
  print "Client SNI:" + domain

  
# Parses a TLS ServerHello packet
# We will have to deal with TCP reassembly
def parseServerHello(hdr, pkt):
  print "Entered parseServerHello"
  eth, ip, tcp = parseTCP(pkt)

  tlsRecord = dpkt.ssl.TLSRecord(tcp.data)
  if(dpkt.ssl.RECORD_TYPES[tlsRecord.type].__name__ != 'TLSHandshake'):
    death("Error:TLS Packet captured not TLSHandshake")

  tlsHandshake = dpkt.ssl.RECORD_TYPES[tlsRecord.type](tlsRecord.data)
  if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ServerHello':
    death("Error:TLSHandshake captured not ServerHello")

  tlsServerHello = tlsHandshake.data
    
  printPkt(hdr, pkt)
  dumpPkt(hdr, pkt)

  
###################
# BEGIN EXECUTION #
###################

# http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
BPF_HELLO = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
BPF_REPLY = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x02) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (src port 443)"

helloPR = initRx('br-lan', BPF_HELLO)
replyPR = initRx('br-lan', BPF_REPLY)

print "Begin Execution"
while True:
  helloPR.dispatch(1, parseClientHello)
  replyPR.dispatch(1, parseServerHello)


  
print "End Execution"
