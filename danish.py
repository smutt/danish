#!/usr/bin/env python

import sys
sys.path.insert(0, sys.path[0] + '/dpkt/')
import os
import datetime
import signal
import pcapy as pcap
import dpkt
import struct
#import dns


# Superclass for ClientHello and ServerHello classes
class DanishCache:
  def __init__(self):
    self._entries = {}
    self._delim = "_"

  def __len__(self):
    return len(self._entries)

  def __repr__(self):
    rv = ''
    for k in self._entries.keys():
      rv += k + ' '
    return rv.strip()

  def __str__(self):
    return self.__repr__()

  def __setitem__(self, k, v):
    self._entries[k] = v
    
  def __getitem__(self, k):
    return self._entries[k]
  
  def __delitem__(self, k):
    del self._entries[k]

  def __contains__(self, k):
    if k in self._entries:
      return True
    else:
      return False

  def idx(self, src, dst, port):
    return pcapToDecStr(str(src)) + self._delim + pcapToDecStr(str(dst)) + self._delim + str(port)

    
# Holds entries that we have received Client Hellos for that we're awaiting ServerHellos
class ClientHelloCache(DanishCache):
  def append(self, k):
    self._entries[k] = True

    
# Holds the TCP.data of fragments of Server Hello packets
class ServerHelloCache(DanishCache):
  # seq is an int, data is a string
  # seq is the sequence number we are waiting to receive
  def append(self, k, seq, data):
    if k in self._entries:
      self._entries[k] = [self._entries[k][0] + seq, self._entries[k][1] + data]
    else:
      self._entries[k] = [seq, data]
      

# Print string then die with error
def death(errStr=''):
  print errStr
  sys.exit(1)

  
# Handle SIGINT and exit cleanly
def handleSIGINT(signal, frame):
  print "SIGINT caught, exiting"
  if dbg:
    dbgFH.close()
  sys.exit(0)

  
# Logs message to /tmp/danish.log
def dbgLog(dbgStr):
  dt = datetime.datetime.now()
  ts = dt.strftime("%b %d %H:%M:%S.%f") + " "
  try:
    dbgFH.write(ts + str(dbgStr) + '\n')
  except IOError:
    death("Error:IOError writing to debug file " + dbgFName)


# Initializes a pcap capture object
# Prints a string on failure and returns pcapy.Reader on success
def initRx(iface, filt, timeout):
  if(os.getuid() or os.geteuid()):
    death("Error:Requires root access")
    
  if not iface in pcap.findalldevs():
    death("Error:Bad interface " + iface)
    
  pr = pcap.open_live(iface, 65536, True, timeout)
  if pr.datalink() != pcap.DLT_EN10MB:
    death("Error:Interface not Ethernet " + iface)
    
  try:
    pr.setfilter(filt)
  except pcap.PcapError:
    death("Error:Bad capture filter")
    
  return pr


# Change pcap character data to padded hex string without leading 0x
# Currently not used
def binToHexStr(val):
  return hex(ord(val)).split("0x")[1].rjust(2, "0")


# Change dpkt character bytes to string decimal values with a delimiter of delim between bytes
def pcapToDecStr(bytes, delim="."):
  rv = ""
  for b in bytes:
    rv += str(ord(b)) + delim
  return rv.rstrip(delim)


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
def dumpPkt(pkt):
  fh = open('/tmp/danish.pcap', 'wb')
  df = dpkt.pcap.Writer(fh)
  df.writepkt(pkt)
  df.close()

  
# Prints a packet for debugging, can assume it's always TCP
def printPkt(hdr, pkt):
  # Print timestamps
  if hdr:
    tAbs, tRel = hdr.getts()
    print "tAbs>" + str(tAbs) + " tRel>" + str(tRel) + " " 

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
    
  if(eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.Ethernet.ETH_TYPE_IP6):
    death("Error:Unsupported ethertype " + eth.type)

  ip = eth.data
  return eth, ip, ip.data

  
# Parses a TLS ClientHello packet
def parseClientHello(hdr, pkt):
  print "\nEntered parseClientHello"
  eth, ip, tcp = parseTCP(pkt)

  tlsRecord = dpkt.ssl.TLSRecord(tcp.data)
  if dpkt.ssl.RECORD_TYPES[tlsRecord.type].__name__ != 'TLSHandshake':
    death("Error:TLS Packet captured not TLSHandshake")

  # RFC 5246 Appx-E.1 says 0x0300 is the lowest value clients can send
  if tlsRecord.version < 768:
    dbgLog("Error:TLS version " + str(tlsRecord.version) + " in ClientHello < SSL 3.0")
    dumpPkt(pkt)
    return

  tlsHandshake = dpkt.ssl.RECORD_TYPES[tlsRecord.type](tlsRecord.data)
  if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ClientHello':
    death("Error:TLSHandshake captured not ClientHello")

  tlsClientHello = tlsHandshake.data
  if 0 not in dict(tlsClientHello.extensions):
    death("Error:SNI not found in TLS ClientHello")

  sni = dict(tlsClientHello.extensions)[0]
  if struct.unpack("!B", sni[2:3])[0] != 0:
    death("Error:SNI not a DNS name")
  domain = sni[5:struct.unpack("!H", sni[3:5])[0]+5]
  print "Client SNI:" + domain

  global chCache
  chCache.append(chCache.idx(ip.src, ip.dst, tcp.sport))
  
  
# Parses a TLS ServerHello packet
# We have to deal with TCP reassembly
def parseServerHello(hdr, pkt):
  global chCache, shCache
  if len(chCache) == 0:
    return

  eth, ip, tcp = parseTCP(pkt)
  if len(tcp.data) == 0:
    return

  print "\nEntered parseServerHello"
  
  #printPkt(hdr, pkt)
  #dumpPkt(pkt)
  #print "tcp.len:" + str(len(tcp))
  print "tcp.seq:" + str(tcp.seq)
  print "tcp.data.len:" + str(len(tcp.data))
  print "tcp.flags:" + hex(tcp.flags)
  
  chIdx = chCache.idx(ip.dst, ip.src, tcp.dport)
  shIdx = shCache.idx(ip.src, ip.dst, tcp.sport)
  if chIdx in chCache:
    if shIdx in shCache:
      if shCache[shIdx][0] == tcp.seq:
        try:
          tls = dpkt.ssl.TLS(shCache[shIdx][1] + tcp.data)
          print "TLS-1"
          print str(len(tls.records))
          del chCache[chIdx]
          del shCache[shIdx]
          parseCert(ip, tls)
        except dpkt.NeedData:
          print "NeedData-1"
          shCache.append(shIdx, len(tcp.data), tcp.data)
          print "shIdx.seq:" + str(shCache[shIdx][0])
    else:
      try:
        tls = dpkt.ssl.TLS(tcp.data)
        print "TLS-2"
        print str(len(tls.records))
        del chCache[chIdx]
        del shCache[shIdx]
        parseCert(ip, tls)
      except dpkt.NeedData:
        print "NeedData-2"
        shCache.append(shIdx, tcp.seq + len(tcp.data), tcp.data)
        print "shIdx.seq:" + str(shCache[shIdx][0])

def parseCert(ip, tls):
  print "\nEntered parseCert"
  for rec in tls.records:
    if dpkt.ssl.RECORD_TYPES[rec.type].__name__ != 'TLSHandshake' :
      death("Error:TLS Record not TLSHandshake")

    # We only support TLS 1.2
    if rec.version != 771:
      dbgLog("Notice:TLS version in ServerHello Record not 1.2")
      return
    
    #print repr(rec.data)

  return
    
#tlsHandshake = dpkt.ssl.RECORD_TYPES[rec.type](rec.data)
#if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ServerHello':
#      death("Error:TLSHandshake captured not ServerHello")


      



  
###################
# BEGIN EXECUTION #
###################
print "Begin Execution"

# Register a signal for Ctrl-C
signal.signal(signal.SIGINT, handleSIGINT)

# Initialize our caches
chCache = ClientHelloCache()
shCache = ServerHelloCache()

# Enable debugging
dbg = True
dbgFName = '/tmp/danish.log'
if dbg:
  try:
    dbgFH = open(dbgFName, 'w+', 0)
  except:
    death("Error:Unable to open debug log file")
    
# http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
BPF_HELLO = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
BPF_REPLY = 'tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2)' \
  ' and (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)'
#ACK == 1, RST == 0, SYN == 0, FIN == 0 

helloPR = initRx('br-lan', BPF_HELLO, 10)
replyPR = initRx('br-lan', BPF_REPLY, 100)

#print str(replyPR.getnonblock())
#replyPR.setnonblock(1)
while True:
  helloPR.dispatch(1, parseClientHello)
  replyPR.dispatch(1, parseServerHello)

  
print "End Execution"
