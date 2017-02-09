#!/usr/bin/env python

import sys
sys.path.insert(0, sys.path[0] + '/dpkt/')
import os
import datetime
import signal
import pcapy
import dpkt
import struct
#import binascii
import dns.resolver
import threading
import hashlib
import subprocess as subp
from time import time
import re

# Superclass for all of our threads
class DanishThr(threading.Thread):
  def __init__(self):
    # Register a signal for Ctrl-C
    signal.signal(signal.SIGINT, handleSIGINT)
    dbgLog("Info:Starting thread " + type(self).__name__ + " for " + self.domain)


# Perform a query for a TLSA RR then die
class ReqThr(DanishThr):
  def __init__(self, domain):
    self.domain = domain
    threading.Thread.__init__(self)
    super(self.__class__, self).__init__()
    try:
      dns.resolver.query('_443._tcp.' + domain, 'TLSA')
    except:
      pass


# Check passed SNI and certs against any TLSA records
class AuthThr(DanishThr):
  mTypes = {
    1: hashlib.sha256,
    2: hashlib.sha512
  }

  def __init__(self, domain, ip, certs):
    self.domain = domain
    threading.Thread.__init__(self)
    super(self.__class__, self).__init__()

    try:
      resp = dns.resolver.query('_443._tcp.' + domain, 'TLSA')
    except dns.resolver.NXDOMAIN:
      return
    except dns.resolver.Timeout:
      dbgLog("Error:DNS timeout for " + domain)
      return
    except dns.resolver.YXDOMAIN:
      dbgLog("Error:DNS YXDOMAIN for " + domain)
      return
    except dns.resolver.NoAnswer:
      dbgLog("Notice:DNS NoAnswer for " + domain)
      return
    except dns.resolver.NoNameservers:
      dbgLog("Error:DNS NoNameservers for " + domain)
      return

    RRs = []
    for tlsa in resp:
      if (tlsa.usage == 1 or tlsa.usage == 3) and tlsa.selector == 0 and \
        (tlsa.mtype > -1 and tlsa.mtype < 3): # Our current DANE limitations
        RRs.append(tlsa)

    if len(RRs) == 0:
      dbgLog("Info:No valid RRs found for " + domain)
      return

    passed = False
    for tlsa in RRs:
      for cert in certs:
        if tlsa.mtype == 0:
          if tlsa.cert == cert:
            passed = True
        elif tlsa.cert == AuthThr.mTypes[tlsa.mtype](cert).digest():
          passed = True

    dbgLog("Info:AuthThr:passed:" + str(passed))
    if not passed:
      if 'thr_' + domain not in threading.enumerate(): # Defensive programming, this doesn't work for some reason :(
        AclThr(domain, ip).start()
      else:
        dbgLog("Error:Thread thr_" + domain + " already running")


# Installs ACLs into the Linux kernel and then manages them
class AclThr(DanishThr):
  def __init__(self, domain, ip):
    self.domain = domain
    threading.Thread.__init__(self, name='thr_' + domain)
    super(self.__class__, self).__init__()

    self.chain = genChainName(domain) 
    dbgLog("Info:chain:" + self.chain)

#    if genChainName(domain) in re.findall(re.compile('danish_[a-z,0-9]{20}'), ipt('-L danish')):
#      dbgLog("Warn:thread:" + self.chain + " already running")

    # ACL definitions
    self.shortEgress4 = ' --destination ' +  pcapToDecStr(ip.src) + '/32' + \
      ' --source ' + pcapToDecStr(ip.dst) + '/32 -p tcp --dport 443' + \
      ' --sport ' + str(ip.data.dport) + ' -j DROP'
    self.shortIngress4 = ' --destination ' +  pcapToDecStr(ip.dst) + '/32' + \
      ' --source ' + pcapToDecStr(ip.src) + '/32 -p tcp --dport ' + \
      str(ip.data.dport) + ' --sport 443 -j DROP'
    self.longEgress4 = ' -p tcp --dport 443 -m string --algo bm --string ' + self.domain + ' -j DROP'

    # Our ACL durations in seconds
    shortSleep = 20
    longSleep = 40

    self.addChain()
    self.addShort()
    self.addLong()

    shrt = threading.Timer(shortSleep, self.delShort)
    lng = threading.Timer(longSleep, self.cleanUp)
    shrt.start()
    lng.start()

  def addChain(self):
    ipt('--new ' + self.chain)
    ipt('-I ' + self.chain + ' -j RETURN')
    ipt('-I danish -j ' + self.chain)

  def delChain(self):
    ipt('-D danish -j ' + self.chain)
    ipt('-F ' + self.chain)
    ipt('--delete-chain ' + self.chain)

  def addShort(self):
    dbgLog("Info:Adding shortEgress4:" + self.shortEgress4)
    dbgLog("Info:Adding shortIngress4:" + self.shortIngress4)
    ipt('-I ' + self.chain + self.shortEgress4)
    ipt('-I ' + self.chain + self.shortIngress4)
    self.shortActive = True

  def delShort(self):
    dbgLog("Info:Deleting shortEgress4:" + self.shortEgress4)
    dbgLog("Info:Deleting shortIngress4:" + self.shortIngress4)
    ipt('-D ' + self.chain + self.shortEgress4)
    ipt('-D ' + self.chain + self.shortIngress4)
    self.shortActive = False

  def addLong(self):
    dbgLog("Info:Adding longEgress4:" + self.longEgress4)
    ipt('-I ' + self.chain + self.longEgress4)

  def delLong(self):
    dbgLog("Info:Deleting longEgress4:" + self.longEgress4)
    ipt('-D ' + self.chain + self.longEgress4)

  def cleanUp(self):
    self.delLong()
    self.delChain()


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
    try:
      del self._entries[k]
    except:
      pass

  def __contains__(self, k):
    if k in self._entries:
      return True
    else:
      return False

  def idx(self, src, dst, port):
    return pcapToDecStr(str(src)) + self._delim + pcapToDecStr(str(dst)) + self._delim + str(port)

    
# Holds entries that we have received Client Hellos for that we're awaiting ServerHellos
class ClientHelloCache(DanishCache):
  def append(self, k, SNI):
    self._entries[k] = SNI

    
# Holds the TCP.data of fragments of Server Hello packets
class ServerHelloCache(DanishCache):
  # seq is an int, data is a string
  # seq is the sequence number we are waiting to receive
  def append(self, k, seq, data):
    if k in self._entries:
      self._entries[k] = [self._entries[k][0] + seq, self._entries[k][1] + data]
    else:
      self._entries[k] = [seq, data]
      

# Calls iptables with passed string as args
def ipt(s):
  return subp.check_output(["/usr/sbin/iptables"] + s.split(' '))


# Generates an iptables chain name based on domain
# maxchars for iptables chain names is 29
def genChainName(domain):
  return 'danish_' + hashlib.sha1(domain).hexdigest()[20:]


# Print string then die with error
# Not thread safe
def death(errStr=''):
  print errStr
  sys.exit(1)

  
# Handle SIGINT and exit cleanly
def handleSIGINT(signal, frame):
  print "SIGINT caught, exiting"
  if dbg == 'file':
    dbgFH.close()

  # Clean up iptables
  ipt('-D FORWARD -j danish')
  subChains = re.findall(re.compile('danish_[a-z,0-9]{20}'), ipt('-L danish'))
  ipt('-F danish')

  for chain in subChains:
    ipt('-F ' + chain)
    ipt('-X ' + chain)

  ipt('-X danish')

  sys.exit(0)

  
# Logs message to /tmp/danish.log
def dbgLog(dbgStr):
  dt = datetime.datetime.now()
  ts = dt.strftime("%b %d %H:%M:%S.%f") + " "

  if dbg == 'file':
    try:
      dbgFH.write(ts + str(dbgStr) + '\n')
    except IOError:
      death("Error:IOError writing to debug file " + dbgFName)
  elif dbg == 'tty':
    print ts + str(dbgStr)

    
# Initializes a pcap capture object
# Prints a string on failure and returns pcapy.Reader on success
def initRx(iface, filt, timeout):
  if(os.getuid() or os.geteuid()):
    death("Error:Requires root access")
    
  if not iface in pcapy.findalldevs():
    death("Error:Bad interface " + iface)
    
  pr = pcapy.open_live(iface, 65536, True, timeout)
  if pr.datalink() != pcapy.DLT_EN10MB:
    death("Error:Interface not Ethernet " + iface)
    
  try:
    pr.setfilter(filt)
  except pcapy.PcapError:
    death("Error:Bad capture filter")
    
  return pr


# Change sequential binary data to padded hex string without leading 0x
# Only used for debugging right now
def binToHexStr(val):
  rv = ''
  for v in val:
    rv += hex(ord(v)).split("0x")[1].rjust(2, "0")
  return rv


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
  dbgLog("Info:Entered parseClientHello")
  eth, ip, tcp = parseTCP(pkt)
  tls = dpkt.ssl.TLS(tcp.data)

  # It's possible to have more than 1 record in the 1st TLS message,
  # but I've never actually seen it and our BPF should prevent it from getting here.
  for rec in tls.records:
    if dpkt.ssl.RECORD_TYPES[rec.type].__name__ != 'TLSHandshake':
      dbgLog("Warn:TLS ClientHello contains record other than TLSHandshake " + str(rec.type))
      continue

    # RFC 5246 Appx-E.1 says 0x0300 is the lowest value clients can send
    if rec.version < 768:
      dbgLog("Error:TLS version " + str(rec.version) + " in ClientHello < SSL 3.0")
      dumpPkt(pkt)
      return
    
    tlsHandshake = dpkt.ssl.RECORD_TYPES[rec.type](rec.data)
    if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ClientHello':
      dbgLog("Error:TLSHandshake captured not ClientHello" + str(tlsHandshake.type))

    tlsClientHello = tlsHandshake.data
    if 0 not in dict(tlsClientHello.extensions):
      dbgLog("Error:SNI not found in TLS ClientHello")

    sni = dict(tlsClientHello.extensions)[0]
    if struct.unpack("!B", sni[2:3])[0] != 0:
      dbgLog("Error:SNI not a DNS name")
    domain = sni[5:struct.unpack("!H", sni[3:5])[0]+5]
    dbgLog("Info:Client SNI:" + domain)

    global chCache
    chCache.append(chCache.idx(ip.src, ip.dst, tcp.sport), domain)
    ReqThr(domain).start()
  
  
# Parses a TLS ServerHello packet
# We have to deal with TCP reassembly
def parseServerHello(hdr, pkt):
  global chCache, shCache
  if len(chCache) == 0:
    return

  eth, ip, tcp = parseTCP(pkt)
  if len(tcp.data) == 0:
    return
  dbgLog("Info:parseServerHello TCP reassembly")
  
  chIdx = chCache.idx(ip.dst, ip.src, tcp.dport)
  shIdx = shCache.idx(ip.src, ip.dst, tcp.sport)
  if chIdx in chCache:
    if shIdx in shCache:
      if shCache[shIdx][0] == tcp.seq:
        try:
          tls = dpkt.ssl.TLS(shCache[shIdx][1] + tcp.data)
          SNI = chCache[chIdx]
          del chCache[chIdx]
          del shCache[shIdx]
          parseCert(SNI, ip, tls)
        except dpkt.NeedData:
          shCache.append(shIdx, len(tcp.data), tcp.data)
    else:
      try:
        tls = dpkt.ssl.TLS(tcp.data)
        SNI = chCache[chIdx]
        del chCache[chIdx]
        del shCache[shIdx]
        parseCert(SNI, ip, tls)
      except dpkt.NeedData:
        shCache.append(shIdx, tcp.seq + len(tcp.data), tcp.data)

        
def parseCert(SNI, ip, tls):
  dbgLog("Info:Entered parseCert")
  for rec in tls.records:
    if dpkt.ssl.RECORD_TYPES[rec.type].__name__ != 'TLSHandshake' :
      death("Error:TLS Record not TLSHandshake, " + SNI)

    # We only support TLS 1.2
    if rec.version != 771:
      dbgLog("Notice:TLS version in ServerHello Record not 1.2, " + SNI)
      return
    
    tlsHandshake = dpkt.ssl.RECORD_TYPES[rec.type](rec.data)
    if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] == 'Certificate':
      tlsCertificate = tlsHandshake.data
      if len(tlsCertificate.certificates) < 1:
        dbgLog("Error:ServerHello contains 0 certificates, " + SNI)
        return

      AuthThr(SNI, ip, tlsCertificate.certificates).start()


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
#dbg = False
#dbg = 'file'
dbg = 'tty'
dbgFName = '/tmp/danish.log'
if dbg == 'file':
  try:
    dbgFH = open(dbgFName, 'w+', 0)
  except:
    death("Error:Unable to open debug log file")

# Init our master iptables chain
ipt('--new danish')
ipt('-I danish -j RETURN')
ipt('-I FORWARD -j danish')

# http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
BPF_HELLO = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
BPF_REPLY = 'tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2)' \
  ' and (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)' # ACK == 1 && RST == 0 && SYN == 0 && FIN == 0 

helloPR = initRx('br-lan', BPF_HELLO, 10)
replyPR = initRx('br-lan', BPF_REPLY, 100)
while True:
  print repr(threading.enumerate())
  helloPR.dispatch(1, parseClientHello)
  replyPR.dispatch(1, parseServerHello)

  
print "End Execution"
