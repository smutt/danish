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
import re

#############
# CONSTANTS #
#############

# Logging level constants
LOG_ERROR = 1
LOG_WARN = 2
LOG_INFO = 3
LOG_DEBUG = 4
LOG_LEVEL = LOG_DEBUG
LOG_OUTPUT = 'file' # 'tty' | 'file' | False
LOG_FNAME = '/tmp/danish.log'

# Interval to trigger cache age check
CACHE_AGE = datetime.timedelta(seconds=600)

# Iptables constants
IPT_BINARY = "/usr/sbin/iptables"
IPT6_BINARY = "/usr/sbin/ip6tables"
IP6_SUPPORT = os.access(IPT6_BINARY, os.X_OK) # TODO: Could refine this more
IPT_CHAIN = "danish"


###########
# Classes #
###########

# Superclass for all of our threads
class DanishThr(threading.Thread):
  def __init__(self, domain):
    self.domain = domain
    dbgLog(LOG_DEBUG, "Starting thread " + type(self).__name__ + '_' + self.domain)
    threading.Thread.__init__(self, name=type(self).__name__ + '_' + self.domain)


# Perform a query for a TLSA RR then die
class ReqThr(DanishThr):
  def run(self):
    try:
      d = dns.resolver.Resolver()
      d.query('_443._tcp.' + self.domain, 'TLSA')
    except:
      pass


# Check passed SNI and certs against any TLSA records
class AuthThr(DanishThr):
  mTypes = {
    1: hashlib.sha256,
    2: hashlib.sha512
  }

  def __init__(self, domain, ip, certs):
    self.ip = ip
    self.certs = certs
    super(self.__class__, self).__init__(domain)

  def run(self):
    try:
      qstr = '_443._tcp.' + self.domain
      d = dns.resolver.Resolver()
      resp = d.query(qstr, 'TLSA')
    except dns.resolver.NXDOMAIN:
      dbgLog(LOG_DEBUG, "NXDOMAIN for " + qstr)
      return
    except dns.resolver.Timeout:
      dbgLog(LOG_ERROR, "timeout for " + qstr)
      return
    except dns.resolver.YXDOMAIN:
      dbgLog(LOG_ERROR, "YXDOMAIN for " + qstr)
      return
    except dns.resolver.NoAnswer:
      dbgLog(LOG_INFO, "NoAnswer for " + qstr)
      return
    except dns.resolver.NoNameservers:
      dbgLog(LOG_ERROR, "NoNameservers for " + qstr)
      return

    RRs = []
    for tlsa in resp.rrset:
      if (tlsa.usage == 1 or tlsa.usage == 3) and tlsa.selector == 0 and \
        (tlsa.mtype > -1 and tlsa.mtype < 3): # Our current DANE limitations
        RRs.append(tlsa)

    if len(RRs) == 0:
      dbgLog(LOG_INFO, "No valid RRs found for " + qstr)
      return

    dbgLog(LOG_INFO, "AuthThr_" + self.domain + ":TLSA RR Found")
    passed = False
    for tlsa in RRs:
      for cert in self.certs:
        if tlsa.mtype == 0:
          if tlsa.cert == cert:
            passed = True
        elif tlsa.cert == AuthThr.mTypes[tlsa.mtype](cert).digest():
          passed = True

    dbgLog(LOG_INFO, "AuthThr_" + self.domain + ":TLSA_match:" + str(passed))
    if not passed:
      if 'AclThr_' + self.domain not in threading.enumerate(): # Defensive programming
        AclThr(self.domain, self.ip, resp.ttl).start()
      else:
        dbgLog(LOG_ERROR, "Thread thr_" + self.domain + " already running")


# Installs ACLs into the Linux kernel and then manages them
class AclThr(DanishThr):
  shortTTL = 600 # Our ACL TTL for the active TCP connection in seconds

  def __init__(self, domain, ip, ttl):
    self.ip = ip
    self.longTTL = ttl * 2 # The SNI will be blocked for this many seconds
    super(self.__class__, self).__init__(domain)

  def run(self):
    self.chain = genChainName(self.domain)
    dbgLog(LOG_DEBUG, "chain:" + self.chain)

    # ACL definitions
    if self.ip.v == 4:
      self.shortEgress = ' --destination ' +  pcapToDecStr(self.ip.src) + '/32' + \
        ' --source ' + pcapToDecStr(self.ip.dst) + '/32 -p tcp --dport 443' + \
        ' --sport ' + str(self.ip.data.dport) + ' -j DROP'
      self.shortIngress = ' --destination ' +  pcapToDecStr(self.ip.dst) + '/32' + \
        ' --source ' + pcapToDecStr(self.ip.src) + '/32 -p tcp --dport ' + \
        str(self.ip.data.dport) + ' --sport 443 -j DROP'
    elif self.ip.v == 6:
      self.shortEgress = ' --destination ' +  pcapToDecStr(self.ip.src) + '/128' + \
        ' --source ' + pcapToDecStr(self.ip.dst) + '/128 -p tcp --dport 443' + \
        ' --sport ' + str(self.ip.data.dport) + ' -j DROP'
      self.shortIngress = ' --destination ' +  pcapToDecStr(self.ip.dst) + '/128' + \
        ' --source ' + pcapToDecStr(self.ip.src) + '/128 -p tcp --dport ' + \
        str(self.ip.data.dport) + ' --sport 443 -j DROP'
    self.longEgress = ' -p tcp --dport 443 -m string --algo bm --string ' + self.domain + ' -j DROP'

    self.addChain()
    self.addShort()
    self.addLong()
    dbgLog(LOG_DEBUG, "Added ACLs IPv" + str(self.ip.v) + ", TTL:" + str(self.longTTL))

    # Set timers to remove ACLs
    shrt = threading.Timer(AclThr.shortTTL, self.delShort)
    lng = threading.Timer(self.longTTL, self.cleanUp)
    shrt.name = name='TS_' + self.domain
    lng.name = name='TL_' + self.domain
    shrt.start()
    lng.start()

  def addChain(self):
    ipt('--new ' + self.chain)
    ipt('-I ' + self.chain + ' -j RETURN')
    ipt('-I ' + IPT_CHAIN + ' -j ' + self.chain)

    if IP6_SUPPORT:
      ipt6('--new ' + self.chain)
      ipt6('-I ' + self.chain + ' -j RETURN')
      ipt6('-I ' + IPT_CHAIN + ' -j ' + self.chain)


  def delChain(self):
    ipt('-D ' + IPT_CHAIN + ' -j ' + self.chain)
    ipt('-F ' + self.chain)
    ipt('--delete-chain ' + self.chain)

    if IP6_SUPPORT:
      ipt6('-D ' + IPT_CHAIN + ' -j ' + self.chain)
      ipt6('-F ' + self.chain)
      ipt6('--delete-chain ' + self.chain)


  def addShort(self):
    dbgLog(LOG_DEBUG, "Adding shortEgress:" + self.shortEgress)
    dbgLog(LOG_DEBUG, "Adding shortIngress:" + self.shortIngress)
    if self.ip.v == 4:
      ipt('-I ' + self.chain + self.shortEgress)
      ipt('-I ' + self.chain + self.shortIngress)
    elif self.ip.v == 6:
      ipt6('-I ' + self.chain + self.shortEgress)
      ipt6('-I ' + self.chain + self.shortIngress)


  def delShort(self):
    dbgLog(LOG_DEBUG, "Deleting shortEgress:" + self.shortEgress)
    dbgLog(LOG_DEBUG, "Deleting shortIngress:" + self.shortIngress)
    if self.ip.v == 4:
      ipt('-D ' + self.chain + self.shortEgress)
      ipt('-D ' + self.chain + self.shortIngress)
    elif self.ip.v == 6:
      ipt6('-D ' + self.chain + self.shortEgress)
      ipt6('-D ' + self.chain + self.shortIngress)


  def addLong(self):
    dbgLog(LOG_DEBUG, "Adding longEgress:" + self.longEgress)
    ipt('-I ' + self.chain + self.longEgress)
    if IP6_SUPPORT:
      ipt6('-I ' + self.chain + self.longEgress)


  def delLong(self):
    dbgLog(LOG_DEBUG, "Deleting longEgress:" + self.longEgress)
    ipt('-D ' + self.chain + self.longEgress)
    if IP6_SUPPORT:
      ipt6('-D ' + self.chain + self.longEgress)


  def cleanUp(self):
    self.delLong()
    self.delChain()


# Superclass for ClientHelloCache and ServerHelloCache classes
class DanishCache:
  def __init__(self, name):
    self._name = name
    self._entries = {}
    self._ts = {}
    self._delim = "_"
    self._timeout = datetime.timedelta(seconds=3600) # Cache timeout

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
    self._ts[k] = datetime.datetime.utcnow()
    
  def __getitem__(self, k):
    return self._entries[k]
  
  def __delitem__(self, k):
    try:
      del self._entries[k]
      del self._ts[k]
    except:
      pass

  def __contains__(self, k):
    if k in self._entries:
      return True
    else:
      return False

  def idx(self, src, dst, port):
    return pcapToDecStr(str(src)) + self._delim + pcapToDecStr(str(dst)) + self._delim + str(port)

  # Set entries to None if cache ttl exceeded
  def age(self):
    dbgLog(LOG_DEBUG, "Initiating age for " + self._name + " l=" + str(len(self)))
    for k, ts in self._ts.items():
      if ts + self._timeout < datetime.datetime.utcnow():
        dbgLog(LOG_DEBUG, self._name + " deletion of " + k)
        del self._entries[k]
        del self._ts[k]


# Holds entries that we have received Client Hellos for that we're awaiting ServerHellos,
# and incomplete ServerHellos 
class ClientHelloCache(DanishCache):
  def insert(self, k, SNI):
    self.__setitem__(k, SNI)


# Holds the TCP.data of fragments of Server Hello packets
class ServerHelloCache(DanishCache):
  # seq is an int, data is a string
  # seq is the sequence number we are waiting to receive
  def insert(self, k, seq, data):
    if k in self._entries:
      self.__setitem__(k, [self._entries[k][0] + seq, self._entries[k][1] + data])
    else:
      self.__setitem__(k, [seq, data])


####################
# GLOBAL FUNCTIONS #
####################

# Calls iptables with passed string as args
def ipt(s):
  return subp.check_output([IPT_BINARY] + s.split())


# Calls ip6tables with passed string as args
def ipt6(s):
  return subp.check_output([IPT6_BINARY] + s.split())


# Generates an iptables chain name based on domain
# maxchars for iptables chain names is 29
def genChainName(domain):
  return IPT_CHAIN + '_' + hashlib.sha1(domain).hexdigest()[20:]


# Print string then die with error, dirty
# Not thread safe
def death(errStr=''):
  print "FATAL:" + errStr
  sys.exit(1)


# Handle SIGINT and exit cleanly
def handleSIGINT(signal, frame):
  dbgLog(LOG_INFO, "SIGINT caught, exiting")
  if LOG_OUTPUT == 'file':
    LOG_HANDLE.close()

  # Kill all timer threads
  for thr in threading.enumerate():
    if isinstance(thr, threading._Timer):
      thr.cancel()

  # Clean up iptables
  ipt('-D FORWARD -j ' + IPT_CHAIN)
  subChains = re.findall(re.compile(IPT_CHAIN + '_[a-z,0-9]{20}'), ipt('-L ' + IPT_CHAIN))
  ipt('-F ' + IPT_CHAIN)

  for chain in subChains:
    ipt('-F ' + chain)
    ipt('-X ' + chain)
  ipt('-X ' + IPT_CHAIN)

  if IP6_SUPPORT:
    ipt6('-D FORWARD -j ' + IPT_CHAIN)
    ipt6('-F ' + IPT_CHAIN)

    for chain in subChains:
      ipt6('-F ' + chain)
      ipt6('-X ' + chain)
    ipt6('-X ' + IPT_CHAIN)

  sys.exit(0)

  
# Logs message to /tmp/danish.log or tty
# TODO: Make sure we don't fill up the /tmp filesystem
def dbgLog(lvl, dbgStr):
  if not LOG_OUTPUT:
    return

  if lvl > LOG_LEVEL:
    return

  logPrefix = {
    LOG_ERROR: "Err",
    LOG_WARN: "Wrn",
    LOG_INFO: "Inf",
    LOG_DEBUG: "Dbg",
  }

  dt = datetime.datetime.now()
  #ts = dt.strftime("%b %d %H:%M:%S.%f")
  ts = dt.strftime("%H:%M:%S.%f")
  outStr = ts + "> " + logPrefix[lvl] + "> " + dbgStr

  if LOG_LEVEL == LOG_DEBUG:
    outStr += "> "
    for thr in threading.enumerate():
      outStr += thr.name + " "
    outStr.rstrip("")

  if LOG_OUTPUT == 'file':
    try:
      LOG_HANDLE.write(outStr + '\n')
    except IOError:
      death("IOError writing to debug file " + dbgFName)
  elif LOG_OUTPUT == 'tty':
    print outStr

    
# Initializes a pcap capture object
# Prints a string on failure and returns pcapy.Reader on success
def initRx(iface, filt, timeout):
  if(os.getuid() or os.geteuid()):
    death("Requires root access")
    
  if not iface in pcapy.findalldevs():
    death("Bad interface " + iface)
    
  pr = pcapy.open_live(iface, 65536, True, timeout)
  if pr.datalink() != pcapy.DLT_EN10MB:
    death("Interface not Ethernet " + iface)
    
  try:
    pr.setfilter(filt)
  except pcapy.PcapError:
    death("initRx:Bad capture filter " + filt)

  # Non-blocking status appears to vary by platform and libpcap version
  if not pr.getnonblock():
    pr.setnonblock(1)
    
  return pr


# Change dpkt character bytes to padded hex string without leading 0x
# Only used for debugging right now
def pcapToHexStr(val, delim=":"):
  rv = ''
  for v in val:
    rv += hex(ord(v)).split("0x")[1].rjust(2, "0") + delim
  return rv


# Change dpkt character bytes to string decimal values with a delimiter of delim between bytes
def pcapToDecStr(val, delim="."):
  rv = ""
  for b in val:
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
# Debugging only
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


# BPF cannot compile TCP offsets for IPv6 packets
# So we have these 2 check functions to check packets from kernel before continuing
def checkV6Hello(hdr, pkt):
  eth, ip, tcp = parseTCP(pkt)
  if (len(tcp.data) > 0) and (ord(tcp.data[0:1]) == 22):
    #dbgLog(LOG_DEBUG, "checkV6Hello to parseClientHello")
    parseClientHello(hdr, pkt)


def checkV6Reply(hdr, pkt):
  eth, ip, tcp = parseTCP(pkt)
  if tcp.flags & dpkt.tcp.TH_ACK:
    if not tcp.flags & dpkt.tcp.TH_RST:
      if not tcp.flags & dpkt.tcp.TH_SYN:
        if not tcp.flags & dpkt.tcp.TH_FIN:
          #dbgLog(LOG_DEBUG, "checkV6Reply to parseServerHello")
          parseServerHello(hdr, pkt)


# Takes pcapy packet and returns 3 layers
def parseTCP(pkt):
  eth = dpkt.ethernet.Ethernet(pkt)

  if(eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.ETH_TYPE_IP6):
    death("Unsupported ethertype " + eth.type)

  ip = eth.data
  return eth, ip, ip.data


# Parses a TLS ClientHello packet
# TODO:Check if it is a resumption of connection, if so ignore
# TODO:Figure out TLS 1.0, 1.1, and 1.3
def parseClientHello(hdr, pkt):
  dbgLog(LOG_DEBUG, "Entered parseClientHello")
  eth, ip, tcp = parseTCP(pkt)

  try:
    tls = dpkt.ssl.TLS(tcp.data)
  except:
    dbgLog(LOG_DEBUG, "Bad TLS ClientHello Record")
    return

  # BPF should prevent this from happening
  if tls.type != 22:
    dbgLog(LOG_DEBUG, "TLS ClientHello not TLS ClientHello, instead type=" + str(tls.type))
    return

  # RFC 5246 Appx-E.1 says 0x0300 is the lowest value clients can send
  if tls.version < 768:
    dbgLog(LOG_DEBUG, "TLS version " + str(tls.version) + " in ClientHello < SSL 3.0")
    return

  # It's possible to have more than 1 record in the TLS ClientHello message,
  # but I've never actually seen it and our BPF/parseTCP should prevent it from getting here.
  for rec in tls.records:
    if dpkt.ssl.RECORD_TYPES[rec.type].__name__ != 'TLSHandshake':
      dbgLog(LOG_DEBUG, "TLS ClientHello contains record other than TLSHandshake " + str(rec.type) + " ip.dst:" + pcapToHexStr(ip.dst))
      continue

    # RFC 5246 Appx-E.1 says 0x0300 is the lowest value clients can send
    if rec.version < 768:
      dbgLog(LOG_DEBUG, "TLS record version " + str(rec.version) + " in ClientHello < SSL 3.0")
      return

    try:
      tlsHandshake = dpkt.ssl.RECORD_TYPES[rec.type](rec.data)
    except:
      dbgLog(LOG_DEBUG, "Bad TLS Handshake in ClientHello")
      return

    if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ClientHello':
      dbgLog(LOG_DEBUG, "TLSHandshake captured not ClientHello " + str(tlsHandshake.type))
      return

    try:
      tlsClientHello = tlsHandshake.data
    except:
      dbgLog(LOG_DEBUG, "Bad TLS Extensions in ClientHello")
      return

    if 0 not in dict(tlsClientHello.extensions):
      dbgLog(LOG_DEBUG, "SNI not found in TLS ClientHello ip.dst:" + pcapToHexStr(ip.dst))
      return

    sni = dict(tlsClientHello.extensions)[0]
    if struct.unpack("!B", sni[2:3])[0] != 0:
      dbgLog(LOG_DEBUG, "SNI not a DNS name")
    domain = sni[5:struct.unpack("!H", sni[3:5])[0]+5]
    dbgLog(LOG_INFO, "Client SNI:" + domain)

    # Don't do anything if we're already investigating this domain
    # TODO: Don't do anything if we're already blocking this domain
    for thr in threading.enumerate():
      if isinstance(thr, DanishThr) or isinstance(thr, threading._Timer):
        if thr.name.split("_")[1] == domain:
          dbgLog(LOG_DEBUG, thr.name + " already active")
          return

    global chCache
    chCache.insert(chCache.idx(ip.src, ip.dst, tcp.sport), domain)
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
  #dbgLog(LOG_DEBUG, "parseServerHello TCP reassembly IPv:" + str(ip.v))
  #dbgLog(LOG_DEBUG, "parseServerHello:" + repr(ip.data))
  
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
          shCache.insert(shIdx, len(tcp.data), tcp.data)
    else:
      try:
        tls = dpkt.ssl.TLS(tcp.data)
        SNI = chCache[chIdx]
        del chCache[chIdx]
        del shCache[shIdx]
        parseCert(SNI, ip, tls)
      except dpkt.NeedData:
        shCache.insert(shIdx, tcp.seq + len(tcp.data), tcp.data)


# TODO: Currently we ignore resumptions, investigate if we want to be fancier
def parseCert(SNI, ip, tls):
  dbgLog(LOG_DEBUG, "Entered parseCert " + SNI + " IPv:" + str(ip.v))

  # We only support TLS 1.2 for now, but let's not barf on TLS 1.0 in ServerHellos
  if tls.version < 769:
    dbgLog(LOG_DEBUG, "TLS version " + str(tls.version) + " in ServerHello < TLS 1.0")
    return

  for rec in tls.records:
    if rec.type != 22: # This can happen if we receive data before the cache has been cleared or on malformed packets
      dbgLog(LOG_DEBUG, "TLS Record not TLSHandshake(22), " + SNI)
      #dbgLog(LOG_DEBUG, "ip.data:" + repr(ip.data))
      return

    # We only support TLS 1.2
    if rec.version != 771:
      dbgLog(LOG_INFO, "TLS version in ServerHello Record not 1.2, " + SNI + ", " + str(rec.version))
      return
    
    try:
      tlsHandshake = dpkt.ssl.RECORD_TYPES[rec.type](rec.data)
    except dpkt.ssl.SSL3Exception:
      dbgLog(LOG_DEBUG, "TLS Handshake type not Certificate(11)" + SNI)
      return

    if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] == 'Certificate':
      tlsCertificate = tlsHandshake.data
      if len(tlsCertificate.certificates) < 1:
        dbgLog(LOG_ERROR, "ServerHello contains 0 certificates, " + SNI)
        return
      AuthThr(SNI, ip, tlsCertificate.certificates).start()


###################
# BEGIN EXECUTION #
###################

# TODO Start using a lockfile in /tmp

# Enable debugging
if LOG_OUTPUT == 'file':
  try:
    LOG_HANDLE = open(LOG_FNAME, 'w+', 0)
  except:
    death("Unable to open debug log file")

dbgLog(LOG_DEBUG, "Begin Execution")

# Register a signal for Ctrl-C
signal.signal(signal.SIGINT, handleSIGINT)

# Initialize our caches
chCache = ClientHelloCache('ClientCache')
shCache = ServerHelloCache('ServerCache')

# Init our master iptables chain
ipt('--new ' + IPT_CHAIN)
ipt('-I ' + IPT_CHAIN + ' -j RETURN')
ipt('-I FORWARD -j ' + IPT_CHAIN)
if IP6_SUPPORT:
  ipt6('--new ' + IPT_CHAIN)
  ipt6('-I ' + IPT_CHAIN + ' -j RETURN')
  ipt6('-I FORWARD -j ' + IPT_CHAIN)


# http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
# TODO: Investigate if we really want to be checking TLS version in ClientHellos(first part below)
BPF_HELLO_4 = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
BPF_REPLY_4 = 'tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2)' \
  ' and (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)'
  # ACK == 1 && RST == 0 && SYN == 0 && FIN == 0
  # Must accept TCP fragments

# From http://www.tcpdump.org/manpages/pcap-filter.7.html
# "Note that tcp, udp and other upper-layer protocol types only apply to IPv4, not IPv6 (this will be fixed in the future)."
if IP6_SUPPORT:
  BPF_HELLO_6 = "ip6 and tcp and dst port 443"
  BPF_REPLY_6 = "ip6 and tcp and src port 443"

helloPR_4 = initRx('br-lan', BPF_HELLO_4, 10)
replyPR_4 = initRx('br-lan', BPF_REPLY_4, 100)
if IP6_SUPPORT:
  helloPR_6 = initRx('br-lan', BPF_HELLO_6, 10)
  replyPR_6 = initRx('br-lan', BPF_REPLY_6, 100)

lastAge = datetime.datetime.utcnow()
while True:
  helloPR_4.dispatch(1, parseClientHello)
  if IP6_SUPPORT:
    helloPR_6.dispatch(1, checkV6Hello)

  # TODO: Make these conditional on client cache entries existing, requires testing
  replyPR_4.dispatch(1, parseServerHello)
  if IP6_SUPPORT:
    replyPR_6.dispatch(1, checkV6Reply)

  if lastAge + CACHE_AGE < datetime.datetime.utcnow():
    chCache.age()
    shCache.age()
    lastAge = datetime.datetime.utcnow()
