#!/usr/bin/env python

import sys
import os
import datetime
import signal
import pcapy
import dpkt
import struct
import dns.resolver
import threading
import hashlib
import subprocess as subp
import re
import time

#####################
# DEFAULT CONSTANTS #
#####################

# Logging constants
LOG_ERROR = 1
LOG_WARN = 2
LOG_INFO = 3
LOG_DEBUG = 4
LOG_LEVEL = LOG_DEBUG
LOG_OUTPUT = 'file' # 'tty' | 'file' | False
LOG_FNAME = '/tmp/danish.log'
LOG_SIZE = 1024 # Max logfile size in KB

# Network constants
IFACE = "br-lan"
IPT_BINARY = "/usr/sbin/iptables"
IPT6_BINARY = "/usr/sbin/ip6tables"
IP6_SUPPORT = False
IPT_CHAIN = "danish"

# Random constants
UCI_BINARY = '/sbin/uci' # Location of Unified Configuration Interface binary
CACHE_AGE = 600 # Interval to trigger cache age check in seconds


###########
# Classes #
###########

# Superclass for all of our DNS threads
class DanishThr(threading.Thread):
  def __init__(self, domain):
    self.domain = domain
    dbgLog(LOG_DEBUG, "Starting thread " + type(self).__name__ + '_' + self.domain)
    threading.Thread.__init__(self, name=type(self).__name__ + '_' + self.domain)


# Capture traffic via pcap object until killed
class RxThr(threading.Thread):
  def __init__(self, name, pcapObj, callBack):
    dbgLog(LOG_DEBUG, "Starting RX thread " + name)
    self.pcapObj = pcapObj
    self.callBack = callBack
    self.thr = threading.Thread.__init__(self, name=type(self).__name__ + '_' + name)

  def run(self):
    while True:
      self.pcapObj.dispatch(1, self.callBack)


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
      dbgLog(LOG_INFO, "No valid and supported RRs found for " + qstr)
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
    self.longTTL = ttl # The SNI will be blocked for this many seconds
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
      self.shortEgress = ' --destination ' +  pcapToHexStr(self.ip.src, ':', 2) + '/128' + \
        ' --source ' + pcapToHexStr(self.ip.dst, ':', 2) + '/128 -p tcp --dport 443' + \
        ' --sport ' + str(self.ip.data.dport) + ' -j DROP'
      self.shortIngress = ' --destination ' +  pcapToHexStr(self.ip.dst, ':', 2) + '/128' + \
        ' --source ' + pcapToHexStr(self.ip.src, ':', 2) + '/128 -p tcp --dport ' + \
        str(self.ip.data.dport) + ' --sport 443 -j DROP'
    self.longEgress = ' -p tcp --dport 443 -m string --algo bm --string ' + self.domain + ' -j DROP'

    try:
      self.addChain()
    except:
      dbgLog(LOG_ERROR, "Add Chain fail for " + self.chain)

    try:
      self.addShort()
    except:
      dbgLog(LOG_ERROR, "Add Short ACL fail for " + self.chain + " IPv" + str(self.ip.v))

    try:
      self.addLong()
    except:
      dbgLog(LOG_ERROR, "Add Long ACL fail for " + self.chain)

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

  def flush(self):
    self._entries = {}
    self._ts = {}

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

# Calls uci to get config vars
def uci(const):
  s = UCI_BINARY + ' -q -s get ' + const
  c = subp.check_output(s.split()).strip()
  if(c) and len(c) > 0:
    return c


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


# Read in UCI config
def readConfig():
  global LOG_LEVEL, LOG_SIZE, LOG_FNAME, IFACE, IPT_BINARY, IPT_CHAIN, IPT6_BINARY

  try:
    logLvl = uci('danish.@danish[0].loglevel')
    UCI_LOG_SIZE = uci('danish.@danish[0].logsize')
    LOG_FNAME = uci('danish.@danish[0].logfile')
    IFACE = uci('danish.@network[0].interface')
    IPT_BINARY = uci('danish.@network[0].iptables')
    IPT_CHAIN = uci('danish.@network[0].ipchain')
  except:
    death("Unable to read in configuration")

  if 'LOG_' + logLvl.upper() in globals():
    LOG_LEVEL = eval('LOG_' + logLvl.upper())
  else:
    LOG_LEVEL = LOG_WARN

  try:
    int(UCI_LOG_SIZE)
    LOG_SIZE = int(UCI_LOG_SIZE)
  except:
    logDbg(LOG_ERROR, "Invalid logsize configured, using default: " + str(LOG_SIZE) + "KB")

  try:
    IPT6_BINARY = uci('danish.@network[0].ip6tables')
  except:
    IPT6_BINARY = '/dev/null'


# Print string then die with error, dirty
# Not thread safe
def death(errStr=''):
  print "FATAL:" + errStr
  sys.exit(1)


# Re-read config and dump cache at SIGHUP
def handleSIGHUP(signal, frame):
  dbgLog(LOG_INFO, "SIGHUP caught, flushing cache, reloading config")
  chCache.flush()
  shCache.flush()
  readConfig()


# Handle killing signals and exit cleanly
def handleKilling(signal, frame):
  dbgLog(LOG_INFO, "SIG " + str(signal) + " caught, exiting")
  if LOG_OUTPUT == 'file':
    LOG_HANDLE.close()

  # Kill all timer threads
  for thr in threading.enumerate():
    if isinstance(thr, threading._Timer):
      try:
        thr.cancel()
      except:
        pass

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

  
# Logs message to LOG_FNAME or tty
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
    global LOG_HANDLE
    try:
      if int(os.stat(LOG_FNAME).st_size / 1024) < LOG_SIZE:
        LOG_HANDLE.write(outStr + '\n')
      else:
        LOG_HANDLE.close()
        try:
          LOG_HANDLE = open(LOG_FNAME, 'w', 1)
          LOG_HANDLE.write(outStr + '\n')
        except IOError:
          death("IOError writing to debug file " + LOG_FNAME)

    except IOError:
      death("IOError writing to debug file " + LOG_FNAME)
  elif LOG_OUTPUT == 'tty':
    print outStr

    
# Initializes a pcap capture object
# Prints a string on failure and returns pcapy.Reader on success
def initPcap(iface, filt):
  if(os.getuid() or os.geteuid()):
    death("Requires root access")

  if not iface in pcapy.findalldevs():
    death("Bad interface " + iface)

  pr = pcapy.open_live(iface, 65536, True, 0)
  if pr.datalink() != pcapy.DLT_EN10MB:
    death("Interface not Ethernet " + iface)

  try:
    pr.setfilter(filt)
  except pcapy.PcapError:
    death("initPcap:Bad capture filter " + filt)

  # Non-blocking status appears to vary by platform and libpcap version
  pr.setnonblock(0)

  return pr


# Wrapper for RxThr
def initRx(name, pcapObj, callBack):
  rv = RxThr(name, pcapObj, callBack)
  rv.daemon = True
  rv.start()
  return rv


# Change dpkt character bytes to padded hex string without leading 0x
# Use delimiter of delim every l bytes
def pcapToHexStr(val, delim=":", l=1):
  rv = ''
  ii = 1
  for v in val:
    rv += hex(ord(v)).split("0x")[1].rjust(2, "0")
    if ii % l == 0:
      rv += delim
    ii += 1
  return rv.strip(":")


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
    parseClientHello(hdr, pkt)


def checkV6Reply(hdr, pkt):
  eth, ip, tcp = parseTCP(pkt)
  if tcp.flags & dpkt.tcp.TH_ACK:
    if not tcp.flags & dpkt.tcp.TH_RST:
      if not tcp.flags & dpkt.tcp.TH_SYN:
        if not tcp.flags & dpkt.tcp.TH_FIN:
          assembleServerHello(hdr, pkt)


# Takes pcapy packet and returns 3 layers
def parseTCP(pkt):
  eth = dpkt.ethernet.Ethernet(pkt)

  if(eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.ETH_TYPE_IP6):
    death("Unsupported ethertype " + eth.type)

  ip = eth.data
  return eth, ip, ip.data


# Parses a TLS ClientHello packet
def parseClientHello(hdr, pkt):
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

  for rec in tls.records:
    if dpkt.ssl.RECORD_TYPES[rec.type].__name__ != 'TLSHandshake':
      dbgLog(LOG_DEBUG, "TLS ClientHello contains record other than TLSHandshake " + str(rec.type) + " ip.dst:" + pcapToHexStr(ip.dst))
      continue

    # We only support TLS 1.0 - 1.2 in TLS Records
    if rec.version < 769 or rec.version > 771:
      dbgLog(LOG_INFO, "TLS version in ClientHello Record not supported, " + str(rec.version))
      return

    try:
      tlsHandshake = dpkt.ssl.RECORD_TYPES[rec.type](rec.data)
    except:
      dbgLog(LOG_DEBUG, "Bad TLS Handshake in ClientHello Record")
      return

    if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ClientHello':
      if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] != 'ClientKeyExchange':
        dbgLog(LOG_DEBUG, "TLSHandshake captured not ClientHello or ClientKeyExchange " + str(tlsHandshake.type))
      return

    try:
      tlsClientHello = tlsHandshake.data
    except:
      dbgLog(LOG_ERROR, "Error setting ClientHello Handshake Record")
      return

    if hasattr(tlsClientHello, 'extensions'):
      if 0 not in dict(tlsClientHello.extensions):
        dbgLog(LOG_DEBUG, "SNI not found in TLS ClientHello ip.dst:" + pcapToHexStr(ip.dst))
        return
    else:
      dbgLog(LOG_DEBUG, "TLSClientHello has no extensions " + str(tlsHandshake.type))
      return

    sni = dict(tlsClientHello.extensions)[0]
    if struct.unpack("!B", sni[2:3])[0] != 0:
      dbgLog(LOG_ERROR, "SNI not a DNS name")
    domain = sni[5:struct.unpack("!H", sni[3:5])[0]+5]
    dbgLog(LOG_INFO, "Client SNI:" + domain)

    # Don't do anything if we're already investigating this domain
    for thr in threading.enumerate():
      if isinstance(thr, DanishThr) or isinstance(thr, threading._Timer):
        if thr.name.split("_")[1] == domain:
          return

    global chCache
    chCache.insert(chCache.idx(ip.src, ip.dst, tcp.sport), domain)
    ReqThr(domain).start()
  
  
# Assembles a TLS ServerHello packet from potentially multiple TCP packets
def assembleServerHello(hdr, pkt):
  global chCache, shCache
  if len(chCache) == 0:
    return

  eth, ip, tcp = parseTCP(pkt)
  if len(tcp.data) == 0:
    return
  
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
          parseServerHello(SNI, ip, tls)
        except dpkt.NeedData:
          shCache.insert(shIdx, len(tcp.data), tcp.data)
    else:
      try:
        tls = dpkt.ssl.TLS(tcp.data)
        SNI = chCache[chIdx]
        del chCache[chIdx]
        del shCache[shIdx]
        parseServerHello(SNI, ip, tls)
      except dpkt.NeedData:
        shCache.insert(shIdx, tcp.seq + len(tcp.data), tcp.data)


def parseServerHello(SNI, ip, tls):
  # We only support TLS 1.0 - 1.2 for now
  if tls.version < 769 or tls.version > 771:
    dbgLog(LOG_DEBUG, "TLS version in ServerHello not supported, " + SNI + ", " + str(tls.version))
    return

  for rec in tls.records:
    if rec.type != 22:
      continue

    # We only support TLS 1.0 - 1.2 in TLS Records
    if rec.version < 769 or rec.version > 771:
      dbgLog(LOG_INFO, "TLS version in ServerHello Record not supported, " + SNI + ", " + str(rec.version))
      return
    
    try:
      tlsHandshake = dpkt.ssl.RECORD_TYPES[rec.type](rec.data)
    except dpkt.ssl.SSL3Exception:
      dbgLog(LOG_ERROR, "Error setting ServerHello Handshake data, " + SNI)
      return

    if dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] == 'Certificate':
      tlsCertificate = tlsHandshake.data
      if len(tlsCertificate.certificates) < 1:
        dbgLog(LOG_ERROR, "ServerHello contains 0 certificates, " + SNI)
        return
      AuthThr(SNI, ip, tlsCertificate.certificates).start()
      return
    elif not dpkt.ssl.HANDSHAKE_TYPES[tlsHandshake.type][0] == 'ServerHello':
      dbgLog(LOG_DEBUG, "TLS Handshake Record type, " + str(tlsHandshake.type) + " " + SNI)


###################
# BEGIN EXECUTION #
###################
readConfig()

# Enable debugging
if LOG_OUTPUT == 'file':
  try:
    LOG_HANDLE = open(LOG_FNAME, 'w', 1)
  except:
    death("Unable to open debug log file")

dbgLog(LOG_DEBUG, "Begin Execution")

# Register some signals
signal.signal(signal.SIGINT, handleKilling)
signal.signal(signal.SIGTERM, handleKilling)
signal.signal(signal.SIGABRT, handleKilling)
signal.signal(signal.SIGALRM, handleKilling)
signal.signal(signal.SIGSEGV, handleKilling)
signal.signal(signal.SIGHUP, handleSIGHUP)

# Initialize our caches
chCache = ClientHelloCache('ClientCache')
shCache = ServerHelloCache('ServerCache')

# Check for IPv6 support
IP6_SUPPORT = os.access(IPT6_BINARY, os.X_OK)

# Init our master iptables chain(s)
ipt('--new ' + IPT_CHAIN)
ipt('-I ' + IPT_CHAIN + ' -j RETURN')
ipt('-I FORWARD -j ' + IPT_CHAIN)
if IP6_SUPPORT:
  ipt6('--new ' + IPT_CHAIN)
  ipt6('-I ' + IPT_CHAIN + ' -j RETURN')
  ipt6('-I FORWARD -j ' + IPT_CHAIN)

# http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
BPF_HELLO_4 = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)"
BPF_REPLY_4 = 'tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2)' \
  ' and (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)'
  # ACK == 1 && RST == 0 && SYN == 0 && FIN == 0
  # Must accept TCP fragments

RX_EGR_4 = initRx('RxEgr4', initPcap(IFACE, BPF_HELLO_4), parseClientHello)
RX_ING_4 = initRx('RxIng4', initPcap(IFACE, BPF_REPLY_4), assembleServerHello)

# From http://www.tcpdump.org/manpages/pcap-filter.7.html
# "Note that tcp, udp and other upper-layer protocol types only apply to IPv4, not IPv6 (this will be fixed in the future)."
if IP6_SUPPORT:
  BPF_HELLO_6 = "ip6 and tcp and dst port 443"
  BPF_REPLY_6 = "ip6 and tcp and src port 443"
  RX_EGR_6 = initRx('RxEgr6', initPcap(IFACE, BPF_HELLO_6), checkV6Hello)
  RX_ING_6 = initRx('RxIng6', initPcap(IFACE, BPF_REPLY_6), checkV6Reply)

while True:
  time.sleep(CACHE_AGE)
  chCache.age()
  shCache.age()
