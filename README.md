## Overview
Danish is an experiment in middle-box DANE (RFC 6698) for HTTPS.

Danish is a daemon that listens for HTTPS TLS handshake traffic and captures the TLS/SNI and certificates. It then performs DNS lookups for DNS TLSA records to determine if the responding server is sending the correct X.509 certificate in its TLS ServerHello message.

If the certificates and DNS TLSA records do NOT match, iptables/ip6tables ACLs are installed to block user traffic to the offending website. ACLs are installed to both blackhole the immediate TCP traffic and prevent any further attempts at users connecting to the offending website. Users are then prevented from connecting to the offending website for the TTL of the relevant DNS TLSA RR.

## Supported Protocols and Versions
Danish currently supports TLS 1.0 - 1.2, IPv4/IPv6, and some TLSA RRs. Danish only supports TLSA certificate usage 1 and 3, and TLSA selector 0. TLSA records that Danish does not support are ignored.

## Installation
Danish is written to work on both [OpenWRT](https://www.openwrt.org/) and [LEDE](https://www.lede-project.org/). It should work equally well on both.

Danish has been tested with DNSMasq and Unbound running on localhost, but it should work with any DNSSEC validating recursive server. It is not required to run a recursive server on localhost and pointing /etc/resolv.conf to a working recursive resolver should also work.

For installation Danish requires the following other packages.
* kmod-ipt-filter
* iptables-mod-filter
* python
* python-dns
* python-pcapy
* python-dpkt

Danish can be installed using OpenWRT's opkg package manager.

### Building an Image with Danish
All shell commands below are to be executed from your OpenWRT or LEDE base directory.

1. Follow the instructions for building an [OpenWRT](https://github.com/openwrt/openwrt) or [LEDE](https://lede-project.org/docs/guide-developer/quickstart-build-images) image.
2. `make menuconfig`
3. Select danish package under Network/IP Addresses and Names/danish 
4. `make` 
5. Take a nap. :zzz:
6. Awaken to a freshly compiled image. :sunglasses:

:grey_exclamation: You may need to de-select package dnsmasq as it may conflict with dnsmasq-full. dnsmasq-full includes DNSSEC support and Danish requires DNSSEC.

## Configuration
Danish uses the Universal Configuration Interface (UCI). The Danish configuration file is stored in `/etc/config/danish`.

Configuration directives are defined below.

| Section | Element | Default | Explanation |
--- | --- | --- | --- | 
| network | interface | br-lan | The 'inside' interface of the middlebox | 
| network | iptables | /usr/sbin/iptables | Location of iptables binary |
| network | ip6tables | /usr/sbin/ip6tables | Location of ip6tables binary |
| network | ipchain | danish | Name prefix Danish uses for iptables rules |
| danish | loglevel | error | log level | 
| danish | logsize | 1024 | Max size of logfile in KB | 
| danish | logfile | /tmp/danish.log | Log file Location | 

Possible values for loglevel listed by increasing verbosity are `error, warn, info, debug`.

