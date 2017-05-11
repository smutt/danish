## Overview
Danish is an experiment in middle-box DANE (RFC 6698) for HTTPS.

Danish is a daemon that listens for HTTPS TLS handshake traffic and captures the TLS/SNI and certificates. It then performs DNS lookups for DNS TLSA records to determine if the responding server is sending the correct X.509 certificate in its TLS ServerHello message.

If the certificates and DNS TLSA records do NOT match, iptables/ip6tables ACLs are installed to block user traffic to the offending website. ACLs are installed to both blackhole the immediate TCP traffic and prevent any further attempts at users connecting to the offending website. Users are then prevented from connecting to the offending website for the TTL of the relevant DNS TLSA RR.

## Supported Protocols and Versions
Danish currently supports TLS 1.0 - 1.2, IPv4/IPv6, and some TLSA RRs. Danish only supports TLSA certificate usage 1 and 3, and TLSA selector 0. TLSA records that Danish does not support are ignored.

Full support for RFC 6698 is dependent on the OpenWRT/LEDE OpenSSL package also supporting DANE.

## Installation
Danish is written to work on both [OpenWRT](https://www.openwrt.org/) and [LEDE](https://www.lede-project.org/). It should work equally well on both.

For installation Danish requires the following other packages.
* kmod-ipt-filter
* iptables-mod-filter
* dnsmasq-full
* python
* python-dns
* python-pcapy
* python-dpkt

### python-dpkt & danish OpenWRT packages
At time of writing the [python-dpkt package](https://github.com/openwrt/packages/pull/4256) is not yet merged into the [OpenWRT Repository](https://github.com/openwrt/packages). Once it is merged, a pull request will be submitted for a Danish package to be created.

Until these packages are merged into the OpenWRT repository step 2 below will be required to install Danish.

### Building an Image with Danish
All shell commands below are to be executed from your OpenWRT or LEDE base directory.

1. Follow the instructions for building an [OpenWRT](https://github.com/openwrt/openwrt) or [LEDE](https://lede-project.org/docs/guide-developer/quickstart-build-images) image.
2. Before actually compiling anything insert python-dpkt and danish package files into feeds/packages
  - `mkdir feeds/packages/lang/python-dpkt/`
  - Copy Makefile from [python-dpkt PR](https://github.com/openwrt/packages/pull/4256) to `feeds/packages/lang/python-dpkt/Makefile`
  - `mkdir feeds/packages/net/danish`
  - Copy Makefile from [danish github repository](https://github.com/smutt/danish) to `feeds/packages/net/danish/Makefile`
  - `./scripts/feeds update -a`
  - `./scripts/feeds install -a`

3. `make menuconfig`
4. Select danish package under Network/IP Addresses and Names/danish 
5. `make` :shipit:
6. Take a nap. :zzz:
7. Awaken to a freshly compiled image. :sunglasses:

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

## TODO
- Add support for TLS 1.3
- Add support for QUIC
- Add configuration directive for LOG_OUTPUT
