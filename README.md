Danish is an experiment in middle-box DANE (RFC 6698) for HTTPS.

Danish is a daemon that listens for HTTPS TLS handshake traffic and captures the TLS/SNI and certificates. It then performs DNS lookups for DNS TLSA records to determine if the responding server is sending the correct X.509 certificate in its TLS ServerHello message.

If the certificates and DNS TLSA records do NOT match, iptables/ip6tables ACLs are installed to block user traffic to the offending website. ACLs are installed to both blackhole the immediate TCP traffic and prevent any further attempts at users connecting to the offending website. Users are currently prevented from connecting to the offending website for 2X the TTL of the relevant DNS TLSA RR.

Danish 0.1 supports TLS 1.0 - 1.2, IPv4/IPv6, and some TLSA RRs. Danish only supports TLSA certificate usage 1 and 3, and TLSA selector 0. TLSA records that Danish does not support are ignored.

Full support for RFC 6698 is dependent on the OpenWRT/LEDE OpenSSL package also supporting DANE.

