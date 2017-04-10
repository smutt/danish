#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='danish',
      version='0.1',
      description='Middlebox DANE(RFC 6698) daemon for LEDE/OpenWRT',
      long_description='Danish listens for HTTPS TLS handshake traffic and captures the TLS/SNI and certificates. Then it performs DNS lookups for DNS TLSA records to determine if the responding server is sending the correct X.509 certificate in its TLS ServerHello message. If the certificates and DNS TLSA records do NOT match, iptables ACLs are installed to block user traffic to the offending website. Currently supports TLS 1.0 - 1.2.',
      author='Andrew McConachie',
      author_email='andrew@depht.com',
      url='https://github.com/smutt/danish',
      platform=['LEDE','OpenWRT','Linux'],
      license='GPL-3',
      packages=find_packages()
      )
