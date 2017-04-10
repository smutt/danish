#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='danish',
      version='0.1',
      description='Middlebox DANE(RFC 6698) daemon for LEDE/OpenWRT',
      author='Andrew McConachie',
      author_email='andrew@depht.com',
      url='https://github.com/smutt/danish',
      packages=find_packages()
      )
