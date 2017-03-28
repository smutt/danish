#!/usr/bin/env python

import sys
sys.path.insert(0, sys.path[0] + '/../dpkt/')
import dpkt

print "start"

tls = dpkt.ssl.TestTLS()
tls.setup_class()

tls.test_records_length()
        
tls.test_record_type()

tls.test_record_version()

tlsCert = dpkt.ssl.TestTLSCertificate()
tlsCert.setup_class()

tlsCert.test_num_certs()
