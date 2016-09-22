#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
Basic TLS server. A preferred ciphersuite may be provided as first argument.

For instance, "sudo ./server_simple.py c014" will start a server accepting
any TLS client connection. If provided, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
will be preferred to any other suite the client might propose.
"""

import sys

from scapy.layers.tls.automaton import TLSServerAutomaton

if len(sys.argv) == 2:
    pcs = int(sys.argv[1], 16)
else:
    pcs = None

t = TLSServerAutomaton(mycert='pki_test/srv_cert.pem',
                       mykey='pki_test/srv_key.pem',
                       preferred_ciphersuite=pcs)
t.run()


