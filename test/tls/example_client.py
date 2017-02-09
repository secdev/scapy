#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
Basic TLS client. A ciphersuite may be commanded via a first argument.

For instance, "sudo ./client_simple.py c014" will try to connect to any TLS
server at 127.0.0.1:4433, with suite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.
"""

import os
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path

from scapy.layers.tls.automaton import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello


if len(sys.argv) == 2:
    ch = TLSClientHello(ciphers=int(sys.argv[1], 16))
else:
    ch = None

t = TLSClientAutomaton(client_hello=ch)
t.run()


