#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
Basic TLS server. A preferred ciphersuite may be provided as first argument.

For instance, "sudo ./server_simple.py c014" will start a server accepting
any TLS client connection. If provided, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
will be preferred to any other suite the client might propose.
"""

import os
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path

from scapy.layers.tls.automaton_srv import TLSServerAutomaton
from argparse import ArgumentParser

parser = ArgumentParser(description='Simple TLS Server')
# args.curve must be a value in the dict _tls_named_curves (see tls/crypto/groups.py)
parser.add_argument("--curve", help="ECC curve to advertise (ex: secp256r1...")
parser.add_argument("--cookie", action="store_true",
                    help="Send cookie extension in HelloRetryRequest message")
args = parser.parse_args()

pcs = None
t = TLSServerAutomaton(mycert=basedir+'/test/tls/pki/srv_cert.pem',
                       mykey=basedir+'/test/tls/pki/srv_key.pem',
                       preferred_ciphersuite=pcs,
                       curve=args.curve,
                       cookie=args.cookie)
t.run()

