#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
Basic TLS client. A ciphersuite may be commanded via a first argument.
Default protocol version is TLS 1.3.
"""

import os
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path

from scapy.layers.tls.automaton_cli import TLSClientAutomaton
from scapy.layers.tls.basefields import _tls_version_options
from scapy.layers.tls.handshake import TLSClientHello, TLS13ClientHello

from argparse import ArgumentParser

psk = None
parser = ArgumentParser(description='Simple TLS Client')
parser.add_argument("--psk",
                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
parser.add_argument("--no_pfs", action="store_true",
                    help="Disable (EC)DHE exchange with PFS")
parser.add_argument("--ciphersuite", help="Ciphersuite preference")
parser.add_argument("--version", help="TLS Version", default="tls13")

args = parser.parse_args()

# By default, PFS is set
if args.no_pfs:
    psk_mode = "psk_ke"
else:
    psk_mode = "psk_dhe_ke"

v = _tls_version_options.get(args.version, None)
if not v:
    sys.exit("Unrecognized TLS version option.")



if args.ciphersuite:
    ciphers = int(args.ciphersuite, 16)
    if ciphers not in list(range(0x1301, 0x1306)):
        ch = TLSClientHello(ciphers=ciphers)
    else:
        ch = TLS13ClientHello(ciphers=ciphers)
else:
    ch = None

t = TLSClientAutomaton(client_hello=ch,
                       version=args.version,
                       mycert=basedir+"/test/tls/pki/cli_cert.pem",
                       mykey=basedir+"/test/tls/pki/cli_key.pem",
                       psk=args.psk,
                       psk_mode=psk_mode,
                      )
t.run()

