#!/usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

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

from scapy.config import conf
from scapy.layers.tls.automaton_srv import TLSServerAutomaton
from argparse import ArgumentParser

parser = ArgumentParser(description='Simple TLS Server')
parser.add_argument("--psk",
                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
parser.add_argument("--no_pfs", action="store_true",
                    help="Disable (EC)DHE exchange with PFS")
# args.curve must be a value in the dict _tls_named_curves (see tls/crypto/groups.py)
parser.add_argument("--curve", help="ECC curve to advertise (ex: secp256r1...")
parser.add_argument("--cookie", action="store_true",
                    help="Send cookie extension in HelloRetryRequest message")
parser.add_argument("--client_auth", action="store_true",
                    help="Require client authentication")
parser.add_argument("--handle_session_ticket", action="store_true",
                    help="Use session tickets. Auto enabled if file provided (for TLS 1.3)")  # noqa: E501
parser.add_argument("--ticket_file", dest='session_ticket_file',
                    help="File to write/read a ticket to (for TLS 1.3)")
parser.add_argument("--debug", action="store_const", const=5, default=0,
                    help="Enter debug mode")
args = parser.parse_args()

pcs = None
# PFS is set by default...
if args.no_pfs and args.psk:
    psk_mode = "psk_ke"
else:
    psk_mode = "psk_dhe_ke"

t = TLSServerAutomaton(mycert=basedir+'/test/tls/pki/srv_cert.pem',
                       mykey=basedir+'/test/tls/pki/srv_key.pem',
                       preferred_ciphersuite=pcs,
                       client_auth=args.client_auth,
                       curve=args.curve,
                       cookie=args.cookie,
                       handle_session_ticket=args.handle_session_ticket,
                       session_ticket_file=args.session_ticket_file,
                       psk=args.psk,
                       psk_mode=psk_mode,
                       debug=args.debug)
t.run()

