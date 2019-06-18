#!/usr/bin/env python

# This file is part of Scapy
# This program is published under a GPLv2 license

"""
Basic TLS server. A preferred ciphersuite may be provided as first argument.

For instance, "sudo ./server_simple.py c014" will start a server accepting
any TLS client connection. If provided, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
will be preferred to any other suite the client might propose.
"""

import os
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path = [basedir] + sys.path

from scapy.layers.tls.automaton_srv import TLSServerAutomaton
from argparse import ArgumentParser



psk = None
session_ticket_path = None

parser = ArgumentParser(description='Simple TLS Client')
parser.add_argument("--psk",
                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
parser.add_argument("--ticket_file", dest='session_ticket_file',
                    help="File to write/read a ticket to (for TLS 1.3)")
parser.add_argument("--no_pfs", action="store_true",
                    help="Disable (EC)DHE exchange with PFS")
parser.add_argument("--early_data", action="store_true",
                    help="Attempt to read 0-RTT data")
parser.add_argument("--client_auth", action="store_true",
                    help="Require client authentication")
parser.add_argument("--curve", help="Group to advertise (ECC)")
parser.add_argument("--cookie", action="store_true",
                    help="Send cookie extension in HelloRetryRequest message")
args = parser.parse_args()

pcs = None

# PFS is set by default...
if args.no_pfs and args.psk:
    psk_mode = "psk_ke"
else:
    psk_mode = "psk_dhe_ke"

t = TLSServerAutomaton(mycert=basedir+'/test/tls/pki/srv_cert.pem',
                       mykey=basedir+'/test/tls/pki/srv_key.pem',
                       psk=args.psk,
                       preferred_ciphersuite=pcs,
                       client_auth=args.client_auth,
                       session_ticket_file=args.session_ticket_file,
                       early_data=args.early_data,
                       curve=args.curve,
                       cookie=args.cookie)
t.run()
