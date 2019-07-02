#!/usr/bin/env python

# This file is part of Scapy
# This program is published under a GPLv2 license

"""
Basic TLS client. A ciphersuite may be commanded via a first argument.
Default protocol version is TLS 1.2.

For instance, "sudo ./client_simple.py c014" will try to connect to any TLS
server at 127.0.0.1:4433, with suite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.
"""
import os
import sys


basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path = [basedir] + sys.path

from scapy.layers.tls.automaton_cli import TLSClientAutomaton
from argparse import ArgumentParser

psk = None
session_ticket_file = None
parser = ArgumentParser(description='Simple TLS Client')
parser.add_argument("--psk",
                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
parser.add_argument("--res_master",
                    help="Resumption master secret (for TLS 1.3)")
parser.add_argument("--ticket_in", dest='session_ticket_file_in',
                    help="File to read a ticket from (for TLS 1.3)")
parser.add_argument("--ticket_out", dest='session_ticket_file_out',
                    help="File to write a ticket to (for TLS 1.3)")
parser.add_argument("--no_pfs", action="store_true",
                    help="Disable (EC)DHE exchange with PFS")
parser.add_argument("--early_data", help="File to read early_data to send")
parser.add_argument("--ciphersuite", help="Ciphersuite preference")
parser.add_argument("--curve", help="Group to advertise (ECC)")

args = parser.parse_args()

print("psk : ", args.psk)
print("res_master : ", args.res_master)
print("ticket_in : ", args.session_ticket_file_in)
print("ticket_out : ", args.session_ticket_file_out)

# By default, PFS is set
if args.no_pfs:
    psk_mode = "psk_ke"
else:
    psk_mode = "psk_dhe_ke"

t = TLSClientAutomaton(client_hello=None,
                       version="tls13",
                       mycert=basedir+"/test/tls/pki/cli_cert.pem",
                       mykey=basedir+"/test/tls/pki/cli_key.pem",
                       psk=args.psk,
                       psk_mode=psk_mode,
                       resumption_master_secret=args.res_master,
                       session_ticket_file_in=args.session_ticket_file_in,
                       session_ticket_file_out=args.session_ticket_file_out,
                       early_data_file=args.early_data,
                       ciphersuite=args.ciphersuite,
                       curve=args.curve
                       )
t.run()
