#!/usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Basic TLS client. A ciphersuite may be commanded via a first argument.
Default protocol version is TLS 1.3.
"""

import os
import socket
import sys

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path

from scapy.config import conf
from scapy.utils import inet_aton
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
parser.add_argument("--ticket_in", dest='session_ticket_file_in',
                    help="File to read a ticket from (for TLS 1.3)")
parser.add_argument("--ticket_out", dest='session_ticket_file_out',
                    help="File to write a ticket to (for TLS 1.3)")
parser.add_argument("--res_master",
                    help="Resumption master secret (for TLS 1.3)")
parser.add_argument("--sni",
                    help="Server Name Indication")
parser.add_argument("--curve", help="ECC group to advertise")
parser.add_argument("--debug", action="store_const", const=5, default=0,
                    help="Enter debug mode")
parser.add_argument("server", nargs="?", default="127.0.0.1",
                    help="The server to connect to")
parser.add_argument("port", nargs="?", type=int, default=4433,
                    help="The TCP destination port")

args = parser.parse_args()

# By default, PFS is set
if args.no_pfs:
    psk_mode = "psk_ke"
else:
    psk_mode = "psk_dhe_ke"

v = _tls_version_options.get(args.version, None)
if not v:
    sys.exit("Unrecognized TLS version option.")

try:
    socket.getaddrinfo(args.server, args.port)
except socket.error as ex:
    sys.exit("Could not resolve host server: %s" % ex)

if args.ciphersuite:
    ciphers = int(args.ciphersuite, 16)
    if ciphers not in list(range(0x1301, 0x1306)):
        ch = TLSClientHello(ciphers=ciphers)
    else:
        ch = TLS13ClientHello(ciphers=ciphers)
else:
    ch = None

server_name = args.sni
# If server name is unknown, try server
if not server_name and args.server:
    try:
        inet_aton(args.server)
    except socket.error:
        server_name = args.server

t = TLSClientAutomaton(server=args.server, dport=args.port,
                       server_name=server_name,
                       client_hello=ch,
                       version=args.version,
                       mycert=basedir+"/test/tls/pki/cli_cert.pem",
                       mykey=basedir+"/test/tls/pki/cli_key.pem",
                       psk=args.psk,
                       psk_mode=psk_mode,
                       resumption_master_secret=args.res_master,
                       session_ticket_file_in=args.session_ticket_file_in,
                       session_ticket_file_out=args.session_ticket_file_out,
                       curve=args.curve,
                       debug=args.debug)
t.run()

