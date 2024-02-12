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
#parser.add_argument("--psk",
#                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
parser.add_argument("--altered_finish", action="store_true",
                    help="Send an Altered Finish Message to Server")
#parser.add_argument("--supported_group",
#                    help="Provide a single supported_group (for TLS 1.3)")
parser.add_argument("--altered_y_coordinate", action="store_true",
                    help="Send an Altered y coordinate to Server (for TLS 1.3 and 1.2).  Can be used with the --curve argument.")
parser.add_argument("--use_legacy", action="store_true",
                    help="Send a client hello message with the legacy supported version set to TLS 1.3")
parser.add_argument("--empty_cke", action="store_true",
                    help="Send an empty Client Key Exchange Message (for TLS 1.2 with DHE or ECDHE key exchange")
parser.add_argument("--tls13_renegotiation", action="store_true",
                    help="Attempt renegotiation by sending a TLS 1.3 Client Hello after successful TLS 1.3 Handshake (for TLS 1.3)")
parser.add_argument("--force_fatal_alert", action="store_true",
                    help="Force a fatal alert after TLS 1.3 Handshake successfully completes (for TLS 1.3)")
parser.add_argument("--provide_early_data", action="store_true",
                    help="Attempt to provide early data (for TLS 1.3)")
parser.add_argument("--empty_pubkey", action="store_true",
                    help="Send an empty public key value in the Client Key Exchange Message (for TLS 1.2 with DHE key exchange")
parser.add_argument("--empty_certificate", action="store_true", help="Supply an empty certificate message to Server (for TLS 1.3)")
parser.add_argument("--missing_finished_message", action="store_true",
                    help="Send an Application Message containing random data in place of the TLS Finished Message (for TLS 1.3)")
parser.add_argument("--altered_pre_master_secret", action="store_true", help="Send and altered Encrypted Pre Master Secret for RSA Key Exchange (for TLS 1.2)")
parser.add_argument("--supported_group",
                    help="Provide a single supported_group (for TLS 1.3)")
parser.add_argument("--no_pfs", action="store_true",
                    help="Disable (EC)DHE exchange with PFS")
parser.add_argument("--ciphersuite", help="Ciphersuite preference")
parser.add_argument("--include_tls12_cipher", help="provide a TLS 1.2 ciphersuites followed by the specified TLS 1.3 ciphersuite")
parser.add_argument("--specify_sig_alg", help="Specify a signature algorithm for TLS 1.2 Client Hello message")
parser.add_argument("--scsv_renegotiation_info", action="store_true", help="Send a new TLS 1.2 client hello on the TLS 1.2 channel with the signaling ciphersuite value, TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
parser.add_argument("--no_renegotiation_info_2nd_ch", action="store_true", help="Do not provide the renegotiation_info extension in the TLS 1.2 Client Hello message when renegotiating")
parser.add_argument("--non_zero_renegotiation_info", action="store_true", help="Provide a non-zero value in the renegotiation_info extension of TLS 1.2 Client Hello message")
parser.add_argument("--valid_renegotiation_info", action="store_true", help="Provide a compliant value in the renegotiation_info extension of TLS 1.2 Client Hello message")
parser.add_argument("--altered_renegotiation_info", action="store_true", help="Complete a TLS 1.2 handshake and send a Client Hello with a renegotiation_info extension that has altered verify_data")
parser.add_argument("--reject_tls12_renegotiation", action="store_true", help="This argument specifies the TLS 1.2 Server rejects renegotiation")
#parser.add_argument("--altered_pre_master_secret", action="store_true", help="Send and altered Encrypted Pre Master Secret for RSA Key Exchange (for TLS 1.2)")
parser.add_argument("--version", help="TLS Version", default="tls13")
parser.add_argument("--psk",
                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
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

#if args.ciphersuite:
#    ciphers = int(args.ciphersuite, 16)
#    if ciphers not in list(range(0x1301, 0x1306)):
#        ch = TLSClientHello(ciphers=ciphers)
#    else:
#ch = TLS13ClientHello(ciphers=ciphers)
#else:
#    ch = None

if args.ciphersuite:
    ciphers = int(args.ciphersuite, 16)
    ch = TLS13ClientHello(ciphers=ciphers)
    if args.include_tls12_cipher:
        include_tls12_cipher = int(args.include_tls12_cipher, 16)
        ch = TLS13ClientHello(ciphers=[include_tls12_cipher, ciphers])
else:
    ch = None

if args.altered_y_coordinate:
    altered_y_coordinate = True
else:
    altered_y_coordinate = False
    
if args.use_legacy:
    use_legacy = True
else:
    use_legacy = False

if args.empty_cke:
    empty_cke = True
else:
    empty_cke = False

if args.empty_pubkey:
    empty_pubkey = True
else:
    empty_pubkey = False

if args.empty_certificate:
    empty_certificate = True
else:
    empty_certificate = False

if args.tls13_renegotiation:
    tls13_renegotiation = True
else:
    tls13_renegotiation = False

if args.force_fatal_alert:
    force_fatal_alert = True
else:
    force_fatal_alert = False

if args.provide_early_data:
    provide_early_data = True
else:
    provide_early_data = False

if args.altered_finish:
    altered_finish = True
else:
    altered_finish = False

if args.missing_finished_message:
    missing_finished_message = True
else:
    missing_finished_message = False
server_name = args.sni
# If server name is unknown, try server
if not server_name and args.server:
    try:
        inet_aton(args.server)
    except socket.error:
        server_name = args.server

if args.altered_pre_master_secret:
    altered_pre_master_secret = True
else:
    altered_pre_master_secret = False

if args.non_zero_renegotiation_info:
    non_zero_renegotiation_info = True
else:
    non_zero_renegotiation_info = False

if args.valid_renegotiation_info:
    valid_renegotiation_info = True
else:
    valid_renegotiation_info = False

if args.altered_renegotiation_info:
    altered_renegotiation_info = True
else:
    altered_renegotiation_info = False
    
if args.scsv_renegotiation_info:
    scsv_renegotiation_info = True
else:
    scsv_renegotiation_info = False

if args.no_renegotiation_info_2nd_ch:
    no_renegotiation_info_2nd_ch = True
else:
    no_renegotiation_info_2nd_ch = False

if args.reject_tls12_renegotiation:
    reject_tls12_renegotiation = True
else:
    reject_tls12_renegotiation = False

if args.specify_sig_alg:
    specify_sig_alg = int(args.specify_sig_alg, 16)
else:
    specify_sig_alg = None

t = TLSClientAutomaton(server=args.server, dport=args.port,
                       server_name=server_name,
                       client_hello=ch,
                       version=args.version,
                       altered_finish=altered_finish,
                       altered_y_coordinate=altered_y_coordinate,
                       use_legacy=use_legacy,
                       empty_cke=empty_cke,
                       empty_pubkey=empty_pubkey,
                       empty_certificate=empty_certificate,
                       tls13_renegotiation=tls13_renegotiation,
                       force_fatal_alert=force_fatal_alert,
                       provide_early_data=provide_early_data,
                       missing_finished_message=missing_finished_message,
                       altered_pre_master_secret=altered_pre_master_secret, 
                       specify_sig_alg=specify_sig_alg,
                       non_zero_renegotiation_info=non_zero_renegotiation_info,
                       valid_renegotiation_info=valid_renegotiation_info,
                       scsv_renegotiation_info = scsv_renegotiation_info,
                       reject_tls12_renegotiation=reject_tls12_renegotiation,
                       no_renegotiation_info_2nd_ch = no_renegotiation_info_2nd_ch,
                       altered_renegotiation_info=altered_renegotiation_info,
                       sg=args.supported_group,
                       mycert=basedir+'/test/tls/pki/ubuntu_2004_cert.pem',
                       mykey=basedir+'/test/tls/pki/ubuntu_2004_key.pem',
                       psk=args.psk,
                       psk_mode=psk_mode,
                       resumption_master_secret=args.res_master,
                       session_ticket_file_in=args.session_ticket_file_in,
                       session_ticket_file_out=args.session_ticket_file_out,
                       curve=args.curve,
                       debug=args.debug)
t.run()

