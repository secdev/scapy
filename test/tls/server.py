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

from scapy.utils import get_temp_file, randstring, repr_hex
from scapy.config import conf
from scapy.layers.tls.automaton_srv import TLSServerAutomaton
from scapy.layers.tls.basefields import _tls_version, _tls_version_options
from argparse import ArgumentParser


_tls13_version_options = {"tls13-d18": 0x7f12,
                        "tls13-d19": 0x7f13,
                        "tls13": 0x0304}

_old_tls_version_options = {"sslv2": 0x0002,
                        "sslv3": 0x0300,
                        "tls1": 0x0301,
                        "tls10": 0x0301,
                        "tls11": 0x0302,
                        "tls12": 0x0303,
                        "tls13-d18": 0x7f12,
                        "tls13-d19": 0x7f13}

tls_server_ciphers = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x002F, 0x0033, 0x0034, 0x0035, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x0041, 0x0045, 0x0046, 0x0067, 0x006B, 0x006D, 0x00C0, 0x00C4, 0x00C5, 0x0096, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, 0x00A6, 0x00A7, 0x00BA, 0x00BE, 0x00BF, 0x00C0, 0x00C4, 0x00C5, 0xC006, 0xC007, 0xC008, 0xC009, 0xC00A, 0xC010, 0xC011, 0xC012, 0xC013, 0xC014, 0xC015, 0xC016, 0xC017, 0xC018, 0xC019, 0xC023, 0xC024, 0xC027, 0xC028, 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xC072, 0xC073, 0xC076, 0xC077, 0xC09C, 0xC09D, 0xC09E, 0xC09F, 0xC0A0, 0xC0A1, 0xC0A2, 0xC0A3, 0xC0AC, 0xC0AD, 0xC0AE, 0xC0AF, 0xCCA8, 0xCCA9, 0xCCAA, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305]

tls12_server_ciphers = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x002F, 0x0033, 0x0034, 0x0035, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x0041, 0x0045, 0x0046, 0x0067, 0x006B, 0x006D, 0x00C0, 0x00C4, 0x00C5, 0x0096, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, 0x00A6, 0x00A7, 0x00BA, 0x00BE, 0x00BF, 0x00C0, 0x00C4, 0x00C5, 0xC006, 0xC007, 0xC008, 0xC009, 0xC00A, 0xC010, 0xC011, 0xC012, 0xC013, 0xC014, 0xC015, 0xC016, 0xC017, 0xC018, 0xC019, 0xC023, 0xC024, 0xC027, 0xC028, 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xC072, 0xC073, 0xC076, 0xC077, 0xC09C, 0xC09D, 0xC09E, 0xC09F, 0xC0A0, 0xC0A1, 0xC0A2, 0xC0A3, 0xC0AC, 0xC0AD, 0xC0AE, 0xC0AF, 0xCCA8, 0xCCA9, 0xCCAA]

tls13_server_ciphers = [0x0000, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305]

parser = ArgumentParser(description='Simple TLS Server')
#parser.add_argument("--psk",
#                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
parser.add_argument("--altered_finish", action="store_true",
                    help="Send an Altered Finish Message to Client (for TLS 1.3)")
parser.add_argument("--plaintext_ee", action="store_true",
                    help="Send a plaintext Encrypted Extension message (for TLS 1.3)")
parser.add_argument("--altered_signature", action="store_true",
                    help="Send an Altered Signature for Certificate Verify message (for TLS 1.3) or Server Key Exchange message (for TLS 1.2)")
parser.add_argument("--altered_y_coordinate", action="store_true",
                    help="Send an Altered y coordinate to Client (for TLS 1.3).  Requires --curve argument. Requires the Client to provide a NIST curve in the Key Share Group")
parser.add_argument("--missing_finished_message", action="store_true",
                    help="Send a Random TLS 1.3 message in place of TLS Finished Message (for TLS 1.3)")
parser.add_argument("--undefined_TLS_version", 
                    help="Send a TLS 1.3 Server Hello with TLS 1.3 (or lower draft) version in the legacy field (for TLS 1.3)")
parser.add_argument("--version_confusion", action="store_true",
                    help="Negotiate a ciphersuite not associated with TLS 1.3.  Requires --ciphersuite with a TLS 1.2 cipher (e.g., 0x003C) OR  Negotiate a TLS 1.3 ciphersuite with TLS 1.2")
parser.add_argument("--invalid_supported_versions", action="store_true",
                    help="specify version TLS 1.2 in the Supported Versions TLS Extension instead of TLS 1.3")
parser.add_argument("--ciphersuite", help="Specify the Ciphersuite this test server must use")
parser.add_argument("--version", help="Specify a TLS Version.  This parameter is required if the client offers only TLS 1.2 (--version tls12)", default='tls13')
parser.add_argument("--specify_sig_alg", help="Specify a signature algorithm for TLS 1.3 certificate verify message or TLS 1.2 Server Key Exchange message")
parser.add_argument("--explicit_ecdh_curve", action="store_true", help="Use explicit ECDH curve paramaters in place of the NIST named group (for TLS 1.2 only)")
parser.add_argument("--empty_certificate", action="store_true", help="Supply an empty certificate message to client (for TLS 1.3 and TLS 1.2)")
parser.add_argument("--altered_legacy_session_id", action="store_true",
                    help="Send TLS 1.3 Server Hello with altered session id from client (for TLS 1.3)")
parser.add_argument("--downgrade_protection", help="Include the TLS 1.2 or TLS 1.1 downgrade indicator in the last eight bytes of the server random field (for TLS 1.2)", default=None)

parser.add_argument("--non_zero_renegotiation_info", action="store_true", help="Provide a non-zero value in the renegotiation_info extension of TLS 1.2 Server Hello message")
parser.add_argument("--valid_renegotiation_info", action="store_true", help="Provide a compliant value in the renegotiation_info extension of TLS 1.2 Server Hello message")
parser.add_argument("--hello_reset", action="store_true", help="Allow a compliant TLS handshake to complete followed by a hello reset message")
parser.add_argument("--altered_renegotiation_info", action="store_true", help="Complete a TLS 1.2 handshake and send a hello reset request with a renegotiation_info extension that has altered verify_data")
parser.add_argument("--no_pfs", action="store_true",
                    help="Disable (EC)DHE exchange with PFS")
# args.curve must be a value in the dict _tls_named_curves (see tls/crypto/groups.py)
parser.add_argument("--curve", help="ECC curve to advertise (ex: secp256r1...")
parser.add_argument("--psk",
                    help="External PSK for symmetric authentication (for TLS 1.3)")  # noqa: E501
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
parser.add_argument("--port", nargs="?", type=int, default=4433,
                    help="The TCP source port")

args = parser.parse_args()

pcs = None
# PFS is set by default...
if args.no_pfs and args.psk:
    psk_mode = "psk_ke"
else:
    psk_mode = "psk_dhe_ke"

if args.altered_finish:
    altered_finish = True
else:
    altered_finish = False

if args.plaintext_ee:
     plain_ee = True
else:
    plain_ee = False
if args.missing_finished_message:
    missing_finished_message = True
else:
    missing_finished_message = False

#v = _tls_version_options.get(args.version, None)
#if not v:
#    sys.exit("Unrecognized TLS version option.")
#else:
#    old_version = v
if args.version:
    version = _tls_version_options.get(args.version, None)
    if not version:
        sys.exit("Unrecognized TLS version number")
else:
    version = None

if args.ciphersuite and args.version_confusion:
    cipher = int(args.ciphersuite, 16)
    if cipher in tls_server_ciphers:
        specify_cipher = cipher
    else:
        sys.exit("Unsupported ciphersuite for TLS Server")
    #if ciphers in list(range(0x1301, 0x1306)):
    #    cc_ciphers = ciphers
elif args.ciphersuite and args.version == 'tls13':
    cipher = int(args.ciphersuite, 16)
    if cipher in tls13_server_ciphers:
    #if cipher in list(range(0x1301, 0x1306)) or cipher == 0:
        specify_cipher = cipher
    else:
        sys.exit("Unrecognized ciphersuite for TLS 1.3")
elif args.ciphersuite and args.version == 'tls12':
    cipher = int(args.ciphersuite, 16)
    #print (cipher)
    if cipher in tls12_server_ciphers:
        specify_cipher = cipher
    else:
        sys.exit("Unsupported ciphersuite for TLS 1.2 Server")
else:
    specify_cipher = None
#
if args.altered_signature:
    altered_signature = True
else:
    altered_signature = False
#
if args.altered_y_coordinate:
    altered_y_coordinate = True
else:
    altered_y_coordinate = False
if args.version_confusion and not args.ciphersuite:
    sys.exit("Required ciphersuite not supplied")
elif args.version_confusion and args.ciphersuite:
    cipher = int(args.ciphersuite, 16)
    if cipher in tls13_server_ciphers or cipher in tls12_server_ciphers:
        specify_cipher = cipher
        version_confusion = True
    else:
        sys.exit("Unsupported ciphersuite for TLS Server")
else:
    version_confusion = False
if args.undefined_TLS_version:
    undefined_TLS_version = _tls13_version_options.get(args.undefined_TLS_version, None)
else:
    undefined_TLS_version = None

if args.invalid_supported_versions:
    invalid_supported_versions = True
else:
    invalid_supported_versions = False

if args.specify_sig_alg:
    specify_sig_alg = int(args.specify_sig_alg, 16)
else:
    specify_sig_alg = None

if args.explicit_ecdh_curve and args.version == 'tls12':
    explicit_ecdh_curve = True
elif args.explicit_ecdh_curve and args.version != 'tls12':
    sys.exit("use of explicit ECDH curve paramaters is for TLS 1.2 only")
else:
    explicit_ecdh_curve = False

if args.empty_certificate:
    empty_certificate = True
else:
    empty_certificate = False

if args.altered_legacy_session_id:
    altered_legacy_session_id = True
else:
    altered_legacy_session_id = False

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

if args.downgrade_protection == 'tls12':
    downgrade_protection = b'DOWNGRD\x01'
elif args.downgrade_protection == 'tls11':
    downgrade_protection = b'DOWNGRD\x00'
elif args.downgrade_protection == None :
    downgrade_protection = None
else:
    downgrade_protection = None

if args.curve:
    curve = args.curve
else:
    curve = None

t = TLSServerAutomaton(mycert=basedir+'/test/tls/pki/ubuntu_2004_cert.pem',
                       mykey=basedir+'/test/tls/pki/ubuntu_2004_key.pem',
                       preferred_ciphersuite=pcs,
                       client_auth=args.client_auth,
                       hello_reset=args.hello_reset,
                       altered_legacy_session_id=altered_legacy_session_id,
                       altered_finish=altered_finish,
                       plain_ee=plain_ee,
                       missing_finished_message=missing_finished_message,
                       version=version,
                       version_confusion=version_confusion,
                       invalid_supported_versions=invalid_supported_versions,
                       specify_cipher=specify_cipher,
                       #cc_ciphers=args.ciphersuite,
                       altered_signature=altered_signature,
                       altered_y_coordinate=altered_y_coordinate,
                       undefined_TLS_version=undefined_TLS_version,
                       specify_sig_alg=specify_sig_alg,
                       explicit_ecdh_curve=explicit_ecdh_curve,
                       empty_certificate=empty_certificate,
                       downgrade_protection=downgrade_protection,
                       non_zero_renegotiation_info=non_zero_renegotiation_info,
                       valid_renegotiation_info=valid_renegotiation_info,
                       altered_renegotiation_info=altered_renegotiation_info,
                       curve=curve,
                       cookie=args.cookie,
                       handle_session_ticket=args.handle_session_ticket,
                       session_ticket_file=args.session_ticket_file,
                       psk=args.psk,
                       psk_mode=psk_mode,
                       sport=args.port,
                       debug=args.debug)
t.run()

