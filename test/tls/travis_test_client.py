#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
TLS client used in unit tests.
Usage: [sudo] ./unit_test_client.py [send_data [cipher_suite_code [version]]]

Start our TLS client, send our send_data, and terminate session with an Alert.
Optional cipher_cuite_code and version may be provided as hexadecimal strings
(e.g. c09e for TLS_DHE_RSA_WITH_AES_128_CCM and 0303 for TLS 1.2).
Reception of the exact send_data on the server is to be checked externally.
"""

import os
import sys

from scapy.layers.tls.automaton import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path


send_data = cipher_suite_code = version = None

if len(sys.argv) >= 2:
    send_data = sys.argv[1]

if len(sys.argv) >= 3:
    cipher_suite_code = int(sys.argv[2], 16)

if len(sys.argv) >= 4:
    version = int(sys.argv[3], 16)


ch = TLSClientHello(version=version, ciphers=cipher_suite_code)
t = TLSClientAutomaton(client_hello=ch, data=send_data)
t.run()


