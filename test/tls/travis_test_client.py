#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
TLS client used in unit tests.

Start our TLS client, send our send_data, and terminate session with an Alert.
Optional cipher_cuite_code and version may be provided as hexadecimal strings
(e.g. c09e for TLS_DHE_RSA_WITH_AES_128_CCM and 0303 for TLS 1.2).
Reception of the exact send_data on the server is to be checked externally.
"""

import sys, os, time
import multiprocessing

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path

from scapy.layers.tls.automaton import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello


send_data = cipher_suite_code = version = None

def run_tls_test_client(send_data=None, cipher_suite_code=None, version=None):
    ch = TLSClientHello(version=int(version, 16), ciphers=int(cipher_suite_code, 16))
    t = TLSClientAutomaton(client_hello=ch, data=send_data)
    t.run()

from travis_test_server import run_tls_test_server

def test_tls_client(suite, version, q):
    msg = "TestC_" + suite + "_data"
    # Run server
    q_ = multiprocessing.Manager().Queue()
    th_ = multiprocessing.Process(target=run_tls_test_server, args=(msg, q_))
    th_.start()
    # Synchronise threads
    q_.get()
    time.sleep(1)
    # Run client
    run_tls_test_client(msg, suite, version)
    # Wait for server
    th_.join(60)
    if th_.is_alive():
        th_.terminate()
        raise RuntimeError("Test timed out")
    # Return values
    q.put(q_.get())
    q.put(th_.exitcode)
