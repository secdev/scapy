#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
TLS server used in unit tests.
Usage: [sudo] ./unit_test_server.py [expected_data]

When some expected_data is provided, a TLS client (e.g. openssl s_client)
should send some application data after the handshake. If this data matches our
expected_data, then we leave with exit code 0. Else we leave with exit code 1.
If no expected_data was provided and the handshake was ok, we exit with 0.
"""

import os
import sys
from contextlib import contextmanager
from StringIO import StringIO

from scapy.layers.tls.automaton import TLSServerAutomaton

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))
sys.path=[basedir]+sys.path


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err

def check_output_for_data(out, err, data):
    if err.getvalue():
        sys.exit(1)

    output = out.getvalue().strip()
    if expected_data:
        lines = output.split("\n")
        for l in lines:
            if l.startswith("Received"):
                break
        if l == ("Received '%s'" % data):
            sys.exit(0)
        sys.exit(1)
    sys.exit(0)


if len(sys.argv) == 2:
    expected_data = sys.argv[1]
else:
    expected_data = None

with captured_output() as (out, err):
    t = TLSServerAutomaton(mycert=basedir+'/test/tls/pki/srv_cert.pem',
                           mykey=basedir+'/test/tls/pki/srv_key.pem')
    t.run()

check_output_for_data(out, err, expected_data)

