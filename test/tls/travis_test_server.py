#!/usr/bin/env python

## This file is part of Scapy
## This program is published under a GPLv2 license

"""
TLS server used in unit tests.

When some expected_data is provided, a TLS client (e.g. openssl s_client)
should send some application data after the handshake. If this data matches our
expected_data, then we leave with exit code 0. Else we leave with exit code 1.
If no expected_data was provided and the handshake was ok, we exit with 0.
"""

from ast import literal_eval
import os
import sys
from contextlib import contextmanager
from io import BytesIO, StringIO

from scapy.modules import six

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                       os.path.pardir, os.path.pardir))
sys.path = [basedir] + sys.path

from scapy.layers.tls.automaton_srv import TLSServerAutomaton


@contextmanager
def captured_output():
    new_out, new_err = (StringIO(), StringIO()) if six.PY3 else (BytesIO(), BytesIO())
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err

def check_output_for_data(out, err, expected_data):
    errored = err.getvalue()
    if errored:
        return (False, errored)
    output = out.getvalue().strip()
    if expected_data:
        for data in output.split('> Received: ')[1:]:
            for line in literal_eval(data).split(b'\n'):
                if line == expected_data:
                    return (True, output)
        return (False, output)
    else:
        return (True, None)

def run_tls_test_server(expected_data, q):
    correct = False
    with captured_output() as (out, err):
        # Prepare automaton
        crt_basedir = os.path.join(basedir, 'test', 'tls', 'pki')
        t = TLSServerAutomaton(mycert=os.path.join(crt_basedir, 'srv_cert.pem'),
                               mykey=os.path.join(crt_basedir, 'srv_key.pem'))
        # Sync threads
        q.put(True)
        # Run server automaton
        t.run()
        # Return correct answer
        correct, out_e = check_output_for_data(out, err, expected_data)
    # Return data
    q.put(out_e)
    if correct:
        sys.exit(0)
    else:
        sys.exit(1)
