## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard <arno@natisbad.com>
##                     2015, 2016 Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
Tools for handling TLS sessions and digital certificates.

Prerequisites:

    - You need to 'pip install ecdsa' for the module to be loaded.

    - We rely on pycrypto for several computations, however the last packaged
    version does not provide AEAD support. If you don't need it, just do
    'pip install pycrypto'. If however you need GCM & CCM support, do
    curl -sL https://github.com/dlitz/pycrypto/archive/v2.7a1.tar.gz | tar xz
    cd pycrypto-2.7a1
    python setup.py build
    sudo python setup.py install


Main features:

    - X.509 certificates parsing/building.

    - RSA & ECDSA keys sign/verify methods.

    - TLS records and sublayers (handshake...) parsing/building. Works with
    versions TLS 1.0, 1.1 and 1.2. SSLv3 should be mostly ok. This may be
    enhanced by a TLS context. For instance, if scapy reads a ServerHello
    with version TLS 1.2 and a cipher suite using AES, it will assume the
    presence of IVs prepending the data. See test/tls.uts for real examples.

    - TLS encryption/decryption capabilities with the usual ciphersuites. Once
    again, the TLS context enables scapy to transparently send/receive
    protected data if it learnt the session secrets. Note that if scapy acts as
    one side of the handshake (e.g. reads all server-related packets and builds
    all client-related packets), it will indeed compute the session secrets.

    - TLS client & server basic automatons, provided for testing and tweaking
    purposes. These make for a very primitive TLS stack.

    - Additionally, a basic test PKI (key + certificate for a CA, a client and
    a server) is provided in tls/examples/pki_test.


Unit tests:

    - Various cryptography checks.

    - Reading a TLS handshake between a Firefox client and a GitHub server.

    - Test our TLS server against s_client with different cipher suites.

    - Test our TLS client against our TLS server (s_server is unscriptable).


TODO list (may it be carved away by good souls):

    - Enrich the automatons. The client should be able to receive data at any
    time, and to send as much data as wanted from stdin (for now, only one
    predefined data message may be sent following the handshake). The server
    should stay online even after the first client leaves. Then we could look
    at more complicated behaviours like renegotiation and resumption.
    We might get some help from tintinweb/scapy-ssl_tls.

    - Add some examples which illustrate how the automatons could be used.
    Typically, we could showcase this with Heartbleed.

    - Split up parts of the automaton, e.g. when our server builds the
    ServerHello, Certificate, ServerKeyExchange and ServerHelloDone in the
    same should_REPLY_TO_CH method.

    - Make the automatons tests more robust and less consuming.

    - Allow for the server to store simultaneously one RSA key and one ECDSA
    key, and select the right one to use according to the ClientHello suites.

    - Find a way to shutdown the automatons sockets properly without
    simultaneously breaking the unit tests.

    - Switch from pycrypto to python-cryptography, once it provides proper
    AEAD support. See if we could get CHACHA20-POLY1305 in the process.

    - Check FFDH and ECDH parameters at SKE/CKE reception.

    - Go through the kx_algs and see what may be commented out without risk.

    - Define the OCSPStatus packet.

    - Define several Certificate Transparency objects.

    - Enhance PSK support.

    - Mostly unused features : DSS, fixed DH, SRP, IDEA, KRB5, char2 curves...

    - Implement SSLv2 structures and automatons. xD

    - Implement TLS 1.3 structures and automatons. :D
"""

try:
    import Crypto
except ImportError:
    import logging
    log_loading = logging.getLogger("scapy.loading")
    log_loading.info("Can't import python Crypto lib. Disabled TLS tools.")
    raise ImportError

