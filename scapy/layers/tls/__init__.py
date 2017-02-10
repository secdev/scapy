## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard <arno@natisbad.com>
##                     2015, 2016 Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
Tools for handling TLS sessions and digital certificates.

Prerequisites:

    - You may need to 'pip install cryptography' for the module to be loaded.


Main features:

    - X.509 certificates parsing/building.

    - RSA & ECDSA keys sign/verify methods.

    - TLS records and sublayers (handshake...) parsing/building. Works with
      versions SSLv3, TLS 1.0, 1.1 and 1.2. This may be enhanced by a TLS
      context. For instance, if scapy reads a ServerHello with version TLS 1.2
      and a cipher suite using AES, it will assume the presence of IVs
      prepending the data. See test/tls.uts for real examples.

    - TLS encryption/decryption capabilities with the usual ciphersuites. Once
      again, the TLS context enables scapy to transparently send/receive
      protected data if it learnt the session secrets. Note that if scapy acts
      as one side of the handshake (e.g. reads all server-related packets and
      builds all client-related packets), it will indeed compute the session
      secrets.

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

    - Features to add (or wait for) in the cryptography library:

        - no limitation on FFDH generator size;
          (remove line 88 in cryptography/hazmat/primitives/asymmetric/dh.py)

        - CCM and CHACHA20-POLY1305 ciphers;

        - ECDH curves (x25519 and x448) from RFC 7748;

        - FFDH groups from RFC 7919;

        - the so-called 'tls' hash used with SSLv3 and TLS 1.0;

        - the compressed EC point format.


    - About the automatons:

        - Enrich the automatons. The client should be able to receive data at
          any time, and to send as much data as wanted from stdin (for now,
          only one predefined data message may be sent following the
          handshake). The server should stay online even after the first client
          leaves. Then we could look at more complicated behaviours like
          renegotiation and resumption. We might get some help from
          tintinweb/scapy-ssl_tls.

        - Add some examples which illustrate how the automatons could be used.
          Typically, we could showcase this with Heartbleed.

        - Split up parts of the automaton, e.g. when our server builds the
          ServerHello, Certificate, ServerKeyExchange and ServerHelloDone in
          the same should_REPLY_TO_CH method.

        - Make the automatons tests more robust and less consuming.

        - Allow the server to store both one RSA key and one ECDSA key, and
          select the right one to use according to the ClientHello suites.

        - Find a way to shutdown the automatons sockets properly without
          simultaneously breaking the unit tests.


    - Miscellaneous:

        - Implement TLS 1.3 structures and automatons. :D

        - Implement SSLv2 structures and automatons. xD

        - Mostly unused features : DSS, fixed DH, SRP, IDEA, char2 curves...

        - Check FFDH and ECDH parameters at SKE/CKE reception.

        - Go through the kx_algs and see what may be commented out.

        - Define several Certificate Transparency objects.

        - Enhance PSK and session ticket support.
"""

from scapy.config import conf

if not conf.crypto_valid:
    import logging
    log_loading = logging.getLogger("scapy.loading")
    log_loading.info("Can't import python-cryptography v1.7+. "
                     "Disabled PKI & TLS crypto-related features.")

