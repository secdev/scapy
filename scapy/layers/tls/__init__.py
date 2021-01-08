# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard <arno@natisbad.com>
#               2015, 2016, 2017 Maxence Tury <maxence.tury@ssi.gouv.fr>
#               2019 Romain Perez
# This program is published under a GPLv2 license

"""
Tools for handling TLS sessions and digital certificates.
Use load_layer('tls') to load them to the main namespace.

Prerequisites:

    - You may need to 'pip install cryptography' for the module to be loaded.


Main features:

    - X.509 certificates parsing/building.

    - RSA & ECDSA keys sign/verify methods.

    - TLS records and sublayers (handshake...) parsing/building. Works with
      versions SSLv2 to TLS 1.3. This may be enhanced by a TLS context. For
      instance, if Scapy reads a ServerHello with version TLS 1.2 and a cipher
      suite using AES, it will assume the presence of IVs prepending the data.
      See test/tls.uts for real examples.

    - TLS encryption/decryption capabilities with many ciphersuites, including
      some which may be deemed dangerous. Once again, the TLS context enables
      Scapy to transparently send/receive protected data if it learnt the
      session secrets. Note that if Scapy acts as one side of the handshake
      (e.g. reads all server-related packets and builds all client-related
      packets), it will indeed compute the session secrets.

    - TLS client & server basic automatons, provided for testing and tweaking
      purposes. These make for a very primitive TLS stack.

    - Additionally, a basic test PKI (key + certificate for a CA, a client and
      a server) is provided in tls/examples/pki_test.


Unit tests:

    - Various cryptography checks.

    - Reading a TLS handshake between a Firefox client and a GitHub server.

    - Reading TLS 1.3 handshakes from test vectors of the 8448 RFC.

    - Reading a SSLv2 handshake between s_client and s_server, without PFS.

    - Test our TLS server against s_client with different cipher suites.

    - Test our TLS client against our TLS server (s_server is unscriptable).


TODO list (may it be carved away by good souls):

    - Features to add (or wait for) in the cryptography library:

        - the compressed EC point format.

    - About the automatons:

        - Allow upgrade from TLS 1.2 to TLS 1.3 in the Automaton client.
          Currently we'll use TLS 1.3 only if the automaton client was given
          version="tls13".

        - Add various checks for discrepancies between client and server.
          Is the ServerHello ciphersuite ok? What about the SKE params? Etc.

        - Add some examples which illustrate how the automatons could be used.
          Typically, we could showcase this with Heartbleed.

        - Allow the server to store both one RSA key and one ECDSA key, and
          select the right one to use according to the ClientHello suites.

        - Find a way to shutdown the automatons sockets properly without
          simultaneously breaking the unit tests.


    - Miscellaneous:

        - Define several Certificate Transparency objects.

        - Add the extended master secret and encrypt-then-mac logic.

        - Mostly unused features : DSS, fixed DH, SRP, char2 curves...
"""

from scapy.config import conf

if not conf.crypto_valid:
    import logging
    log_loading = logging.getLogger("scapy.loading")
    log_loading.info("Can't import python-cryptography v1.7+. "
                     "Disabled PKI & TLS crypto-related features.")
