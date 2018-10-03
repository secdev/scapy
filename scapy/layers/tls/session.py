# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
# This program is published under a GPLv2 license

"""
TLS session handler.
"""

import socket
import struct

from scapy.config import conf
from scapy.compat import raw
import scapy.modules.six as six
from scapy.error import log_runtime, warning
from scapy.packet import Packet
from scapy.utils import repr_hex, strxor
from scapy.layers.tls.crypto.compression import Comp_NULL
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.layers.tls.crypto.prf import PRF

# Note the following import may happen inside connState.__init__()
# in order to avoid to avoid cyclical dependencies.
# from scapy.layers.tls.crypto.suites import TLS_NULL_WITH_NULL_NULL


###############################################################################
#   Connection states                                                         #
###############################################################################

class connState(object):
    """
    From RFC 5246, section 6.1:
    A TLS connection state is the operating environment of the TLS Record
    Protocol.  It specifies a compression algorithm, an encryption
    algorithm, and a MAC algorithm.  In addition, the parameters for
    these algorithms are known: the MAC key and the bulk encryption keys
    for the connection in both the read and the write directions.
    Logically, there are always four connection states outstanding: the
    current read and write states, and the pending read and write states.
    All records are processed under the current read and write states.
    The security parameters for the pending states can be set by the TLS
    Handshake Protocol, and the ChangeCipherSpec can selectively make
    either of the pending states current, in which case the appropriate
    current state is disposed of and replaced with the pending state; the
    pending state is then reinitialized to an empty state.  It is illegal
    to make a state that has not been initialized with security
    parameters a current state.  The initial current state always
    specifies that no encryption, compression, or MAC will be used.

    (For practical reasons, Scapy scraps these two last lines, through the
    implementation of dummy ciphers and MAC with TLS_NULL_WITH_NULL_NULL.)

    These attributes and behaviours are mostly mapped in this class.
    Also, note that Scapy may make a current state out of a pending state
    which has been initialized with dummy security parameters. We need
    this in order to know when the content of a TLS message is encrypted,
    whether we possess the right keys to decipher/verify it or not.
    For instance, when Scapy parses a CKE without knowledge of any secret,
    and then a CCS, it needs to know that the following Finished
    is encrypted and signed according to a new cipher suite, even though
    it cannot decipher the message nor verify its integrity.
    """

    def __init__(self,
                 connection_end="server",
                 read_or_write="read",
                 seq_num=0,
                 compression_alg=Comp_NULL,
                 ciphersuite=None,
                 tls_version=0x0303):

        self.tls_version = tls_version

        # It is the user's responsibility to keep the record seq_num
        # under 2**64-1. If this value gets maxed out, the TLS class in
        # record.py will crash when trying to encode it with struct.pack().
        self.seq_num = seq_num

        self.connection_end = connection_end
        self.row = read_or_write

        if ciphersuite is None:
            from scapy.layers.tls.crypto.suites import TLS_NULL_WITH_NULL_NULL
            ciphersuite = TLS_NULL_WITH_NULL_NULL
        self.ciphersuite = ciphersuite(tls_version=tls_version)

        if not self.ciphersuite.usable:
            warning("TLS ciphersuite not usable. Is the cryptography Python module installed ?")  # noqa: E501
            return

        self.compression = compression_alg()
        self.key_exchange = ciphersuite.kx_alg()
        self.cipher = ciphersuite.cipher_alg()
        self.hash = ciphersuite.hash_alg()

        if tls_version > 0x0200:
            if ciphersuite.cipher_alg.type == "aead":
                self.hmac = None
                self.mac_len = self.cipher.tag_len
            else:
                self.hmac = ciphersuite.hmac_alg()
                self.mac_len = self.hmac.hmac_len
        else:
            self.hmac = ciphersuite.hmac_alg()          # should be Hmac_NULL
            self.mac_len = self.hash.hash_len

        if tls_version >= 0x0304:
            self.hkdf = TLS13_HKDF(self.hash.name.lower())
        else:
            self.prf = PRF(ciphersuite.hash_alg.name, tls_version)

    def debug_repr(self, name, secret):
        if conf.debug_tls and secret:
            log_runtime.debug("TLS: %s %s %s: %s",
                              self.connection_end,
                              self.row,
                              name,
                              repr_hex(secret))

    def derive_keys(self,
                    client_random=b"",
                    server_random=b"",
                    master_secret=b""):
        # XXX Can this be called over a non-usable suite? What happens then?

        cs = self.ciphersuite

        # Derive the keys according to the cipher type and protocol version
        key_block = self.prf.derive_key_block(master_secret,
                                              server_random,
                                              client_random,
                                              cs.key_block_len)

        # When slicing the key_block, keep the right half of the material
        skip_first = False
        if ((self.connection_end == "client" and self.row == "read") or
                (self.connection_end == "server" and self.row == "write")):
            skip_first = True

        pos = 0
        cipher_alg = cs.cipher_alg

        # MAC secret (for block and stream ciphers)
        if (cipher_alg.type == "stream") or (cipher_alg.type == "block"):
            start = pos
            if skip_first:
                start += cs.hmac_alg.key_len
            end = start + cs.hmac_alg.key_len
            mac_secret = key_block[start:end]
            self.debug_repr("mac_secret", mac_secret)
            pos += 2 * cs.hmac_alg.key_len
        else:
            mac_secret = None

        # Cipher secret
        start = pos
        if skip_first:
            start += cipher_alg.key_len
        end = start + cipher_alg.key_len
        cipher_secret = key_block[start:end]
        if cs.kx_alg.export:
            reqLen = cipher_alg.expanded_key_len
            cipher_secret = self.prf.postprocess_key_for_export(cipher_secret,
                                                                client_random,
                                                                server_random,
                                                                self.connection_end,  # noqa: E501
                                                                self.row,
                                                                reqLen)
        self.debug_repr("cipher_secret", cipher_secret)
        pos += 2 * cipher_alg.key_len

        # Implicit IV (for block and AEAD ciphers)
        start = pos
        if cipher_alg.type == "block":
            if skip_first:
                start += cipher_alg.block_size
            end = start + cipher_alg.block_size
        elif cipher_alg.type == "aead":
            if skip_first:
                start += cipher_alg.fixed_iv_len
            end = start + cipher_alg.fixed_iv_len

        # Now we have the secrets, we can instantiate the algorithms
        if cs.hmac_alg is None:         # AEAD
            self.hmac = None
            self.mac_len = cipher_alg.tag_len
        else:
            self.hmac = cs.hmac_alg(mac_secret)
            self.mac_len = self.hmac.hmac_len

        if cipher_alg.type == "stream":
            cipher = cipher_alg(cipher_secret)
        elif cipher_alg.type == "block":
            # We set an IV every time, even though it does not matter for
            # TLS 1.1+ as it requires an explicit IV. Indeed the cipher.iv
            # would get updated in TLS.post_build() or TLS.pre_dissect().
            iv = key_block[start:end]
            if cs.kx_alg.export:
                reqLen = cipher_alg.block_size
                iv = self.prf.generate_iv_for_export(client_random,
                                                     server_random,
                                                     self.connection_end,
                                                     self.row,
                                                     reqLen)
            cipher = cipher_alg(cipher_secret, iv)
            self.debug_repr("block iv", iv)
        elif cipher_alg.type == "aead":
            fixed_iv = key_block[start:end]
            nonce_explicit_init = 0
            # If you ever wanted to set a random nonce_explicit, use this:
            # exp_bit_len = cipher_alg.nonce_explicit_len * 8
            # nonce_explicit_init = random.randint(0, 2**exp_bit_len - 1)
            cipher = cipher_alg(cipher_secret, fixed_iv, nonce_explicit_init)
            self.debug_repr("aead fixed iv", fixed_iv)
        self.cipher = cipher

    def sslv2_derive_keys(self, key_material):
        """
        There is actually only one key, the CLIENT-READ-KEY or -WRITE-KEY.

        Note that skip_first is opposite from the one with SSLv3 derivation.

        Also, if needed, the IV should be set elsewhere.
        """
        skip_first = True
        if ((self.connection_end == "client" and self.row == "read") or
                (self.connection_end == "server" and self.row == "write")):
            skip_first = False

        cipher_alg = self.ciphersuite.cipher_alg

        start = 0
        if skip_first:
            start += cipher_alg.key_len
        end = start + cipher_alg.key_len
        cipher_secret = key_material[start:end]
        self.cipher = cipher_alg(cipher_secret)
        self.debug_repr("cipher_secret", cipher_secret)

    def tls13_derive_keys(self, key_material):
        cipher_alg = self.ciphersuite.cipher_alg
        key_len = cipher_alg.key_len
        iv_len = cipher_alg.fixed_iv_len
        write_key = self.hkdf.expand_label(key_material, b"key", b"", key_len)
        write_iv = self.hkdf.expand_label(key_material, b"iv", b"", iv_len)
        self.cipher = cipher_alg(write_key, write_iv)

    def snapshot(self):
        """
        This is used mostly as a way to keep the cipher state and the seq_num.
        """
        snap = connState(connection_end=self.connection_end,
                         read_or_write=self.row,
                         seq_num=self.seq_num,
                         compression_alg=type(self.compression),
                         ciphersuite=type(self.ciphersuite),
                         tls_version=self.tls_version)
        snap.cipher = self.cipher.snapshot()
        if self.hmac:
            snap.hmac.key = self.hmac.key
        return snap

    def __repr__(self):
        def indent(s):
            if s and s[-1] == '\n':
                s = s[:-1]
            s = '\n'.join('\t' + x for x in s.split('\n')) + '\n'
            return s

        res = "Connection end : %s\n" % self.connection_end.upper()
        res += "Cipher suite   : %s (0x%04x)\n" % (self.ciphersuite.name,
                                                   self.ciphersuite.val)
        res += "Compression    : %s (0x%02x)\n" % (self.compression.name,
                                                   self.compression.val)
        tabsize = 4
        return res.expandtabs(tabsize)


class readConnState(connState):
    def __init__(self, **kargs):
        connState.__init__(self, read_or_write="read", **kargs)


class writeConnState(connState):
    def __init__(self, **kargs):
        connState.__init__(self, read_or_write="write", **kargs)


###############################################################################
#   TLS session                                                               #
###############################################################################

class tlsSession(object):
    """
    This is our TLS context, which gathers information from both sides of the
    TLS connection. These sides are represented by a readConnState instance and
    a writeConnState instance. Along with overarching network attributes, a
    tlsSession object also holds negotiated, shared information, such as the
    key exchange parameters and the master secret (when available).

    The default connection_end is "server". This corresponds to the expected
    behaviour for static exchange analysis (with a ClientHello parsed first).
    """

    def __init__(self,
                 ipsrc=None, ipdst=None,
                 sport=None, dport=None, sid=None,
                 connection_end="server",
                 wcs=None, rcs=None):

        # Use this switch to prevent additions to the 'handshake_messages'.
        self.frozen = False

        # Network settings
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.sport = sport
        self.dport = dport
        self.sid = sid

        # Our TCP socket. None until we send (or receive) a packet.
        self.sock = None

        # Connection states
        self.connection_end = connection_end

        if wcs is None:
            # Instantiate wcs with dummy values.
            self.wcs = writeConnState(connection_end=connection_end)
            self.wcs.derive_keys()
        else:
            self.wcs = wcs

        if rcs is None:
            # Instantiate rcs with dummy values.
            self.rcs = readConnState(connection_end=connection_end)
            self.rcs.derive_keys()
        else:
            self.rcs = rcs

        # The pending write/read states are updated by the building/parsing
        # of various TLS packets. They get committed to self.wcs/self.rcs
        # once Scapy builds/parses a ChangeCipherSpec message, or for certain
        # other messages in case of TLS 1.3.
        self.pwcs = None
        self.triggered_pwcs_commit = False
        self.prcs = None
        self.triggered_prcs_commit = False

        # Certificates and private keys

        # The server certificate chain, as a list of Cert instances.
        # Either we act as server and it has to be provided, or it is expected
        # to be sent by the server through a Certificate message.
        # The server certificate should be self.server_certs[0].
        self.server_certs = []

        # The server private key, as a PrivKey instance, when acting as server.
        # XXX It would be nice to be able to provide both an RSA and an ECDSA
        # key in order for the same Scapy server to support both families of
        # cipher suites. See INIT_TLS_SESSION() in automaton_srv.py.
        # (For now server_key holds either one of both types for DHE
        # authentication, while server_rsa_key is used only for RSAkx.)
        self.server_key = None
        self.server_rsa_key = None
        # self.server_ecdsa_key = None

        # Back in the dreadful EXPORT days, US servers were forbidden to use
        # RSA keys longer than 512 bits for RSAkx. When their usual RSA key
        # was longer than this, they had to create a new key and send it via
        # a ServerRSAParams message. When receiving such a message,
        # Scapy stores this key in server_tmp_rsa_key as a PubKey instance.
        self.server_tmp_rsa_key = None

        # When client authentication is performed, we need at least a
        # client certificate chain. If we act as client, we also have
        # to provide the key associated with the first certificate.
        self.client_certs = []
        self.client_key = None

        # Ephemeral key exchange parameters

        # These are the group/curve parameters, needed to hold the information
        # e.g. from receiving an SKE to sending a CKE. Usually, only one of
        # these attributes will be different from None.
        self.client_kx_ffdh_params = None
        self.client_kx_ecdh_params = None

        # These are PrivateKeys and PublicKeys from the appropriate FFDH/ECDH
        # cryptography module, i.e. these are not raw bytes. Usually, only one
        # in two will be different from None, e.g. when being a TLS client you
        # will need the client_kx_privkey (the serialized public key is not
        # actually registered) and you will receive a server_kx_pubkey.
        self.client_kx_privkey = None
        self.client_kx_pubkey = None
        self.server_kx_privkey = None
        self.server_kx_pubkey = None

        # When using TLS 1.3, the tls13_client_pubshares will contain every
        # potential key share (equate the 'client_kx_pubkey' before) the client
        # offered, indexed by the id of the FFDH/ECDH group. These dicts
        # effectively replace the four previous attributes.
        self.tls13_client_privshares = {}
        self.tls13_client_pubshares = {}
        self.tls13_server_privshare = {}
        self.tls13_server_pubshare = {}

        # Negotiated session parameters

        # The advertised TLS version found in the ClientHello (and
        # EncryptedPreMasterSecret if used). If acting as server, it is set to
        # the value advertised by the client in its ClientHello.
        # The default value corresponds to TLS 1.2 (and TLS 1.3, incidentally).
        self.advertised_tls_version = 0x0303

        # The agreed-upon TLS version found in the ServerHello.
        self.tls_version = None

        # These attributes should eventually be known to both sides (SSLv3-TLS 1.2).  # noqa: E501
        self.client_random = None
        self.server_random = None
        self.pre_master_secret = None
        self.master_secret = None

        # A session ticket received by the client.
        self.client_session_ticket = None

        # These attributes should only be used with SSLv2 connections.
        # We need to keep the KEY-MATERIAL here because it may be reused.
        self.sslv2_common_cs = []
        self.sslv2_connection_id = None
        self.sslv2_challenge = None
        self.sslv2_challenge_clientcert = None
        self.sslv2_key_material = None

        # These attributes should only be used with TLS 1.3 connections.
        self.tls13_psk_secret = None
        self.tls13_early_secret = None
        self.tls13_dhe_secret = None
        self.tls13_handshake_secret = None
        self.tls13_master_secret = None
        self.tls13_derived_secrets = {}

        # Handshake messages needed for Finished computation/validation.
        # No record layer headers, no HelloRequests, no ChangeCipherSpecs.
        self.handshake_messages = []
        self.handshake_messages_parsed = []

        # All exchanged TLS packets.
        # XXX no support for now
        # self.exchanged_pkts = []

    def __setattr__(self, name, val):
        if name == "connection_end":
            if hasattr(self, "rcs") and self.rcs:
                self.rcs.connection_end = val
            if hasattr(self, "wcs") and self.wcs:
                self.wcs.connection_end = val
            if hasattr(self, "prcs") and self.prcs:
                self.prcs.connection_end = val
            if hasattr(self, "pwcs") and self.pwcs:
                self.pwcs.connection_end = val
        super(tlsSession, self).__setattr__(name, val)

    # Mirroring

    def mirror(self):
        """
        This function takes a tlsSession object and swaps the IP addresses,
        ports, connection ends and connection states. The triggered_commit are
        also swapped (though it is probably overkill, it is cleaner this way).

        It is useful for static analysis of a series of messages from both the
        client and the server. In such a situation, it should be used every
        time the message being read comes from a different side than the one
        read right before, as the reading state becomes the writing state, and
        vice versa. For instance you could do:

        client_hello = open('client_hello.raw').read()
        <read other messages>

        m1 = TLS(client_hello)
        m2 = TLS(server_hello, tls_session=m1.tls_session.mirror())
        m3 = TLS(server_cert, tls_session=m2.tls_session)
        m4 = TLS(client_keyexchange, tls_session=m3.tls_session.mirror())
        """

        self.ipdst, self.ipsrc = self.ipsrc, self.ipdst
        self.dport, self.sport = self.sport, self.dport

        self.rcs, self.wcs = self.wcs, self.rcs
        if self.rcs:
            self.rcs.row = "read"
        if self.wcs:
            self.wcs.row = "write"

        self.prcs, self.pwcs = self.pwcs, self.prcs
        if self.prcs:
            self.prcs.row = "read"
        if self.pwcs:
            self.pwcs.row = "write"

        self.triggered_prcs_commit, self.triggered_pwcs_commit = \
            self.triggered_pwcs_commit, self.triggered_prcs_commit

        if self.connection_end == "client":
            self.connection_end = "server"
        elif self.connection_end == "server":
            self.connection_end = "client"

        return self

    # Secrets management for SSLv3 to TLS 1.2

    def compute_master_secret(self):
        if self.pre_master_secret is None:
            warning("Missing pre_master_secret while computing master_secret!")
        if self.client_random is None:
            warning("Missing client_random while computing master_secret!")
        if self.server_random is None:
            warning("Missing server_random while computing master_secret!")

        ms = self.pwcs.prf.compute_master_secret(self.pre_master_secret,
                                                 self.client_random,
                                                 self.server_random)
        self.master_secret = ms
        if conf.debug_tls:
            log_runtime.debug("TLS: master secret: %s", repr_hex(ms))

    def compute_ms_and_derive_keys(self):
        self.compute_master_secret()
        self.prcs.derive_keys(client_random=self.client_random,
                              server_random=self.server_random,
                              master_secret=self.master_secret)
        self.pwcs.derive_keys(client_random=self.client_random,
                              server_random=self.server_random,
                              master_secret=self.master_secret)

    # Secrets management for SSLv2

    def compute_sslv2_key_material(self):
        if self.master_secret is None:
            warning("Missing master_secret while computing key_material!")
        if self.sslv2_challenge is None:
            warning("Missing challenge while computing key_material!")
        if self.sslv2_connection_id is None:
            warning("Missing connection_id while computing key_material!")

        km = self.pwcs.prf.derive_key_block(self.master_secret,
                                            self.sslv2_challenge,
                                            self.sslv2_connection_id,
                                            2 * self.pwcs.cipher.key_len)
        self.sslv2_key_material = km
        if conf.debug_tls:
            log_runtime.debug("TLS: master secret: %s", repr_hex(self.master_secret))  # noqa: E501
            log_runtime.debug("TLS: key material: %s", repr_hex(km))

    def compute_sslv2_km_and_derive_keys(self):
        self.compute_sslv2_key_material()
        self.prcs.sslv2_derive_keys(key_material=self.sslv2_key_material)
        self.pwcs.sslv2_derive_keys(key_material=self.sslv2_key_material)

    # Secrets management for TLS 1.3

    def compute_tls13_early_secrets(self):
        """
        Ciphers key and IV are updated accordingly for 0-RTT data.
        self.handshake_messages should be ClientHello only.
        """
        # we use the prcs rather than the pwcs in a totally arbitrary way
        if self.prcs is None:
            # too soon
            return

        hkdf = self.prcs.hkdf

        self.tls13_early_secret = hkdf.extract(None,
                                               self.tls13_psk_secret)

        bk = hkdf.derive_secret(self.tls13_early_secret,
                                b"external psk binder key",
                                # "resumption psk binder key",
                                b"")
        self.tls13_derived_secrets["binder_key"] = bk

        if len(self.handshake_messages) > 1:
            # these secrets are not defined in case of HRR
            return

        cets = hkdf.derive_secret(self.tls13_early_secret,
                                  b"client early traffic secret",
                                  b"".join(self.handshake_messages))
        self.tls13_derived_secrets["client_early_traffic_secret"] = cets

        ees = hkdf.derive_secret(self.tls13_early_secret,
                                 b"early exporter master secret",
                                 b"".join(self.handshake_messages))
        self.tls13_derived_secrets["early_exporter_secret"] = ees

        if self.connection_end == "server":
            self.prcs.tls13_derive_keys(cets)
        elif self.connection_end == "client":
            self.pwcs.tls13_derive_keys(cets)

    def compute_tls13_handshake_secrets(self):
        """
        Ciphers key and IV are updated accordingly for Handshake data.
        self.handshake_messages should be ClientHello...ServerHello.
        """
        if self.tls13_early_secret is None:
            warning("No early secret. This is abnormal.")

        hkdf = self.prcs.hkdf

        self.tls13_handshake_secret = hkdf.extract(self.tls13_early_secret,
                                                   self.tls13_dhe_secret)

        chts = hkdf.derive_secret(self.tls13_handshake_secret,
                                  b"client handshake traffic secret",
                                  b"".join(self.handshake_messages))
        self.tls13_derived_secrets["client_handshake_traffic_secret"] = chts

        shts = hkdf.derive_secret(self.tls13_handshake_secret,
                                  b"server handshake traffic secret",
                                  b"".join(self.handshake_messages))
        self.tls13_derived_secrets["server_handshake_traffic_secret"] = shts

        if self.connection_end == "server":
            self.prcs.tls13_derive_keys(chts)
            self.pwcs.tls13_derive_keys(shts)
        elif self.connection_end == "client":
            self.pwcs.tls13_derive_keys(chts)
            self.prcs.tls13_derive_keys(shts)

    def compute_tls13_traffic_secrets(self):
        """
        Ciphers key and IV are updated accordingly for Application data.
        self.handshake_messages should be ClientHello...ServerFinished.
        """
        hkdf = self.prcs.hkdf

        self.tls13_master_secret = hkdf.extract(self.tls13_handshake_secret,
                                                None)

        cts0 = hkdf.derive_secret(self.tls13_master_secret,
                                  b"client application traffic secret",
                                  b"".join(self.handshake_messages))
        self.tls13_derived_secrets["client_traffic_secrets"] = [cts0]

        sts0 = hkdf.derive_secret(self.tls13_master_secret,
                                  b"server application traffic secret",
                                  b"".join(self.handshake_messages))
        self.tls13_derived_secrets["server_traffic_secrets"] = [sts0]

        es = hkdf.derive_secret(self.tls13_master_secret,
                                b"exporter master secret",
                                b"".join(self.handshake_messages))
        self.tls13_derived_secrets["exporter_secret"] = es

        if self.connection_end == "server":
            # self.prcs.tls13_derive_keys(cts0)
            self.pwcs.tls13_derive_keys(sts0)
        elif self.connection_end == "client":
            # self.pwcs.tls13_derive_keys(cts0)
            self.prcs.tls13_derive_keys(sts0)

    def compute_tls13_traffic_secrets_end(self):
        cts0 = self.tls13_derived_secrets["client_traffic_secrets"][0]
        if self.connection_end == "server":
            self.prcs.tls13_derive_keys(cts0)
        elif self.connection_end == "client":
            self.pwcs.tls13_derive_keys(cts0)

    def compute_tls13_verify_data(self, connection_end, read_or_write):
        shts = "server_handshake_traffic_secret"
        chts = "client_handshake_traffic_secret"
        if read_or_write == "read":
            hkdf = self.rcs.hkdf
            if connection_end == "client":
                basekey = self.tls13_derived_secrets[shts]
            elif connection_end == "server":
                basekey = self.tls13_derived_secrets[chts]
        elif read_or_write == "write":
            hkdf = self.wcs.hkdf
            if connection_end == "client":
                basekey = self.tls13_derived_secrets[chts]
            elif connection_end == "server":
                basekey = self.tls13_derived_secrets[shts]

        if not hkdf or not basekey:
            warning("Missing arguments for verify_data computation!")
            return None
        # XXX this join() works in standard cases, but does it in all of them?
        handshake_context = b"".join(self.handshake_messages)
        return hkdf.compute_verify_data(basekey, handshake_context)

    def compute_tls13_resumption_secret(self):
        """
        self.handshake_messages should be ClientHello...ClientFinished.
        """
        if self.connection_end == "server":
            hkdf = self.prcs.hkdf
        elif self.connection_end == "client":
            hkdf = self.pwcs.hkdf
        rs = hkdf.derive_secret(self.tls13_master_secret,
                                b"resumption master secret",
                                b"".join(self.handshake_messages))
        self.tls13_derived_secrets["resumption_secret"] = rs

    def compute_tls13_next_traffic_secrets(self):
        """
        Ciphers key and IV are updated accordingly.
        """
        hkdf = self.prcs.hkdf
        hl = hkdf.hash.digest_size

        cts = self.tls13_derived_secrets["client_traffic_secrets"]
        ctsN = cts[-1]
        ctsN_1 = hkdf.expand_label(ctsN, "application traffic secret", "", hl)
        cts.append(ctsN_1)

        stsN_1 = hkdf.expand_label(ctsN, "application traffic secret", "", hl)
        cts.append(stsN_1)

        if self.connection_end == "server":
            self.prcs.tls13_derive_keys(ctsN_1)
            self.pwcs.tls13_derive_keys(stsN_1)
        elif self.connection_end == "client":
            self.pwcs.tls13_derive_keys(ctsN_1)
            self.prcs.tls13_derive_keys(stsN_1)

    # Tests for record building/parsing

    def consider_read_padding(self):
        # Return True if padding is needed. Used by TLSPadField.
        return (self.rcs.cipher.type == "block" and
                not (False in six.itervalues(self.rcs.cipher.ready)))

    def consider_write_padding(self):
        # Return True if padding is needed. Used by TLSPadField.
        return self.wcs.cipher.type == "block"

    def use_explicit_iv(self, version, cipher_type):
        # Return True if an explicit IV is needed. Required for TLS 1.1+
        # when either a block or an AEAD cipher is used.
        if cipher_type == "stream":
            return False
        return version >= 0x0302

    # Python object management

    def hash(self):
        s1 = struct.pack("!H", self.sport)
        s2 = struct.pack("!H", self.dport)
        family = socket.AF_INET
        if ':' in self.ipsrc:
            family = socket.AF_INET6
        s1 += socket.inet_pton(family, self.ipsrc)
        s2 += socket.inet_pton(family, self.ipdst)
        return strxor(s1, s2)

    def eq(self, other):
        ok = False
        if (self.sport == other.sport and self.dport == other.dport and
                self.ipsrc == other.ipsrc and self.ipdst == other.ipdst):
            ok = True

        if (not ok and
            self.dport == other.sport and self.sport == other.dport and
                self.ipdst == other.ipsrc and self.ipsrc == other.ipdst):
            ok = True

        if ok:
            if self.sid and other.sid:
                return self.sid == other.sid
            return True

        return False

    def __repr__(self):
        sid = repr(self.sid)
        if len(sid) > 12:
            sid = sid[:11] + "..."
        return "%s:%s > %s:%s" % (self.ipsrc, str(self.sport),
                                  self.ipdst, str(self.dport))

###############################################################################
#   Session singleton                                                         #
###############################################################################


class _GenericTLSSessionInheritance(Packet):
    """
    Many classes inside the TLS module need to get access to session-related
    information. For instance, an encrypted TLS record cannot be parsed without
    some knowledge of the cipher suite being used and the secrets which have
    been negotiated. Passing information is also essential to the handshake.
    To this end, various TLS objects inherit from the present class.
    """
    __slots__ = ["tls_session", "rcs_snap_init", "wcs_snap_init"]
    name = "Dummy Generic TLS Packet"
    fields_desc = []

    def __init__(self, _pkt="", post_transform=None, _internal=0,
                 _underlayer=None, tls_session=None, **fields):
        try:
            setme = self.tls_session is None
        except Exception:
            setme = True

        if setme:
            if tls_session is None:
                self.tls_session = tlsSession()
            else:
                self.tls_session = tls_session

        self.rcs_snap_init = self.tls_session.rcs.snapshot()
        self.wcs_snap_init = self.tls_session.wcs.snapshot()

        Packet.__init__(self, _pkt=_pkt, post_transform=post_transform,
                        _internal=_internal, _underlayer=_underlayer,
                        **fields)

    def __getattr__(self, attr):
        """
        The tls_session should be found only through the normal mechanism.
        """
        if attr == "tls_session":
            return None
        return super(_GenericTLSSessionInheritance, self).__getattr__(attr)

    def tls_session_update(self, msg_str):
        """
        post_{build, dissection}_tls_session_update() are used to update the
        tlsSession context. The default definitions below, along with
        tls_session_update(), may prevent code duplication in some cases.
        """
        pass

    def post_build_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)

    def copy(self):
        pkt = Packet.copy(self)
        pkt.tls_session = self.tls_session
        return pkt

    def clone_with(self, payload=None, **kargs):
        pkt = Packet.clone_with(self, payload=payload, **kargs)
        pkt.tls_session = self.tls_session
        return pkt

    def raw_stateful(self):
        return super(_GenericTLSSessionInheritance, self).__bytes__()

    def str_stateful(self):
        return self.raw_stateful()

    def __bytes__(self):
        """
        The __bytes__ call has to leave the connection states unchanged.
        We also have to delete raw_packet_cache in order to access post_build.

        For performance, the pending connStates are not snapshotted.
        This should not be an issue, but maybe pay attention to this.

        The previous_freeze_state prevents issues with calling a raw() calling
        in turn another raw(), which would unfreeze the session too soon.
        """
        s = self.tls_session
        rcs_snap = s.rcs.snapshot()
        wcs_snap = s.wcs.snapshot()
        rpc_snap = self.raw_packet_cache

        s.wcs = self.rcs_snap_init

        self.raw_packet_cache = None
        previous_freeze_state = s.frozen
        s.frozen = True
        built_packet = super(_GenericTLSSessionInheritance, self).__bytes__()
        s.frozen = previous_freeze_state

        s.rcs = rcs_snap
        s.wcs = wcs_snap
        self.raw_packet_cache = rpc_snap

        return built_packet
    __str__ = __bytes__

    def show2(self):
        """
        Rebuild the TLS packet with the same context, and then .show() it.
        We need self.__class__ to call the subclass in a dynamic way.

        Howether we do not want the tls_session.{r,w}cs.seq_num to be updated.
        We have to bring back the init states (it's possible the cipher context
        has been updated because of parsing) but also to keep the current state
        and restore it afterwards (the raw() call may also update the states).
        """
        s = self.tls_session
        rcs_snap = s.rcs.snapshot()
        wcs_snap = s.wcs.snapshot()

        s.rcs = self.rcs_snap_init

        built_packet = raw(self)
        s.frozen = True
        self.__class__(built_packet, tls_session=s).show()
        s.frozen = False

        s.rcs = rcs_snap
        s.wcs = wcs_snap

    # Uncomment this when the automata update IPs and ports properly
    # def mysummary(self):
    #    return "TLS %s" % repr(self.tls_session)


###############################################################################
#   Multiple TLS sessions                                                     #
###############################################################################

class _tls_sessions(object):
    def __init__(self):
        self.sessions = {}

    def add(self, session):
        s = self.find(session)
        if s:
            log_runtime.info("TLS: previous session shall not be overwritten")
            return

        h = session.hash()
        if h in self.sessions:
            self.sessions[h].append(session)
        else:
            self.sessions[h] = [session]

    def rem(self, session):
        s = self.find(session)
        if s:
            log_runtime.info("TLS: previous session shall not be overwritten")
            return

        h = session.hash()
        self.sessions[h].remove(session)

    def find(self, session):
        h = session.hash()
        if h in self.sessions:
            for k in self.sessions[h]:
                if k.eq(session):
                    if conf.tls_verbose:
                        log_runtime.info("TLS: found session matching %s", k)
                    return k
        if conf.tls_verbose:
            log_runtime.info("TLS: did not find session matching %s", session)
        return None

    def __repr__(self):
        res = [("First endpoint", "Second endpoint", "Session ID")]
        for l in self.sessions.values():
            for s in l:
                src = "%s[%d]" % (s.ipsrc, s.sport)
                dst = "%s[%d]" % (s.ipdst, s.dport)
                sid = repr(s.sid)
                if len(sid) > 12:
                    sid = sid[:11] + "..."
                res.append((src, dst, sid))
        colwidth = (max([len(y) for y in x]) for x in zip(*res))
        fmt = "  ".join(map(lambda x: "%%-%ds" % x, colwidth))
        return "\n".join(map(lambda x: fmt % x, res))


conf.tls_sessions = _tls_sessions()
conf.tls_verbose = False
