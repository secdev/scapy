# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
#               2019 Romain Perez
# This program is published under a GPLv2 license

"""
TLS handshake fields & logic.

This module covers the handshake TLS subprotocol, except for the key exchange
mechanisms which are addressed with keyexchange.py.
"""

from __future__ import absolute_import
import math
import os
import struct

from scapy.error import log_runtime, warning
from scapy.fields import (
    ByteEnumField,
    ByteField,
    Field,
    FieldLenField,
    IntField,
    PacketField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrFixedLenField,
    StrLenField,
    ThreeBytesField,
    UTCTimeField,
)

from scapy.compat import hex_bytes, orb, raw
from scapy.config import conf
from scapy.modules import six
from scapy.packet import Packet, Raw, Padding
from scapy.utils import randstring, repr_hex
from scapy.layers.x509 import OCSP_Response
from scapy.layers.tls.cert import Cert
from scapy.layers.tls.basefields import (_tls_version, _TLSVersionField,
                                         _TLSClientVersionField)
from scapy.layers.tls.extensions import (_ExtensionsLenField, _ExtensionsField,
                                         _cert_status_type,
                                         TLS_Ext_SupportedVersion_CH,
                                         TLS_Ext_SignatureAlgorithms,
                                         TLS_Ext_SupportedVersion_SH,
                                         TLS_Ext_EarlyDataIndication,
                                         _tls_hello_retry_magic)
from scapy.layers.tls.keyexchange import (_TLSSignature, _TLSServerParamsField,
                                          _TLSSignatureField, ServerRSAParams,
                                          SigAndHashAlgsField, _tls_hash_sig,
                                          SigAndHashAlgsLenField)
from scapy.layers.tls.session import (_GenericTLSSessionInheritance,
                                      readConnState, writeConnState)
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_PreSharedKey_CH
from scapy.layers.tls.crypto.compression import (_tls_compression_algs,
                                                 _tls_compression_algs_cls,
                                                 Comp_NULL, _GenericComp,
                                                 _GenericCompMetaclass)
from scapy.layers.tls.crypto.suites import (_tls_cipher_suites,
                                            _tls_cipher_suites_cls,
                                            _GenericCipherSuite,
                                            _GenericCipherSuiteMetaclass)
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF

if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes


###############################################################################
#   Generic TLS Handshake message                                             #
###############################################################################

_tls_handshake_type = {0: "hello_request", 1: "client_hello",
                       2: "server_hello", 3: "hello_verify_request",
                       4: "session_ticket", 6: "hello_retry_request",
                       8: "encrypted_extensions", 11: "certificate",
                       12: "server_key_exchange", 13: "certificate_request",
                       14: "server_hello_done", 15: "certificate_verify",
                       16: "client_key_exchange", 20: "finished",
                       21: "certificate_url", 22: "certificate_status",
                       23: "supplemental_data", 24: "key_update"}


class _TLSHandshake(_GenericTLSSessionInheritance):
    """
    Inherited by other Handshake classes to get post_build().
    Also used as a fallback for unknown TLS Handshake packets.
    """
    name = "TLS Handshake Generic message"
    fields_desc = [ByteEnumField("msgtype", None, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   StrLenField("msg", "",
                               length_from=lambda pkt: pkt.msglen)]

    def post_build(self, p, pay):
        tmp_len = len(p)
        if self.msglen is None:
            l2 = tmp_len - 4
            p = struct.pack("!I", (orb(p[0]) << 24) | l2) + p[4:]
        return p + pay

    def guess_payload_class(self, p):
        return conf.padding_layer

    def tls_session_update(self, msg_str):
        """
        Covers both post_build- and post_dissection- context updates.
        """
        self.tls_session.handshake_messages.append(msg_str)
        self.tls_session.handshake_messages_parsed.append(self)


###############################################################################
#   HelloRequest                                                              #
###############################################################################

class TLSHelloRequest(_TLSHandshake):
    name = "TLS Handshake - Hello Request"
    fields_desc = [ByteEnumField("msgtype", 0, _tls_handshake_type),
                   ThreeBytesField("msglen", None)]

    def tls_session_update(self, msg_str):
        """
        Message should not be added to the list of handshake messages
        that will be hashed in the finished and certificate verify messages.
        """
        return


###############################################################################
#   ClientHello fields                                                        #
###############################################################################

class _GMTUnixTimeField(UTCTimeField):
    """
    "The current time and date in standard UNIX 32-bit format (seconds since
     the midnight starting Jan 1, 1970, GMT, ignoring leap seconds)."
    """

    def i2h(self, pkt, x):
        if x is not None:
            return x
        return 0


class _TLSRandomBytesField(StrFixedLenField):
    def i2repr(self, pkt, x):
        if x is None:
            return repr(x)
        return repr_hex(self.i2h(pkt, x))


class _SessionIDField(StrLenField):
    """
    opaque SessionID<0..32>; section 7.4.1.2 of RFC 4346
    """
    pass


class _CipherSuitesField(StrLenField):
    __slots__ = ["itemfmt", "itemsize", "i2s", "s2i"]
    islist = 1

    def __init__(self, name, default, dico, length_from=None, itemfmt="!H"):
        StrLenField.__init__(self, name, default, length_from=length_from)
        self.itemfmt = itemfmt
        self.itemsize = struct.calcsize(itemfmt)
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        for k in six.iterkeys(dico):
            i2s[k] = dico[k]
            s2i[dico[k]] = k

    def any2i_one(self, pkt, x):
        if (isinstance(x, _GenericCipherSuite) or
                isinstance(x, _GenericCipherSuiteMetaclass)):
            x = x.val
        if isinstance(x, bytes):
            x = self.s2i[x]
        return x

    def i2repr_one(self, pkt, x):
        fmt = "0x%%0%dx" % self.itemsize
        return self.i2s.get(x, fmt % x)

    def any2i(self, pkt, x):
        if x is None:
            return None
        if not isinstance(x, list):
            x = [x]
        return [self.any2i_one(pkt, z) for z in x]

    def i2repr(self, pkt, x):
        if x is None:
            return "None"
        tmp_len = [self.i2repr_one(pkt, z) for z in x]
        if len(tmp_len) == 1:
            tmp_len = tmp_len[0]
        else:
            tmp_len = "[%s]" % ", ".join(tmp_len)
        return tmp_len

    def i2m(self, pkt, val):
        if val is None:
            val = []
        return b"".join(struct.pack(self.itemfmt, x) for x in val)

    def m2i(self, pkt, m):
        res = []
        itemlen = struct.calcsize(self.itemfmt)
        while m:
            res.append(struct.unpack(self.itemfmt, m[:itemlen])[0])
            m = m[itemlen:]
        return res

    def i2len(self, pkt, i):
        if i is None:
            return 0
        return len(i) * self.itemsize


class _CompressionMethodsField(_CipherSuitesField):

    def any2i_one(self, pkt, x):
        if (isinstance(x, _GenericComp) or
                isinstance(x, _GenericCompMetaclass)):
            x = x.val
        if isinstance(x, str):
            x = self.s2i[x]
        return x


###############################################################################
#   ClientHello                                                               #
###############################################################################

class TLSClientHello(_TLSHandshake):
    """
    TLS ClientHello, with abilities to handle extensions.

    The Random structure follows the RFC 5246: while it is 32-byte long,
    many implementations use the first 4 bytes as a gmt_unix_time, and then
    the remaining 28 byts should be completely random. This was designed in
    order to (sort of) mitigate broken RNGs. If you prefer to show the full
    32 random bytes without any GMT time, just comment in/out the lines below.
    """
    name = "TLS Handshake - Client Hello"
    fields_desc = [ByteEnumField("msgtype", 1, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _TLSClientVersionField("version", None, _tls_version),

                   # _TLSRandomBytesField("random_bytes", None, 32),
                   _GMTUnixTimeField("gmt_unix_time", None),
                   _TLSRandomBytesField("random_bytes", None, 28),

                   FieldLenField("sidlen", None, fmt="B", length_of="sid"),
                   _SessionIDField("sid", "",
                                   length_from=lambda pkt: pkt.sidlen),

                   FieldLenField("cipherslen", None, fmt="!H",
                                 length_of="ciphers"),
                   _CipherSuitesField("ciphers", None,
                                      _tls_cipher_suites, itemfmt="!H",
                                      length_from=lambda pkt: pkt.cipherslen),

                   FieldLenField("complen", None, fmt="B", length_of="comp"),
                   _CompressionMethodsField("comp", [0],
                                            _tls_compression_algs,
                                            itemfmt="B",
                                            length_from=lambda pkt: pkt.complen),  # noqa: E501

                   _ExtensionsLenField("extlen", None, length_of="ext"),
                   _ExtensionsField("ext", None,
                                    length_from=lambda pkt: (pkt.msglen -
                                                             (pkt.sidlen or 0) -  # noqa: E501
                                                             (pkt.cipherslen or 0) -  # noqa: E501
                                                             (pkt.complen or 0) -  # noqa: E501
                                                             40))]

    def post_build(self, p, pay):
        if self.random_bytes is None:
            p = p[:10] + randstring(28) + p[10 + 28:]

        # if no ciphersuites were provided, we add a few usual, supported
        # ciphersuites along with the appropriate extensions
        if self.ciphers is None:
            cipherstart = 39 + (self.sidlen or 0)
            s = b"001ac02bc023c02fc027009e0067009c003cc009c0130033002f000a"
            p = p[:cipherstart] + hex_bytes(s) + p[cipherstart + 2:]
            if self.ext is None:
                ext_len = b'\x00\x2c'
                ext_reneg = b'\xff\x01\x00\x01\x00'
                ext_sn = b'\x00\x00\x00\x0f\x00\r\x00\x00\nsecdev.org'
                ext_sigalg = b'\x00\r\x00\x08\x00\x06\x04\x03\x04\x01\x02\x01'
                ext_supgroups = b'\x00\n\x00\x04\x00\x02\x00\x17'
                p += ext_len + ext_reneg + ext_sn + ext_sigalg + ext_supgroups

        return super(TLSClientHello, self).post_build(p, pay)

    def tls_session_update(self, msg_str):
        """
        Either for parsing or building, we store the client_random
        along with the raw string representing this handshake message.
        """
        super(TLSClientHello, self).tls_session_update(msg_str)
        s = self.tls_session
        s.advertised_tls_version = self.version
        # This ClientHello could be a 1.3 one. Let's store the sid
        # in all cases
        if self.sidlen and self.sidlen > 0:
            s.sid = self.sid
        self.random_bytes = msg_str[10:38]
        s.client_random = (struct.pack('!I', self.gmt_unix_time) +
                           self.random_bytes)

        # No distinction between a TLS 1.2 ClientHello and a TLS
        # 1.3 ClientHello when dissecting : TLS 1.3 CH will be
        # parsed as TLSClientHello
        if self.ext:
            for e in self.ext:
                if isinstance(e, TLS_Ext_SupportedVersion_CH):
                    for ver in e.versions:
                        # RFC 8701: GREASE of TLS will send unknown versions
                        # here. We have to ignore them
                        if ver in _tls_version:
                            s.advertised_tls_version = ver
                            break
                    if s.sid:
                        s.middlebox_compatibility = True

                if isinstance(e, TLS_Ext_SignatureAlgorithms):
                    s.advertised_sig_algs = e.sig_algs


class TLS13ClientHello(_TLSHandshake):
    """
    TLS 1.3 ClientHello, with abilities to handle extensions.

    The Random structure is 32 random bytes without any GMT time
    """
    name = "TLS 1.3 Handshake - Client Hello"
    fields_desc = [ByteEnumField("msgtype", 1, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _TLSClientVersionField("version", None, _tls_version),

                   _TLSRandomBytesField("random_bytes", None, 32),

                   FieldLenField("sidlen", None, fmt="B", length_of="sid"),
                   _SessionIDField("sid", "",
                                   length_from=lambda pkt: pkt.sidlen),

                   FieldLenField("cipherslen", None, fmt="!H",
                                 length_of="ciphers"),
                   _CipherSuitesField("ciphers", None,
                                      _tls_cipher_suites, itemfmt="!H",
                                      length_from=lambda pkt: pkt.cipherslen),

                   FieldLenField("complen", None, fmt="B", length_of="comp"),
                   _CompressionMethodsField("comp", [0],
                                            _tls_compression_algs,
                                            itemfmt="B",
                                            length_from=lambda pkt: pkt.complen),  # noqa: E501

                   _ExtensionsLenField("extlen", None, length_of="ext"),
                   _ExtensionsField("ext", None,
                                    length_from=lambda pkt: (pkt.msglen -
                                                             (pkt.sidlen or 0) -  # noqa: E501
                                                             (pkt.cipherslen or 0) -  # noqa: E501
                                                             (pkt.complen or 0) -  # noqa: E501
                                                             40))]

    def post_build(self, p, pay):
        if self.random_bytes is None:
            p = p[:6] + randstring(32) + p[6 + 32:]
        # We don't call the post_build function from class _TLSHandshake
        # to compute the message length because we need that value now
        # for the HMAC in binder
        tmp_len = len(p)
        if self.msglen is None:
            sz = tmp_len - 4
            p = struct.pack("!I", (orb(p[0]) << 24) | sz) + p[4:]
        s = self.tls_session
        if self.ext:
            for e in self.ext:
                if isinstance(e, TLS_Ext_PreSharedKey_CH):
                    if s.client_session_ticket:
                        # For a resumed PSK, the hash function use
                        # to compute the binder must be the same
                        # as the one used to establish the original
                        # conntection. For that, we assume that
                        # the ciphersuite associate with the ticket
                        # is given as argument to tlsSession
                        # (see layers/tls/automaton_cli.py for an
                        # example)
                        res_suite = s.tls13_ticket_ciphersuite
                        cs_cls = _tls_cipher_suites_cls[res_suite]
                        hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
                        hash_len = hkdf.hash.digest_size
                        s.compute_tls13_early_secrets(external=False)
                    else:
                        # For out of band PSK, SHA-256 is used as default
                        # hash functions for HKDF
                        hkdf = TLS13_HKDF("sha256")
                        hash_len = hkdf.hash.digest_size
                        s.compute_tls13_early_secrets(external=True)

                    # RFC8446 4.2.11.2
                    # "Each entry in the binders list is computed as an HMAC
                    # over a transcript hash (see Section 4.4.1) containing a
                    # partial ClientHello up to and including the
                    # PreSharedKeyExtension.identities field."
                    # PSK Binders field is :
                    #   - PSK Binders length (2 bytes)
                    #   - First PSK Binder length (1 byte) +
                    #         HMAC (hash_len bytes)
                    # The PSK Binder is computed in the same way as the
                    # Finished message with binder_key as BaseKey

                    handshake_context = b""
                    if s.tls13_retry:
                        for m in s.handshake_messages:
                            handshake_context += m
                    handshake_context += p[:-hash_len - 3]

                    binder_key = s.tls13_derived_secrets["binder_key"]
                    psk_binder = hkdf.compute_verify_data(binder_key,
                                                          handshake_context)

                    # Here, we replaced the last 32 bytes of the packet by the
                    # new HMAC values computed over the ClientHello (without
                    # the binders)
                    p = p[:-hash_len] + psk_binder

        return p + pay

    def tls_session_update(self, msg_str):
        """
        Either for parsing or building, we store the client_random
        along with the raw string representing this handshake message.
        """
        super(TLS13ClientHello, self).tls_session_update(msg_str)
        s = self.tls_session

        if self.sidlen and self.sidlen > 0:
            s.sid = self.sid
            s.middlebox_compatibility = True

        self.random_bytes = msg_str[10:38]
        s.client_random = self.random_bytes
        if self.ext:
            for e in self.ext:
                if isinstance(e, TLS_Ext_SupportedVersion_CH):
                    for ver in e.versions:
                        # RFC 8701: GREASE of TLS will send unknown versions
                        # here. We have to ignore them
                        if ver in _tls_version:
                            self.tls_session.advertised_tls_version = ver
                            break
                if isinstance(e, TLS_Ext_SignatureAlgorithms):
                    s.advertised_sig_algs = e.sig_algs


###############################################################################
#   ServerHello                                                               #
###############################################################################


class TLSServerHello(_TLSHandshake):
    """
    TLS ServerHello, with abilities to handle extensions.

    The Random structure follows the RFC 5246: while it is 32-byte long,
    many implementations use the first 4 bytes as a gmt_unix_time, and then
    the remaining 28 byts should be completely random. This was designed in
    order to (sort of) mitigate broken RNGs. If you prefer to show the full
    32 random bytes without any GMT time, just comment in/out the lines below.
    """
    name = "TLS Handshake - Server Hello"
    fields_desc = [ByteEnumField("msgtype", 2, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _TLSVersionField("version", None, _tls_version),

                   # _TLSRandomBytesField("random_bytes", None, 32),
                   _GMTUnixTimeField("gmt_unix_time", None),
                   _TLSRandomBytesField("random_bytes", None, 28),

                   FieldLenField("sidlen", None, length_of="sid", fmt="B"),
                   _SessionIDField("sid", "",
                                   length_from=lambda pkt: pkt.sidlen),

                   ShortEnumField("cipher", None, _tls_cipher_suites),
                   _CompressionMethodsField("comp", [0],
                                            _tls_compression_algs,
                                            itemfmt="B",
                                            length_from=lambda pkt: 1),

                   _ExtensionsLenField("extlen", None, length_of="ext"),
                   _ExtensionsField("ext", None,
                                    length_from=lambda pkt: (
                                        pkt.msglen - (pkt.sidlen or 0) - 40
                                    ))]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 6:
            version = struct.unpack("!H", _pkt[4:6])[0]
            if version == 0x0304 or version > 0x7f00:
                return TLS13ServerHello
        return TLSServerHello

    def post_build(self, p, pay):
        if self.random_bytes is None:
            p = p[:10] + randstring(28) + p[10 + 28:]
        return super(TLSServerHello, self).post_build(p, pay)

    def tls_session_update(self, msg_str):
        """
        Either for parsing or building, we store the server_random
        along with the raw string representing this handshake message.
        We also store the session_id, the cipher suite (if recognized),
        the compression method, and finally we instantiate the pending write
        and read connection states. Usually they get updated later on in the
        negotiation when we learn the session keys, and eventually they
        are committed once a ChangeCipherSpec has been sent/received.
        """
        super(TLSServerHello, self).tls_session_update(msg_str)

        self.tls_session.tls_version = self.version
        self.random_bytes = msg_str[10:38]
        self.tls_session.server_random = (struct.pack('!I',
                                                      self.gmt_unix_time) +
                                          self.random_bytes)
        self.tls_session.sid = self.sid

        cs_cls = None
        if self.cipher:
            cs_val = self.cipher
            if cs_val not in _tls_cipher_suites_cls:
                warning("Unknown cipher suite %d from ServerHello" % cs_val)
                # we do not try to set a default nor stop the execution
            else:
                cs_cls = _tls_cipher_suites_cls[cs_val]

        comp_cls = Comp_NULL
        if self.comp:
            comp_val = self.comp[0]
            if comp_val not in _tls_compression_algs_cls:
                err = "Unknown compression alg %d from ServerHello" % comp_val
                warning(err)
                comp_val = 0
            comp_cls = _tls_compression_algs_cls[comp_val]

        connection_end = self.tls_session.connection_end
        self.tls_session.pwcs = writeConnState(ciphersuite=cs_cls,
                                               compression_alg=comp_cls,
                                               connection_end=connection_end,
                                               tls_version=self.version)
        self.tls_session.prcs = readConnState(ciphersuite=cs_cls,
                                              compression_alg=comp_cls,
                                              connection_end=connection_end,
                                              tls_version=self.version)


_tls_13_server_hello_fields = [
    ByteEnumField("msgtype", 2, _tls_handshake_type),
    ThreeBytesField("msglen", None),
    _TLSVersionField("version", 0x0303, _tls_version),
    _TLSRandomBytesField("random_bytes", None, 32),
    FieldLenField("sidlen", None, length_of="sid", fmt="B"),
    _SessionIDField("sid", "",
                    length_from=lambda pkt: pkt.sidlen),
    ShortEnumField("cipher", None, _tls_cipher_suites),
    _CompressionMethodsField("comp", [0],
                             _tls_compression_algs,
                             itemfmt="B",
                             length_from=lambda pkt: 1),
    _ExtensionsLenField("extlen", None, length_of="ext"),
    _ExtensionsField("ext", None,
                     length_from=lambda pkt: (pkt.msglen -
                                              38))
]


class TLS13ServerHello(_TLSHandshake):
    """ TLS 1.3 ServerHello """
    name = "TLS 1.3 Handshake - Server Hello"
    fields_desc = _tls_13_server_hello_fields

    # ServerHello and HelloRetryRequest has the same structure and the same
    # msgId. We need to check the server_random value to determine which it is.
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 38:
            # If SHA-256("HelloRetryRequest") == server_random,
            # this message is a HelloRetryRequest
            random_bytes = _pkt[6:38]
            if random_bytes == _tls_hello_retry_magic:
                return TLS13HelloRetryRequest
        return TLS13ServerHello

    def post_build(self, p, pay):
        if self.random_bytes is None:
            p = p[:6] + randstring(32) + p[6 + 32:]
        return super(TLS13ServerHello, self).post_build(p, pay)

    def tls_session_update(self, msg_str):
        """
        Either for parsing or building, we store the server_random along with
        the raw string representing this handshake message. We also store the
        cipher suite (if recognized), and finally we instantiate the write and
        read connection states.
        """
        super(TLS13ServerHello, self).tls_session_update(msg_str)

        s = self.tls_session
        if self.ext:
            for e in self.ext:
                if isinstance(e, TLS_Ext_SupportedVersion_SH):
                    s.tls_version = e.version
                    break
        s.server_random = self.random_bytes
        s.ciphersuite = self.cipher

        cs_cls = None
        if self.cipher:
            cs_val = self.cipher
            if cs_val not in _tls_cipher_suites_cls:
                warning("Unknown cipher suite %d from ServerHello" % cs_val)
                # we do not try to set a default nor stop the execution
            else:
                cs_cls = _tls_cipher_suites_cls[cs_val]

        connection_end = s.connection_end
        if connection_end == "server":
            s.pwcs = writeConnState(ciphersuite=cs_cls,
                                    connection_end=connection_end,
                                    tls_version=s.tls_version)

            if not s.middlebox_compatibility:
                s.triggered_pwcs_commit = True
        elif connection_end == "client":

            s.prcs = readConnState(ciphersuite=cs_cls,
                                   connection_end=connection_end,
                                   tls_version=s.tls_version)
            if not s.middlebox_compatibility:
                s.triggered_prcs_commit = True

        if s.tls13_early_secret is None:
            # In case the connState was not pre-initialized, we could not
            # compute the early secrets at the ClientHello, so we do it here.
            s.compute_tls13_early_secrets()
        s.compute_tls13_handshake_secrets()
        if connection_end == "server":
            shts = s.tls13_derived_secrets["server_handshake_traffic_secret"]
            s.pwcs.tls13_derive_keys(shts)
        elif connection_end == "client":
            shts = s.tls13_derived_secrets["server_handshake_traffic_secret"]
            s.prcs.tls13_derive_keys(shts)


###############################################################################
#   HelloRetryRequest                                                         #
###############################################################################

class TLS13HelloRetryRequest(_TLSHandshake):
    name = "TLS 1.3 Handshake - Hello Retry Request"

    fields_desc = _tls_13_server_hello_fields

    def build(self):
        fval = self.getfieldval("random_bytes")
        if fval is None:
            self.random_bytes = _tls_hello_retry_magic
        return _TLSHandshake.build(self)

    def tls_session_update(self, msg_str):
        s = self.tls_session
        s.tls13_retry = True
        s.tls13_client_pubshares = {}
        # If the server responds to a ClientHello with a HelloRetryRequest
        # The value of the first ClientHello is replaced by a message_hash
        if s.client_session_ticket:
            cs_cls = _tls_cipher_suites_cls[s.tls13_ticket_ciphersuite]
            hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
            hash_len = hkdf.hash.digest_size
        else:
            cs_cls = _tls_cipher_suites_cls[self.cipher]
            hkdf = TLS13_HKDF(cs_cls.hash_alg.name.lower())
            hash_len = hkdf.hash.digest_size

        handshake_context = struct.pack("B", 254)
        handshake_context += struct.pack("B", 0)
        handshake_context += struct.pack("B", 0)
        handshake_context += struct.pack("B", hash_len)
        digest = hashes.Hash(hkdf.hash, backend=default_backend())
        digest.update(s.handshake_messages[0])
        handshake_context += digest.finalize()
        s.handshake_messages[0] = handshake_context
        super(TLS13HelloRetryRequest, self).tls_session_update(msg_str)


###############################################################################
#   EncryptedExtensions                                                       #
###############################################################################


class TLSEncryptedExtensions(_TLSHandshake):
    name = "TLS 1.3 Handshake - Encrypted Extensions"
    fields_desc = [ByteEnumField("msgtype", 8, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _ExtensionsLenField("extlen", None, length_of="ext"),
                   _ExtensionsField("ext", None,
                                    length_from=lambda pkt: pkt.msglen - 2)]

    def post_build_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)

        s = self.tls_session
        connection_end = s.connection_end

        # Check if the server early_data extension is present in
        # EncryptedExtensions message (if so, early data was accepted by the
        # server)
        early_data_accepted = False
        if self.ext:
            for e in self.ext:
                if isinstance(e, TLS_Ext_EarlyDataIndication):
                    early_data_accepted = True

        # If the serveur did not accept early_data, we change prcs traffic
        # encryption keys. Otherwise, the the keys will be updated after the
        # EndOfEarlyData message
        if connection_end == "server":
            if not early_data_accepted:
                s.prcs = readConnState(ciphersuite=type(s.wcs.ciphersuite),
                                       connection_end=connection_end,
                                       tls_version=s.tls_version)

                chts = s.tls13_derived_secrets["client_handshake_traffic_secret"]  # noqa: E501
                s.prcs.tls13_derive_keys(chts)

                if not s.middlebox_compatibility:
                    s.rcs = self.tls_session.prcs
                    s.triggered_prcs_commit = False
                else:
                    s.triggered_prcs_commit = True

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        s = self.tls_session
        connection_end = s.connection_end

        # Check if the server early_data extension is present in
        # EncryptedExtensions message (if so, early data was accepted by the
        # server)
        early_data_accepted = False
        if self.ext:
            for e in self.ext:
                if isinstance(e, TLS_Ext_EarlyDataIndication):
                    early_data_accepted = True

        # If the serveur did not accept early_data, we change pwcs traffic
        # encryption key. Otherwise, the the keys will be updated after the
        # EndOfEarlyData message
        if connection_end == "client":
            if not early_data_accepted:
                s.pwcs = writeConnState(ciphersuite=type(s.rcs.ciphersuite),
                                        connection_end=connection_end,
                                        tls_version=s.tls_version)
                chts = s.tls13_derived_secrets["client_handshake_traffic_secret"]  # noqa: E501
                s.pwcs.tls13_derive_keys(chts)
                if not s.middlebox_compatibility:
                    s.wcs = self.tls_session.pwcs
                    s.triggered_pwcs_commit = False
                else:
                    s.triggered_prcs_commit = True
###############################################################################
#   Certificate                                                               #
###############################################################################

# XXX It might be appropriate to rewrite this mess with basic 3-byte FieldLenField.  # noqa: E501


class _ASN1CertLenField(FieldLenField):
    """
    This is mostly a 3-byte FieldLenField.
    """
    def __init__(self, name, default, length_of=None, adjust=lambda pkt, x: x):
        self.length_of = length_of
        self.adjust = adjust
        Field.__init__(self, name, default, fmt="!I")

    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
                x = self.adjust(pkt, f)
        return x

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[1:4]

    def getfield(self, pkt, s):
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, b"\x00" + s[:3])[0])  # noqa: E501


class _ASN1CertListField(StrLenField):
    islist = 1

    def i2len(self, pkt, i):
        if i is None:
            return 0
        return len(self.i2m(pkt, i))

    def getfield(self, pkt, s):
        """
        Extract Certs in a loop.
        XXX We should provide safeguards when trying to parse a Cert.
        """
        tmp_len = None
        if self.length_from is not None:
            tmp_len = self.length_from(pkt)

        lst = []
        ret = b""
        m = s
        if tmp_len is not None:
            m, ret = s[:tmp_len], s[tmp_len:]
        while m:
            clen = struct.unpack("!I", b'\x00' + m[:3])[0]
            lst.append((clen, Cert(m[3:3 + clen])))
            m = m[3 + clen:]
        return m + ret, lst

    def i2m(self, pkt, i):
        def i2m_one(i):
            if isinstance(i, str):
                return i
            if isinstance(i, Cert):
                s = i.der
                tmp_len = struct.pack("!I", len(s))[1:4]
                return tmp_len + s

            (tmp_len, s) = i
            if isinstance(s, Cert):
                s = s.der
            return struct.pack("!I", tmp_len)[1:4] + s

        if i is None:
            return b""
        if isinstance(i, str):
            return i
        if isinstance(i, Cert):
            i = [i]
        return b"".join(i2m_one(x) for x in i)

    def any2i(self, pkt, x):
        return x


class _ASN1CertField(StrLenField):
    def i2len(self, pkt, i):
        if i is None:
            return 0
        return len(self.i2m(pkt, i))

    def getfield(self, pkt, s):
        tmp_len = None
        if self.length_from is not None:
            tmp_len = self.length_from(pkt)
        ret = b""
        m = s
        if tmp_len is not None:
            m, ret = s[:tmp_len], s[tmp_len:]
        clen = struct.unpack("!I", b'\x00' + m[:3])[0]
        len_cert = (clen, Cert(m[3:3 + clen]))
        m = m[3 + clen:]
        return m + ret, len_cert

    def i2m(self, pkt, i):
        def i2m_one(i):
            if isinstance(i, str):
                return i
            if isinstance(i, Cert):
                s = i.der
                tmp_len = struct.pack("!I", len(s))[1:4]
                return tmp_len + s

            (tmp_len, s) = i
            if isinstance(s, Cert):
                s = s.der
            return struct.pack("!I", tmp_len)[1:4] + s

        if i is None:
            return b""
        return i2m_one(i)

    def any2i(self, pkt, x):
        return x


class TLSCertificate(_TLSHandshake):
    """
    XXX We do not support RFC 5081, i.e. OpenPGP certificates.
    """
    name = "TLS Handshake - Certificate"
    fields_desc = [ByteEnumField("msgtype", 11, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _ASN1CertLenField("certslen", None, length_of="certs"),
                   _ASN1CertListField("certs", [],
                                      length_from=lambda pkt: pkt.certslen)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            tls_session = kargs.get("tls_session", None)
            if tls_session and (tls_session.tls_version or 0) >= 0x0304:
                return TLS13Certificate
        return TLSCertificate

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        connection_end = self.tls_session.connection_end
        if connection_end == "client":
            self.tls_session.server_certs = [x[1] for x in self.certs]
        else:
            self.tls_session.client_certs = [x[1] for x in self.certs]


class _ASN1CertAndExt(_GenericTLSSessionInheritance):
    name = "Certificate and Extensions"
    fields_desc = [_ASN1CertField("cert", ""),
                   FieldLenField("extlen", None, length_of="ext"),
                   _ExtensionsField("ext", [],
                                    length_from=lambda pkt: pkt.extlen)]

    def extract_padding(self, s):
        return b"", s


class _ASN1CertAndExtListField(PacketListField):
    def m2i(self, pkt, m):
        return self.cls(m, tls_session=pkt.tls_session)


class TLS13Certificate(_TLSHandshake):
    name = "TLS 1.3 Handshake - Certificate"
    fields_desc = [ByteEnumField("msgtype", 11, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   FieldLenField("cert_req_ctxt_len", None, fmt="B",
                                 length_of="cert_req_ctxt"),
                   StrLenField("cert_req_ctxt", "",
                               length_from=lambda pkt: pkt.cert_req_ctxt_len),
                   _ASN1CertLenField("certslen", None, length_of="certs"),
                   _ASN1CertAndExtListField("certs", [], _ASN1CertAndExt,
                                            length_from=lambda pkt: pkt.certslen)]  # noqa: E501

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        connection_end = self.tls_session.connection_end
        if connection_end == "client":
            if self.certs:
                sc = [x.cert[1] for x in self.certs]
                self.tls_session.server_certs = sc
        else:
            if self.certs:
                cc = [x.cert[1] for x in self.certs]
                self.tls_session.client_certs = cc


###############################################################################
#   ServerKeyExchange                                                         #
###############################################################################

class TLSServerKeyExchange(_TLSHandshake):
    name = "TLS Handshake - Server Key Exchange"
    fields_desc = [ByteEnumField("msgtype", 12, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _TLSServerParamsField("params", None,
                                         length_from=lambda pkt: pkt.msglen),
                   _TLSSignatureField("sig", None,
                                      length_from=lambda pkt: pkt.msglen - len(pkt.params))]  # noqa: E501

    def build(self, *args, **kargs):
        r"""
        We overload build() method in order to provide a valid default value
        for params based on TLS session if not provided. This cannot be done by
        overriding i2m() because the method is called on a copy of the packet.

        The 'params' field is built according to key_exchange.server_kx_msg_cls
        which should have been set after receiving a cipher suite in a
        previous ServerHello. Usual cases are:

        - None: for RSA encryption or fixed FF/ECDH. This should never happen,
          as no ServerKeyExchange should be generated in the first place.
        - ServerDHParams: for ephemeral FFDH. In that case, the parameter to
          server_kx_msg_cls does not matter.
        - ServerECDH\*Params: for ephemeral ECDH. There are actually three
          classes, which are dispatched by _tls_server_ecdh_cls_guess on
          the first byte retrieved. The default here is b"\03", which
          corresponds to ServerECDHNamedCurveParams (implicit curves).

        When the Server\*DHParams are built via .fill_missing(), the session
        server_kx_privkey will be updated accordingly.
        """
        fval = self.getfieldval("params")
        if fval is None:
            s = self.tls_session
            if s.pwcs:
                if s.pwcs.key_exchange.export:
                    cls = ServerRSAParams(tls_session=s)
                else:
                    cls = s.pwcs.key_exchange.server_kx_msg_cls(b"\x03")
                    cls = cls(tls_session=s)
                try:
                    cls.fill_missing()
                except Exception:
                    if conf.debug_dissector:
                        raise
            else:
                cls = Raw()
            self.params = cls

        fval = self.getfieldval("sig")
        if fval is None:
            s = self.tls_session
            if s.pwcs and s.client_random:
                if not s.pwcs.key_exchange.anonymous:
                    p = self.params
                    if p is None:
                        p = b""
                    m = s.client_random + s.server_random + raw(p)
                    cls = _TLSSignature(tls_session=s)
                    cls._update_sig(m, s.server_key)
                else:
                    cls = Raw()
            else:
                cls = Raw()
            self.sig = cls

        return _TLSHandshake.build(self, *args, **kargs)

    def post_dissection(self, pkt):
        """
        While previously dissecting Server*DHParams, the session
        server_kx_pubkey should have been updated.

        XXX Add a 'fixed_dh' OR condition to the 'anonymous' test.
        """
        s = self.tls_session
        if s.prcs and s.prcs.key_exchange.no_ske:
            pkt_info = pkt.firstlayer().summary()
            log_runtime.info("TLS: useless ServerKeyExchange [%s]", pkt_info)
        if (s.prcs and
            not s.prcs.key_exchange.anonymous and
            s.client_random and s.server_random and
                s.server_certs and len(s.server_certs) > 0):
            m = s.client_random + s.server_random + raw(self.params)
            sig_test = self.sig._verify_sig(m, s.server_certs[0])
            if not sig_test:
                pkt_info = pkt.firstlayer().summary()
                log_runtime.info("TLS: invalid ServerKeyExchange signature [%s]", pkt_info)  # noqa: E501


###############################################################################
#   CertificateRequest                                                        #
###############################################################################

_tls_client_certificate_types = {1: "rsa_sign",
                                 2: "dss_sign",
                                 3: "rsa_fixed_dh",
                                 4: "dss_fixed_dh",
                                 5: "rsa_ephemeral_dh_RESERVED",
                                 6: "dss_ephemeral_dh_RESERVED",
                                 20: "fortezza_dms_RESERVED",
                                 64: "ecdsa_sign",
                                 65: "rsa_fixed_ecdh",
                                 66: "ecdsa_fixed_ecdh"}


class _CertTypesField(_CipherSuitesField):
    pass


class _CertAuthoritiesField(StrLenField):
    """
    XXX Rework this with proper ASN.1 parsing.
    """
    islist = 1

    def getfield(self, pkt, s):
        tmp_len = self.length_from(pkt)
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])

    def m2i(self, pkt, m):
        res = []
        while len(m) > 1:
            tmp_len = struct.unpack("!H", m[:2])[0]
            if len(m) < tmp_len + 2:
                res.append((tmp_len, m[2:]))
                break
            dn = m[2:2 + tmp_len]
            res.append((tmp_len, dn))
            m = m[2 + tmp_len:]
        return res

    def i2m(self, pkt, i):
        return b"".join(map(lambda x_y: struct.pack("!H", x_y[0]) + x_y[1], i))

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def i2len(self, pkt, val):
        if val is None:
            return 0
        else:
            return len(self.i2m(pkt, val))


class TLSCertificateRequest(_TLSHandshake):
    name = "TLS Handshake - Certificate Request"
    fields_desc = [ByteEnumField("msgtype", 13, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   FieldLenField("ctypeslen", None, fmt="B",
                                 length_of="ctypes"),
                   _CertTypesField("ctypes", [1, 64],
                                   _tls_client_certificate_types,
                                   itemfmt="!B",
                                   length_from=lambda pkt: pkt.ctypeslen),
                   SigAndHashAlgsLenField("sig_algs_len", None,
                                          length_of="sig_algs"),
                   SigAndHashAlgsField("sig_algs", [0x0403, 0x0401, 0x0201],
                                       ShortEnumField("hash_sig", None, _tls_hash_sig),  # noqa: E501
                                       length_from=lambda pkt: pkt.sig_algs_len),  # noqa: E501
                   FieldLenField("certauthlen", None, fmt="!H",
                                 length_of="certauth"),
                   _CertAuthoritiesField("certauth", [],
                                         length_from=lambda pkt: pkt.certauthlen)]  # noqa: E501


class TLS13CertificateRequest(_TLSHandshake):
    name = "TLS 1.3 Handshake - Certificate Request"
    fields_desc = [ByteEnumField("msgtype", 13, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   FieldLenField("cert_req_ctxt_len", None, fmt="B",
                                 length_of="cert_req_ctxt"),
                   StrLenField("cert_req_ctxt", "",
                               length_from=lambda pkt: pkt.cert_req_ctxt_len),
                   _ExtensionsLenField("extlen", None, length_of="ext"),
                   _ExtensionsField("ext", None,
                                    length_from=lambda pkt: pkt.msglen -
                                    pkt.cert_req_ctxt_len - 3)]

###############################################################################
#   ServerHelloDone                                                           #
###############################################################################


class TLSServerHelloDone(_TLSHandshake):
    name = "TLS Handshake - Server Hello Done"
    fields_desc = [ByteEnumField("msgtype", 14, _tls_handshake_type),
                   ThreeBytesField("msglen", None)]


###############################################################################
#   CertificateVerify                                                         #
###############################################################################

class TLSCertificateVerify(_TLSHandshake):
    name = "TLS Handshake - Certificate Verify"
    fields_desc = [ByteEnumField("msgtype", 15, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _TLSSignatureField("sig", None,
                                      length_from=lambda pkt: pkt.msglen)]

    def build(self, *args, **kargs):
        sig = self.getfieldval("sig")
        if sig is None:
            s = self.tls_session
            m = b"".join(s.handshake_messages)
            tls_version = s.tls_version
            if tls_version is None:
                tls_version = s.advertised_tls_version
            if tls_version >= 0x0304:
                if s.connection_end == "client":
                    context_string = b"TLS 1.3, client CertificateVerify"
                elif s.connection_end == "server":
                    context_string = b"TLS 1.3, server CertificateVerify"
                m = b"\x20" * 64 + context_string + b"\x00" + s.wcs.hash.digest(m)  # noqa: E501
            self.sig = _TLSSignature(tls_session=s)
            if s.connection_end == "client":
                self.sig._update_sig(m, s.client_key)
            elif s.connection_end == "server":
                # should be TLS 1.3 only
                self.sig._update_sig(m, s.server_key)
        return _TLSHandshake.build(self, *args, **kargs)

    def post_dissection(self, pkt):
        s = self.tls_session
        m = b"".join(s.handshake_messages)
        tls_version = s.tls_version
        if tls_version is None:
            tls_version = s.advertised_tls_version
        if tls_version >= 0x0304:
            if s.connection_end == "client":
                context_string = b"TLS 1.3, server CertificateVerify"
            elif s.connection_end == "server":
                context_string = b"TLS 1.3, client CertificateVerify"
            m = b"\x20" * 64 + context_string + b"\x00" + s.rcs.hash.digest(m)

        if s.connection_end == "server":
            if s.client_certs and len(s.client_certs) > 0:
                sig_test = self.sig._verify_sig(m, s.client_certs[0])
                if not sig_test:
                    pkt_info = pkt.firstlayer().summary()
                    log_runtime.info("TLS: invalid CertificateVerify signature [%s]", pkt_info)  # noqa: E501
        elif s.connection_end == "client":
            # should be TLS 1.3 only
            if s.server_certs and len(s.server_certs) > 0:
                sig_test = self.sig._verify_sig(m, s.server_certs[0])
                if not sig_test:
                    pkt_info = pkt.firstlayer().summary()
                    log_runtime.info("TLS: invalid CertificateVerify signature [%s]", pkt_info)  # noqa: E501


###############################################################################
#   ClientKeyExchange                                                         #
###############################################################################

class _TLSCKExchKeysField(PacketField):
    __slots__ = ["length_from"]
    holds_packet = 1

    def __init__(self, name, length_from=None, remain=0):
        self.length_from = length_from
        PacketField.__init__(self, name, None, None, remain=remain)

    def m2i(self, pkt, m):
        """
        The client_kx_msg may be either None, EncryptedPreMasterSecret
        (for RSA encryption key exchange), ClientDiffieHellmanPublic,
        or ClientECDiffieHellmanPublic. When either one of them gets
        dissected, the session context is updated accordingly.
        """
        tmp_len = self.length_from(pkt)
        tbd, rem = m[:tmp_len], m[tmp_len:]

        s = pkt.tls_session
        cls = None

        if s.prcs and s.prcs.key_exchange:
            cls = s.prcs.key_exchange.client_kx_msg_cls

        if cls is None:
            return Raw(tbd) / Padding(rem)

        return cls(tbd, tls_session=s) / Padding(rem)


class TLSClientKeyExchange(_TLSHandshake):
    """
    This class mostly works like TLSServerKeyExchange and its 'params' field.
    """
    name = "TLS Handshake - Client Key Exchange"
    fields_desc = [ByteEnumField("msgtype", 16, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _TLSCKExchKeysField("exchkeys",
                                       length_from=lambda pkt: pkt.msglen)]

    def build(self, *args, **kargs):
        fval = self.getfieldval("exchkeys")
        if fval is None:
            s = self.tls_session
            if s.prcs:
                cls = s.prcs.key_exchange.client_kx_msg_cls
                cls = cls(tls_session=s)
            else:
                cls = Raw()
            self.exchkeys = cls
        return _TLSHandshake.build(self, *args, **kargs)


###############################################################################
#   Finished                                                                  #
###############################################################################

class _VerifyDataField(StrLenField):
    def getfield(self, pkt, s):
        if pkt.tls_session.tls_version == 0x0300:
            sep = 36
        elif pkt.tls_session.tls_version >= 0x0304:
            sep = pkt.tls_session.rcs.hash.hash_len
        else:
            sep = 12
        return s[sep:], s[:sep]


class TLSFinished(_TLSHandshake):
    name = "TLS Handshake - Finished"
    fields_desc = [ByteEnumField("msgtype", 20, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   _VerifyDataField("vdata", None)]

    def build(self, *args, **kargs):
        fval = self.getfieldval("vdata")
        if fval is None:
            s = self.tls_session
            handshake_msg = b"".join(s.handshake_messages)
            con_end = s.connection_end
            tls_version = s.tls_version
            if tls_version is None:
                tls_version = s.advertised_tls_version
            if tls_version < 0x0304:
                ms = s.master_secret
                self.vdata = s.wcs.prf.compute_verify_data(con_end, "write",
                                                           handshake_msg, ms)
            else:
                self.vdata = s.compute_tls13_verify_data(con_end, "write")
        return _TLSHandshake.build(self, *args, **kargs)

    def post_dissection(self, pkt):
        s = self.tls_session
        if not s.frozen:
            handshake_msg = b"".join(s.handshake_messages)
            tls_version = s.tls_version
            if tls_version is None:
                tls_version = s.advertised_tls_version
            if tls_version < 0x0304 and s.master_secret is not None:
                ms = s.master_secret
                con_end = s.connection_end
                verify_data = s.rcs.prf.compute_verify_data(con_end, "read",
                                                            handshake_msg, ms)
                if self.vdata != verify_data:
                    pkt_info = pkt.firstlayer().summary()
                    log_runtime.info("TLS: invalid Finished received [%s]", pkt_info)  # noqa: E501
            elif tls_version >= 0x0304:
                con_end = s.connection_end
                verify_data = s.compute_tls13_verify_data(con_end, "read")
                if self.vdata != verify_data:
                    pkt_info = pkt.firstlayer().summary()
                    log_runtime.info("TLS: invalid Finished received [%s]", pkt_info)  # noqa: E501

    def post_build_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        s = self.tls_session
        tls_version = s.tls_version
        if tls_version is None:
            tls_version = s.advertised_tls_version
        if tls_version >= 0x0304:
            s.pwcs = writeConnState(ciphersuite=type(s.wcs.ciphersuite),
                                    connection_end=s.connection_end,
                                    tls_version=s.tls_version)
            s.triggered_pwcs_commit = True
            if s.connection_end == "server":
                s.compute_tls13_traffic_secrets()
            elif s.connection_end == "client":
                s.compute_tls13_traffic_secrets_end()
                s.compute_tls13_resumption_secret()

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        s = self.tls_session
        tls_version = s.tls_version
        if tls_version is None:
            tls_version = s.advertised_tls_version
        if tls_version >= 0x0304:
            s.prcs = readConnState(ciphersuite=type(s.rcs.ciphersuite),
                                   connection_end=s.connection_end,
                                   tls_version=s.tls_version)
            s.triggered_prcs_commit = True
            if s.connection_end == "client":
                s.compute_tls13_traffic_secrets()
            elif s.connection_end == "server":
                s.compute_tls13_traffic_secrets_end()
                s.compute_tls13_resumption_secret()


# Additional handshake messages

###############################################################################
#   HelloVerifyRequest                                                        #
###############################################################################

class TLSHelloVerifyRequest(_TLSHandshake):
    """
    Defined for DTLS, see RFC 6347.
    """
    name = "TLS Handshake - Hello Verify Request"
    fields_desc = [ByteEnumField("msgtype", 21, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   FieldLenField("cookielen", None,
                                 fmt="B", length_of="cookie"),
                   StrLenField("cookie", "",
                               length_from=lambda pkt: pkt.cookielen)]


###############################################################################
#   CertificateURL                                                            #
###############################################################################

_tls_cert_chain_types = {0: "individual_certs",
                         1: "pkipath"}


class URLAndOptionalHash(Packet):
    name = "URLAndOptionHash structure for TLSCertificateURL"
    fields_desc = [FieldLenField("urllen", None, length_of="url"),
                   StrLenField("url", "",
                               length_from=lambda pkt: pkt.urllen),
                   FieldLenField("hash_present", None,
                                 fmt="B", length_of="hash",
                                 adjust=lambda pkt, x: int(math.ceil(x / 20.))),  # noqa: E501
                   StrLenField("hash", "",
                               length_from=lambda pkt: 20 * pkt.hash_present)]

    def guess_payload_class(self, p):
        return Padding


class TLSCertificateURL(_TLSHandshake):
    """
    Defined in RFC 4366. PkiPath structure of section 8 is not implemented yet.
    """
    name = "TLS Handshake - Certificate URL"
    fields_desc = [ByteEnumField("msgtype", 21, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   ByteEnumField("certchaintype", None, _tls_cert_chain_types),
                   FieldLenField("uahlen", None, length_of="uah"),
                   PacketListField("uah", [], URLAndOptionalHash,
                                   length_from=lambda pkt: pkt.uahlen)]


###############################################################################
#   CertificateStatus                                                         #
###############################################################################

class ThreeBytesLenField(FieldLenField):
    def __init__(self, name, default, length_of=None, adjust=lambda pkt, x: x):
        FieldLenField.__init__(self, name, default, length_of=length_of,
                               fmt='!I', adjust=adjust)

    def i2repr(self, pkt, x):
        if x is None:
            return 0
        return repr(self.i2h(pkt, x))

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[1:4]

    def getfield(self, pkt, s):
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, b"\x00" + s[:3])[0])  # noqa: E501


_cert_status_cls = {1: OCSP_Response}


class _StatusField(PacketField):
    def m2i(self, pkt, m):
        idtype = pkt.status_type
        cls = self.cls
        if idtype in _cert_status_cls:
            cls = _cert_status_cls[idtype]
        return cls(m)


class TLSCertificateStatus(_TLSHandshake):
    name = "TLS Handshake - Certificate Status"
    fields_desc = [ByteEnumField("msgtype", 22, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   ByteEnumField("status_type", 1, _cert_status_type),
                   ThreeBytesLenField("responselen", None,
                                      length_of="response"),
                   _StatusField("response", None, Raw)]


###############################################################################
#   SupplementalData                                                          #
###############################################################################

class SupDataEntry(Packet):
    name = "Supplemental Data Entry - Generic"
    fields_desc = [ShortField("sdtype", None),
                   FieldLenField("len", None, length_of="data"),
                   StrLenField("data", "",
                               length_from=lambda pkt:pkt.len)]

    def guess_payload_class(self, p):
        return Padding


class UserMappingData(Packet):
    name = "User Mapping Data"
    fields_desc = [ByteField("version", None),
                   FieldLenField("len", None, length_of="data"),
                   StrLenField("data", "",
                               length_from=lambda pkt: pkt.len)]

    def guess_payload_class(self, p):
        return Padding


class SupDataEntryUM(Packet):
    name = "Supplemental Data Entry - User Mapping"
    fields_desc = [ShortField("sdtype", None),
                   FieldLenField("len", None, length_of="data",
                                 adjust=lambda pkt, x: x + 2),
                   FieldLenField("dlen", None, length_of="data"),
                   PacketListField("data", [], UserMappingData,
                                   length_from=lambda pkt:pkt.dlen)]

    def guess_payload_class(self, p):
        return Padding


class TLSSupplementalData(_TLSHandshake):
    name = "TLS Handshake - Supplemental Data"
    fields_desc = [ByteEnumField("msgtype", 23, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   ThreeBytesLenField("sdatalen", None, length_of="sdata"),
                   PacketListField("sdata", [], SupDataEntry,
                                   length_from=lambda pkt: pkt.sdatalen)]


###############################################################################
#   NewSessionTicket                                                          #
###############################################################################

class TLSNewSessionTicket(_TLSHandshake):
    """
    XXX When knowing the right secret, we should be able to read the ticket.
    """
    name = "TLS Handshake - New Session Ticket"
    fields_desc = [ByteEnumField("msgtype", 4, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   IntField("lifetime", 0xffffffff),
                   FieldLenField("ticketlen", None, length_of="ticket"),
                   StrLenField("ticket", "",
                               length_from=lambda pkt: pkt.ticketlen)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        s = kargs.get("tls_session", None)
        if s and s.tls_version and s.tls_version >= 0x0304:
            return TLS13NewSessionTicket
        return TLSNewSessionTicket

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        if self.tls_session.connection_end == "client":
            self.tls_session.client_session_ticket = self.ticket


class TLS13NewSessionTicket(_TLSHandshake):
    """
    Uncomment the TicketField line for parsing a RFC 5077 ticket.
    """
    name = "TLS 1.3 Handshake - New Session Ticket"
    fields_desc = [ByteEnumField("msgtype", 4, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   IntField("ticket_lifetime", 0xffffffff),
                   IntField("ticket_age_add", 0),
                   FieldLenField("noncelen", None, fmt="B",
                                 length_of="ticket_nonce"),
                   StrLenField("ticket_nonce", "",
                               length_from=lambda pkt: pkt.noncelen),
                   FieldLenField("ticketlen", None, length_of="ticket"),
                   # TicketField("ticket", "",
                   StrLenField("ticket", "",
                               length_from=lambda pkt: pkt.ticketlen),
                   _ExtensionsLenField("extlen", None, length_of="ext"),
                   _ExtensionsField("ext", None,
                                    length_from=lambda pkt: (pkt.msglen -
                                                             (pkt.ticketlen or 0) -  # noqa: E501
                                                             pkt.noncelen or 0) - 13)]  # noqa: E501

    def build(self):
        fval = self.getfieldval("ticket")
        if fval == b"":
            # Here, the ticket is just a random 48-byte label
            # The ticket may also be a self-encrypted and self-authenticated
            # value
            self.ticket = os.urandom(48)

        fval = self.getfieldval("ticket_nonce")
        if fval == b"":
            # Nonce is randomly chosen
            self.ticket_nonce = os.urandom(32)

        fval = self.getfieldval("ticket_lifetime")
        if fval == 0xffffffff:
            # ticket_lifetime is set to 12 hours
            self.ticket_lifetime = 43200

        fval = self.getfieldval("ticket_age_add")
        if fval == 0:
            # ticket_age_add is a random 32-bit value
            self.ticket_age_add = struct.unpack("!I", os.urandom(4))[0]

        return _TLSHandshake.build(self)

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        if self.tls_session.connection_end == "client":
            self.tls_session.client_session_ticket = self.ticket


###############################################################################
#   EndOfEarlyData                                                            #
###############################################################################

class TLS13EndOfEarlyData(_TLSHandshake):
    name = "TLS 1.3 Handshake - End Of Early Data"

    fields_desc = [ByteEnumField("msgtype", 5, _tls_handshake_type),
                   ThreeBytesField("msglen", None)]


###############################################################################
#   KeyUpdate                                                                 #
###############################################################################
_key_update_request = {0: "update_not_requested", 1: "update_requested"}


class TLS13KeyUpdate(_TLSHandshake):
    name = "TLS 1.3 Handshake - Key Update"
    fields_desc = [ByteEnumField("msgtype", 24, _tls_handshake_type),
                   ThreeBytesField("msglen", None),
                   ByteEnumField("request_update", 0, _key_update_request)]

    def post_build_tls_session_update(self, msg_str):
        s = self.tls_session
        s.pwcs = writeConnState(ciphersuite=type(s.wcs.ciphersuite),
                                connection_end=s.connection_end,
                                tls_version=s.tls_version)
        s.triggered_pwcs_commit = True
        s.compute_tls13_next_traffic_secrets(s.connection_end, "write")

    def post_dissection_tls_session_update(self, msg_str):
        s = self.tls_session
        s.prcs = writeConnState(ciphersuite=type(s.rcs.ciphersuite),
                                connection_end=s.connection_end,
                                tls_version=s.tls_version)
        s.triggered_prcs_commit = True
        if s.connection_end == "server":
            s.compute_tls13_next_traffic_secrets("client", "read")
        elif s.connection_end == "client":
            s.compute_tls13_next_traffic_secrets("server", "read")


###############################################################################
#   All handshake messages defined in this module                             #
###############################################################################

_tls_handshake_cls = {0: TLSHelloRequest, 1: TLSClientHello,
                      2: TLSServerHello, 3: TLSHelloVerifyRequest,
                      4: TLSNewSessionTicket,
                      8: TLSEncryptedExtensions, 11: TLSCertificate,
                      12: TLSServerKeyExchange, 13: TLSCertificateRequest,
                      14: TLSServerHelloDone, 15: TLSCertificateVerify,
                      16: TLSClientKeyExchange, 20: TLSFinished,
                      21: TLSCertificateURL, 22: TLSCertificateStatus,
                      23: TLSSupplementalData}

_tls13_handshake_cls = {1: TLS13ClientHello, 2: TLS13ServerHello,
                        4: TLS13NewSessionTicket, 5: TLS13EndOfEarlyData,
                        8: TLSEncryptedExtensions, 11: TLS13Certificate,
                        13: TLS13CertificateRequest, 15: TLSCertificateVerify,
                        20: TLSFinished, 24: TLS13KeyUpdate}
