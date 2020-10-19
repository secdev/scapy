# This file is part of Scapy
# Copyright (C) 2017 Maxence Tury
# This program is published under a GPLv2 license

"""
SSLv2 handshake fields & logic.
"""

import struct

from scapy.error import log_runtime, warning
from scapy.utils import randstring
from scapy.fields import ByteEnumField, ByteField, EnumField, FieldLenField, \
    ShortEnumField, StrLenField, XStrField, XStrLenField

from scapy.packet import Padding
from scapy.layers.tls.cert import Cert
from scapy.layers.tls.basefields import _tls_version, _TLSVersionField
from scapy.layers.tls.handshake import _CipherSuitesField
from scapy.layers.tls.keyexchange import _TLSSignatureField, _TLSSignature
from scapy.layers.tls.session import (_GenericTLSSessionInheritance,
                                      readConnState, writeConnState)
from scapy.layers.tls.crypto.suites import (_tls_cipher_suites,
                                            _tls_cipher_suites_cls,
                                            get_usable_ciphersuites,
                                            SSL_CK_DES_192_EDE3_CBC_WITH_MD5)


###############################################################################
#   Generic SSLv2 Handshake message                                           #
###############################################################################

_sslv2_handshake_type = {0: "error", 1: "client_hello",
                         2: "client_master_key", 3: "client_finished",
                         4: "server_hello", 5: "server_verify",
                         6: "server_finished", 7: "request_certificate",
                         8: "client_certificate"}


class _SSLv2Handshake(_GenericTLSSessionInheritance):
    """
    Inherited by other Handshake classes to get post_build().
    Also used as a fallback for unknown TLS Handshake packets.
    """
    name = "SSLv2 Handshake Generic message"
    fields_desc = [ByteEnumField("msgtype", None, _sslv2_handshake_type)]

    def guess_payload_class(self, p):
        return Padding

    def tls_session_update(self, msg_str):
        """
        Covers both post_build- and post_dissection- context updates.
        """
        self.tls_session.handshake_messages.append(msg_str)
        self.tls_session.handshake_messages_parsed.append(self)


###############################################################################
#   Error                                                                     #
###############################################################################

_tls_error_code = {1: "no_cipher", 2: "no_certificate",
                   4: "bad_certificate", 6: "unsupported_certificate_type"}


class SSLv2Error(_SSLv2Handshake):
    """
    SSLv2 Error.
    """
    name = "SSLv2 Handshake - Error"
    fields_desc = [ByteEnumField("msgtype", 0, _sslv2_handshake_type),
                   ShortEnumField("code", None, _tls_error_code)]


###############################################################################
#   ClientHello                                                               #
###############################################################################

class _SSLv2CipherSuitesField(_CipherSuitesField):
    def __init__(self, name, default, dico, length_from=None):
        _CipherSuitesField.__init__(self, name, default, dico,
                                    length_from=length_from)
        self.itemfmt = b""
        self.itemsize = 3

    def i2m(self, pkt, val):
        if val is None:
            val2 = []
        val2 = [(x >> 16, x & 0x00ffff) for x in val]
        return b"".join([struct.pack(">BH", x[0], x[1]) for x in val2])

    def m2i(self, pkt, m):
        res = []
        while m:
            res.append(struct.unpack("!I", b"\x00" + m[:3])[0])
            m = m[3:]
        return res


class SSLv2ClientHello(_SSLv2Handshake):
    """
    SSLv2 ClientHello.
    """
    name = "SSLv2 Handshake - Client Hello"
    fields_desc = [ByteEnumField("msgtype", 1, _sslv2_handshake_type),
                   _TLSVersionField("version", 0x0002, _tls_version),

                   FieldLenField("cipherslen", None, fmt="!H",
                                 length_of="ciphers"),
                   FieldLenField("sidlen", None, fmt="!H",
                                 length_of="sid"),
                   FieldLenField("challengelen", None, fmt="!H",
                                 length_of="challenge"),

                   XStrLenField("sid", b"",
                                length_from=lambda pkt:pkt.sidlen),
                   _SSLv2CipherSuitesField("ciphers",
                                           [SSL_CK_DES_192_EDE3_CBC_WITH_MD5],
                                           _tls_cipher_suites,
                                           length_from=lambda pkt: pkt.cipherslen),  # noqa: E501
                   XStrLenField("challenge", b"",
                                length_from=lambda pkt:pkt.challengelen)]

    def tls_session_update(self, msg_str):
        super(SSLv2ClientHello, self).tls_session_update(msg_str)
        self.tls_session.advertised_tls_version = self.version
        self.tls_session.sslv2_common_cs = self.ciphers
        self.tls_session.sslv2_challenge = self.challenge


###############################################################################
#   ServerHello                                                               #
###############################################################################

class _SSLv2CertDataField(StrLenField):
    def getfield(self, pkt, s):
        tmp_len = 0
        if self.length_from is not None:
            tmp_len = self.length_from(pkt)
        try:
            certdata = Cert(s[:tmp_len])
        except Exception:
            # Packets are sometimes wrongly interpreted as SSLv2
            # (see record.py). We ignore failures silently
            certdata = s[:tmp_len]
        return s[tmp_len:], certdata

    def i2len(self, pkt, i):
        if isinstance(i, Cert):
            return len(i.der)
        return len(i)

    def i2m(self, pkt, i):
        if isinstance(i, Cert):
            return i.der
        return i


class SSLv2ServerHello(_SSLv2Handshake):
    """
    SSLv2 ServerHello.
    """
    name = "SSLv2 Handshake - Server Hello"
    fields_desc = [ByteEnumField("msgtype", 4, _sslv2_handshake_type),

                   ByteField("sid_hit", 0),
                   ByteEnumField("certtype", 1, {1: "x509_cert"}),
                   _TLSVersionField("version", 0x0002, _tls_version),

                   FieldLenField("certlen", None, fmt="!H",
                                 length_of="cert"),
                   FieldLenField("cipherslen", None, fmt="!H",
                                 length_of="ciphers"),
                   FieldLenField("connection_idlen", None, fmt="!H",
                                 length_of="connection_id"),

                   _SSLv2CertDataField("cert", b"",
                                       length_from=lambda pkt: pkt.certlen),
                   _SSLv2CipherSuitesField("ciphers", [], _tls_cipher_suites,
                                           length_from=lambda pkt: pkt.cipherslen),  # noqa: E501
                   XStrLenField("connection_id", b"",
                                length_from=lambda pkt: pkt.connection_idlen)]

    def tls_session_update(self, msg_str):
        """
        XXX Something should be done about the session ID here.
        """
        super(SSLv2ServerHello, self).tls_session_update(msg_str)

        s = self.tls_session
        client_cs = s.sslv2_common_cs
        css = [cs for cs in client_cs if cs in self.ciphers]
        s.sslv2_common_cs = css
        s.sslv2_connection_id = self.connection_id
        s.tls_version = self.version
        if self.cert is not None:
            s.server_certs = [self.cert]


###############################################################################
#   ClientMasterKey                                                           #
###############################################################################

class _SSLv2CipherSuiteField(EnumField):
    def __init__(self, name, default, dico):
        EnumField.__init__(self, name, default, dico)

    def i2m(self, pkt, val):
        if val is None:
            return b""
        val2 = (val >> 16, val & 0x00ffff)
        return struct.pack(">BH", val2[0], val2[1])

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def m2i(self, pkt, m):
        return struct.unpack("!I", b"\x00" + m[:3])[0]

    def getfield(self, pkt, s):
        return s[3:], self.m2i(pkt, s)


class _SSLv2EncryptedKeyField(XStrLenField):
    def i2repr(self, pkt, x):
        s = super(_SSLv2EncryptedKeyField, self).i2repr(pkt, x)
        if pkt.decryptedkey is not None:
            dx = pkt.decryptedkey
            ds = super(_SSLv2EncryptedKeyField, self).i2repr(pkt, dx)
            s += "    [decryptedkey= %s]" % ds
        return s


class SSLv2ClientMasterKey(_SSLv2Handshake):
    """
    SSLv2 ClientMasterKey.
    """
    __slots__ = ["decryptedkey"]
    name = "SSLv2 Handshake - Client Master Key"
    fields_desc = [ByteEnumField("msgtype", 2, _sslv2_handshake_type),
                   _SSLv2CipherSuiteField("cipher", None, _tls_cipher_suites),

                   FieldLenField("clearkeylen", None, fmt="!H",
                                 length_of="clearkey"),
                   FieldLenField("encryptedkeylen", None, fmt="!H",
                                 length_of="encryptedkey"),
                   FieldLenField("keyarglen", None, fmt="!H",
                                 length_of="keyarg"),

                   XStrLenField("clearkey", "",
                                length_from=lambda pkt: pkt.clearkeylen),
                   _SSLv2EncryptedKeyField("encryptedkey", "",
                                           length_from=lambda pkt: pkt.encryptedkeylen),  # noqa: E501
                   XStrLenField("keyarg", "",
                                length_from=lambda pkt: pkt.keyarglen)]

    def __init__(self, *args, **kargs):
        """
        When post_building, the packets fields are updated (this is somewhat
        non-standard). We might need these fields later, but calling __str__
        on a new packet (i.e. not dissected from a raw string) applies
        post_build to an object different from the original one... unless
        we hackishly always set self.explicit to 1.
        """
        self.decryptedkey = kargs.pop("decryptedkey", b"")
        super(SSLv2ClientMasterKey, self).__init__(*args, **kargs)
        self.explicit = 1

    def pre_dissect(self, s):
        clearkeylen = struct.unpack("!H", s[4:6])[0]
        encryptedkeylen = struct.unpack("!H", s[6:8])[0]
        encryptedkeystart = 10 + clearkeylen
        encryptedkey = s[encryptedkeystart:encryptedkeystart + encryptedkeylen]
        if self.tls_session.server_rsa_key:
            self.decryptedkey = \
                self.tls_session.server_rsa_key.decrypt(encryptedkey)
        else:
            self.decryptedkey = None
        return s

    def post_build(self, pkt, pay):
        cs_val = None
        if self.cipher is None:
            common_cs = self.tls_session.sslv2_common_cs
            cs_vals = get_usable_ciphersuites(common_cs, "SSLv2")
            if len(cs_vals) == 0:
                warning("No known common cipher suite between SSLv2 Hellos.")
                cs_val = 0x0700c0
                cipher = b"\x07\x00\xc0"
            else:
                cs_val = cs_vals[0]  # XXX choose the best one
                cipher = struct.pack(">BH", cs_val >> 16, cs_val & 0x00ffff)
            cs_cls = _tls_cipher_suites_cls[cs_val]
            self.cipher = cs_val
        else:
            cipher = pkt[1:4]
            cs_val = struct.unpack("!I", b"\x00" + cipher)[0]
            if cs_val not in _tls_cipher_suites_cls:
                warning("Unknown cipher suite %d from ClientMasterKey", cs_val)
                cs_cls = None
            else:
                cs_cls = _tls_cipher_suites_cls[cs_val]

        if cs_cls:
            if (self.encryptedkey == b"" and
                    len(self.tls_session.server_certs) > 0):
                # else, the user is responsible for export slicing & encryption
                key = randstring(cs_cls.cipher_alg.key_len)

                if self.clearkey == b"" and cs_cls.kx_alg.export:
                    self.clearkey = key[:-5]

                if self.decryptedkey == b"":
                    if cs_cls.kx_alg.export:
                        self.decryptedkey = key[-5:]
                    else:
                        self.decryptedkey = key

                pubkey = self.tls_session.server_certs[0].pubKey
                self.encryptedkey = pubkey.encrypt(self.decryptedkey)

            if self.keyarg == b"" and cs_cls.cipher_alg.type == "block":
                self.keyarg = randstring(cs_cls.cipher_alg.block_size)

        clearkey = self.clearkey or b""
        if self.clearkeylen is None:
            self.clearkeylen = len(clearkey)
        clearkeylen = struct.pack("!H", self.clearkeylen)

        encryptedkey = self.encryptedkey or b""
        if self.encryptedkeylen is None:
            self.encryptedkeylen = len(encryptedkey)
        encryptedkeylen = struct.pack("!H", self.encryptedkeylen)

        keyarg = self.keyarg or b""
        if self.keyarglen is None:
            self.keyarglen = len(keyarg)
        keyarglen = struct.pack("!H", self.keyarglen)

        s = (pkt[:1] + cipher +
             clearkeylen + encryptedkeylen + keyarglen +
             clearkey + encryptedkey + keyarg)
        return s + pay

    def tls_session_update(self, msg_str):
        super(SSLv2ClientMasterKey, self).tls_session_update(msg_str)

        s = self.tls_session
        cs_val = self.cipher
        if cs_val not in _tls_cipher_suites_cls:
            warning("Unknown cipher suite %d from ClientMasterKey", cs_val)
            cs_cls = None
        else:
            cs_cls = _tls_cipher_suites_cls[cs_val]

        tls_version = s.tls_version or 0x0002
        connection_end = s.connection_end
        wcs_seq_num = s.wcs.seq_num
        s.pwcs = writeConnState(ciphersuite=cs_cls,
                                connection_end=connection_end,
                                seq_num=wcs_seq_num,
                                tls_version=tls_version)
        rcs_seq_num = s.rcs.seq_num
        s.prcs = readConnState(ciphersuite=cs_cls,
                               connection_end=connection_end,
                               seq_num=rcs_seq_num,
                               tls_version=tls_version)

        if self.decryptedkey is not None:
            s.master_secret = self.clearkey + self.decryptedkey
            s.compute_sslv2_km_and_derive_keys()

            if s.pwcs.cipher.type == "block":
                s.pwcs.cipher.iv = self.keyarg
            if s.prcs.cipher.type == "block":
                s.prcs.cipher.iv = self.keyarg

            s.triggered_prcs_commit = True
            s.triggered_pwcs_commit = True


###############################################################################
#   ServerVerify                                                              #
###############################################################################

class SSLv2ServerVerify(_SSLv2Handshake):
    """
    In order to parse a ServerVerify, the exact message string should be
    fed to the class. This is how SSLv2 defines the challenge length...
    """
    name = "SSLv2 Handshake - Server Verify"
    fields_desc = [ByteEnumField("msgtype", 5, _sslv2_handshake_type),
                   XStrField("challenge", "")]

    def build(self, *args, **kargs):
        fval = self.getfieldval("challenge")
        if fval is None:
            self.challenge = self.tls_session.sslv2_challenge
        return super(SSLv2ServerVerify, self).build(*args, **kargs)

    def post_dissection(self, pkt):
        s = self.tls_session
        if s.sslv2_challenge is not None:
            if self.challenge != s.sslv2_challenge:
                pkt_info = pkt.firstlayer().summary()
                log_runtime.info("TLS: invalid ServerVerify received [%s]", pkt_info)  # noqa: E501


###############################################################################
#   RequestCertificate                                                        #
###############################################################################

class SSLv2RequestCertificate(_SSLv2Handshake):
    """
    In order to parse a RequestCertificate, the exact message string should be
    fed to the class. This is how SSLv2 defines the challenge length...
    """
    name = "SSLv2 Handshake - Request Certificate"
    fields_desc = [ByteEnumField("msgtype", 7, _sslv2_handshake_type),
                   ByteEnumField("authtype", 1, {1: "md5_with_rsa"}),
                   XStrField("challenge", "")]

    def tls_session_update(self, msg_str):
        super(SSLv2RequestCertificate, self).tls_session_update(msg_str)
        self.tls_session.sslv2_challenge_clientcert = self.challenge


###############################################################################
#   ClientCertificate                                                         #
###############################################################################

class SSLv2ClientCertificate(_SSLv2Handshake):
    """
    SSLv2 ClientCertificate.
    """
    name = "SSLv2 Handshake - Client Certificate"
    fields_desc = [ByteEnumField("msgtype", 8, _sslv2_handshake_type),

                   ByteEnumField("certtype", 1, {1: "x509_cert"}),
                   FieldLenField("certlen", None, fmt="!H",
                                 length_of="certdata"),
                   FieldLenField("responselen", None, fmt="!H",
                                 length_of="responsedata"),

                   _SSLv2CertDataField("certdata", b"",
                                       length_from=lambda pkt: pkt.certlen),
                   _TLSSignatureField("responsedata", None,
                                      length_from=lambda pkt: pkt.responselen)]

    def build(self, *args, **kargs):
        s = self.tls_session
        sig = self.getfieldval("responsedata")
        test = (sig is None and
                s.sslv2_key_material is not None and
                s.sslv2_challenge_clientcert is not None and
                len(s.server_certs) > 0)
        if test:
            s = self.tls_session
            m = (s.sslv2_key_material +
                 s.sslv2_challenge_clientcert +
                 s.server_certs[0].der)
            self.responsedata = _TLSSignature(tls_session=s)
            self.responsedata._update_sig(m, s.client_key)
        else:
            self.responsedata = b""
        return super(SSLv2ClientCertificate, self).build(*args, **kargs)

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)

        s = self.tls_session
        test = (len(s.client_certs) > 0 and
                s.sslv2_key_material is not None and
                s.sslv2_challenge_clientcert is not None and
                len(s.server_certs) > 0)
        if test:
            m = (s.sslv2_key_material +
                 s.sslv2_challenge_clientcert +
                 s.server_certs[0].der)
            sig_test = self.responsedata._verify_sig(m, s.client_certs[0])
            if not sig_test:
                pkt_info = self.firstlayer().summary()
                log_runtime.info("TLS: invalid client CertificateVerify signature [%s]", pkt_info)  # noqa: E501

    def tls_session_update(self, msg_str):
        super(SSLv2ClientCertificate, self).tls_session_update(msg_str)
        if self.certdata:
            self.tls_session.client_certs = [self.certdata]


###############################################################################
#   Finished                                                                  #
###############################################################################

class SSLv2ClientFinished(_SSLv2Handshake):
    """
    In order to parse a ClientFinished, the exact message string should be fed
    to the class. SSLv2 does not offer any other way to know the c_id length.
    """
    name = "SSLv2 Handshake - Client Finished"
    fields_desc = [ByteEnumField("msgtype", 3, _sslv2_handshake_type),
                   XStrField("connection_id", "")]

    def build(self, *args, **kargs):
        fval = self.getfieldval("connection_id")
        if fval == b"":
            self.connection_id = self.tls_session.sslv2_connection_id
        return super(SSLv2ClientFinished, self).build(*args, **kargs)

    def post_dissection(self, pkt):
        s = self.tls_session
        if s.sslv2_connection_id is not None:
            if self.connection_id != s.sslv2_connection_id:
                pkt_info = pkt.firstlayer().summary()
                log_runtime.info("TLS: invalid client Finished received [%s]", pkt_info)  # noqa: E501


class SSLv2ServerFinished(_SSLv2Handshake):
    """
    In order to parse a ServerFinished, the exact message string should be fed
    to the class. SSLv2 does not offer any other way to know the sid length.
    """
    name = "SSLv2 Handshake - Server Finished"
    fields_desc = [ByteEnumField("msgtype", 6, _sslv2_handshake_type),
                   XStrField("sid", "")]

    def build(self, *args, **kargs):
        fval = self.getfieldval("sid")
        if fval == b"":
            self.sid = self.tls_session.sid
        return super(SSLv2ServerFinished, self).build(*args, **kargs)

    def post_dissection_tls_session_update(self, msg_str):
        self.tls_session_update(msg_str)
        self.tls_session.sid = self.sid


###############################################################################
#   All handshake messages defined in this module                             #
###############################################################################

_sslv2_handshake_cls = {0: SSLv2Error, 1: SSLv2ClientHello,
                        2: SSLv2ClientMasterKey, 3: SSLv2ClientFinished,
                        4: SSLv2ServerHello, 5: SSLv2ServerVerify,
                        6: SSLv2ServerFinished, 7: SSLv2RequestCertificate,
                        8: SSLv2ClientCertificate}
