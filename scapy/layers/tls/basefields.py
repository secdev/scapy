## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS base fields, used for record parsing/building. As several operations depend
upon the TLS version or ciphersuite, the packet has to provide a TLS context.
"""

from scapy.fields import *


_tls_type = { 20: "change_cipher_spec",
	      21: "alert",
	      22: "handshake",
	      23: "application_data" }

_tls_version = { 0x0200: "SSLv2",
                 0x0300: "SSLv3",
                 0x0301: "TLS 1.0",
                 0x0302: "TLS 1.1",
                 0x0303: "TLS 1.2" }


class _TLSVersionField(ShortEnumField):
    """
    Behavior: if the user does not provide a value, we use the version provided
    by tls_version parameter in packet's session, only if it is defined. In
    that case, this is the version selected by the server. Otherwise, we use
    the value provided by advertised_tls_version parameter in packet's session.
    In that latter case, this is simply the version provided by the client.
    """
    def i2h(self, pkt, x):
        if x is None:
            if pkt.tls_session.tls_version:
                return pkt.tls_session.tls_version
            return pkt.tls_session.advertised_tls_version
        return x

    def i2m(self, pkt, x):
        if x is None:
            if pkt.tls_session.tls_version:
                return pkt.tls_session.tls_version
            return pkt.tls_session.advertised_tls_version
        return x


class _TLSClientVersionField(ShortEnumField):
    """
    Unlike _TLSVersionField, we use advertised_tls_version preferentially,
    and then tls_version if there was none advertised.
    """
    def i2h(self, pkt, x):
        if x is None:
            if pkt.tls_session.advertised_tls_version:
                return pkt.tls_session.advertised_tls_version
            return pkt.tls_session.tls_version
        return x

    def i2m(self, pkt, x):
        if x is None:
            if pkt.tls_session.advertised_tls_version:
                return pkt.tls_session.advertised_tls_version
            return pkt.tls_session.tls_version
        return x


class _TLSLengthField(ShortField):
    pass


class _TLSIVField(StrField):
    """
    As stated in Section 6.2.3.2. RFC 4346, TLS 1.1 implements an explicit IV
    mechanism. For that reason, the behavior of the field is dependent on the
    TLS version found in the packet if available or otherwise (on build, if
    not overloaded, it is provided by the session). The size of the IV and
    its value are obviously provided by the session. As a side note, for the
    first packets exchanged by peers, NULL being the default enc alg, it is
    empty (except if forced to a specific value). Also note that the field is
    kept empty (unless forced to a specific value) when the cipher is a stream
    cipher (and NULL is considered a stream cipher).
    """
    def i2len(self, pkt, i):
        if i is not None:
            return len(i)
        l = 0
        cipher_type = pkt.tls_session.rcs.cipher.type
        if cipher_type == "block":
            if pkt.tls_session.tls_version >= 0x0302:
                l = pkt.tls_session.rcs.cipher.block_size
        elif cipher_type == "aead":
            l = pkt.tls_session.rcs.cipher.nonce_explicit_len
        return l

    def i2m(self, pkt, x):
        return x or ""

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        l = 0
        cipher_type = pkt.tls_session.rcs.cipher.type
        if cipher_type == "block":
            if pkt.tls_session.tls_version >= 0x0302:
                l = pkt.tls_session.rcs.cipher.block_size
        elif cipher_type == "aead":
            l = pkt.tls_session.rcs.cipher.nonce_explicit_len
        return s[l:], self.m2i(pkt, s[:l])

    def i2repr(self, pkt, x):
        return repr(self.i2m(pkt, x))


class _TLSMACField(StrField):
    def i2len(self, pkt, i):
        if i is not None:
            return len(i)
        return pkt.tls_session.wcs.mac_len

    def i2m(self, pkt, x):
        if x is None:
            return ""
        return x

    def addfield(self, pkt, s, val):
        # We add nothing here. This is done in .post_build() if needed.
        return s

    def getfield(self, pkt, s):
        l = pkt.tls_session.rcs.mac_len
        return s[l:], self.m2i(pkt, s[:l])

    def i2repr(self, pkt, x):
        #XXX Provide status when dissection has been performed successfully?
        return repr(self.i2m(pkt, x))


class _TLSPadField(StrField):
    def i2len(self, pkt, i):
        if i is not None:
            return len(i)
        return 0

    def i2m(self, pkt, x):
        if x is None:
            return ""
        return x

    def addfield(self, pkt, s, val):
        # We add nothing here. This is done in .post_build() if needed.
        return s

    def getfield(self, pkt, s):
        if pkt.tls_session.consider_read_padding():
            # We get the length from the last byte of s which
            # is either the first byte of padding or the padding
            # length field itself is padding length is 0.
            # This should work with SSLv3 and also TLS versions.
            l = ord(s[-1])
            return s[l:], self.m2i(pkt, s[:l])
        return s, None

    def i2repr(self, pkt, x):
        #XXX Provide status when dissection has been performed successfully?
        return repr(self.i2m(pkt, x))


class _TLSPadLenField(ByteField):
    def addfield(self, pkt, s, val):
        # We add nothing here. This is done in .post_build() if needed.
        return s

    def getfield(self, pkt, s):
        if pkt.tls_session.consider_read_padding():
            return ByteField.getfield(self, pkt, s)
        return s, None

