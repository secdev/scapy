# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury

"""
TLS base fields, used for record parsing/building. As several operations depend
upon the TLS version or ciphersuite, the packet has to provide a TLS context.
"""
import struct

from scapy.fields import ByteField, ShortEnumField, ShortField, StrField
from scapy.compat import orb

_tls_type = {20: "change_cipher_spec",
             21: "alert",
             22: "handshake",
             23: "application_data"}

_tls_version = {0x0002: "SSLv2",
                0x0200: "SSLv2",
                0x0300: "SSLv3",
                0x0301: "TLS 1.0",
                0x0302: "TLS 1.1",
                0x0303: "TLS 1.2",
                0x7f12: "TLS 1.3-d18",
                0x7f13: "TLS 1.3-d19",
                0x0304: "TLS 1.3"}

_tls_version_options = {"sslv2": 0x0002,
                        "sslv3": 0x0300,
                        "tls1": 0x0301,
                        "tls10": 0x0301,
                        "tls11": 0x0302,
                        "tls12": 0x0303,
                        "tls13-d18": 0x7f12,
                        "tls13-d19": 0x7f13,
                        "tls13": 0x0304}


def _tls13_version_filter(version, legacy_version):
    if version < 0x0304:
        return version
    else:
        return legacy_version


class _TLSClientVersionField(ShortEnumField):
    """
    We use the advertised_tls_version if it has been defined,
    and the legacy 0x0303 for TLS 1.3 packets.
    """

    def i2h(self, pkt, x):
        if x is None:
            v = pkt.tls_session.advertised_tls_version
            if v:
                return _tls13_version_filter(v, 0x0303)
            return ""
        return x

    def i2m(self, pkt, x):
        if x is None:
            v = pkt.tls_session.advertised_tls_version
            if v:
                return _tls13_version_filter(v, 0x0303)
            return b""
        return x


class _TLSVersionField(ShortEnumField):
    """
    We use the tls_version if it has been defined, else the advertised version.
    Also, the legacy 0x0301 is used for TLS 1.3 packets.
    """

    def i2h(self, pkt, x):
        if x is None:
            v = pkt.tls_session.tls_version
            if v:
                return _tls13_version_filter(v, 0x0301)
            else:
                adv_v = pkt.tls_session.advertised_tls_version
                return _tls13_version_filter(adv_v, 0x0301)
        return x

    def i2m(self, pkt, x):
        if x is None:
            v = pkt.tls_session.tls_version
            if v:
                return _tls13_version_filter(v, 0x0301)
            else:
                adv_v = pkt.tls_session.advertised_tls_version
                return _tls13_version_filter(adv_v, 0x0301)
        return x


class _TLSLengthField(ShortField):
    def i2repr(self, pkt, x):
        s = super(_TLSLengthField, self).i2repr(pkt, x)
        if pkt.deciphered_len is not None:
            dx = pkt.deciphered_len
            ds = super(_TLSLengthField, self).i2repr(pkt, dx)
            s += "    [deciphered_len= %s]" % ds
        return s


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
        tmp_len = 0
        cipher_type = pkt.tls_session.rcs.cipher.type
        if cipher_type == "block":
            if pkt.tls_session.tls_version >= 0x0302:
                tmp_len = pkt.tls_session.rcs.cipher.block_size
        elif cipher_type == "aead":
            tmp_len = pkt.tls_session.rcs.cipher.nonce_explicit_len
        return tmp_len

    def i2m(self, pkt, x):
        return x or b""

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        tmp_len = 0
        cipher_type = pkt.tls_session.rcs.cipher.type
        if cipher_type == "block":
            if pkt.tls_session.tls_version >= 0x0302:
                tmp_len = pkt.tls_session.rcs.cipher.block_size
        elif cipher_type == "aead":
            tmp_len = pkt.tls_session.rcs.cipher.nonce_explicit_len
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])

    def i2repr(self, pkt, x):
        return repr(self.i2m(pkt, x))


class _TLSMACField(StrField):
    def i2len(self, pkt, i):
        if i is not None:
            return len(i)
        return pkt.tls_session.wcs.mac_len

    def i2m(self, pkt, x):
        if x is None:
            return b""
        return x

    def addfield(self, pkt, s, val):
        # We add nothing here. This is done in .post_build() if needed.
        return s

    def getfield(self, pkt, s):
        if (
            pkt.tls_session.rcs.cipher.type != "aead" and
            False in pkt.tls_session.rcs.cipher.ready.values()
        ):
            # XXX Find a more proper way to handle the still-encrypted case
            return s, b""
        tmp_len = pkt.tls_session.rcs.mac_len
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])

    def i2repr(self, pkt, x):
        # XXX Provide status when dissection has been performed successfully?
        return repr(self.i2m(pkt, x))


class _TLSPadField(StrField):
    def i2len(self, pkt, i):
        if i is not None:
            return len(i)
        return 0

    def i2m(self, pkt, x):
        if x is None:
            return b""
        return x

    def addfield(self, pkt, s, val):
        # We add nothing here. This is done in .post_build() if needed.
        return s

    def getfield(self, pkt, s):
        if pkt.tls_session.consider_read_padding():
            # This should work with SSLv3 and also TLS versions.
            # Note that we need to retrieve pkt.padlen beforehand,
            # because it's possible that the padding is followed by some data
            # from another TLS record (hence the last byte from s would not be
            # the last byte from the current record padding).
            tmp_len = orb(s[pkt.padlen - 1])
            return s[tmp_len:], self.m2i(pkt, s[:tmp_len])
        return s, None

    def i2repr(self, pkt, x):
        # XXX Provide status when dissection has been performed successfully?
        return repr(self.i2m(pkt, x))


class _TLSPadLenField(ByteField):
    def addfield(self, pkt, s, val):
        # We add nothing here. This is done in .post_build() if needed.
        return s

    def getfield(self, pkt, s):
        if pkt.tls_session.consider_read_padding():
            return ByteField.getfield(self, pkt, s)
        return s, None


# SSLv2 fields

class _SSLv2LengthField(_TLSLengthField):
    def i2repr(self, pkt, x):
        s = super(_SSLv2LengthField, self).i2repr(pkt, x)
        if pkt.with_padding:
            x |= 0x8000
        # elif pkt.with_escape:      #XXX no complete support for 'escape' yet
        #   x |= 0x4000
            s += "    [with padding: %s]" % hex(x)
        return s

    def getfield(self, pkt, s):
        msglen = struct.unpack('!H', s[:2])[0]
        pkt.with_padding = (msglen & 0x8000) == 0
        if pkt.with_padding:
            msglen_clean = msglen & 0x3fff
        else:
            msglen_clean = msglen & 0x7fff
        return s[2:], msglen_clean


class _SSLv2MACField(_TLSMACField):
    pass


class _SSLv2PadField(_TLSPadField):
    def getfield(self, pkt, s):
        if pkt.padlen is not None:
            tmp_len = pkt.padlen
            return s[tmp_len:], self.m2i(pkt, s[:tmp_len])
        return s, None


class _SSLv2PadLenField(_TLSPadLenField):
    def getfield(self, pkt, s):
        if pkt.with_padding:
            return ByteField.getfield(self, pkt, s)
        return s, None
