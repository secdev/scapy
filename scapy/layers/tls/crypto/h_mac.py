# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016 Maxence Tury

"""
HMAC classes.
"""

import hmac

from scapy.layers.tls.crypto.hash import _tls_hash_algs
from scapy.compat import bytes_encode

_SSLv3_PAD1_MD5 = b"\x36" * 48
_SSLv3_PAD1_SHA1 = b"\x36" * 40
_SSLv3_PAD2_MD5 = b"\x5c" * 48
_SSLv3_PAD2_SHA1 = b"\x5c" * 40

_tls_hmac_algs = {}


class _GenericHMACMetaclass(type):
    """
    HMAC classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.

    Note that, when used with TLS, the HMAC key length equates the output of
    the associated hash function (see RFC 5246, appendix C).
    Also, we do not need to instantiate the associated hash function.
    """
    def __new__(cls, hmac_name, bases, dct):
        hash_name = hmac_name[5:]               # remove leading "Hmac_"
        if hmac_name != "_GenericHMAC":
            dct["name"] = "HMAC-%s" % hash_name
            dct["hash_alg"] = _tls_hash_algs[hash_name]
            dct["hmac_len"] = _tls_hash_algs[hash_name].hash_len
            dct["key_len"] = dct["hmac_len"]
        the_class = super(_GenericHMACMetaclass, cls).__new__(cls, hmac_name,
                                                              bases, dct)
        if hmac_name != "_GenericHMAC":
            _tls_hmac_algs[dct["name"]] = the_class
        return the_class


class HMACError(Exception):
    """
    Raised when HMAC verification fails.
    """
    pass


class _GenericHMAC(metaclass=_GenericHMACMetaclass):
    def __init__(self, key=None):
        if key is None:
            self.key = b""
        else:
            self.key = bytes_encode(key)

    def digest(self, tbd):
        if self.key is None:
            raise HMACError
        tbd = bytes_encode(tbd)
        return hmac.new(self.key, tbd, self.hash_alg.hash_cls).digest()

    def digest_sslv3(self, tbd):
        if self.key is None:
            raise HMACError

        h = self.hash_alg()
        if h.name == "SHA":
            pad1 = _SSLv3_PAD1_SHA1
            pad2 = _SSLv3_PAD2_SHA1
        elif h.name == "MD5":
            pad1 = _SSLv3_PAD1_MD5
            pad2 = _SSLv3_PAD2_MD5
        else:
            raise HMACError("Provided hash does not work with SSLv3.")

        return h.digest(self.key + pad2 +
                        h.digest(self.key + pad1 + tbd))


class Hmac_NULL(_GenericHMAC):
    hmac_len = 0
    key_len = 0

    def digest(self, tbd):
        return b""

    def digest_sslv3(self, tbd):
        return b""


class Hmac_MD4(_GenericHMAC):
    pass


class Hmac_MD5(_GenericHMAC):
    pass


class Hmac_SHA(_GenericHMAC):
    pass


class Hmac_SHA224(_GenericHMAC):
    pass


class Hmac_SHA256(_GenericHMAC):
    pass


class Hmac_SHA384(_GenericHMAC):
    pass


class Hmac_SHA512(_GenericHMAC):
    pass


def Hmac(key, hashtype):
    """
    Return Hmac object from Hash object and key
    """
    return _tls_hmac_algs[f"HMAC-{hashtype.name}"](key=key)
