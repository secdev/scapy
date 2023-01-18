# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016 Maxence Tury

"""
Hash classes.
"""

from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from scapy.layers.tls.crypto.md4 import MD4 as md4


_tls_hash_algs = {}


class _GenericHashMetaclass(type):
    """
    Hash classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.
    """
    def __new__(cls, hash_name, bases, dct):
        if hash_name != "_GenericHash":
            dct["name"] = hash_name[5:]     # remove leading "Hash_"
        the_class = super(_GenericHashMetaclass, cls).__new__(cls, hash_name,
                                                              bases, dct)
        if hash_name != "_GenericHash":
            _tls_hash_algs[hash_name[5:]] = the_class
        return the_class


class _GenericHash(metaclass=_GenericHashMetaclass):
    def digest(self, tbd):
        return self.hash_cls(tbd).digest()


class Hash_NULL(_GenericHash):
    hash_len = 0

    def digest(self, tbd):
        return b""


class Hash_MD4(_GenericHash):
    hash_cls = md4
    hash_len = 16


class Hash_MD5(_GenericHash):
    hash_cls = md5
    hash_len = 16


class Hash_SHA(_GenericHash):
    hash_cls = sha1
    hash_len = 20


class Hash_SHA224(_GenericHash):
    hash_cls = sha224
    hash_len = 28


class Hash_SHA256(_GenericHash):
    hash_cls = sha256
    hash_len = 32


class Hash_SHA384(_GenericHash):
    hash_cls = sha384
    hash_len = 48


class Hash_SHA512(_GenericHash):
    hash_cls = sha512
    hash_len = 64
