# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016 Maxence Tury

"""
Hash classes.
"""

from scapy.config import conf, crypto_validator
from scapy.layers.tls.crypto.md4 import MD4 as md4

if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.hashes import (
        MD5,
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        SHAKE256,
    )
    from cryptography.hazmat.primitives.hashes import HashAlgorithm
else:
    MD5 = SHA1 = SHA224 = SHA256 = SHA384 = SHA512 = SHAKE256 = None
    HashAlgorithm = object

_tls_hash_algs = {}


class _GenericHashMetaclass(type):
    """
    Hash classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.
    """

    def __new__(cls, hash_name, bases, dct):
        if hash_name != "_GenericHash":
            dct["name"] = hash_name[5:].lower()  # remove leading "Hash_"
        the_class = super(_GenericHashMetaclass, cls).__new__(
            cls, hash_name, bases, dct
        )
        if hash_name != "_GenericHash":
            _tls_hash_algs[dct["name"]] = the_class
        return the_class


class _GenericHash(metaclass=_GenericHashMetaclass):
    def digest(self, tbd):
        digest = hashes.Hash(self.hash_cls(), backend=default_backend())
        digest.update(tbd)
        return digest.finalize()


class Hash_NULL(_GenericHash):
    hash_len = 0

    def digest(self, tbd):
        return b""


class Hash_MD4(_GenericHash):
    hash_cls = md4
    hash_len = 16

    def digest(self, tbd):
        return self.hash_cls(tbd).digest()


class Hash_MD5(_GenericHash):
    hash_cls = MD5
    hash_len = 16


class Hash_SHA(_GenericHash):
    hash_cls = SHA1
    hash_len = 20


_tls_hash_algs["sha1"] = Hash_SHA


class Hash_SHA224(_GenericHash):
    hash_cls = SHA224
    hash_len = 28


class Hash_SHA256(_GenericHash):
    hash_cls = SHA256
    hash_len = 32


class Hash_SHA384(_GenericHash):
    hash_cls = SHA384
    hash_len = 48


class Hash_SHA512(_GenericHash):
    hash_cls = SHA512
    hash_len = 64


# first, we add the "md5-sha1" hash from openssl to python-cryptography
class MD5_SHA1(HashAlgorithm):
    name = "md5-sha1"
    digest_size = 36
    block_size = 64


class Hash_MD5SHA1(_GenericHash):
    hash_cls = MD5_SHA1
    hash_len = 36


_tls_hash_algs["md5-sha1"] = Hash_MD5SHA1


class Hash_SHAKE256(_GenericHash):
    hash_cls = SHAKE256

    def __init__(self, digest_size: int):
        self.hash_len = digest_size

    def digest(self, tbd):
        digest = hashes.Hash(self.hash_cls(self.hash_len), backend=default_backend())
        digest.update(tbd)
        return digest.finalize()


@crypto_validator
def _get_hash(hashStr):
    """
    Return a cryptography-hash by its name
    """
    try:
        return _tls_hash_algs[hashStr].hash_cls()
    except KeyError:
        raise KeyError("Unknown hash function %s" % hashStr)
