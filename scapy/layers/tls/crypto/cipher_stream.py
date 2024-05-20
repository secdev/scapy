# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury

"""
Stream ciphers.
"""

from scapy.config import conf
from scapy.layers.tls.crypto.common import CipherError

if conf.crypto_valid:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.backends import default_backend
    try:
        # cryptography > 43.0
        from cryptography.hazmat.decrepit.ciphers import (
            algorithms as decrepit_algorithms,
        )
    except ImportError:
        decrepit_algorithms = algorithms


_tls_stream_cipher_algs = {}


class _StreamCipherMetaclass(type):
    """
    Cipher classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.
    """
    def __new__(cls, ciph_name, bases, dct):
        if ciph_name != "_StreamCipher":
            dct["name"] = ciph_name[7:]     # remove leading "Cipher_"
        the_class = super(_StreamCipherMetaclass, cls).__new__(cls, ciph_name,
                                                               bases, dct)
        if ciph_name != "_StreamCipher":
            _tls_stream_cipher_algs[ciph_name[7:]] = the_class
        return the_class


class _StreamCipher(metaclass=_StreamCipherMetaclass):
    type = "stream"

    def __init__(self, key=None):
        """
        Note that we have to keep the encryption/decryption state in unique
        encryptor and decryptor objects. This differs from _BlockCipher.

        In order to do connection state snapshots, we need to be able to
        recreate past cipher contexts. This is why we feed _enc_updated_with
        and _dec_updated_with every time encrypt() or decrypt() is called.
        """
        self.ready = {"key": True}
        if key is None:
            self.ready["key"] = False
            if hasattr(self, "expanded_key_len"):
                tmp_len = self.expanded_key_len
            else:
                tmp_len = self.key_len
            key = b"\0" * tmp_len

        # we use super() in order to avoid any deadlock with __setattr__
        super(_StreamCipher, self).__setattr__("key", key)

        self._cipher = Cipher(self.pc_cls(key),
                              mode=None,
                              backend=default_backend())
        self.encryptor = self._cipher.encryptor()
        self.decryptor = self._cipher.decryptor()
        self._enc_updated_with = b""
        self._dec_updated_with = b""

    def __setattr__(self, name, val):
        """
        We have to keep the encryptor/decryptor for a long time,
        however they have to be updated every time the key is changed.
        """
        if name == "key":
            if self._cipher is not None:
                self._cipher.algorithm.key = val
                self.encryptor = self._cipher.encryptor()
                self.decryptor = self._cipher.decryptor()
            self.ready["key"] = True
        super(_StreamCipher, self).__setattr__(name, val)

    def encrypt(self, data):
        if False in self.ready.values():
            raise CipherError(data)
        self._enc_updated_with += data
        return self.encryptor.update(data)

    def decrypt(self, data):
        if False in self.ready.values():
            raise CipherError(data)
        self._dec_updated_with += data
        return self.decryptor.update(data)

    def snapshot(self):
        c = self.__class__(self.key)
        c.ready = self.ready.copy()
        c.encryptor.update(self._enc_updated_with)
        c.decryptor.update(self._dec_updated_with)
        c._enc_updated_with = self._enc_updated_with
        c._dec_updated_with = self._dec_updated_with
        return c


if conf.crypto_valid:
    class Cipher_RC4_128(_StreamCipher):
        pc_cls = decrepit_algorithms.ARC4
        key_len = 16

    class Cipher_RC4_40(Cipher_RC4_128):
        expanded_key_len = 16
        key_len = 5


class Cipher_NULL(_StreamCipher):
    key_len = 0

    def __init__(self, key=None):
        self.ready = {"key": True}
        self._cipher = None
        # we use super() in order to avoid any deadlock with __setattr__
        super(Cipher_NULL, self).__setattr__("key", key)

    def snapshot(self):
        c = self.__class__(self.key)
        c.ready = self.ready.copy()
        return c

    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data
