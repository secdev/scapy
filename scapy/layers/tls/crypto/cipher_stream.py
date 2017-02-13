## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Stream ciphers.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

from scapy.layers.tls.crypto.ciphers import CipherError


tls_stream_cipher_algs = {}

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
            tls_stream_cipher_algs[ciph_name[7:]] = the_class
        return the_class


class _StreamCipher(object):
    __metaclass__ = _StreamCipherMetaclass
    type = "stream"

    def __init__(self, key=None):
        """
        Note that we have to keep the encryption/decryption state in unique
        encryptor and decryptor objects. This differs from _BlockCipher.
        """
        self.ready = {"key":True}
        if key is None:
            self.ready["key"] = False
            if hasattr(self, "expanded_key_len"):
                l = self.expanded_key_len
            else:
                l = self.key_len
            key = "\0" * l

        # we use super() in order to avoid any deadlock with __setattr__
        super(_StreamCipher, self).__setattr__("key", key)

        self._cipher = Cipher(self.pc_cls(key),
                              mode=None,
                              backend=default_backend())
        self.encryptor = self._cipher.encryptor()
        self.decryptor = self._cipher.decryptor()

    def __setattr__(self, name, val):
        if name == "key":
            if self._cipher is not None:
                self._cipher.algorithm.key = val
            self.ready["key"] = True
        super(_StreamCipher, self).__setattr__(name, val)

    def encrypt(self, data):
        if False in self.ready.itervalues():
            raise CipherError, data
        return self.encryptor.update(data)

    def decrypt(self, data):
        if False in self.ready.itervalues():
            raise CipherError, data
        return self.decryptor.update(data)


class Cipher_RC4_128(_StreamCipher):
    pc_cls = algorithms.ARC4
    key_len = 16

class Cipher_RC4_40(Cipher_RC4_128):
    expanded_key_len = 16
    key_len = 5


class Cipher_NULL(_StreamCipher):
    key_len = 0

    def __init__(self, key=None):
        self.ready = {"key":True}
        # we use super() in order to avoid any deadlock with __setattr__
        super(_StreamCipher, self).__setattr__("key", key)
        self._cipher = None

    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data

