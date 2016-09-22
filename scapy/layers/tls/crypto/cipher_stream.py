## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Stream ciphers.
"""

from Crypto.Cipher import ARC4

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


class Cipher_NULL(_StreamCipher):
    key_len = 0
    expanded_key_len = 0

    def __init__(self, key=None):
        self.key = key

    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data

class Cipher_RC4_40(_StreamCipher):
    key_len = 5
    expanded_key_len = 16

    def __init__(self, key=None):
        self.alg_state = None
        self.key = key

    def __setattr__(self, name, value):
        super(Cipher_RC4_40, self).__setattr__(name, value)
        if name == "key" and value is not None:
            self.alg_state = ARC4.new(value)

    def encrypt(self, data):
        return self.alg_state.encrypt(data)

    def decrypt(self, data):
        if self.key is None:
            raise CipherError, data
        return self.alg_state.decrypt(data)

class Cipher_RC4_128(Cipher_RC4_40):
    key_len = 16

