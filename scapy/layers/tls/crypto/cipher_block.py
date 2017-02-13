## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Block ciphers.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from scapy.utils import strxor
from scapy.layers.tls.crypto.ciphers import CipherError


tls_block_cipher_algs = {}

class _BlockCipherMetaclass(type):
    """
    Cipher classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.
    """
    def __new__(cls, ciph_name, bases, dct):
        if ciph_name != "_BlockCipher":
            dct["name"] = ciph_name[7:]     # remove leading "Cipher_"
        the_class = super(_BlockCipherMetaclass, cls).__new__(cls, ciph_name,
                                                              bases, dct)
        if ciph_name != "_BlockCipher":
            tls_block_cipher_algs[ciph_name[7:]] = the_class
        return the_class


class _BlockCipher(object):
    __metaclass__ = _BlockCipherMetaclass
    type = "block"

    def __init__(self, key=None, iv=None):
        self.ready = {"key":True, "iv":True}
        if key is None:
            self.ready["key"] = False
            if hasattr(self, "expanded_key_len"):
                l = self.expanded_key_len
            else:
                l = self.key_len
            key = "\0" * l
        if iv is None or iv == "":
            self.ready["iv"] = False
            iv = "\0" * self.block_size

        # we use super() in order to avoid any deadlock with __setattr__
        super(_BlockCipher, self).__setattr__("key", key)
        super(_BlockCipher, self).__setattr__("iv", iv)

        self._cipher = Cipher(self.pc_cls(key),
                              self.pc_cls_mode(iv),
                              backend=default_backend())

    def __setattr__(self, name, val):
        if name == "key":
            if self._cipher is not None:
                self._cipher.algorithm.key = val
            self.ready["key"] = True
        elif name == "iv":
            if self._cipher is not None:
                self._cipher.mode._initialization_vector = val
            self.ready["iv"] = True
        super(_BlockCipher, self).__setattr__(name, val)


    def encrypt(self, data):
        """
        Encrypt the data. Also, update the cipher iv. This is needed for SSLv3
        and TLS 1.0. For TLS 1.1/1.2, it is overwritten in TLS.post_build().
        """
        if False in self.ready.itervalues():
            raise CipherError, data
        encryptor = self._cipher.encryptor()
        tmp = encryptor.update(data) + encryptor.finalize()
        self.iv = tmp[-self.block_size:]
        return tmp

    def decrypt(self, data):
        """
        Decrypt the data. Also, update the cipher iv. This is needed for SSLv3
        and TLS 1.0. For TLS 1.1/1.2, it is overwritten in TLS.pre_dissect().
        If we lack the key, we raise a CipherError which contains the input.
        """
        if False in self.ready.itervalues():
            raise CipherError, data
        decryptor = self._cipher.decryptor()
        tmp = decryptor.update(data) + decryptor.finalize()
        self.iv = data[-self.block_size:]
        return tmp


class Cipher_AES_128_CBC(_BlockCipher):
    pc_cls = algorithms.AES
    pc_cls_mode = modes.CBC
    block_size = 16
    key_len = 16

class Cipher_AES_256_CBC(Cipher_AES_128_CBC):
    key_len = 32


class Cipher_CAMELLIA_128_CBC(_BlockCipher):
    pc_cls = algorithms.Camellia
    pc_cls_mode = modes.CBC
    block_size = 16
    key_len = 16

class Cipher_CAMELLIA_256_CBC(Cipher_CAMELLIA_128_CBC):
    key_len = 32


### Mostly deprecated ciphers

class Cipher_DES_CBC(_BlockCipher):
    pc_cls = algorithms.TripleDES
    pc_cls_mode = modes.CBC
    block_size = 8
    key_len = 8

class Cipher_DES40_CBC(Cipher_DES_CBC):
    """
    This is an export cipher example. The key length has been weakened to 5
    random bytes (i.e. 5 bytes will be extracted from the master_secret).
    Yet, we still need to know the original length which will actually be
    fed into the encryption algorithm. This is what expanded_key_len
    is for, and it gets used in PRF.postprocess_key_for_export().
    We never define this attribute with non-export ciphers.
    """
    expanded_key_len = 8
    key_len = 5

class Cipher_3DES_EDE_CBC(_BlockCipher):
    pc_cls = algorithms.TripleDES
    pc_cls_mode = modes.CBC
    block_size = 8
    key_len = 24

class Cipher_IDEA_CBC(_BlockCipher):
    pc_cls = algorithms.IDEA
    pc_cls_mode = modes.CBC
    block_size = 8
    key_len = 16

class Cipher_SEED_CBC(_BlockCipher):
    pc_cls = algorithms.SEED
    pc_cls_mode = modes.CBC
    block_size = 16
    key_len = 16

#class Cipher_RC2_CBC_40(_BlockCipher): # RFC 2268
#    pc_cls = ARC2              # no support in the cryptography library
#    pc_cls_mode = modes.CBC
#    block_size = 8
#    key_len = 5
#    expanded_key_len = 16

