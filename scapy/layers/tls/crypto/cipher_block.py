## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Block ciphers.
"""

from Crypto.Cipher import AES, DES3, DES, ARC2

from scapy.utils import strxor
from scapy.layers.tls.crypto.camellia import Camellia
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
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        """
        Encrypt the data. Also, update the cipher iv. This is needed for SSLv3
        and TLS 1.0. For TLS 1.1/1.2, it is overwritten in TLS.post_build().
        """
        tmp = self.pc_cls.new(self.key, self.pc_cls_mode, self.iv).encrypt(data)
        self.iv = tmp[-self.block_size:]
        return tmp

    def decrypt(self, data):
        """
        Decrypt the data. Also, update the cipher iv. This is needed for SSLv3
        and TLS 1.0. For TLS 1.1/1.2, it is overwritten in TLS.pre_dissect().
        If we lack the key, we raise a CipherError which contains the input.
        """
        if self.key is None:
            raise CipherError, data
        tmp = self.pc_cls.new(self.key, self.pc_cls_mode, self.iv).decrypt(data)
        self.iv = data[-self.block_size:]
        return tmp


### Standard AES

class Cipher_AES_128_CBC(_BlockCipher):
    pc_cls = AES
    pc_cls_mode = AES.MODE_CBC
    block_size = 16
    key_len = 16

class Cipher_AES_256_CBC(Cipher_AES_128_CBC):
    key_len = 32


### Camellia

class Cipher_CAMELLIA_128_CBC(_BlockCipher):
    """
    As Camellia is not supported in pycrypto, we rely on our camellia.py.
    Don't expect speed, it's more for completeness than anything else.
    """
    type = "block"
    block_size = 16
    key_len = 16

    def __init__(self, key=None, iv=None):
        self.key = key
        self.iv = iv
        self.c = Camellia()

    def encrypt(self, data):
        l = len(data)/16
        p = 0
        res = []
        tmp = self.iv
        while p != l:
            tmp = strxor(tmp, data[p*16:(p+1)*16])
            tmp = self.c.encrypt(tmp, self.key)
            res.append(tmp)
            p += 1
        self.iv = tmp
        return "".join(res)

    def decrypt(self, data):
        if self.key is None:
            raise Exception, data
        l = len(data)/16
        p = 0
        res = []
        while p != l:
            s = data[p*16:(p+1)*16]
            tmp = self.c.decrypt(s, self.key)
            tmp = strxor(tmp, self.iv)
            self.iv = s
            res.append(tmp)
            p += 1
        return "".join(res)

class Cipher_CAMELLIA_256_CBC(Cipher_CAMELLIA_128_CBC):
    name = "CAMELLIA_256_CBC"
    key_len = 32


### Mostly deprecated ciphers

class Cipher_RC2_CBC_40(_BlockCipher): # RFC 2268
    pc_cls = ARC2
    pc_cls_mode = ARC2.MODE_CBC
    block_size = 8
    key_len = 5
    expanded_key_len = 16

class Cipher_DES_CBC(_BlockCipher):
    pc_cls = DES
    pc_cls_mode = DES.MODE_CBC
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
    key_len = 5
    expanded_key_len = 8

class Cipher_3DES_EDE_CBC(_BlockCipher):
    pc_cls = DES3
    pc_cls_mode = DES.MODE_CBC
    block_size = 8
    key_len = 24


### IDEA & SEED (XXX no support for now)

# http://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
# IPR claim on IDEA : http://www.ietf.org/ietf/IPR/ASCOM-IDEA
# class Cipher_IDEA_CBC(_BlockCipher):
#     key_len = 16
#     block_size = 8
#
#     def encrypt(self, data):
#         print "IDEA is unavailable"
#         return data
#
#     def decrypt(self, data):
#         print "IDEA is unavailable"
#         return data

# SEED is a symmetric encryption algorithm that was developed by Korea
# Information Security Agency (KISA) and a group of experts.
# Specif: http://www.kisa.or.kr/kisa/seed/data/Document_pdf/SEED_Specification_english.pdf
#         http://tools.ietf.org/rfc/rfc4269.txt
# RFC 4162 : Addition of SEED Cipher Suites to TLS
# class Cipher_SEED_CBC(_BlockCipher):
#     key_len = 16
#     block_size = 16
#
#     def encrypt(self, data):
#         print "SEED is unavailable"
#         return data
#
#     def decrypt(self, data):
#         print "SEED is unavailable"
#         return data

