# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury

"""
Block ciphers.
"""

import warnings

from scapy.config import conf
from scapy.layers.tls.crypto.common import CipherError
import scapy.libs.six as six

if conf.crypto_valid:
    from cryptography.utils import (
        CryptographyDeprecationWarning,
    )
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes,  # noqa: E501
                                                        BlockCipherAlgorithm,
                                                        CipherAlgorithm)
    from cryptography.hazmat.backends.openssl.backend import (backend,
                                                              GetCipherByName)


_tls_block_cipher_algs = {}


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
            _tls_block_cipher_algs[ciph_name[7:]] = the_class
        return the_class


class _BlockCipher(six.with_metaclass(_BlockCipherMetaclass, object)):
    type = "block"

    def __init__(self, key=None, iv=None):
        self.ready = {"key": True, "iv": True}
        if key is None:
            self.ready["key"] = False
            if hasattr(self, "expanded_key_len"):
                key_len = self.expanded_key_len
            else:
                key_len = self.key_len
            key = b"\0" * key_len
        if not iv:
            self.ready["iv"] = False
            iv = b"\0" * self.block_size

        # we use super() in order to avoid any deadlock with __setattr__
        super(_BlockCipher, self).__setattr__("key", key)
        super(_BlockCipher, self).__setattr__("iv", iv)

        self._cipher = Cipher(self.pc_cls(key),
                              self.pc_cls_mode(iv),
                              backend=backend)

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
        if False in six.itervalues(self.ready):
            raise CipherError(data)
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
        if False in six.itervalues(self.ready):
            raise CipherError(data)
        decryptor = self._cipher.decryptor()
        tmp = decryptor.update(data) + decryptor.finalize()
        self.iv = data[-self.block_size:]
        return tmp

    def snapshot(self):
        c = self.__class__(self.key, self.iv)
        c.ready = self.ready.copy()
        return c


if conf.crypto_valid:
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


# Mostly deprecated ciphers

_sslv2_block_cipher_algs = {}

if conf.crypto_valid:
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

    _sslv2_block_cipher_algs["DES_192_EDE3_CBC"] = Cipher_3DES_EDE_CBC

    try:
        with warnings.catch_warnings():
            # Hide deprecation warnings
            warnings.filterwarnings("ignore",
                                    category=CryptographyDeprecationWarning)

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

            _sslv2_block_cipher_algs.update({
                "IDEA_128_CBC": Cipher_IDEA_CBC,
                "DES_64_CBC": Cipher_DES_CBC,
            })
    except AttributeError:
        pass


# We need some black magic for RC2, which is not registered by default
# to the openssl backend of the cryptography library.
# If the current version of openssl does not support rc2, the RC2 ciphers are
# silently not declared, and the corresponding suites will have 'usable' False.

if conf.crypto_valid:
    class _ARC2(BlockCipherAlgorithm, CipherAlgorithm):
        name = "RC2"
        block_size = 64
        key_sizes = frozenset([128])

        def __init__(self, key):
            self.key = algorithms._verify_key_size(self, key)

        @property
        def key_size(self):
            return len(self.key) * 8

    _gcbn_format = "{cipher.name}-{mode.name}"
    if GetCipherByName(_gcbn_format)(backend, _ARC2, modes.CBC) != \
            backend._ffi.NULL:

        class Cipher_RC2_CBC(_BlockCipher):
            pc_cls = _ARC2
            pc_cls_mode = modes.CBC
            block_size = 8
            key_len = 16

        class Cipher_RC2_CBC_40(Cipher_RC2_CBC):
            expanded_key_len = 16
            key_len = 5

        backend.register_cipher_adapter(Cipher_RC2_CBC.pc_cls,
                                        Cipher_RC2_CBC.pc_cls_mode,
                                        GetCipherByName(_gcbn_format))

        _sslv2_block_cipher_algs["RC2_128_CBC"] = Cipher_RC2_CBC


_tls_block_cipher_algs.update(_sslv2_block_cipher_algs)
