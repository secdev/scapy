# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
# This program is published under a GPLv2 license

"""
Authenticated Encryption with Associated Data ciphers.

RFC 5288 introduces new ciphersuites for TLS 1.2 which are based on AES in
Galois/Counter Mode (GCM). RFC 6655 in turn introduces AES_CCM ciphersuites.
The related AEAD algorithms are defined in RFC 5116. Later on, RFC 7905
introduced cipher suites based on a ChaCha20-Poly1305 construction.
"""

from __future__ import absolute_import
import struct

from scapy.config import conf
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip
from scapy.layers.tls.crypto.ciphers import CipherError
from scapy.utils import strxor
import scapy.modules.six as six

if conf.crypto_valid:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E501
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
if conf.crypto_valid_advanced:
    from cryptography.hazmat.primitives.ciphers.aead import (AESCCM,
                                                             ChaCha20Poly1305)


_tls_aead_cipher_algs = {}


class _AEADCipherMetaclass(type):
    """
    Cipher classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.
    """
    def __new__(cls, ciph_name, bases, dct):
        if not ciph_name.startswith("_AEADCipher"):
            dct["name"] = ciph_name[7:]     # remove leading "Cipher_"
        the_class = super(_AEADCipherMetaclass, cls).__new__(cls, ciph_name,
                                                             bases, dct)
        if not ciph_name.startswith("_AEADCipher"):
            _tls_aead_cipher_algs[ciph_name[7:]] = the_class
        return the_class


class AEADTagError(Exception):
    """
    Raised when MAC verification fails.
    """
    pass


class _AEADCipher(six.with_metaclass(_AEADCipherMetaclass, object)):
    """
    The hasattr(self, "pc_cls") tests correspond to the legacy API of the
    crypto library. With cryptography v2.0, both CCM and GCM should follow
    the else case.

    Note that the "fixed_iv" in TLS RFCs is called "salt" in the AEAD RFC 5116.
    """
    type = "aead"
    fixed_iv_len = 4
    nonce_explicit_len = 8

    def __init__(self, key=None, fixed_iv=None, nonce_explicit=None):
        """
        'key' and 'fixed_iv' are to be provided as strings, whereas the internal  # noqa: E501
        'nonce_explicit' is an integer (it is simpler for incrementation).
        !! The whole 'nonce' may be called IV in certain RFCs.
        """
        self.ready = {"key": True, "fixed_iv": True, "nonce_explicit": True}
        if key is None:
            self.ready["key"] = False
            key = b"\0" * self.key_len
        if fixed_iv is None:
            self.ready["fixed_iv"] = False
            fixed_iv = b"\0" * self.fixed_iv_len
        if nonce_explicit is None:
            self.ready["nonce_explicit"] = False
            nonce_explicit = 0

        if isinstance(nonce_explicit, str):
            nonce_explicit = pkcs_os2ip(nonce_explicit)

        # we use super() in order to avoid any deadlock with __setattr__
        super(_AEADCipher, self).__setattr__("key", key)
        super(_AEADCipher, self).__setattr__("fixed_iv", fixed_iv)
        super(_AEADCipher, self).__setattr__("nonce_explicit", nonce_explicit)

        if hasattr(self, "pc_cls"):
            self._cipher = Cipher(self.pc_cls(key),
                                  self.pc_cls_mode(self._get_nonce()),
                                  backend=default_backend())
        else:
            self._cipher = self.cipher_cls(key)

    def __setattr__(self, name, val):
        if name == "key":
            if self._cipher is not None:
                if hasattr(self, "pc_cls"):
                    self._cipher.algorithm.key = val
                else:
                    self._cipher._key = val
            self.ready["key"] = True
        elif name == "fixed_iv":
            self.ready["fixed_iv"] = True
        elif name == "nonce_explicit":
            if isinstance(val, str):
                val = pkcs_os2ip(val)
            self.ready["nonce_explicit"] = True
        super(_AEADCipher, self).__setattr__(name, val)

    def _get_nonce(self):
        return (self.fixed_iv +
                pkcs_i2osp(self.nonce_explicit, self.nonce_explicit_len))

    def _update_nonce_explicit(self):
        """
        Increment the explicit nonce while avoiding any overflow.
        """
        ne = self.nonce_explicit + 1
        self.nonce_explicit = ne % 2**(self.nonce_explicit_len * 8)

    def auth_encrypt(self, P, A, seq_num=None):
        """
        Encrypt the data then prepend the explicit part of the nonce. The
        authentication tag is directly appended with the most recent crypto
        API. Additional data may be authenticated without encryption (as A).

        The 'seq_num' should never be used here, it is only a safeguard needed
        because one cipher (ChaCha20Poly1305) using TLS 1.2 logic in record.py
        actually is a _AEADCipher_TLS13 (even though others are not).
        """
        if False in six.itervalues(self.ready):
            raise CipherError(P, A)

        if hasattr(self, "pc_cls"):
            self._cipher.mode._initialization_vector = self._get_nonce()
            self._cipher.mode._tag = None
            encryptor = self._cipher.encryptor()
            encryptor.authenticate_additional_data(A)
            res = encryptor.update(P) + encryptor.finalize()
            res += encryptor.tag
        else:
            if isinstance(self._cipher, AESCCM):
                res = self._cipher.encrypt(self._get_nonce(), P, A,
                                           tag_length=self.tag_len)
            else:
                res = self._cipher.encrypt(self._get_nonce(), P, A)

        nonce_explicit = pkcs_i2osp(self.nonce_explicit,
                                    self.nonce_explicit_len)
        self._update_nonce_explicit()
        return nonce_explicit + res

    def auth_decrypt(self, A, C, seq_num=None, add_length=True):
        """
        Decrypt the data and authenticate the associated data (i.e. A).
        If the verification fails, an AEADTagError is raised. It is the user's
        responsibility to catch it if deemed useful. If we lack the key, we
        raise a CipherError which contains the encrypted input.

        Note that we add the TLSCiphertext length to A although we're supposed
        to add the TLSCompressed length. Fortunately, they are the same,
        but the specifications actually messed up here. :'(

        The 'add_length' switch should always be True for TLS, but we provide
        it anyway (mostly for test cases, hum).

        The 'seq_num' should never be used here, it is only a safeguard needed
        because one cipher (ChaCha20Poly1305) using TLS 1.2 logic in record.py
        actually is a _AEADCipher_TLS13 (even though others are not).
        """
        nonce_explicit_str, C, mac = (C[:self.nonce_explicit_len],
                                      C[self.nonce_explicit_len:-self.tag_len],
                                      C[-self.tag_len:])

        if False in six.itervalues(self.ready):
            raise CipherError(nonce_explicit_str, C, mac)

        self.nonce_explicit = pkcs_os2ip(nonce_explicit_str)
        if add_length:
            A += struct.pack("!H", len(C))

        if hasattr(self, "pc_cls"):
            self._cipher.mode._initialization_vector = self._get_nonce()
            self._cipher.mode._tag = mac
            decryptor = self._cipher.decryptor()
            decryptor.authenticate_additional_data(A)
            P = decryptor.update(C)
            try:
                decryptor.finalize()
            except InvalidTag:
                raise AEADTagError(nonce_explicit_str, P, mac)
        else:
            try:
                if isinstance(self._cipher, AESCCM):
                    P = self._cipher.decrypt(self._get_nonce(), C + mac, A,
                                             tag_length=self.tag_len)
                else:
                    P = self._cipher.decrypt(self._get_nonce(), C + mac, A)
            except InvalidTag:
                raise AEADTagError(nonce_explicit_str,
                                   "<unauthenticated data>",
                                   mac)
        return nonce_explicit_str, P, mac

    def snapshot(self):
        c = self.__class__(self.key, self.fixed_iv, self.nonce_explicit)
        c.ready = self.ready.copy()
        return c


if conf.crypto_valid:
    class Cipher_AES_128_GCM(_AEADCipher):
        # XXX use the new AESGCM if available
        # if conf.crypto_valid_advanced:
        #    cipher_cls = AESGCM
        # else:
        pc_cls = algorithms.AES
        pc_cls_mode = modes.GCM
        key_len = 16
        tag_len = 16

    class Cipher_AES_256_GCM(Cipher_AES_128_GCM):
        key_len = 32


if conf.crypto_valid_advanced:
    class Cipher_AES_128_CCM(_AEADCipher):
        cipher_cls = AESCCM
        key_len = 16
        tag_len = 16

    class Cipher_AES_256_CCM(Cipher_AES_128_CCM):
        key_len = 32

    class Cipher_AES_128_CCM_8(Cipher_AES_128_CCM):
        tag_len = 8

    class Cipher_AES_256_CCM_8(Cipher_AES_128_CCM_8):
        key_len = 32


class _AEADCipher_TLS13(six.with_metaclass(_AEADCipherMetaclass, object)):
    """
    The hasattr(self, "pc_cls") enable support for the legacy implementation
    of GCM in the cryptography library. They should not be used, and might
    eventually be removed, with cryptography v2.0. XXX
    """
    type = "aead"

    def __init__(self, key=None, fixed_iv=None, nonce_explicit=None):
        """
        'key' and 'fixed_iv' are to be provided as strings. This IV never
        changes: it is either the client_write_IV or server_write_IV.

        Note that 'nonce_explicit' is never used. It is only a safeguard for a
        call in session.py to the TLS 1.2/ChaCha20Poly1305 case (see RFC 7905).
        """
        self.ready = {"key": True, "fixed_iv": True}
        if key is None:
            self.ready["key"] = False
            key = b"\0" * self.key_len
        if fixed_iv is None:
            self.ready["fixed_iv"] = False
            fixed_iv = b"\0" * self.fixed_iv_len

        # we use super() in order to avoid any deadlock with __setattr__
        super(_AEADCipher_TLS13, self).__setattr__("key", key)
        super(_AEADCipher_TLS13, self).__setattr__("fixed_iv", fixed_iv)

        if hasattr(self, "pc_cls"):
            self._cipher = Cipher(self.pc_cls(key),
                                  self.pc_cls_mode(fixed_iv),
                                  backend=default_backend())
        else:
            self._cipher = self.cipher_cls(key)

    def __setattr__(self, name, val):
        if name == "key":
            if self._cipher is not None:
                if hasattr(self, "pc_cls"):
                    self._cipher.algorithm.key = val
                else:
                    self._cipher._key = val
            self.ready["key"] = True
        elif name == "fixed_iv":
            self.ready["fixed_iv"] = True
        super(_AEADCipher_TLS13, self).__setattr__(name, val)

    def _get_nonce(self, seq_num):
        padlen = self.fixed_iv_len - len(seq_num)
        padded_seq_num = b"\x00" * padlen + seq_num
        return strxor(padded_seq_num, self.fixed_iv)

    def auth_encrypt(self, P, A, seq_num):
        """
        Encrypt the data, and append the computed authentication code.
        TLS 1.3 does not use additional data, but we leave this option to the
        user nonetheless.

        Note that the cipher's authentication tag must be None when encrypting.
        """
        if False in six.itervalues(self.ready):
            raise CipherError(P, A)

        if hasattr(self, "pc_cls"):
            self._cipher.mode._tag = None
            self._cipher.mode._initialization_vector = self._get_nonce(seq_num)
            encryptor = self._cipher.encryptor()
            encryptor.authenticate_additional_data(A)
            res = encryptor.update(P) + encryptor.finalize()
            res += encryptor.tag
        else:
            if (conf.crypto_valid_advanced and
                    isinstance(self._cipher, AESCCM)):
                res = self._cipher.encrypt(self._get_nonce(seq_num), P, A,
                                           tag_length=self.tag_len)
            else:
                res = self._cipher.encrypt(self._get_nonce(seq_num), P, A)
        return res

    def auth_decrypt(self, A, C, seq_num):
        """
        Decrypt the data and verify the authentication code (in this order).
        Note that TLS 1.3 is not supposed to use any additional data A.
        If the verification fails, an AEADTagError is raised. It is the user's
        responsibility to catch it if deemed useful. If we lack the key, we
        raise a CipherError which contains the encrypted input.
        """
        C, mac = C[:-self.tag_len], C[-self.tag_len:]
        if False in six.itervalues(self.ready):
            raise CipherError(C, mac)

        if hasattr(self, "pc_cls"):
            self._cipher.mode._initialization_vector = self._get_nonce(seq_num)
            self._cipher.mode._tag = mac
            decryptor = self._cipher.decryptor()
            decryptor.authenticate_additional_data(A)
            P = decryptor.update(C)
            try:
                decryptor.finalize()
            except InvalidTag:
                raise AEADTagError(P, mac)
        else:
            try:
                if (conf.crypto_valid_advanced and
                        isinstance(self._cipher, AESCCM)):
                    P = self._cipher.decrypt(self._get_nonce(seq_num), C + mac, A,  # noqa: E501
                                             tag_length=self.tag_len)
                else:
                    if (conf.crypto_valid_advanced and
                            isinstance(self, Cipher_CHACHA20_POLY1305)):
                        A += struct.pack("!H", len(C))
                    P = self._cipher.decrypt(self._get_nonce(seq_num), C + mac, A)  # noqa: E501
            except InvalidTag:
                raise AEADTagError("<unauthenticated data>", mac)
        return P, mac

    def snapshot(self):
        c = self.__class__(self.key, self.fixed_iv)
        c.ready = self.ready.copy()
        return c


if conf.crypto_valid_advanced:
    class Cipher_CHACHA20_POLY1305_TLS13(_AEADCipher_TLS13):
        cipher_cls = ChaCha20Poly1305
        key_len = 32
        tag_len = 16
        fixed_iv_len = 12
        nonce_explicit_len = 0

    class Cipher_CHACHA20_POLY1305(Cipher_CHACHA20_POLY1305_TLS13):
        """
        This TLS 1.2 cipher actually uses TLS 1.3 logic, as per RFC 7905.
        Changes occur at the record layer (in record.py).
        """
        pass


if conf.crypto_valid:
    class Cipher_AES_128_GCM_TLS13(_AEADCipher_TLS13):
        # XXX use the new AESGCM if available
        # if conf.crypto_valid_advanced:
        #    cipher_cls = AESGCM
        # else:
        pc_cls = algorithms.AES
        pc_cls_mode = modes.GCM
        key_len = 16
        fixed_iv_len = 12
        tag_len = 16

    class Cipher_AES_256_GCM_TLS13(Cipher_AES_128_GCM_TLS13):
        key_len = 32


if conf.crypto_valid_advanced:
    class Cipher_AES_128_CCM_TLS13(_AEADCipher_TLS13):
        cipher_cls = AESCCM
        key_len = 16
        tag_len = 16

    class Cipher_AES_128_CCM_8_TLS13(Cipher_AES_128_CCM_TLS13):
        tag_len = 8
