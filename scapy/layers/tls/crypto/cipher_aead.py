## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Authenticated Encryption with Associated Data ciphers.

RFC 5288 introduces new ciphersuites for TLS 1.2 which are based on AES in
Galois/Counter Mode (GCM). RFC 6655 in turn introduces AES_CCM ciphersuites.
The related AEAD algorithms are defined in RFC 5116.

For now the cryptography library only supports GCM mode.
Their interface might (and should) be changed in the future.
"""

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip
from scapy.layers.tls.crypto.ciphers import CipherError


tls_aead_cipher_algs = {}

class _AEADCipherMetaclass(type):
    """
    Cipher classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.
    """
    def __new__(cls, ciph_name, bases, dct):
        if ciph_name != "_AEADCipher":
            dct["name"] = ciph_name[7:]     # remove leading "Cipher_"
        the_class = super(_AEADCipherMetaclass, cls).__new__(cls, ciph_name,
                                                             bases, dct)
        if ciph_name != "_AEADCipher":
            tls_aead_cipher_algs[ciph_name[7:]] = the_class
        return the_class


class AEADTagError(Exception):
    """
    Raised when MAC verification fails. Hopefully you can access to the
    deciphered (but unathenticated) plaintext as e.args.
    """
    pass

class _AEADCipher(object):
    __metaclass__ = _AEADCipherMetaclass
    type = "aead"

    def __init__(self, key=None, salt=None, nonce_explicit=None):
        """
        'key' and 'salt' are to be provided as strings, whereas the internal
        'nonce_explicit' is an integer (it is simpler for incrementation).
        """
        self.ready = {"key":True, "salt":True, "nonce_explicit":True}
        if key is None:
            self.ready["key"] = False
            key = "\0" * self.key_len
        if salt is None:
            self.ready["salt"] = False
            salt = "\0" * self.salt_len
        if nonce_explicit is None:
            self.ready["nonce_explicit"] = False
            nonce_explicit = 0

        if type(nonce_explicit) is str:
            nonce_explicit = pkcs_os2ip(nonce_explicit)

        # we use super() in order to avoid any deadlock with __setattr__
        super(_AEADCipher, self).__setattr__("key", key)
        super(_AEADCipher, self).__setattr__("salt", salt)
        super(_AEADCipher, self).__setattr__("nonce_explicit", nonce_explicit)

        iv = salt + pkcs_i2osp(nonce_explicit, self.nonce_explicit_len)
        self._cipher = Cipher(self.pc_cls(key),
                              self.pc_cls_mode(iv),
                              backend=default_backend())

    def __setattr__(self, name, val):
        if name == "key":
            if self._cipher is not None:
                self._cipher.algorithm.key = val
            self.ready["key"] = True
        elif name == "salt":
            iv = val + pkcs_i2osp(self.nonce_explicit, self.nonce_explicit_len)
            if self._cipher is not None:
                self._cipher.mode._initialization_vector = iv
            self.ready["salt"] = True
        elif name == "nonce_explicit":
            if type(val) is str:
                val = pkcs_os2ip(val)
            iv = self.salt + pkcs_i2osp(val, self.nonce_explicit_len)
            if self._cipher is not None:
                self._cipher.mode._initialization_vector = iv
            self.ready["nonce_explicit"] = True
        super(_AEADCipher, self).__setattr__(name, val)

    def _update_nonce(self):
        """
        Increment the explicit nonce while avoiding any overflow.
        """
        ne = self.nonce_explicit + 1
        self.nonce_explicit = ne % 2**(self.nonce_explicit_len*8)

    def auth_encrypt(self, P, A):
        """
        Encrypt the data, prepend the explicit part of the nonce,
        and append the computed authentication code.
        Additional data may be authenticated without encryption (as A).

        Note that the cipher's authentication tag must be None when encrypting.
        """
        if False in self.ready.itervalues():
            raise CipherError, (P, A)
        self._cipher.mode._tag = None
        encryptor = self._cipher.encryptor()
        encryptor.authenticate_additional_data(A)
        res = encryptor.update(P) + encryptor.finalize()
        res += encryptor.tag

        nonce_explicit = pkcs_i2osp(self.nonce_explicit,
                                    self.nonce_explicit_len)
        self._update_nonce()
        return nonce_explicit + res

    def auth_decrypt(self, A, C, add_length=True):
        """
        Decrypt the data and verify the authentication code (in this order).
        When additional data was authenticated, it has to be passed (as A).
        If the verification fails, an AEADTagError is raised. It is the user's
        responsibility to catch it if deemed useful. If we lack the key, we
        raise a CipherError which contains the encrypted input.

        Note that we add the TLSCiphertext length to A although we're supposed
        to add the TLSCompressed length. Fortunately, they are the same,
        but the specifications actually messed up here. :'(

        The 'add_length' switch should always be True for TLS, but we provide
        it anyway (mostly for test cases, hum).
        """
        nonce_explicit_str, C, mac = (C[:self.nonce_explicit_len],
                                      C[self.nonce_explicit_len:-self.tag_len],
                                      C[-self.tag_len:])

        if False in self.ready.itervalues():
            raise CipherError, (nonce_explicit_str, C, mac)

        self.nonce_explicit = pkcs_os2ip(nonce_explicit_str)
        self._cipher.mode._tag = mac

        decryptor = self._cipher.decryptor()
        if add_length:
            A += struct.pack("!H", len(C))
        decryptor.authenticate_additional_data(A)

        P = decryptor.update(C)
        try:
            decryptor.finalize()
        except InvalidTag:
            raise AEADTagError, (nonce_explicit_str, P, mac)
        return nonce_explicit_str, P, mac


class Cipher_AES_128_GCM(_AEADCipher):
    pc_cls = algorithms.AES
    pc_cls_mode = modes.GCM
    block_size = 16
    key_len = 16
    salt_len = 4
    nonce_explicit_len = 8
    tag_len = 16

class Cipher_AES_256_GCM(Cipher_AES_128_GCM):
    key_len = 32


# no support for now in the cryptography library
#class Cipher_AES_128_CCM(_AEADCipher):
#    pc_cls_mode = modes.CCM
#
#class Cipher_AES_256_CCM(Cipher_AES_128_CCM):
#    key_len = 32
#
#class Cipher_AES_128_CCM_8(Cipher_AES_128_CCM):
#    tag_len = 8
#
#class Cipher_AES_256_CCM_8(Cipher_AES_128_CCM_8):
#    key_len = 32

