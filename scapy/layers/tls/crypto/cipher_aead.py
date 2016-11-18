## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Authenticated Encryption with Associated Data ciphers.

RFC 5288 introduces new ciphersuites for TLS 1.2 which are based on AES in
Galois/Counter Mode (GCM). RFC 6655 in turn introduces AES_CCM ciphersuites.
The related AEAD algorithms are defined in RFC 5116.

For now, we use AES.MODE_GCM and AES.MODE_CCM from the pycrypto library.
Note that, even though they are supported in the last version 2.7a,
they are not supported by the last commonly packaged version 2.6.

For the installation of pycrypto 2.7a, see doc/scapy/installation.rst
If you keep pycrypto 2.6, the suites supposed to use the ciphers below
will be tagged with 'usable' False.
"""

import struct

from Crypto.Cipher import AES

from scapy.error import warning
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

    pc_cls = AES
    block_size = 16
    key_len = 16

    salt_len = 4
    nonce_explicit_len = 8
    tag_len = 16

    def __init__(self, key=None, salt=None, nonce_explicit_init=None):
        """
        'key' and 'salt' are to be provided as strings, whereas the internal
        'nonce_explicit' is an integer (it is simpler for incrementation).
        """
        self.key = key
        self.salt = salt

        if type(nonce_explicit_init) is str:
            nonce_explicit_init = pkcs_os2ip(nonce_explicit_init)
        self.nonce_explicit = nonce_explicit_init

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
        """
        if self.pc_cls_mode is None:
            warning("No AEAD support! Please install pycrypto 2.7a or later.")
            raise CipherError

        nonce_explicit = pkcs_i2osp(self.nonce_explicit,
                                    self.nonce_explicit_len)
        K = self.key
        N = self.salt + nonce_explicit
        ciph = self.pc_cls.new(K, self.pc_cls_mode, N, mac_len=self.tag_len)
        ciph.update(A)
        self._update_nonce()
        return nonce_explicit + ciph.encrypt(P) + ciph.digest()

    def auth_decrypt(self, A, C, add_length=True):
        """
        Decrypt the data and verify the authentication code (in this order).
        When additional data was authenticated, it has to be passed (as A).
        If the verification fails, a ValueError is raised. It is the user's
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

        if self.pc_cls_mode is None:
            warning("No AEAD support! Please install pycrypto 2.7a or later.")
            raise CipherError, (nonce_explicit_str, C, mac)

        if self.key is None:
            raise CipherError, (nonce_explicit_str, C, mac)

        K = self.key
        N = self.salt + nonce_explicit_str
        ciph = self.pc_cls.new(K, self.pc_cls_mode, N, mac_len=self.tag_len)
        if add_length:
            A += struct.pack("!H", len(C))
        ciph.update(A)
        P = ciph.decrypt(C)
        try:
            ciph.verify(mac)
        except ValueError:
            raise AEADTagError, (nonce_explicit_str, P, mac)
        return nonce_explicit_str, P, mac


class Cipher_AES_128_GCM(_AEADCipher):
    pc_cls_mode = AES.MODE_GCM if hasattr(AES, "MODE_GCM") else None

class Cipher_AES_256_GCM(Cipher_AES_128_GCM):
    key_len = 32


class Cipher_AES_128_CCM(_AEADCipher):
    pc_cls_mode = AES.MODE_CCM if hasattr(AES, "MODE_CCM") else None

class Cipher_AES_256_CCM(Cipher_AES_128_CCM):
    key_len = 32

class Cipher_AES_128_CCM_8(Cipher_AES_128_CCM):
    tag_len = 8

class Cipher_AES_256_CCM_8(Cipher_AES_128_CCM_8):
    key_len = 32

