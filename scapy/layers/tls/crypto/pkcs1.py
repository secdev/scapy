## This file is part of Scapy
## Copyright (C) 2008 Arnaud Ebalard <arno@natisbad.org>
##         2015, 2016 Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
PKCS #1 methods as defined in RFC 3447.
"""

from scapy.config import conf, crypto_validator
if conf.crypto_valid:
    from cryptography import utils
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.hashes import HashAlgorithm

from scapy.utils import randstring, zerofree_randstring, strxor, strand
from scapy.error import warning


#####################################################################
# Some helpers
#####################################################################

def pkcs_os2ip(s):
    """
    OS2IP conversion function from RFC 3447.

    Input : s        octet string to be converted
    Output: n        corresponding nonnegative integer
    """
    return int(s.encode("hex"), 16)

def pkcs_i2osp(n, sLen):
    """
    I2OSP conversion function from RFC 3447.
    The length parameter allows the function to perform the padding needed.
    Note that the user is responsible for providing a sufficient xLen.

    Input : n        nonnegative integer to be converted
            sLen     intended length of the resulting octet string
    Output: s        corresponding octet string
    """
    #if n >= 256**sLen:
    #    raise Exception("Integer too large for provided sLen %d" % sLen)
    fmt = "%%0%dx" % (2*sLen)
    return (fmt % n).decode("hex")

def pkcs_ilen(n):
    """
    This is a log base 256 which determines the minimum octet string
    length for unequivocal representation of integer n by pkcs_i2osp.
    """
    i = 0
    while n > 0:
        n >>= 8
        i += 1
    return i


#####################################################################
# Hash and padding helpers
#####################################################################

_get_hash = None
if conf.crypto_valid:

    # first, we add the "md5-sha1" hash from openssl to python-cryptography
    @utils.register_interface(HashAlgorithm)
    class MD5_SHA1(object):
        name = "md5-sha1"
        digest_size = 36
        block_size = 64

    _hashes = {
            "md5"      : hashes.MD5,
            "sha1"     : hashes.SHA1,
            "sha224"   : hashes.SHA224,
            "sha256"   : hashes.SHA256,
            "sha384"   : hashes.SHA384,
            "sha512"   : hashes.SHA512,
            "md5-sha1" : MD5_SHA1
            }

    def _get_hash(hashStr):
        try:
            return _hashes[hashStr]()
        except KeyError:
            raise KeyError("Unknown hash function %s" % hashStr)


    def _get_padding(padStr, mgf=padding.MGF1, h=hashes.SHA256, label=None):
        if padStr == "pkcs":
            return padding.PKCS1v15()
        elif padStr == "oaep":
            return padding.OAEP(mgf=mgf(h), algorithm=h, label=label)
        else:
            warning("Key.encrypt(): Unknown padding type (%s) provided" % t)
            return None


#####################################################################
# Asymmetric Cryptography wrappers
#####################################################################

# Make sure that default values are consistent accross the whole TLS module,
# lest they be explicitly set to None between cert.py and pkcs1.py.

class _EncryptAndVerifyRSA(object):

    @crypto_validator
    def encrypt(self, m, t="pkcs", h="sha256", mgf=None, L=None):
        mgf = mgf or padding.MGF1
        h = _get_hash(h)
        pad = _get_padding(t, mgf, h, L)
        return self.pubkey.encrypt(m, pad)

    @crypto_validator
    def verify(self, M, S, t="pkcs", h="sha256", mgf=None, L=None):
        mgf = mgf or padding.MGF1
        h = _get_hash(h)
        pad = _get_padding(t, mgf, h, L)
        try:
            self.pubkey.verify(S, M, pad, h)
            return True
        except InvalidSignature:
            return False


class _DecryptAndSignRSA(object):

    @crypto_validator
    def decrypt(self, C, t="pkcs", h="sha256", mgf=None, L=None):
        mgf = mgf or padding.MGF1
        h = _get_hash(h)
        pad = _get_padding(t, mgf, h, L)
        return self.key.decrypt(C, pad)

    @crypto_validator
    def sign(self, M, t="pkcs", h="sha256", mgf=None, L=None):
        mgf = mgf or padding.MGF1
        h = _get_hash(h)
        pad = _get_padding(t, mgf, h, L)
        return self.key.sign(M, pad, h)

