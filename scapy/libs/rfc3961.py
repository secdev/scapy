# SPDX-License-Identifier: BSD-2-Clause
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (c) 2013, Marc Horowitz
# Copyright (C) 2013, Massachusetts Institute of Technology
# Copyright (C) 2022-2024, Gabriel Potter and the secdev/scapy community

"""
Implementation of cryptographic functions for Kerberos 5

- RFC 3961: Encryption and Checksum Specifications for Kerberos 5
- RFC 3962: Advanced Encryption Standard (AES) Encryption for Kerberos 5
- RFC 4757: The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows
- RFC 6113: A Generalized Framework for Kerberos Pre-Authentication
- RFC 8009: AES Encryption with HMAC-SHA2 for Kerberos 5
"""

# TODO: support cipher states...

__all__ = [
    "EncryptionType",
    "ChecksumType",
    "Key",
    "InvalidChecksum",
    "_rfc1964pad",
]

# The following is a heavily modified version of
# https://github.com/SecureAuthCorp/impacket/blob/3ec59074ec35c06bbd4312d1042f0e23f4a1b41f/impacket/krb5/crypto.py
# itself heavily inspired from
# https://github.com/mhorowitz/pykrb5/blob/master/krb5/crypto.py
# Note that the following work is based only on THIS COMMIT from impacket,
# which is therefore under mhorowitz's BSD 2-clause "simplified" license.

import abc
import enum
import math
import os
import struct
from scapy.compat import (
    orb,
    chb,
    int_bytes,
    bytes_int,
    plain_str,
)

# Typing
from typing import (
    Any,
    Callable,
    List,
    Optional,
    Type,
    Union,
)

# We end up using our own crypto module for hashes / hmac because
# we need MD4 which was dropped everywhere. It's just a wrapper above
# the builtin python ones (except for MD4).

from scapy.layers.tls.crypto.hash import (
    _GenericHash,
    Hash_MD4,
    Hash_MD5,
    Hash_SHA,
    Hash_SHA256,
    Hash_SHA384,
)
from scapy.layers.tls.crypto.h_mac import (
    Hmac,
    Hmac_MD5,
    Hmac_SHA,
)

# For everything else, use cryptography.

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    try:
        # cryptography > 43.0
        from cryptography.hazmat.decrepit.ciphers import (
            algorithms as decrepit_algorithms,
        )
    except ImportError:
        decrepit_algorithms = algorithms
except ImportError:
    raise ImportError("To use kerberos cryptography, you need to install cryptography.")


# cryptography's TripleDES allow the usage of a 56bit key, which thus behaves like DES
DES = decrepit_algorithms.TripleDES


# https://go.microsoft.com/fwlink/?LinkId=186039
# https://csrc.nist.gov/CSRC/media/Publications/sp/800-108/archive/2008-11-06/documents/sp800-108-Nov2008.pdf
# [SP800-108] section 5.1 (used in [MS-SMB2] sect 3.1.4.2)


def SP800108_KDFCTR(
    K_I: bytes,
    Label: bytes,
    Context: bytes,
    L: int,
    hashmod: _GenericHash = Hash_SHA256,
) -> bytes:
    """
    KDF in Counter Mode as section 5.1 of [SP800-108]

    This assumes r=32, and defaults to SHA256 ([MS-SMB2] default).
    """
    PRF = Hmac(K_I, hashmod).digest
    h = hashmod.hash_len
    n = math.ceil(L / h)
    if n >= 0xFFFFFFFF:
        # 2^r-1 = 0xffffffff with r=32 per [MS-SMB2]
        raise ValueError("Invalid n value in SP800108_KDFCTR")
    result = b"".join(
        PRF(struct.pack(">I", i) + Label + b"\x00" + Context + struct.pack(">I", L))
        for i in range(1, n + 1)
    )
    return result[: L // 8]


# https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1


class EncryptionType(enum.IntEnum):
    DES_CBC_CRC = 1
    DES_CBC_MD4 = 2
    DES_CBC_MD5 = 3
    # DES3_CBC_SHA1 = 7
    DES3_CBC_SHA1_KD = 16
    AES128_CTS_HMAC_SHA1_96 = 17
    AES256_CTS_HMAC_SHA1_96 = 18
    AES128_CTS_HMAC_SHA256_128 = 19
    AES256_CTS_HMAC_SHA384_192 = 20
    RC4_HMAC = 23
    RC4_HMAC_EXP = 24
    # CAMELLIA128-CTS-CMAC = 25
    # CAMELLIA256-CTS-CMAC = 26


# https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-2


class ChecksumType(enum.IntEnum):
    CRC32 = 1
    # RSA_MD4 = 2
    RSA_MD4_DES = 3
    # RSA_MD5 = 7
    RSA_MD5_DES = 8
    # RSA_MD5_DES3 = 9
    # SHA1 = 10
    HMAC_SHA1_DES3_KD = 12
    # HMAC_SHA1_DES3 = 13
    # SHA1 = 14
    HMAC_SHA1_96_AES128 = 15
    HMAC_SHA1_96_AES256 = 16
    # CMAC-CAMELLIA128 = 17
    # CMAC-CAMELLIA256 = 18
    HMAC_SHA256_128_AES128 = 19
    HMAC_SHA384_192_AES256 = 20
    HMAC_MD5 = -138


class InvalidChecksum(ValueError):
    pass


#########
# Utils #
#########


# https://www.gnu.org/software/shishi/ides.pdf - APPENDIX B


def _n_fold(s, n):
    # type: (bytes, int) -> bytes
    """
    n-fold is an algorithm that takes m input bits and "stretches" them
    to form n output bits with equal contribution from each input bit to
    the output (quote from RFC 3961 sect 3.1).
    """

    def rot13(y, nb):
        # type: (bytes, int) -> bytes
        x = bytes_int(y)
        mod = (1 << (nb * 8)) - 1
        if nb == 0:
            return y
        elif nb == 1:
            return int_bytes(((x >> 5) | (x << (nb * 8 - 5))) & mod, nb)
        else:
            return int_bytes(((x >> 13) | (x << (nb * 8 - 13))) & mod, nb)

    def ocadd(x, y, nb):
        # type: (bytearray, bytearray, int) -> bytearray
        v = [a + b for a, b in zip(x, y)]
        while any(x & ~0xFF for x in v):
            v = [(v[i - nb + 1] >> 8) + (v[i] & 0xFF) for i in range(nb)]
        return bytearray(x for x in v)

    m = len(s)
    lcm = n // math.gcd(n, m) * m  # lcm = math.lcm(n, m) on Python>=3.9
    buf = bytearray()
    for _ in range(lcm // m):
        buf += s
        s = rot13(s, m)
    out = bytearray(b"\x00" * n)
    for i in range(0, lcm, n):
        out = ocadd(out, buf[i : i + n], n)
    return bytes(out)


def _zeropad(s, padsize):
    # type: (bytes, int) -> bytes
    """
    Return s padded with 0 bytes to a multiple of padsize.
    """
    return s + b"\x00" * (-len(s) % padsize)


def _rfc1964pad(s):
    # type: (bytes) -> bytes
    """
    Return s padded as RFC1964 mandates
    """
    pad = (-len(s)) % 8
    return s + pad * struct.pack("!B", pad)


def _xorbytes(b1, b2):
    # type: (bytearray, bytearray) -> bytearray
    """
    xor two strings together and return the resulting string
    """
    assert len(b1) == len(b2)
    return bytearray((x ^ y) for x, y in zip(b1, b2))


def _mac_equal(mac1, mac2):
    # type: (bytes, bytes) -> bool
    # Constant-time comparison function.  (We can't use HMAC.verify
    # since we use truncated macs.)
    return all(x == y for x, y in zip(mac1, mac2))


# https://doi.org/10.6028/NBS.FIPS.74 sect 3.6

WEAK_DES_KEYS = set(
    [
        # 1
        b"\xe0\x01\xe0\x01\xf1\x01\xf1\x01",
        b"\x01\xe0\x01\xe0\x01\xf1\x01\xf1",
        # 2
        b"\xfe\x1f\xfe\x1f\xfe\x0e\xfe\x0e",
        b"\x1f\xfe\x1f\xfe\x0e\xfe\x0e\xfe",
        # 3
        b"\xe0\x1f\xe0\x1f\xf1\x0e\xf1\x0e",
        b"\x1f\xe0\x1f\xe0\x0e\xf1\x0e\xf1",
        # 4
        b"\x01\xfe\x01\xfe\x01\xfe\x01\xfe",
        b"\xfe\x01\xfe\x01\xfe\x01\xfe\x01",
        # 5
        b"\x01\x1f\x01\x1f\x01\x0e\x01\x0e",
        b"\x1f\x01\x1f\x01\x0e\x01\x0e\x01",
        # 6
        b"\xe0\xfe\xe0\xfe\xf1\xfe\xf1\xfe",
        b"\xfe\xe0\xfe\xe0\xfe\xf1\xfe\xf1",
        # 7
        b"\x01" * 8,
        # 8
        b"\xfe" * 8,
        # 9
        b"\xe0" * 4 + b"\xf1" * 4,
        # 10
        b"\x1f" * 4 + b"\x0e" * 4,
    ]
)

# fmt: off
CRC32_TABLE = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
]
# fmt: on

############
# RFC 3961 #
############


# RFC3961 sect 3


class _EncryptionAlgorithmProfile(abc.ABCMeta):
    """
    Base class for etype profiles.

    Usable etype classes must define:
    :attr etype: etype number
    :attr keysize: protocol size of key in bytes
    :attr seedsize: random_to_key input size in bytes
    :attr reqcksum: 'required checksum mechanism' per RFC3961.
                    this is the default checksum used for this algorithm.
    :attr random_to_key: (if the keyspace is not dense)
    :attr string_to_key:
    :attr encrypt:
    :attr decrypt:
    :attr prf:
    """

    etype = None  # type: EncryptionType
    keysize = None  # type: int
    seedsize = None  # type: int
    reqcksum = None  # type: ChecksumType

    @classmethod
    @abc.abstractmethod
    def derive(cls, key, constant):
        # type: (Key, bytes) -> bytes
        pass

    @classmethod
    @abc.abstractmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        # type: (Key, int, bytes, Optional[bytes]) -> bytes
        pass

    @classmethod
    @abc.abstractmethod
    def decrypt(cls, key, keyusage, ciphertext):
        # type: (Key, int, bytes) -> bytes
        pass

    @classmethod
    @abc.abstractmethod
    def prf(cls, key, string):
        # type: (Key, bytes) -> bytes
        pass

    @classmethod
    @abc.abstractmethod
    def string_to_key(cls, string, salt, params):
        # type: (bytes, bytes, Optional[bytes]) -> Key
        pass

    @classmethod
    def random_to_key(cls, seed):
        # type: (bytes) -> Key
        if len(seed) != cls.seedsize:
            raise ValueError("Wrong seed length")
        return Key(cls.etype, key=seed)


# RFC3961 sect 4


class _ChecksumProfile(object):
    """
    Base class for checksum profiles.

    Usable checksum classes must define:
    :func checksum:
    :attr macsize: Size of checksum in bytes
    :func verify: (if verification is not just checksum-and-compare)
    """

    macsize = None  # type: int

    @classmethod
    @abc.abstractmethod
    def checksum(cls, key, keyusage, text):
        # type: (Key, int, bytes) -> bytes
        pass

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        # type: (Key, int, bytes, bytes) -> None
        expected = cls.checksum(key, keyusage, text)
        if not _mac_equal(cksum, expected):
            raise InvalidChecksum("checksum verification failure")


# RFC3961 sect 5.3


class _SimplifiedEncryptionProfile(_EncryptionAlgorithmProfile):
    """
    Base class for etypes using the RFC 3961 simplified profile.
    Defines the encrypt, decrypt, and prf methods.

    Subclasses must define:

    :param blocksize: Underlying cipher block size in bytes
    :param padsize: Underlying cipher padding multiple (1 or blocksize)
    :param macsize: Size of integrity MAC in bytes
    :param hashmod: underlying hash function
    :param basic_encrypt, basic_decrypt: Underlying CBC/CTS cipher
    """

    blocksize = None  # type: int
    padsize = None  # type: int
    macsize = None  # type: int
    hashmod = None  # type: Any

    # Used in RFC 8009. This is not a simplified profile per se but
    # is still pretty close.
    rfc8009 = False

    @classmethod
    @abc.abstractmethod
    def basic_encrypt(cls, key, plaintext):
        # type: (bytes, bytes) -> bytes
        pass

    @classmethod
    @abc.abstractmethod
    def basic_decrypt(cls, key, ciphertext):
        # type: (bytes, bytes) -> bytes
        pass

    @classmethod
    def derive(cls, key, constant):
        # type: (Key, bytes) -> bytes
        """
        Also known as "DK" in RFC3961.
        """
        # RFC 3961 only says to n-fold the constant only if it is
        # shorter than the cipher block size.  But all Unix
        # implementations n-fold constants if their length is larger
        # than the block size as well, and n-folding when the length
        # is equal to the block size is a no-op.
        plaintext = _n_fold(constant, cls.blocksize)
        rndseed = b""
        while len(rndseed) < cls.seedsize:
            ciphertext = cls.basic_encrypt(key.key, plaintext)
            rndseed += ciphertext
            plaintext = ciphertext
        # DK(Key, Constant) = random-to-key(DR(Key, Constant))
        return cls.random_to_key(rndseed[0 : cls.seedsize]).key

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder, signtext=None):
        # type: (Key, int, bytes, Optional[bytes], Optional[bytes]) -> bytes
        """
        Encryption function.

        :param key: the key
        :param keyusage: the keyusage
        :param plaintext: the text to encrypt
        :param confounder: (optional) the confounder. If none, will be random
        :param signtext: (optional) make the checksum include different data than what
                         is encrypted. Useful for kerberos GSS_WrapEx. If none, same as
                         plaintext.
        """
        if not cls.rfc8009:
            ki = cls.derive(key, struct.pack(">IB", keyusage, 0x55))
            ke = cls.derive(key, struct.pack(">IB", keyusage, 0xAA))
        else:
            ki = cls.derive(key, struct.pack(">IB", keyusage, 0x55), cls.macsize * 8)  # type: ignore  # noqa: E501
            ke = cls.derive(key, struct.pack(">IB", keyusage, 0xAA), cls.keysize * 8)  # type: ignore  # noqa: E501
        if confounder is None:
            confounder = os.urandom(cls.blocksize)
        basic_plaintext = confounder + _zeropad(plaintext, cls.padsize)
        if signtext is None:
            signtext = basic_plaintext
        if not cls.rfc8009:
            # Simplified profile
            hmac = Hmac(ki, cls.hashmod).digest(signtext)
            return cls.basic_encrypt(ke, basic_plaintext) + hmac[: cls.macsize]
        else:
            # RFC 8009
            C = cls.basic_encrypt(ke, basic_plaintext)
            hmac = Hmac(ki, cls.hashmod).digest(b"\0" * 16 + C)  # XXX IV
            return C + hmac[: cls.macsize]

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext, presignfunc=None):
        # type: (Key, int, bytes, Optional[Callable[[bytes, bytes], bytes]]) -> bytes
        """
        decryption function
        """
        if not cls.rfc8009:
            ki = cls.derive(key, struct.pack(">IB", keyusage, 0x55))
            ke = cls.derive(key, struct.pack(">IB", keyusage, 0xAA))
        else:
            ki = cls.derive(key, struct.pack(">IB", keyusage, 0x55), cls.macsize * 8)  # type: ignore  # noqa: E501
            ke = cls.derive(key, struct.pack(">IB", keyusage, 0xAA), cls.keysize * 8)  # type: ignore  # noqa: E501
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError("Ciphertext too short")
        basic_ctext, mac = ciphertext[: -cls.macsize], ciphertext[-cls.macsize :]
        if len(basic_ctext) % cls.padsize != 0:
            raise ValueError("ciphertext does not meet padding requirement")
        if not cls.rfc8009:
            # Simplified profile
            basic_plaintext = cls.basic_decrypt(ke, basic_ctext)
            signtext = basic_plaintext
            if presignfunc:
                # Allow to have additional processing of the data that is to be signed.
                # This is useful for GSS_WrapEx
                signtext = presignfunc(
                    basic_plaintext[: cls.blocksize],
                    basic_plaintext[cls.blocksize :],
                )
            hmac = Hmac(ki, cls.hashmod).digest(signtext)
            expmac = hmac[: cls.macsize]
            if not _mac_equal(mac, expmac):
                raise ValueError("ciphertext integrity failure")
        else:
            # RFC 8009
            signtext = b"\0" * 16 + basic_ctext  # XXX IV
            if presignfunc:
                # Allow to have additional processing of the data that is to be signed.
                # This is useful for GSS_WrapEx
                signtext = presignfunc(
                    basic_ctext[16 : 16 + cls.blocksize],
                    basic_ctext[16 + cls.blocksize :],
                )
            hmac = Hmac(ki, cls.hashmod).digest(signtext)
            expmac = hmac[: cls.macsize]
            if not _mac_equal(mac, expmac):
                raise ValueError("ciphertext integrity failure")
            basic_plaintext = cls.basic_decrypt(ke, basic_ctext)
        # Discard the confounder.
        return bytes(basic_plaintext[cls.blocksize :])

    @classmethod
    def prf(cls, key, string):
        # type: (Key, bytes) -> bytes
        """
        pseudo-random function
        """
        # Hash the input.  RFC 3961 says to truncate to the padding
        # size, but implementations truncate to the block size.
        hashval = cls.hashmod().digest(string)
        if len(hashval) % cls.blocksize:
            hashval = hashval[: -(len(hashval) % cls.blocksize)]
        # Encrypt the hash with a derived key.
        kp = cls.derive(key, b"prf")
        return cls.basic_encrypt(kp, hashval)


# RFC3961 sect 5.4


class _SimplifiedChecksum(_ChecksumProfile):
    """
    Base class for checksums using the RFC 3961 simplified profile.
    Defines the checksum and verify methods.

    Subclasses must define:
    :attr enc: Profile of associated etype
    """

    enc = None  # type: Type[_SimplifiedEncryptionProfile]

    # Used in RFC 8009. This is not a simplified profile per se but
    # is still pretty close.
    rfc8009 = False

    @classmethod
    def checksum(cls, key, keyusage, text):
        # type: (Key, int, bytes) -> bytes
        if not cls.rfc8009:
            # Simplified profile
            kc = cls.enc.derive(key, struct.pack(">IB", keyusage, 0x99))
        else:
            # RFC 8009
            kc = cls.enc.derive(  # type: ignore
                key, struct.pack(">IB", keyusage, 0x99), cls.macsize * 8
            )
        hmac = Hmac(kc, cls.enc.hashmod).digest(text)
        return hmac[: cls.macsize]

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        # type: (Key, int, bytes, bytes) -> None
        if key.etype != cls.enc.etype:
            raise ValueError("Wrong key type for checksum")
        super(_SimplifiedChecksum, cls).verify(key, keyusage, text, cksum)


# RFC3961 sect 6.1


class _CRC32(_ChecksumProfile):
    macsize = 4

    # This isn't your usual CRC32, it's a "modified version" according to the RFC3961.
    # Another RFC states it's just a buggy version of the actual CRC32.

    @classmethod
    def checksum(cls, key, keyusage, text):
        # type: (Optional[Key], int, bytes) -> bytes
        c = 0
        for i in range(len(text)):
            idx = text[i] ^ c
            idx &= 0xFF
            c >>= 8
            c ^= CRC32_TABLE[idx]
        return c.to_bytes(4, "little")


# RFC3961 sect 6.2


class _DESCBC(_SimplifiedEncryptionProfile):
    keysize = 8
    seedsize = 8
    blocksize = 8
    padsize = 8
    macsize = 16
    hashmod = Hash_MD5

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder, signtext=None):
        # type: (Key, int, bytes, Optional[bytes], Any) -> bytes
        if confounder is None:
            confounder = os.urandom(cls.blocksize)
        basic_plaintext = (
            confounder + b"\x00" * cls.macsize + _zeropad(plaintext, cls.padsize)
        )
        checksum = cls.hashmod().digest(basic_plaintext)
        basic_plaintext = (
            basic_plaintext[: len(confounder)]
            + checksum
            + basic_plaintext[len(confounder) + len(checksum) :]
        )
        return cls.basic_encrypt(key.key, basic_plaintext)

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext, presignfunc=None):
        # type: (Key, int, bytes, Any) -> bytes
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError("ciphertext too short")

        complex_plaintext = cls.basic_decrypt(key.key, ciphertext)
        cofounder = complex_plaintext[: cls.padsize]
        mac = complex_plaintext[cls.padsize : cls.padsize + cls.macsize]
        message = complex_plaintext[cls.padsize + cls.macsize :]

        expmac = cls.hashmod().digest(cofounder + b"\x00" * cls.macsize + message)
        if not _mac_equal(mac, expmac):
            raise InvalidChecksum("ciphertext integrity failure")
        return bytes(message)

    @classmethod
    def mit_des_string_to_key(cls, string, salt):
        # type: (bytes, bytes) -> Key
        def fixparity(deskey):
            # type: (List[int]) -> bytes
            temp = b""
            for i in range(len(deskey)):
                t = (bin(orb(deskey[i]))[2:]).rjust(8, "0")
                if t[:7].count("1") % 2 == 0:
                    temp += chb(int(t[:7] + "1", 2))
                else:
                    temp += chb(int(t[:7] + "0", 2))
            return temp

        def addparity(l1):
            # type: (List[int]) -> List[int]
            temp = list()
            for byte in l1:
                if (bin(byte).count("1") % 2) == 0:
                    byte = (byte << 1) | 0b00000001
                else:
                    byte = (byte << 1) & 0b11111110
                temp.append(byte)
            return temp

        def XOR(l1, l2):
            # type: (List[int], List[int]) -> List[int]
            temp = list()
            for b1, b2 in zip(l1, l2):
                temp.append((b1 ^ b2) & 0b01111111)

            return temp

        odd = True
        tempstring = [0, 0, 0, 0, 0, 0, 0, 0]
        s = _zeropad(string + salt, cls.padsize)

        for block in [s[i : i + 8] for i in range(0, len(s), 8)]:
            temp56 = list()
            # removeMSBits
            for byte in block:
                temp56.append(orb(byte) & 0b01111111)

            # reverse
            if odd is False:
                bintemp = b""
                for byte in temp56:
                    bintemp += bin(byte)[2:].rjust(7, "0").encode()
                bintemp = bintemp[::-1]

                temp56 = list()
                for bits7 in [bintemp[i : i + 7] for i in range(0, len(bintemp), 7)]:
                    temp56.append(int(bits7, 2))

            odd = not odd
            tempstring = XOR(tempstring, temp56)

        tempkey = bytearray(b"".join(chb(byte) for byte in addparity(tempstring)))
        if bytes(tempkey) in WEAK_DES_KEYS:
            tempkey[7] = tempkey[7] ^ 0xF0

        tempkeyb = bytes(tempkey)
        des = Cipher(DES(tempkeyb), modes.CBC(tempkeyb)).encryptor()
        chekcsumkey = des.update(s)[-8:]
        chekcsumkey = bytearray(fixparity(chekcsumkey))
        if bytes(chekcsumkey) in WEAK_DES_KEYS:
            chekcsumkey[7] = chekcsumkey[7] ^ 0xF0

        return Key(cls.etype, key=bytes(chekcsumkey))

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        # type: (bytes, bytes) -> bytes
        assert len(plaintext) % 8 == 0
        des = Cipher(DES(key), modes.CBC(b"\0" * 8)).encryptor()
        return des.update(bytes(plaintext))

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        # type: (bytes, bytes) -> bytes
        assert len(ciphertext) % 8 == 0
        des = Cipher(DES(key), modes.CBC(b"\0" * 8)).decryptor()
        return des.update(bytes(ciphertext))

    @classmethod
    def string_to_key(cls, string, salt, params):
        # type: (bytes, bytes, Optional[bytes]) -> Key
        if params is not None and params != b"":
            raise ValueError("Invalid DES string-to-key parameters")
        key = cls.mit_des_string_to_key(string, salt)
        return key


# RFC3961 sect 6.2.1


class _DESMD5(_DESCBC):
    etype = EncryptionType.DES_CBC_MD5
    hashmod = Hash_MD5
    reqcksum = ChecksumType.RSA_MD5_DES


# RFC3961 sect 6.2.2


class _DESMD4(_DESCBC):
    etype = EncryptionType.DES_CBC_MD4
    hashmod = Hash_MD4
    reqcksum = ChecksumType.RSA_MD4_DES


# RFC3961 sect 6.3


class _DES3CBC(_SimplifiedEncryptionProfile):
    etype = EncryptionType.DES3_CBC_SHA1_KD
    keysize = 24
    seedsize = 21
    blocksize = 8
    padsize = 8
    macsize = 20
    hashmod = Hash_SHA
    reqcksum = ChecksumType.HMAC_SHA1_DES3_KD

    @classmethod
    def random_to_key(cls, seed):
        # type: (bytes) -> Key
        # XXX Maybe reframe as _DESEncryptionType.random_to_key and use that
        # way from DES3 random-to-key when DES is implemented, since
        # MIT does this instead of the RFC 3961 random-to-key.
        def expand(seed):
            # type: (bytes) -> bytes
            def parity(b):
                # type: (int) -> int
                # Return b with the low-order bit set to yield odd parity.
                b &= ~1
                return b if bin(b & ~1).count("1") % 2 else b | 1

            assert len(seed) == 7
            firstbytes = [parity(b & ~1) for b in seed]
            lastbyte = parity(sum((seed[i] & 1) << i + 1 for i in range(7)))
            keybytes = bytearray(firstbytes + [lastbyte])
            if bytes(keybytes) in WEAK_DES_KEYS:
                keybytes[7] = keybytes[7] ^ 0xF0
            return bytes(keybytes)

        if len(seed) != 21:
            raise ValueError("Wrong seed length")
        k1, k2, k3 = expand(seed[:7]), expand(seed[7:14]), expand(seed[14:])
        return Key(cls.etype, key=k1 + k2 + k3)

    @classmethod
    def string_to_key(cls, string, salt, params):
        # type: (bytes, bytes, Optional[bytes]) -> Key
        if params is not None and params != b"":
            raise ValueError("Invalid DES3 string-to-key parameters")
        k = cls.random_to_key(_n_fold(string + salt, 21))
        return Key(
            cls.etype,
            key=cls.derive(k, b"kerberos"),
        )

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        # type: (bytes, bytes) -> bytes
        assert len(plaintext) % 8 == 0
        des3 = Cipher(
            decrepit_algorithms.TripleDES(key), modes.CBC(b"\0" * 8)
        ).encryptor()
        return des3.update(bytes(plaintext))

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        # type: (bytes, bytes) -> bytes
        assert len(ciphertext) % 8 == 0
        des3 = Cipher(
            decrepit_algorithms.TripleDES(key), modes.CBC(b"\0" * 8)
        ).decryptor()
        return des3.update(bytes(ciphertext))


class _SHA1DES3(_SimplifiedChecksum):
    macsize = 20
    enc = _DES3CBC


############
# RFC 3962 #
############


# RFC3962 sect 6


class _AESEncryptionType_SHA1_96(_SimplifiedEncryptionProfile, abc.ABCMeta):
    blocksize = 16
    padsize = 1
    macsize = 12
    hashmod = Hash_SHA

    @classmethod
    def string_to_key(cls, string, salt, params):
        # type: (bytes, bytes, Optional[bytes]) -> Key
        iterations = struct.unpack(">L", params or b"\x00\x00\x10\x00")[0]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=cls.seedsize,
            salt=salt,
            iterations=iterations,
        )
        tkey = cls.random_to_key(kdf.derive(string))
        return Key(
            cls.etype,
            key=cls.derive(tkey, b"kerberos"),
        )

    # basic_encrypt and basic_decrypt implement AES in CBC-CS3 mode

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        # type: (bytes, bytes) -> bytes
        assert len(plaintext) >= 16
        aes = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).encryptor()
        ctext = aes.update(_zeropad(bytes(plaintext), 16))
        if len(plaintext) > 16:
            # Swap the last two ciphertext blocks and truncate the
            # final block to match the plaintext length.
            lastlen = len(plaintext) % 16 or 16
            ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
        return ctext

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        # type: (bytes, bytes) -> bytes
        assert len(ciphertext) >= 16
        aes = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        if len(ciphertext) == 16:
            return aes.update(ciphertext)
        # Split the ciphertext into blocks.  The last block may be partial.
        cblocks = [
            bytearray(ciphertext[p : p + 16]) for p in range(0, len(ciphertext), 16)
        ]
        lastlen = len(cblocks[-1])
        # CBC-decrypt all but the last two blocks.
        prev_cblock = bytearray(16)
        plaintext = b""
        for bb in cblocks[:-2]:
            plaintext += _xorbytes(bytearray(aes.update(bytes(bb))), prev_cblock)
            prev_cblock = bb
        # Decrypt the second-to-last cipher block.  The left side of
        # the decrypted block will be the final block of plaintext
        # xor'd with the final partial cipher block; the right side
        # will be the omitted bytes of ciphertext from the final
        # block.
        bb = bytearray(aes.update(bytes(cblocks[-2])))
        lastplaintext = _xorbytes(bb[:lastlen], cblocks[-1])
        omitted = bb[lastlen:]
        # Decrypt the final cipher block plus the omitted bytes to get
        # the second-to-last plaintext block.
        plaintext += _xorbytes(
            bytearray(aes.update(bytes(cblocks[-1]) + bytes(omitted))), prev_cblock
        )
        return plaintext + lastplaintext


# RFC3962 sect 7


class _AES128CTS_SHA1_96(_AESEncryptionType_SHA1_96):
    etype = EncryptionType.AES128_CTS_HMAC_SHA1_96
    keysize = 16
    seedsize = 16
    reqcksum = ChecksumType.HMAC_SHA1_96_AES128


class _AES256CTS_SHA1_96(_AESEncryptionType_SHA1_96):
    etype = EncryptionType.AES256_CTS_HMAC_SHA1_96
    keysize = 32
    seedsize = 32
    reqcksum = ChecksumType.HMAC_SHA1_96_AES256


class _SHA1_96_AES128(_SimplifiedChecksum):
    macsize = 12
    enc = _AES128CTS_SHA1_96


class _SHA1_96_AES256(_SimplifiedChecksum):
    macsize = 12
    enc = _AES256CTS_SHA1_96


############
# RFC 4757 #
############

# RFC4757 sect 4


class _HMACMD5(_ChecksumProfile):
    macsize = 16

    @classmethod
    def checksum(cls, key, keyusage, text):
        # type: (Key, int, bytes) -> bytes
        ksign = Hmac_MD5(key.key).digest(b"signaturekey\0")
        md5hash = Hash_MD5().digest(_RC4.usage_str(keyusage) + text)
        return Hmac_MD5(ksign).digest(md5hash)

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        # type: (Key, int, bytes, bytes) -> None
        if key.etype not in [EncryptionType.RC4_HMAC, EncryptionType.RC4_HMAC_EXP]:
            raise ValueError("Wrong key type for checksum")
        super(_HMACMD5, cls).verify(key, keyusage, text, cksum)


# RFC4757 sect 5


class _RC4(_EncryptionAlgorithmProfile):
    etype = EncryptionType.RC4_HMAC
    keysize = 16
    seedsize = 16
    reqcksum = ChecksumType.HMAC_MD5
    export = False

    @staticmethod
    def usage_str(keyusage):
        # type: (int) -> bytes
        # Return a four-byte string for an RFC 3961 keyusage, using
        # the RFC 4757 rules sect 3. Per the errata, do not map 9 to 8.
        table = {3: 8, 23: 13}
        msusage = table[keyusage] if keyusage in table else keyusage
        return struct.pack("<I", msusage)

    @classmethod
    def string_to_key(cls, string, salt, params):
        # type: (bytes, bytes, Optional[bytes]) -> Key
        if params is not None and params != b"":
            raise ValueError("Invalid RC4 string-to-key parameters")
        utf16string = plain_str(string).encode("UTF-16LE")
        return Key(cls.etype, key=Hash_MD4().digest(utf16string))

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        # type: (Key, int, bytes, Optional[bytes]) -> bytes
        if confounder is None:
            confounder = os.urandom(8)
        if cls.export:
            ki = Hmac_MD5(key.key).digest(b"fortybits\x00" + cls.usage_str(keyusage))
        else:
            ki = Hmac_MD5(key.key).digest(cls.usage_str(keyusage))
        cksum = Hmac_MD5(ki).digest(confounder + plaintext)
        if cls.export:
            ki = ki[:7] + b"\xab" * 9
        ke = Hmac_MD5(ki).digest(cksum)
        rc4 = Cipher(algorithms.ARC4(ke), mode=None).encryptor()
        return cksum + rc4.update(bytes(confounder + plaintext))

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        # type: (Key, int, bytes) -> bytes
        if len(ciphertext) < 24:
            raise ValueError("ciphertext too short")
        cksum, basic_ctext = ciphertext[:16], ciphertext[16:]
        if cls.export:
            ki = Hmac_MD5(key.key).digest(b"fortybits\x00" + cls.usage_str(keyusage))
        else:
            ki = Hmac_MD5(key.key).digest(cls.usage_str(keyusage))
        if cls.export:
            kie = ki[:7] + b"\xab" * 9
        else:
            kie = ki
        ke = Hmac_MD5(kie).digest(cksum)
        rc4 = Cipher(decrepit_algorithms.ARC4(ke), mode=None).decryptor()
        basic_plaintext = rc4.update(bytes(basic_ctext))
        exp_cksum = Hmac_MD5(ki).digest(basic_plaintext)
        ok = _mac_equal(cksum, exp_cksum)
        if not ok and keyusage == 9:
            # Try again with usage 8, due to RFC 4757 errata.
            ki = Hmac_MD5(key.key).digest(struct.pack("<I", 8))
            exp_cksum = Hmac_MD5(ki).digest(basic_plaintext)
            ok = _mac_equal(cksum, exp_cksum)
        if not ok:
            raise InvalidChecksum("ciphertext integrity failure")
        # Discard the confounder.
        return bytes(basic_plaintext[8:])

    @classmethod
    def prf(cls, key, string):
        # type: (Key, bytes) -> bytes
        return Hmac_SHA(key.key).digest(string)


class _RC4_EXPORT(_RC4):
    etype = EncryptionType.RC4_HMAC_EXP
    export = True


############
# RFC 8009 #
############


class _AESEncryptionType_SHA256_SHA384(_AESEncryptionType_SHA1_96, abc.ABCMeta):
    enctypename = None  # type: bytes
    hashmod: _GenericHash = None  # Scapy
    _hashmod: hashes.HashAlgorithm = None  # Cryptography

    # Turn on RFC 8009 mode
    rfc8009 = True

    @classmethod
    def derive(cls, key, label, k, context=b""):  # type: ignore
        # type: (Key, bytes, int, bytes) -> bytes
        """
        Also known as "KDF-HMAC-SHA2" in RFC8009.
        """
        # RFC 8009 sect 3
        return SP800108_KDFCTR(
            K_I=key.key,
            Label=label,
            Context=context,
            L=k,
            hashmod=cls.hashmod,
        )

    @classmethod
    def string_to_key(cls, string, salt, params):
        # type: (bytes, bytes, Optional[bytes]) -> Key
        # RFC 8009 sect 4
        iterations = struct.unpack(">L", params or b"\x00\x00\x80\x00")[0]
        saltp = cls.enctypename + b"\x00" + salt
        kdf = PBKDF2HMAC(
            algorithm=cls._hashmod(),
            length=cls.seedsize,
            salt=saltp,
            iterations=iterations,
        )
        tkey = cls.random_to_key(kdf.derive(string))
        return Key(
            cls.etype,
            key=cls.derive(tkey, b"kerberos", cls.keysize * 8),
        )

    @classmethod
    def prf(cls, key, string):
        # type: (Key, bytes) -> bytes
        return cls.derive(key, b"prf", cls.hashmod.hash_len * 8, string)


class _AES128CTS_SHA256_128(_AESEncryptionType_SHA256_SHA384):
    etype = EncryptionType.AES128_CTS_HMAC_SHA256_128
    keysize = 16
    seedsize = 16
    macsize = 16
    reqcksum = ChecksumType.HMAC_SHA256_128_AES128
    # _AESEncryptionType_SHA256_SHA384 parameters
    enctypename = b"aes128-cts-hmac-sha256-128"
    hashmod = Hash_SHA256
    _hashmod = hashes.SHA256


class _AES256CTS_SHA384_192(_AESEncryptionType_SHA256_SHA384):
    etype = EncryptionType.AES256_CTS_HMAC_SHA384_192
    keysize = 32
    seedsize = 32
    macsize = 24
    reqcksum = ChecksumType.HMAC_SHA384_192_AES256
    # _AESEncryptionType_SHA256_SHA384 parameters
    enctypename = b"aes256-cts-hmac-sha384-192"
    hashmod = Hash_SHA384
    _hashmod = hashes.SHA384


class _SHA256_128_AES128(_SimplifiedChecksum):
    macsize = 16
    enc = _AES128CTS_SHA256_128
    rfc8009 = True


class _SHA384_182_AES256(_SimplifiedChecksum):
    macsize = 24
    enc = _AES256CTS_SHA384_192
    rfc8009 = True


##############
# Key object #
##############

_enctypes = {
    # DES_CBC_CRC - UNIMPLEMENTED
    EncryptionType.DES_CBC_MD5: _DESMD5,
    EncryptionType.DES_CBC_MD4: _DESMD4,
    # DES3_CBC_SHA1 - UNIMPLEMENTED
    EncryptionType.DES3_CBC_SHA1_KD: _DES3CBC,
    EncryptionType.AES128_CTS_HMAC_SHA1_96: _AES128CTS_SHA1_96,
    EncryptionType.AES256_CTS_HMAC_SHA1_96: _AES256CTS_SHA1_96,
    EncryptionType.AES128_CTS_HMAC_SHA256_128: _AES128CTS_SHA256_128,
    EncryptionType.AES256_CTS_HMAC_SHA384_192: _AES256CTS_SHA384_192,
    # CAMELLIA128-CTS-CMAC - UNIMPLEMENTED
    # CAMELLIA256-CTS-CMAC - UNIMPLEMENTED
    EncryptionType.RC4_HMAC: _RC4,
    EncryptionType.RC4_HMAC_EXP: _RC4_EXPORT,
}


_checksums = {
    ChecksumType.CRC32: _CRC32,
    # RSA_MD4 - UNIMPLEMENTED
    # RSA_MD4_DES - UNIMPLEMENTED
    # RSA_MD5 - UNIMPLEMENTED
    # RSA_MD5_DES - UNIMPLEMENTED
    # SHA1 - UNIMPLEMENTED
    ChecksumType.HMAC_SHA1_DES3_KD: _SHA1DES3,
    # HMAC_SHA1_DES3 - UNIMPLEMENTED
    ChecksumType.HMAC_SHA1_96_AES128: _SHA1_96_AES128,
    ChecksumType.HMAC_SHA1_96_AES256: _SHA1_96_AES256,
    # CMAC-CAMELLIA128 - UNIMPLEMENTED
    # CMAC-CAMELLIA256 - UNIMPLEMENTED
    ChecksumType.HMAC_SHA256_128_AES128: _SHA256_128_AES128,
    ChecksumType.HMAC_SHA384_192_AES256: _SHA384_182_AES256,
    ChecksumType.HMAC_MD5: _HMACMD5,
    0xFFFFFF76: _HMACMD5,
}


class Key(object):
    def __init__(
        self,
        etype: Union[EncryptionType, int, None] = None,
        key: bytes = b"",
        cksumtype: Union[ChecksumType, int, None] = None,
    ) -> None:
        """
        Kerberos Key object.

        :param etype: the EncryptionType
        :param cksumtype: the ChecksumType
        :param key: the bytes containing the key bytes for this Key.
        """
        assert etype or cksumtype, "Provide an etype or a cksumtype !"
        assert key, "Provide a key !"
        if isinstance(etype, int):
            etype = EncryptionType(etype)
        if isinstance(cksumtype, int):
            cksumtype = ChecksumType(cksumtype)
        self.etype = etype
        if etype is not None:
            try:
                self.ep = _enctypes[etype]
            except ValueError:
                raise ValueError("UNKNOWN/UNIMPLEMENTED etype '%s'" % etype)
            if len(key) != self.ep.keysize:
                raise ValueError(
                    "Wrong key length. Got %s. Expected %s"
                    % (len(key), self.ep.keysize)
                )
            if cksumtype is None and self.ep.reqcksum in _checksums:
                cksumtype = self.ep.reqcksum
        self.cksumtype = cksumtype
        if cksumtype is not None:
            try:
                self.cp = _checksums[cksumtype]
            except ValueError:
                raise ValueError("UNKNOWN/UNIMPLEMENTED cksumtype '%s'" % cksumtype)
            if self.etype is None and issubclass(self.cp, _SimplifiedChecksum):
                self.etype = self.cp.enc.etype  # type: ignore
        self.key = key

    def __repr__(self):
        # type: () -> str
        if self.etype:
            name = self.etype.name
        elif self.cksumtype:
            name = self.cksumtype.name
        else:
            return "<Key UNKNOWN>"
        return "<Key %s%s>" % (
            name,
            " (%s octets)" % len(self.key),
        )

    def encrypt(self, keyusage, plaintext, confounder=None, **kwargs):
        # type: (int, bytes, Optional[bytes], **Any) -> bytes
        """
        Encrypt data using the current Key.

        :param keyusage: the key usage
        :param plaintext: the plain text to encrypt
        :param confounder: (optional) choose the confounder. Otherwise random.
        """
        return self.ep.encrypt(self, keyusage, bytes(plaintext), confounder, **kwargs)

    def decrypt(self, keyusage, ciphertext, **kwargs):
        # type: (int, bytes, **Any) -> bytes
        """
        Decrypt data using the current Key.

        :param keyusage: the key usage
        :param ciphertext: the encrypted text to decrypt
        """
        # Throw InvalidChecksum on checksum failure.  Throw ValueError on
        # invalid key enctype or malformed ciphertext.
        return self.ep.decrypt(self, keyusage, ciphertext, **kwargs)

    def prf(self, string):
        # type: (bytes) -> bytes
        return self.ep.prf(self, string)

    def make_checksum(self, keyusage, text, cksumtype=None, **kwargs):
        # type: (int, bytes, Optional[int], **Any) -> bytes
        """
        Create a checksum using the current Key.

        :param keyusage: the key usage
        :param text: the text to create a checksum from
        :param cksumtype: (optional) override the checksum type
        """
        if cksumtype is not None and cksumtype != self.cksumtype:
            # Clone key and use a different cksumtype
            return Key(
                cksumtype=cksumtype,
                key=self.key,
            ).make_checksum(keyusage=keyusage, text=text, **kwargs)
        if self.cksumtype is None:
            raise ValueError("cksumtype not specified !")
        return self.cp.checksum(self, keyusage, text, **kwargs)

    def verify_checksum(self, keyusage, text, cksum, cksumtype=None):
        # type: (int, bytes, bytes, Optional[int]) -> None
        """
        Verify a checksum using the current Key.

        :param keyusage: the key usage
        :param text: the text to verify
        :param cksum: the expected checksum
        :param cksumtype: (optional) override the checksum type
        """
        if cksumtype is not None and cksumtype != self.cksumtype:
            # Clone key and use a different cksumtype
            return Key(
                cksumtype=cksumtype,
                key=self.key,
            ).verify_checksum(keyusage=keyusage, text=text, cksum=cksum)
        # Throw InvalidChecksum exception on checksum failure.  Throw
        # ValueError on invalid cksumtype, invalid key enctype, or
        # malformed checksum.
        if self.cksumtype is None:
            raise ValueError("cksumtype not specified !")
        self.cp.verify(self, keyusage, text, cksum)

    @classmethod
    def random_to_key(cls, etype, seed):
        # type: (EncryptionType, bytes) -> Key
        """
        random-to-key per RFC3961

        This is used to create a random Key from a seed.
        """
        try:
            ep = _enctypes[etype]
        except ValueError:
            raise ValueError("Unknown etype '%s'" % etype)
        if len(seed) != ep.seedsize:
            raise ValueError("Wrong crypto seed length")
        return ep.random_to_key(seed)

    @classmethod
    def string_to_key(cls, etype, string, salt, params=None):
        # type: (EncryptionType, bytes, bytes, Optional[bytes]) -> Key
        """
        string-to-key per RFC3961

        This is typically used to create a Key object from a password + salt
        """
        try:
            ep = _enctypes[etype]
        except ValueError:
            raise ValueError("Unknown etype '%s'" % etype)
        return ep.string_to_key(string, salt, params)


############
# RFC 6113 #
############


def KRB_FX_CF2(key1, key2, pepper1, pepper2):
    # type: (Key, Key, bytes, bytes) -> Key
    """
    KRB-FX-CF2 RFC6113
    """

    def prfplus(key, pepper):
        # type: (Key, bytes) -> bytes
        # Produce l bytes of output using the RFC 6113 PRF+ function.
        out = b""
        count = 1
        while len(out) < key.ep.seedsize:
            out += key.prf(chb(count) + pepper)
            count += 1
        return out[: key.ep.seedsize]

    return Key(
        key1.etype,
        key=bytes(
            _xorbytes(
                bytearray(prfplus(key1, pepper1)), bytearray(prfplus(key2, pepper2))
            )
        ),
    )
