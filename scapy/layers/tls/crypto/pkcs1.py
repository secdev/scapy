## This file is part of Scapy
## Copyright (C) 2008 Arnaud Ebalard <arno@natisbad.org>
##         2015, 2016 Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
PKCS #1 methods as defined in RFC 3447.

XXX We cannot rely solely on the cryptography library, because it does not
support our "tls" hash used with TLS 1.0. Once it is added to (or from) the
library, most of the present module should be removed.
"""

import os, popen2, tempfile
import math, random, struct

from scapy.config import conf, crypto_validator
if conf.crypto_valid:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
else:
    InvalidSignature = dafault_backend = hashes = padding = None

from scapy.utils import randstring, zerofree_randstring, strxor, strand
from scapy.error import warning


#####################################################################
# Some helpers
#####################################################################

# OS2IP function defined in RFC 3447 for octet string to integer conversion
def pkcs_os2ip(x):
    """
    Accepts a byte string as input parameter and return the associated long
    value:

    Input : x        octet string to be converted

    Output: x        corresponding nonnegative integer

    Reverse function is pkcs_i2osp()
    """
    return int(x.encode("hex"), 16)

# I2OSP function defined in RFC 3447 for integer to octet string conversion
def pkcs_i2osp(x, xLen):
    """
    Converts a long (the first parameter) to the associated byte string
    representation of length l (second parameter). Basically, the length
    parameters allow the function to perform the associated padding.

    Input : x        nonnegative integer to be converted
            xLen     intended length of the resulting octet string

    Output: x        corresponding octet string

    Reverse function is pkcs_os2ip().
    """
    # The user is responsible for providing an appropriate xLen.
    #if x >= 256**xLen:
    #    raise Exception("Integer too large for provided xLen %d" % xLen)
    fmt = "%%0%dx" % (2*xLen)
    return (fmt % x).decode("hex")

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
# Hash functions
#####################################################################

# For every hash function a tuple is provided, giving access to
# - hash output length in byte
# - associated hash function that take data to be hashed as parameter
#   XXX I do not provide update() at the moment.
# - DER encoding of the leading bits of digestInfo (the hash value
#   will be concatenated to create the complete digestInfo).
#
# Note that 'tls' is the concatenation of both md5 and sha1 hashes used by
# SSL/TLS 1.0 when signing/verifying things.

_hashFuncParams = {}
if conf.crypto_valid:

    def _hashWrapper(hash_algo, message, backend=default_backend()):
        digest = hashes.Hash(hash_algo(), backend)
        digest.update(message)
        return digest.finalize()

    _hashFuncParams = {
        "md5"    : (16,
                    hashes.MD5,
                    lambda x: _hashWrapper(hashes.MD5, x),
                    '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'),
        "sha1"   : (20,
                    hashes.SHA1,
                    lambda x: _hashWrapper(hashes.SHA1, x),
                    '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'),
        "sha224" : (28,
                    hashes.SHA224,
                    lambda x: _hashWrapper(hashes.SHA224, x),
                    '\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c'),
        "sha256" : (32,
                    hashes.SHA256,
                    lambda x: _hashWrapper(hashes.SHA256, x),
                    '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'),
        "sha384" : (48,
                    hashes.SHA384,
                    lambda x: _hashWrapper(hashes.SHA384, x),
                    '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30'),
        "sha512" : (64,
                    hashes.SHA512,
                    lambda x: _hashWrapper(hashes.SHA512, x),
                    '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'),
        "tls"    : (36,
                    None,
                    lambda x: _hashWrapper(hashes.MD5, x) + _hashWrapper(hashes.SHA1, x),
                    '')
        }

def mapHashFunc(hashStr):
    if hashStr == "tls":
        raise Exception("mapHashFunc is not supposed to be called on 'tls'")
    try:
        return _hashFuncParams[hashStr][1]()
    except:
        raise Exception("Unknown hash function %s" % hashStr)


#####################################################################
# Some more PKCS helpers
#####################################################################

def pkcs_mgf1(mgfSeed, maskLen, h):
    """
    Implements generic MGF1 Mask Generation function as described in
    Appendix B.2.1 of RFC 3447. The hash function is passed by name.
    valid values are 'md2', 'md4', 'md5', 'sha1', 'tls, 'sha256',
    'sha384' and 'sha512'. Returns None on error.

    Input:
       mgfSeed: seed from which mask is generated, an octet string
       maskLen: intended length in octets of the mask, at most 2^32 * hLen
                hLen (see below)
       h      : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
                'sha256', 'sha384'). hLen denotes the length in octets of
                the hash function output.

    Output:
       an octet string of length maskLen
    """

    # steps are those of Appendix B.2.1
    if not _hashFuncParams.has_key(h):
        warning("pkcs_mgf1: invalid hash (%s) provided" % h)
        return None
    hLen = _hashFuncParams[h][0]
    hFunc = _hashFuncParams[h][2]
    if maskLen > 2**32 * hLen:                               # 1)
        warning("pkcs_mgf1: maskLen > 2**32 * hLen")
        return None
    T = ""                                                   # 2)
    maxCounter = math.ceil(float(maskLen) / float(hLen))     # 3)
    counter = 0
    while counter < maxCounter:
        C = pkcs_i2osp(counter, 4)
        T += hFunc(mgfSeed + C)
        counter += 1
    return T[:maskLen]


def pkcs_emsa_pss_encode(M, emBits, h, mgf, sLen):
    """
    Implements EMSA-PSS-ENCODE() function described in Sect. 9.1.1 of RFC 3447

    Input:
       M     : message to be encoded, an octet string
       emBits: maximal bit length of the integer resulting of pkcs_os2ip(EM),
               where EM is the encoded message, output of the function.
       h     : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
               'sha256', 'sha384'). hLen denotes the length in octets of
               the hash function output.
       mgf   : the mask generation function f : seed, maskLen -> mask
       sLen  : intended length in octets of the salt

    Output:
       encoded message, an octet string of length emLen = ceil(emBits/8)

    On error, None is returned.
    """

    # 1) is not done
    hLen = _hashFuncParams[h][0]                             # 2)
    hFunc = _hashFuncParams[h][2]
    mHash = hFunc(M)
    emLen = int(math.ceil(emBits/8.))
    if emLen < hLen + sLen + 2:                              # 3)
        warning("encoding error (emLen < hLen + sLen + 2)")
        return None
    salt = randstring(sLen)                                  # 4)
    MPrime = '\x00'*8 + mHash + salt                         # 5)
    H = hFunc(MPrime)                                        # 6)
    PS = '\x00'*(emLen - sLen - hLen - 2)                    # 7)
    DB = PS + '\x01' + salt                                  # 8)
    dbMask = mgf(H, emLen - hLen - 1)                        # 9)
    maskedDB = strxor(DB, dbMask)                            # 10)
    l = (8*emLen - emBits)/8                                 # 11)
    rem = 8*emLen - emBits - 8*l # additionnal bits
    andMask = l*'\x00'
    if rem:
        j = chr(reduce(lambda x,y: x+y, map(lambda x: 1<<x, range(8-rem))))
        andMask += j
        l += 1
    maskedDB = strand(maskedDB[:l], andMask) + maskedDB[l:]
    EM = maskedDB + H + '\xbc'                               # 12)
    return EM                                                # 13)


def pkcs_emsa_pss_verify(M, EM, emBits, h, mgf, sLen):
    """
    Implements EMSA-PSS-VERIFY() function described in Sect. 9.1.2 of RFC 3447

    Input:
       M     : message to be encoded, an octet string
       EM    : encoded message, an octet string of length emLen=ceil(emBits/8)
       emBits: maximal bit length of the integer resulting of pkcs_os2ip(EM)
       h     : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
               'sha256', 'sha384'). hLen denotes the length in octets of
               the hash function output.
       mgf   : the mask generation function f : seed, maskLen -> mask
       sLen  : intended length in octets of the salt

    Output:
       True if the verification is ok, False otherwise.
    """

    # 1) is not done
    hLen = _hashFuncParams[h][0]                             # 2)
    hFunc = _hashFuncParams[h][2]
    mHash = hFunc(M)
    emLen = int(math.ceil(emBits/8.))                        # 3)
    if emLen < hLen + sLen + 2:
        return False
    if EM[-1] != '\xbc':                                     # 4)
        return False
    l = emLen - hLen - 1                                     # 5)
    maskedDB = EM[:l]
    H = EM[l:l+hLen]
    l = (8*emLen - emBits)/8                                 # 6)
    rem = 8*emLen - emBits - 8*l # additionnal bits
    andMask = l*'\xff'
    if rem:
        val = reduce(lambda x,y: x+y, map(lambda x: 1<<x, range(8-rem)))
        j = chr(~val & 0xff)
        andMask += j
        l += 1
    if strand(maskedDB[:l], andMask) != '\x00'*l:
        return False
    dbMask = mgf(H, emLen - hLen - 1)                        # 7)
    DB = strxor(maskedDB, dbMask)                            # 8)
    l = (8*emLen - emBits)/8                                 # 9)
    rem = 8*emLen - emBits - 8*l # additionnal bits
    andMask = l*'\x00'
    if rem:
        j = chr(reduce(lambda x,y: x+y, map(lambda x: 1<<x, range(8-rem))))
        andMask += j
        l += 1
    DB = strand(DB[:l], andMask) + DB[l:]
    l = emLen - hLen - sLen - 1                              # 10)
    if DB[:l] != '\x00'*(l-1) + '\x01':
        return False
    salt = DB[-sLen:]                                        # 11)
    MPrime = '\x00'*8 + mHash + salt                         # 12)
    HPrime = hFunc(MPrime)                                   # 13)
    return H == HPrime                                       # 14)


def pkcs_emsa_pkcs1_v1_5_encode(M, emLen, h): # section 9.2 of RFC 3447
    """
    Implements EMSA-PKCS1-V1_5-ENCODE() function described in Sect.
    9.2 of RFC 3447.

    Input:
       M    : message to be encode, an octet string
       emLen: intended length in octets of the encoded message, at least
              tLen + 11, where tLen is the octet length of the DER encoding
              T of a certain value computed during the encoding operation.
       h    : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
              'sha256', 'sha384'). hLen denotes the length in octets of
              the hash function output.

    Output:
       encoded message, an octet string of length emLen

    On error, None is returned.
    """
    hLen = _hashFuncParams[h][0]                             # 1)
    hFunc = _hashFuncParams[h][2]
    H = hFunc(M)
    hLeadingDigestInfo = _hashFuncParams[h][3]               # 2)
    T = hLeadingDigestInfo + H
    tLen = len(T)
    if emLen < tLen + 11:                                    # 3)
        warning("pkcs_emsa_pkcs1_v1_5_encode:"
                "intended encoded message length too short")
        return None
    PS = '\xff'*(emLen - tLen - 3)                           # 4)
    EM = '\x00' + '\x01' + PS + '\x00' + T                   # 5)
    return EM                                                # 6)


#####################################################################
# Asymmetric Cryptography wrappers
#####################################################################

class _EncryptAndVerifyRSA(object):

    def _rsaep(self, m):
        """
        Internal method providing raw RSA encryption, i.e. simple modular
        exponentiation of the given message representative 'm', a long
        between 0 and n-1.

        This is the encryption primitive RSAEP described in PKCS#1 v2.1,
        i.e. RFC 3447 Sect. 5.1.1.

        Input:
           m: message representative, a long between 0 and n-1, where
              n is the key modulus.

        Output:
           ciphertext representative, a long between 0 and n-1

        Not intended to be used directly. Please, see encrypt() method.
        """

        n = self._modulus
        if isinstance(m, int):
            m = long(m)
        if (not isinstance(m, long)) or m > n-1:
            warning("Key._rsaep() expects a long between 0 and n-1")
            return None

        return pow(m, self._pubExp, n)


    @crypto_validator
    def encrypt(self, m, t="pkcs", h=None, mgf=None, L=None):
        if h == "tls" or t is None:
            #return self.encrypt_legacy(m, t=t, h=h, mgf=mgf, L=L)
            warning("Cannot call encrypt_legacy anymore.")
            return None

        if h is not None:
            h = mapHashFunc(h)

        if t == "pkcs":
            pad = padding.PKCS1v15()
        elif t == "oaep":
            pad = padding.OAEP(mgf=mgf(h), algorithm=h, label=L)
        else:
            warning("Key.encrypt(): Unknown encryption type (%s) provided" % t)
            return None
        return self.pubkey.encrypt(m, pad)


    ### Below are verification related methods

    def _rsavp1(self, s):
        """
        Internal method providing raw RSA verification, i.e. simple modular
        exponentiation of the given signature representative 'c', an integer
        between 0 and n-1.

        This is the signature verification primitive RSAVP1 described in
        PKCS#1 v2.1, i.e. RFC 3447 Sect. 5.2.2.

        Input:
          s: signature representative, an integer between 0 and n-1,
             where n is the key modulus.

        Output:
           message representative, an integer between 0 and n-1

        Not intended to be used directly. Please, see verify() method.
        """
        return self._rsaep(s)

    def _rsassa_pss_verify(self, M, S, h=None, mgf=None, sLen=None):
        """
        Implements RSASSA-PSS-VERIFY() function described in Sect 8.1.2
        of RFC 3447

        Input:
           M: message whose signature is to be verified
           S: signature to be verified, an octet string of length k, where k
              is the length in octets of the RSA modulus n.

        Output:
           True is the signature is valid. False otherwise.
        """

        # Set default parameters if not provided
        if h is None: # By default, sha1
            h = "sha1"
        if not _hashFuncParams.has_key(h):
            warning("Key._rsassa_pss_verify(): unknown hash function "
                    "provided (%s)" % h)
            return False
        if mgf is None: # use mgf1 with underlying hash function
            mgf = lambda x,y: pkcs_mgf1(x, y, h)
        if sLen is None: # use Hash output length (A.2.3 of RFC 3447)
            hLen = _hashFuncParams[h][0]
            sLen = hLen

        # 1) Length checking
        modBits = self._modulusLen
        k = modBits / 8
        if len(S) != k:
            return False

        # 2) RSA verification
        s = pkcs_os2ip(S)                           # 2.a)
        m = self._rsavp1(s)                         # 2.b)
        emLen = math.ceil((modBits - 1) / 8.)       # 2.c)
        EM = pkcs_i2osp(m, emLen)

        # 3) EMSA-PSS verification
        result = pkcs_emsa_pss_verify(M, EM, modBits - 1, h, mgf, sLen)

        return result                               # 4)


    def _rsassa_pkcs1_v1_5_verify(self, M, S, h):
        """
        Implements RSASSA-PKCS1-v1_5-VERIFY() function as described in
        Sect. 8.2.2 of RFC 3447.

        Input:
           M: message whose signature is to be verified, an octet string
           S: signature to be verified, an octet string of length k, where
              k is the length in octets of the RSA modulus n
           h: hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
                'sha256', 'sha384').

        Output:
           True if the signature is valid. False otherwise.
        """

        # 1) Length checking
        k = self._modulusLen / 8
        if len(S) != k:
            warning("invalid signature (len(S) != k)")
            return False

        # 2) RSA verification
        s = pkcs_os2ip(S)                           # 2.a)
        m = self._rsavp1(s)                         # 2.b)
        EM = pkcs_i2osp(m, k)                       # 2.c)

        # 3) EMSA-PKCS1-v1_5 encoding
        EMPrime = pkcs_emsa_pkcs1_v1_5_encode(M, k, h)
        if EMPrime is None:
            warning("Key._rsassa_pkcs1_v1_5_verify(): unable to encode.")
            return False

        # 4) Comparison
        return EM == EMPrime


    def verify_legacy(self, M, S, t=None, h=None, mgf=None, sLen=None):
        """
        Verify alleged signature 'S' is indeed the signature of message 'M'
        using 't' signature scheme where 't' can be:

        - None: the alleged signature 'S' is directly applied the RSAVP1
                signature primitive, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 5.2.1. Simply put, the provided signature is applied a
                modular exponentiation using the public key. Then, a comparison
                of the result is done against 'M'. On match, True is returned.
                Additional method parameters are just ignored.

        -'pkcs': the alleged signature 'S' and message 'M' are applied
                RSASSA-PKCS1-v1_5-VERIFY signature verification scheme as
                described in Sect. 8.2.2 of RFC 3447. In that context, the hash
                function name is passed using 'h'. Possible values are "md2",
                "md4", "md5", "sha1", "tls", "sha224", "sha256", "sha384" and
                "sha512". If none is provided, sha1 is used. Other additional
                parameters are ignored.

        -'pss': the alleged signature 'S' and message 'M' are applied
                RSASSA-PSS-VERIFY signature scheme as described in Sect. 8.1.2.
                of RFC 3447. In that context,

                o 'h' parameter provides the name of the hash method to use.
                   Possible values are "md2", "md4", "md5", "sha1", "tls",
                   "sha224", "sha256", "sha384" and "sha512". If None is
                   provided, sha1 is used.

                o 'mgf' is the mask generation function. By default, mgf
                   is derived from the provided hash function using the
                   generic MGF1 (see pkcs_mgf1() for details).

                o 'sLen' is the byte length of the salt. You can overload the
                  default value (the byte length of the hash value for provided
                  algorithm) by providing another one with that parameter.
        """
        if t is None: # RSAVP1
            S = pkcs_os2ip(S)
            n = self._modulus
            if S > n-1:
                warning("Signature to be verified is too long for key modulus")
                return False
            m = self._rsavp1(S)
            if m is None:
                return False
            l = int(math.ceil(math.log(m, 2) / 8.)) # Hack
            m = pkcs_i2osp(m, l)
            return M == m
        elif t == "pkcs": # RSASSA-PKCS1-v1_5-VERIFY
            if h is None:
                h = "sha1"
            return self._rsassa_pkcs1_v1_5_verify(M, S, h)
        elif t == "pss": # RSASSA-PSS-VERIFY
            return self._rsassa_pss_verify(M, S, h, mgf, sLen)
        else:
            warning("Key.verify(): Unknown signature type (%s) provided" % t)
            return None

    @crypto_validator
    def verify(self, M, S, t="pkcs", h=None, mgf=None, sLen=None):
        if h == "tls" or t is None:
            return self.verify_legacy(M, S, t=t, h=h, mgf=mgf, sLen=sLen)

        if h is not None:
            h = mapHashFunc(h)

        if t == "pkcs": # RSASSA-PKCS1-v1_5-VERIFY
            pad = padding.PKCS1v15()
        elif t == "pss": # RSASSA-PSS-VERIFY
            pad = padding.PSS(mgf=mgf(h), salt_length=sLen)
        else:
            warning("Key.verify(): Unknown signature type (%s) provided" % t)
            return None

        try:
            self.pubkey.verify(signature=S, data=M, padding=pad, algorithm=h)
            return True
        except InvalidSignature:
            return False


class _DecryptAndSignRSA(object):
    ### Below are decryption related methods. Encryption ones are inherited
    ### from PubKey

    def _rsadp(self, c):
        """
        Internal method providing raw RSA decryption, i.e. simple modular
        exponentiation of the given ciphertext representative 'c', a long
        between 0 and n-1.

        This is the decryption primitive RSADP described in PKCS#1 v2.1,
        i.e. RFC 3447 Sect. 5.1.2.

        Input:
           c: ciphertest representative, a long between 0 and n-1, where
              n is the key modulus.

        Output:
           message representative, a long between 0 and n-1

        Not intended to be used directly. Please, see decrypt() method.
        """

        n = self._modulus
        if isinstance(c, int):
            c = long(c)
        if (not isinstance(c, long)) or c > n-1:
            warning("Key._rsaep() expects a long between 0 and n-1")
            return None

        privExp = self.key.private_numbers().d
        return pow(c, privExp, n)


    def decrypt(self, C, t="pkcs", h=None, mgf=None, L=None):
        if h == "tls" or t is None:
            #return self.decrypt_legacy(C, t=t, h=h, mgf=mgf, L=L)
            warning("Cannot call decrypt_legacy anymore.")
            return None

        if h is not None:
            h = mapHashFunc(h)

        if t == "pkcs":
            pad = padding.PKCS1v15()
        elif t == "oaep":
            pad = padding.OAEP(mgf=mgf(h), algorithm=h, label=L)
        else:
            warning("Key.decrypt(): Unknown decryption type (%s) provided" % t)
            return None
        return self.key.decrypt(C, pad)


    ### Below are signature related methods.
    ### Verification methods are inherited from PubKey.

    def _rsasp1(self, m):
        """
        Internal method providing raw RSA signature, i.e. simple modular
        exponentiation of the given message representative 'm', an integer
        between 0 and n-1.

        This is the signature primitive RSASP1 described in PKCS#1 v2.1,
        i.e. RFC 3447 Sect. 5.2.1.

        Input:
           m: message representative, an integer between 0 and n-1, where
              n is the key modulus.

        Output:
           signature representative, an integer between 0 and n-1

        Not intended to be used directly. Please, see sign() method.
        """
        return self._rsadp(m)


    def _rsassa_pss_sign(self, M, h=None, mgf=None, sLen=None):
        """
        Implements RSASSA-PSS-SIGN() function described in Sect. 8.1.1 of
        RFC 3447.

        Input:
           M: message to be signed, an octet string

        Output:
           signature, an octet string of length k, where k is the length in
           octets of the RSA modulus n.

        On error, None is returned.
        """

        # Set default parameters if not provided
        if h is None: # By default, sha1
            h = "sha1"
        if not _hashFuncParams.has_key(h):
            warning("Key._rsassa_pss_sign(): unknown hash function "
                    "provided (%s)" % h)
            return None
        if mgf is None: # use mgf1 with underlying hash function
            mgf = lambda x,y: pkcs_mgf1(x, y, h)
        if sLen is None: # use Hash output length (A.2.3 of RFC 3447)
            hLen = _hashFuncParams[h][0]
            sLen = hLen

        # 1) EMSA-PSS encoding
        modBits = self._modulusLen
        k = modBits / 8
        EM = pkcs_emsa_pss_encode(M, modBits - 1, h, mgf, sLen)
        if EM is None:
            warning("Key._rsassa_pss_sign(): unable to encode")
            return None

        # 2) RSA signature
        m = pkcs_os2ip(EM)                          # 2.a)
        s = self._rsasp1(m)                         # 2.b)
        S = pkcs_i2osp(s, k)                        # 2.c)

        return S                                    # 3)


    def _rsassa_pkcs1_v1_5_sign(self, M, h):
        """
        Implements RSASSA-PKCS1-v1_5-SIGN() function as described in
        Sect. 8.2.1 of RFC 3447.

        Input:
           M: message to be signed, an octet string
           h: hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls'
                'sha256', 'sha384').

        Output:
           the signature, an octet string.
        """

        # 1) EMSA-PKCS1-v1_5 encoding
        k = self._modulusLen / 8
        EM = pkcs_emsa_pkcs1_v1_5_encode(M, k, h)
        if EM is None:
            warning("Key._rsassa_pkcs1_v1_5_sign(): unable to encode")
            return None

        # 2) RSA signature
        m = pkcs_os2ip(EM)                          # 2.a)
        s = self._rsasp1(m)                         # 2.b)
        S = pkcs_i2osp(s, k)                        # 2.c)

        return S                                    # 3)


    def sign_legacy(self, M, t=None, h=None, mgf=None, sLen=None):
        """
        Sign message 'M' using 't' signature scheme where 't' can be:

        - None: the message 'M' is directly applied the RSASP1 signature
                primitive, as described in PKCS#1 v2.1, i.e. RFC 3447 Sect
                5.2.1. Simply put, the message undergo a modular exponentiation
                using the private key. Additional method parameters are just
                ignored.

        - 'pkcs': the message 'M' is applied RSASSA-PKCS1-v1_5-SIGN signature
                scheme as described in Sect. 8.2.1 of RFC 3447. In that
                context, the hash function name is passed using 'h'. Possible
                values are "md2", "md4", "md5", "sha1", "tls", "sha224",
                "sha256", "sha384" and "sha512". If none is provided, sha1 is
                used. Other additional parameters are ignored.

        - 'pss' : the message 'M' is applied RSASSA-PSS-SIGN signature scheme
                as described in Sect. 8.1.1. of RFC 3447. In that context,

                o 'h' parameter provides the name of the hash method to use.
                   Possible values are "md2", "md4", "md5", "sha1", "tls",
                   "sha224", "sha256", "sha384" and "sha512". If None is
                   provided, sha1 is used.

                o 'mgf' is the mask generation function. By default, mgf
                   is derived from the provided hash function using the
                   generic MGF1 (see pkcs_mgf1() for details).

                o 'sLen' is the byte length of the salt. You can overload the
                  default value (the byte length of the hash value for provided
                  algorithm) by providing another one with that parameter.
        """
        if t is None: # RSASP1
            M = pkcs_os2ip(M)
            n = self._modulus
            if M > n-1:
                warning("Message to be signed is too long for key modulus")
                return None
            s = self._rsasp1(M)
            if s is None:
                return None
            return pkcs_i2osp(s, self._modulusLen/8)
        elif t == "pkcs": # RSASSA-PKCS1-v1_5-SIGN
            if h is None:
                h = "sha1"
            return self._rsassa_pkcs1_v1_5_sign(M, h)
        elif t == "pss": # RSASSA-PSS-SIGN
            return self._rsassa_pss_sign(M, h, mgf, sLen)
        else:
            warning("Key.sign(): Unknown signature type (%s) provided" % t)
            return None

    def sign(self, M, t="pkcs", h=None, mgf=None, sLen=None):
        if h == "tls" or t is None:
            return self.sign_legacy(M, t=t, h=h, mgf=mgf, sLen=sLen)

        if h is not None:
            h = mapHashFunc(h)

        if t == "pkcs": # RSASSA-PKCS1-v1_5-SIGN
            pad = padding.PKCS1v15()
        elif t == "pss": # RSASSA-PSS-SIGN
            pad = padding.PSS(mgf=mgf(h), salt_length=sLen)
        else:
            warning("Key.sign(): Unknown signature type (%s) provided" % t)
            return None
        return self.key.sign(M, pad, h)



#####################################################################
# CA files helpers
#####################################################################

def create_ca_file(anchor_list, filename):
    """
    Concatenate all the certificates (PEM format for the export) in
    'anchor_list' and write the result to file 'filename'. On success
    'filename' is returned, None otherwise.

    If you are used to OpenSSL tools, this function builds a CAfile
    that can be used for certificate and CRL check.

    Also see create_temporary_ca_file().
    """
    try:
        f = open(filename, "w")
        for a in anchor_list:
            s = a.output(fmt="PEM")
            f.write(s)
        f.close()
    except:
        return None
    return filename

def create_temporary_ca_file(anchor_list):
    """
    Concatenate all the certificates (PEM format for the export) in
    'anchor_list' and write the result to file to a temporary file
    using mkstemp() from tempfile module. On success 'filename' is
    returned, None otherwise.

    If you are used to OpenSSL tools, this function builds a CAfile
    that can be used for certificate and CRL check.
    """
    try:
        f, fname = tempfile.mkstemp()
        for a in anchor_list:
            s = a.output(fmt="PEM")
            l = os.write(f, s)
        os.close(f)
    except:
        return None
    return fname

def create_temporary_ca_path(anchor_list, folder):
    """
    Create a CA path folder as defined in OpenSSL terminology, by
    storing all certificates in 'anchor_list' list in PEM format
    under provided 'folder' and then creating the associated links
    using the hash as usually done by c_rehash.

    Note that you can also include CRL in 'anchor_list'. In that
    case, they will also be stored under 'folder' and associated
    links will be created.

    In folder, the files are created with names of the form
    0...ZZ.pem. If you provide an empty list, folder will be created
    if it does not already exist, but that's all.

    The number of certificates written to folder is returned on
    success, None on error.
    """
    # We should probably avoid writing duplicate anchors and also
    # check if they are all certs.
    try:
        if not os.path.isdir(folder):
            os.makedirs(folder)
    except:
        return None

    l = len(anchor_list)
    if l == 0:
        return None
    fmtstr = "%%0%sd.pem" % math.ceil(math.log(l, 10))
    i = 0
    try:
        for a in anchor_list:
            fname = os.path.join(folder, fmtstr % i)
            f = open(fname, "w")
            s = a.output(fmt="PEM")
            f.write(s)
            f.close()
            i += 1
    except:
        return None

    r,w=popen2.popen2("c_rehash %s" % folder)
    r.close(); w.close()

    return l

