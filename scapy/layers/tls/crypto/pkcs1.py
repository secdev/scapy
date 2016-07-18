## This file is part of Scapy
## Copyright (C) 2008 Arnaud Ebalard <arno@natisbad.org>
##         2015, 2016 Maxence Tury <maxence.tury@ssi.gouv.fr>
## This program is published under a GPLv2 license

"""
PKCS #1 methods as defined in RFC 3447.
"""

import os, popen2, tempfile
import math, random, struct
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from Crypto.Hash import MD2, MD4


#####################################################################
# Some helpers
#####################################################################

def _warning(m):
    print "WARNING: %s" % m

def randstring(l):
    """
    Returns a random string of length l (l >= 0)
    """
    tmp = map(lambda x: struct.pack("B", random.randrange(0, 256, 1)), [""]*l)
    return "".join(tmp)

def zerofree_randstring(l):
    """
    Returns a random string of length l (l >= 0) without zero in it.
    """
    tmp = map(lambda x: struct.pack("B", random.randrange(1, 256, 1)), [""]*l)
    return "".join(tmp)

def strxor(s1, s2):
    """
    Returns the binary XOR of the 2 provided strings s1 and s2. s1 and s2
    must be of same length.
    """
    return "".join(map(lambda x,y:chr(ord(x)^ord(y)), s1, s2))

def strand(s1, s2):
    """
    Returns the binary AND of the 2 provided strings s1 and s2. s1 and s2
    must be of same length.
    """
    return "".join(map(lambda x,y:chr(ord(x)&ord(y)), s1, s2))

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

# for every hash function a tuple is provided, giving access to
# - hash output length in byte
# - associated hash function that take data to be hashed as parameter
#   XXX I do not provide update() at the moment.
# - DER encoding of the leading bits of digestInfo (the hash value
#   will be concatenated to create the complete digestInfo).
#
# Notes:
# - MD4 asn.1 value should be verified. Also, as stated in
#   PKCS#1 v2.1, MD4 should not be used.
# - 'tls' one is the concatenation of both md5 and sha1 hashes used
#   by SSL/TLS when signing/verifying things
_hashFuncParams = {
    "md2"    : (16,
                MD2.new,
                lambda x: MD2.new(x).digest(),
                '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10'),
    "md4"    : (16,
                MD4.new,
                lambda x: MD4.new(x).digest(),
                '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x04\x05\x00\x04\x10'),
    "md5"    : (16,
                md5,
                lambda x: md5(x).digest(),
                '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'),
    "sha1"   : (20,
                sha1,
                lambda x: sha1(x).digest(),
                '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'),
    "sha224" : (28,
                sha224,
                lambda x: sha224(x).digest(),
                '\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c'),
    "sha256" : (32,
                sha256,
                lambda x: sha256(x).digest(),
                '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'),
    "sha384" : (48,
                sha384,
                lambda x: sha384(x).digest(),
                '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30'),
    "sha512" : (64,
                sha512,
                lambda x: sha512(x).digest(),
                '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'),
    "tls"    : (36,
                None,
                lambda x: md5(x).digest() + sha1(x).digest(),
                '')
    }

def mapHashFunc(hashStr):
    try:
        return _hashFuncParams[hashStr][1]
    except:
        raise Exception("Unknown hash function %s" % hashStr)


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
        _warning("pkcs_mgf1: invalid hash (%s) provided")
        return None
    hLen = _hashFuncParams[h][0]
    hFunc = _hashFuncParams[h][2]
    if maskLen > 2**32 * hLen:                               # 1)
        _warning("pkcs_mgf1: maskLen > 2**32 * hLen")
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
        _warning("encoding error (emLen < hLen + sLen + 2)")
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
        _warning("pkcs_emsa_pkcs1_v1_5_encode:"
                "intended encoded message length too short")
        return None
    PS = '\xff'*(emLen - tLen - 3)                           # 4)
    EM = '\x00' + '\x01' + PS + '\x00' + T                   # 5)
    return EM                                                # 6)


# XXX should add other pgf1 instance in a better fashion.

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


#####################################################################
# Public Key Cryptography related stuff
#####################################################################

class _EncryptAndVerifyRSA(object):
    ### Below are encryption methods

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

        n = self.modulus
        if isinstance(m, int):
            m = long(m)
        if (not isinstance(m, long)) or m > n-1:
            _warning("Key._rsaep() expects a long between 0 and n-1")
            return None

        return self.key.encrypt(m, "")[0]


    def _rsaes_pkcs1_v1_5_encrypt(self, M):
        """
        Implements RSAES-PKCS1-V1_5-ENCRYPT() function described in section
        7.2.1 of RFC 3447.

        Input:
           M: message to be encrypted, an octet string of length mLen, where
              mLen <= k-11 (k denotes the length in octets of the key modulus)

        Output:
           ciphertext, an octet string of length k

        On error, None is returned.
        """

        # 1) Length checking
        mLen = len(M)
        k = self.modulusLen / 8
        if mLen > k - 11:
            _warning("Key._rsaes_pkcs1_v1_5_encrypt(): message too "
                    "long (%d > %d - 11)" % (mLen, k))
            return None

        # 2) EME-PKCS1-v1_5 encoding
        PS = zerofree_randstring(k - mLen - 3)      # 2.a)
        EM = '\x00' + '\x02' + PS + '\x00' + M      # 2.b)

        # 3) RSA encryption
        m = pkcs_os2ip(EM)                          # 3.a)
        c = self._rsaep(m)                          # 3.b)
        C = pkcs_i2osp(c, k)                        # 3.c)

        return C                                    # 4)


    def _rsaes_oaep_encrypt(self, M, h=None, mgf=None, L=None):
        """
        Internal method providing RSAES-OAEP-ENCRYPT as defined in Sect.
        7.1.1 of RFC 3447. Not intended to be used directly. Please, see
        encrypt() method for type "OAEP".

        Input:
           M  : message to be encrypted, an octet string of length mLen
                where mLen <= k - 2*hLen - 2 (k denotes the length in octets
                of the RSA modulus and hLen the length in octets of the hash
                function output)
           h  : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
                'sha256', 'sha384'). hLen denotes the length in octets of
                the hash function output. 'sha1' is used by default if not
                provided.
           mgf: the mask generation function f : seed, maskLen -> mask
           L  : optional label to be associated with the message; the default
                value for L, if not provided is the empty string

        Output:
           ciphertext, an octet string of length k

        On error, None is returned.
        """
        # The steps below are the one described in Sect. 7.1.1 of RFC 3447.
        # 1) Length Checking
                                                    # 1.a) is not done
        mLen = len(M)
        if h is None:
            h = "sha1"
        if not _hashFuncParams.has_key(h):
            _warning("Key._rsaes_oaep_encrypt(): unknown hash function %s." % h)
            return None
        hLen = _hashFuncParams[h][0]
        hFun = _hashFuncParams[h][2]
        k = self.modulusLen / 8
        if mLen > k - 2*hLen - 2:                   # 1.b)
            _warning("Key._rsaes_oaep_encrypt(): message too long.")
            return None

        # 2) EME-OAEP encoding
        if L is None:                               # 2.a)
            L = ""
        lHash = hFun(L)
        PS = '\x00'*(k - mLen - 2*hLen - 2)         # 2.b)
        DB = lHash + PS + '\x01' + M                # 2.c)
        seed = randstring(hLen)                     # 2.d)
        if mgf is None:                             # 2.e)
            mgf = lambda x,y: pkcs_mgf1(x,y,h)
        dbMask = mgf(seed, k - hLen - 1)
        maskedDB = strxor(DB, dbMask)               # 2.f)
        seedMask = mgf(maskedDB, hLen)              # 2.g)
        maskedSeed = strxor(seed, seedMask)         # 2.h)
        EM = '\x00' + maskedSeed + maskedDB         # 2.i)

        # 3) RSA Encryption
        m = pkcs_os2ip(EM)                          # 3.a)
        c = self._rsaep(m)                          # 3.b)
        C = pkcs_i2osp(c, k)                        # 3.c)

        return C                                    # 4)


    def encrypt(self, m, t=None, h=None, mgf=None, L=None):
        """
        Encrypt message 'm' using 't' encryption scheme where 't' can be:

        - None: the message 'm' is directly applied the RSAEP encryption
                primitive, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 5.1.1. Simply put, the message undergo a modular
                exponentiation using the public key. Additionnal method
                parameters are just ignored.

        -'pkcs': the message 'm' is applied RSAES-PKCS1-V1_5-ENCRYPT encryption
                scheme as described in section 7.2.1 of RFC 3447. In that
                context, other parameters ('h', 'mgf', 'l') are not used.

        -'oaep': the message 'm' is applied the RSAES-OAEP-ENCRYPT encryption
                scheme, as described in PKCS#1 v2.1, i.e. RFC 3447 Sect
                7.1.1. In that context,

                o 'h' parameter provides the name of the hash method to use.
                  Possible values are "md2", "md4", "md5", "sha1", "tls",
                  "sha224", "sha256", "sha384" and "sha512". If none is
                  provided, sha1 is used.

                o 'mgf' is the mask generation function. By default, mgf
                  is derived from the provided hash function using the
                  generic MGF1 (see pkcs_mgf1() for details).

                o 'L' is the optional label to be associated with the message.
                  If not provided, the default value is used, i.e the empty
                  string. No check is done on the input limitation of the hash
                  function regarding the size of 'L' (for instance, 2^61 - 1
                  for SHA-1). You have been warned.
        """

        if t is None: # Raw encryption
            m = pkcs_os2ip(m)
            c = self._rsaep(m)
            return pkcs_i2osp(c, self.modulusLen/8)

        elif t == "pkcs":
            return self._rsaes_pkcs1_v1_5_encrypt(m)

        elif t == "oaep":
            return self._rsaes_oaep_encrypt(m, h, mgf, L)

        else:
            _warning("Key.encrypt(): Unknown encryption type (%s) provided" % t)
            return None

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
            _warning("Key._rsassa_pss_verify(): unknown hash function "
                    "provided (%s)" % h)
            return False
        if mgf is None: # use mgf1 with underlying hash function
            mgf = lambda x,y: pkcs_mgf1(x, y, h)
        if sLen is None: # use Hash output length (A.2.3 of RFC 3447)
            hLen = _hashFuncParams[h][0]
            sLen = hLen

        # 1) Length checking
        modBits = self.modulusLen
        k = modBits / 8
        if len(S) != k:
            return False

        # 2) RSA verification
        s = pkcs_os2ip(S)                           # 2.a)
        m = self._rsavp1(s)                         # 2.b)
        emLen = math.ceil((modBits - 1) / 8.)       # 2.c)
        EM = pkcs_i2osp(m, emLen)

        # 3) EMSA-PSS verification
        Result = pkcs_emsa_pss_verify(M, EM, modBits - 1, h, mgf, sLen)

        return Result                               # 4)


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
        k = self.modulusLen / 8
        if len(S) != k:
            _warning("invalid signature (len(S) != k)")
            return False

        # 2) RSA verification
        s = pkcs_os2ip(S)                           # 2.a)
        m = self._rsavp1(s)                         # 2.b)
        EM = pkcs_i2osp(m, k)                       # 2.c)

        # 3) EMSA-PKCS1-v1_5 encoding
        EMPrime = pkcs_emsa_pkcs1_v1_5_encode(M, k, h)
        if EMPrime is None:
            _warning("Key._rsassa_pkcs1_v1_5_verify(): unable to encode.")
            return False

        # 4) Comparison
        return EM == EMPrime


    def verify(self, M, S, t=None, h=None, mgf=None, sLen=None):
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
            n = self.modulus
            if S > n-1:
                _warning("Signature to be verified is too long for key modulus")
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
            _warning("Key.verify(): Unknown signature type (%s) provided" % t)
            return None

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

        n = self.modulus
        if isinstance(c, int):
            c = long(c)
        if (not isinstance(c, long)) or c > n-1:
            _warning("Key._rsaep() expects a long between 0 and n-1")
            return None

        return self.key.decrypt(c)


    def _rsaes_pkcs1_v1_5_decrypt(self, C):
        """
        Implements RSAES-PKCS1-V1_5-DECRYPT() function described in section
        7.2.2 of RFC 3447.

        Input:
           C: ciphertext to be decrypted, an octet string of length k, where
              k is the length in octets of the RSA modulus n.

        Output:
           an octet string of length k at most k - 11

        on error, None is returned.
        """

        # 1) Length checking
        cLen = len(C)
        k = self.modulusLen / 8
        if cLen != k or k < 11:
            _warning("Key._rsaes_pkcs1_v1_5_decrypt() decryption error "
                    "(cLen != k or k < 11)")
            return None

        # 2) RSA decryption
        c = pkcs_os2ip(C)                           # 2.a)
        m = self._rsadp(c)                          # 2.b)
        EM = pkcs_i2osp(m, k)                       # 2.c)

        # 3) EME-PKCS1-v1_5 decoding

        # I am aware of the note at the end of 7.2.2 regarding error
        # conditions reporting but the one provided below are for _local_
        # debugging purposes. --arno

        if EM[0] != '\x00':
            _warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(first byte is not 0x00)")
            return None

        if EM[1] != '\x02':
            _warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(second byte is not 0x02)")
            return None

        tmp = EM[2:].split('\x00', 1)
        if len(tmp) != 2:
            _warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(no 0x00 to separate PS from M)")
            return None

        PS, M = tmp
        if len(PS) < 8:
            _warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(PS is less than 8 byte long)")
            return None

        return M                                    # 4)


    def _rsaes_oaep_decrypt(self, C, h=None, mgf=None, L=None):
        """
        Internal method providing RSAES-OAEP-DECRYPT as defined in Sect.
        7.1.2 of RFC 3447. Not intended to be used directly. Please, see
        encrypt() method for type "OAEP".


        Input:
           C  : ciphertext to be decrypted, an octet string of length k, where
                k = 2*hLen + 2 (k denotes the byte length of the RSA modulus
                and hLen the byte length of the hash function output)
           h  : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
                'sha256', 'sha384'). 'sha1' is used if none is provided.
           mgf: the mask generation function f : seed, maskLen -> mask
           L  : optional label whose association with the message is to be
                verified; the default value for L, if not provided is the empty
                string.

        Output:
           message, an octet string of length k mLen, where mLen <= k-2*hLen-2

        On error, None is returned.
        """
        # The steps below are the one described in Sect. 7.1.2 of RFC 3447.

        # 1) Length Checking
                                                    # 1.a) is not done
        if h is None:
            h = "sha1"
        if not _hashFuncParams.has_key(h):
            _warning("Key._rsaes_oaep_decrypt(): unknown hash function %s.", h)
            return None
        hLen = _hashFuncParams[h][0]
        hFun = _hashFuncParams[h][2]
        k = self.modulusLen / 8
        cLen = len(C)
        if cLen != k:                               # 1.b)
            _warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(cLen != k)")
            return None
        if k < 2*hLen + 2:
            _warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(k < 2*hLen + 2)")
            return None

        # 2) RSA decryption
        c = pkcs_os2ip(C)                           # 2.a)
        m = self._rsadp(c)                          # 2.b)
        EM = pkcs_i2osp(m, k)                       # 2.c)

        # 3) EME-OAEP decoding
        if L is None:                               # 3.a)
            L = ""
        lHash = hFun(L)
        Y = EM[:1]                                  # 3.b)
        if Y != '\x00':
            _warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(Y is not zero)")
            return None
        maskedSeed = EM[1:1+hLen]
        maskedDB = EM[1+hLen:]
        if mgf is None:
            mgf = lambda x,y: pkcs_mgf1(x, y, h)
        seedMask = mgf(maskedDB, hLen)              # 3.c)
        seed = strxor(maskedSeed, seedMask)         # 3.d)
        dbMask = mgf(seed, k - hLen - 1)            # 3.e)
        DB = strxor(maskedDB, dbMask)               # 3.f)

        # I am aware of the note at the end of 7.1.2 regarding error
        # conditions reporting but the one provided below are for _local_
        # debugging purposes. --arno

        lHashPrime = DB[:hLen]                      # 3.g)
        tmp = DB[hLen:].split('\x01', 1)
        if len(tmp) != 2:
            _warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(0x01 separator not found)")
            return None
        PS, M = tmp
        if PS != '\x00'*len(PS):
            _warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(invalid padding string)")
            return None
        if lHash != lHashPrime:
            _warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(invalid hash)")
            return None
        return M                                    # 4)


    def decrypt(self, C, t=None, h=None, mgf=None, L=None):
        """
        Decrypt ciphertext 'C' using 't' decryption scheme where 't' can be:

        - None: the ciphertext 'C' is directly applied the RSADP decryption
                primitive, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 5.1.2. Simply, put the message undergo a modular
                exponentiation using the private key. Additionnal method
                parameters are just ignored.

        - 'pkcs': the ciphertext 'C' is applied RSAES-PKCS1-V1_5-DECRYPT
                decryption scheme as described in section 7.2.2 of RFC 3447.
                In that context, other parameters ('h', 'mgf', 'l') are not
                used.

        - 'oaep': the ciphertext 'C' is applied the RSAES-OAEP-DECRYPT
                decryption scheme, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 7.1.2. In that context,

                o 'h' parameter provides the name of the hash method to use.
                  Possible values are "md2", "md4", "md5", "sha1", "tls",
                  "sha224", "sha256", "sha384" and "sha512". If None is
                  provided, sha1 is used by default.

                o 'mgf' is the mask generation function. By default, mgf
                  is derived from the provided hash function using the
                  generic MGF1 (see pkcs_mgf1() for details).

                o 'L' is the optional label to be associated with the
                  message. If not provided, the default value is used, i.e
                  the empty string. No check is done on the input limitation
                  of the hash function regarding the size of 'L' (for
                  instance, 2^61 - 1 for SHA-1). You have been warned.
        """
        if t is None:
            C = pkcs_os2ip(C)
            c = self._rsadp(C)
            l = int(math.ceil(math.log(c, 2) / 8.)) # Hack
            return pkcs_i2osp(c, l)

        elif t == "pkcs":
            return self._rsaes_pkcs1_v1_5_decrypt(C)

        elif t == "oaep":
            return self._rsaes_oaep_decrypt(C, h, mgf, L)

        else:
            _warning("Key.decrypt(): Unknown decryption type (%s) provided" % t)
            return None

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
            _warning("Key._rsassa_pss_sign(): unknown hash function "
                    "provided (%s)" % h)
            return None
        if mgf is None: # use mgf1 with underlying hash function
            mgf = lambda x,y: pkcs_mgf1(x, y, h)
        if sLen is None: # use Hash output length (A.2.3 of RFC 3447)
            hLen = _hashFuncParams[h][0]
            sLen = hLen

        # 1) EMSA-PSS encoding
        modBits = self.modulusLen
        k = modBits / 8
        EM = pkcs_emsa_pss_encode(M, modBits - 1, h, mgf, sLen)
        if EM is None:
            _warning("Key._rsassa_pss_sign(): unable to encode")
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
        k = self.modulusLen / 8
        EM = pkcs_emsa_pkcs1_v1_5_encode(M, k, h)
        if EM is None:
            _warning("Key._rsassa_pkcs1_v1_5_sign(): unable to encode")
            return None

        # 2) RSA signature
        m = pkcs_os2ip(EM)                          # 2.a)
        s = self._rsasp1(m)                         # 2.b)
        S = pkcs_i2osp(s, k)                        # 2.c)

        return S                                    # 3)


    def sign(self, M, t=None, h=None, mgf=None, sLen=None):
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
            n = self.modulus
            if M > n-1:
                _warning("Message to be signed is too long for key modulus")
                return None
            s = self._rsasp1(M)
            if s is None:
                return None
            return pkcs_i2osp(s, self.modulusLen/8)

        elif t == "pkcs": # RSASSA-PKCS1-v1_5-SIGN
            if h is None:
                h = "sha1"
            return self._rsassa_pkcs1_v1_5_sign(M, h)

        elif t == "pss": # RSASSA-PSS-SIGN
            return self._rsassa_pss_sign(M, h, mgf, sLen)

        else:
            _warning("Key.sign(): Unknown signature type (%s) provided" % t)
            return None


