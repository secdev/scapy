## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Arnaud Ebalard <arno@natisbad.org>
## This program is published under a GPLv2 license

"""
Cryptographic certificates.
"""

import os, sys, math, socket, struct, hmac, string, time, random, tempfile
from subprocess import Popen, PIPE
from scapy.utils import strxor
try:
    HAS_HASHLIB=True
    import hashlib
except:
    HAS_HASHLIB=False

from Crypto.PublicKey import *
from Crypto.Cipher import *
from Crypto.Hash import *
from Crypto.Util import number

# Maximum allowed size in bytes for a certificate file, to avoid
# loading huge file when importing a cert
MAX_KEY_SIZE=50*1024
MAX_CERT_SIZE=50*1024
MAX_CRL_SIZE=10*1024*1024   # some are that big

#####################################################################
# Some helpers
#####################################################################

def popen3(cmd):
    p = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE,
              close_fds=True)
    return p.stdout, p.stdin, p.stderr

def warning(m):
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
    return number.bytes_to_long(x) 

# IP2OS function defined in RFC 3447 for octet string to integer conversion
def pkcs_i2osp(x,xLen):
    """
    Converts a long (the first parameter) to the associated byte string
    representation of length l (second parameter). Basically, the length
    parameters allow the function to perform the associated padding.

    Input : x        nonnegative integer to be converted
            xLen     intended length of the resulting octet string

    Output: x        corresponding nonnegative integer

    Reverse function is pkcs_os2ip().
    """
    z = number.long_to_bytes(x)
    padlen = max(0, xLen-len(z))
    return '\x00'*padlen + z

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
# - hashlib is available from http://code.krypto.org/python/hashlib/
# - 'tls' one is the concatenation of both md5 and sha1 hashes used
#   by SSL/TLS when signing/verifying things
_hashFuncParams = {
    "md2"    : (16, 
                lambda x: MD2.new(x).digest(), 
                '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10'),
    "md4"    : (16, 
                lambda x: MD4.new(x).digest(), 
                '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x04\x05\x00\x04\x10'), # is that right ?
    "md5"    : (16, 
                lambda x: MD5.new(x).digest(), 
                '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'),
    "sha1"   : (20,
                lambda x: SHA.new(x).digest(), 
                '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'),
    "tls"    : (36,
                lambda x: MD5.new(x).digest() + SHA.new(x).digest(),
                '') }

if HAS_HASHLIB:
    _hashFuncParams["sha224"] = (28, 
                lambda x: hashlib.sha224(x).digest(),
                '\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c')
    _hashFuncParams["sha256"] = (32, 
                lambda x: hashlib.sha256(x).digest(), 
                '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20')
    _hashFuncParams["sha384"] = (48, 
                lambda x: hashlib.sha384(x).digest(),
               '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30')
    _hashFuncParams["sha512"] = (64, 
               lambda x: hashlib.sha512(x).digest(),
               '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40')
else:
    warning("hashlib support is not available. Consider installing it")
    warning("if you need sha224, sha256, sha384 and sha512 algs.")
    
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
        warning("pkcs_mgf1: invalid hash (%s) provided")
        return None
    hLen = _hashFuncParams[h][0]
    hFunc = _hashFuncParams[h][1]
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
    hFunc = _hashFuncParams[h][1]
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
       EM    : encoded message, an octet string of length emLen = ceil(emBits/8)
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
    hFunc = _hashFuncParams[h][1]
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
    hFunc = _hashFuncParams[h][1]
    H = hFunc(M)
    hLeadingDigestInfo = _hashFuncParams[h][2]               # 2)
    T = hLeadingDigestInfo + H
    tLen = len(T)
    if emLen < tLen + 11:                                    # 3)
        warning("pkcs_emsa_pkcs1_v1_5_encode: intended encoded message length too short")
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

    Also see create_temporary_ca_file().
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

    r,w,e=popen3(["c_rehash", folder])
    r.close(); w.close(); e.close()

    return l


#####################################################################
# Public Key Cryptography related stuff
#####################################################################

class OSSLHelper:
    def _apply_ossl_cmd(self, osslcmd, rawdata):
        r,w,e=popen3(osslcmd)
        w.write(rawdata)
        w.close()
        res = r.read()
        r.close()
        e.close()
        return res

class _EncryptAndVerify:
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
        if type(m) is int:
            m = long(m)
        if type(m) is not long or m > n-1:
            warning("Key._rsaep() expects a long between 0 and n-1")
            return None

        return self.key.encrypt(m, "")[0]


    def _rsaes_pkcs1_v1_5_encrypt(self, M):
        """
        Implements RSAES-PKCS1-V1_5-ENCRYPT() function described in section
        7.2.1 of RFC 3447.

        Input:
           M: message to be encrypted, an octet string of length mLen, where
              mLen <= k - 11 (k denotes the length in octets of the key modulus)

        Output:
           ciphertext, an octet string of length k

        On error, None is returned.
        """

        # 1) Length checking
        mLen = len(M)
        k = self.modulusLen / 8
        if mLen > k - 11:
            warning("Key._rsaes_pkcs1_v1_5_encrypt(): message too "
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
            warning("Key._rsaes_oaep_encrypt(): unknown hash function %s.", h)
            return None
        hLen = _hashFuncParams[h][0]
        hFun = _hashFuncParams[h][1]
        k = self.modulusLen / 8
        if mLen > k - 2*hLen - 2:                   # 1.b)
            warning("Key._rsaes_oaep_encrypt(): message too long.")
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

        - 'pkcs': the message 'm' is applied RSAES-PKCS1-V1_5-ENCRYPT encryption
                scheme as described in section 7.2.1 of RFC 3447. In that
                context, other parameters ('h', 'mgf', 'l') are not used.

        - 'oaep': the message 'm' is applied the RSAES-OAEP-ENCRYPT encryption
                scheme, as described in PKCS#1 v2.1, i.e. RFC 3447 Sect
                7.1.1. In that context,

                o 'h' parameter provides the name of the hash method to use.
                  Possible values are "md2", "md4", "md5", "sha1", "tls",
                  "sha224", "sha256", "sha384" and "sha512". if none is provided,
                  sha1 is used.

                o 'mgf' is the mask generation function. By default, mgf
                  is derived from the provided hash function using the
                  generic MGF1 (see pkcs_mgf1() for details).

                o 'L' is the optional label to be associated with the
                  message. If not provided, the default value is used, i.e
                  the empty string. No check is done on the input limitation
                  of the hash function regarding the size of 'L' (for
                  instance, 2^61 - 1 for SHA-1). You have been warned.
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
            warning("Key.encrypt(): Unknown encryption type (%s) provided" % t)
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
            warning("Key._rsassa_pss_verify(): unknown hash function "
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


    def verify(self, M, S, t=None, h=None, mgf=None, sLen=None):
        """
        Verify alleged signature 'S' is indeed the signature of message 'M' using
        't' signature scheme where 't' can be:

        - None: the alleged signature 'S' is directly applied the RSAVP1 signature
                primitive, as described in PKCS#1 v2.1, i.e. RFC 3447 Sect
                5.2.1. Simply put, the provided signature is applied a moular
                exponentiation using the public key. Then, a comparison of the
                result is done against 'M'. On match, True is returned.
                Additionnal method parameters are just ignored.

        - 'pkcs': the alleged signature 'S' and message 'M' are applied
                RSASSA-PKCS1-v1_5-VERIFY signature verification scheme as
                described in Sect. 8.2.2 of RFC 3447. In that context,
                the hash function name is passed using 'h'. Possible values are
                "md2", "md4", "md5", "sha1", "tls", "sha224", "sha256", "sha384"
                and "sha512". If none is provided, sha1 is used. Other additionnal
                parameters are ignored.

        - 'pss': the alleged signature 'S' and message 'M' are applied
                RSASSA-PSS-VERIFY signature scheme as described in Sect. 8.1.2.
                of RFC 3447. In that context,

                o 'h' parameter provides the name of the hash method to use.
                   Possible values are "md2", "md4", "md5", "sha1", "tls", "sha224",
                   "sha256", "sha384" and "sha512". if none is provided, sha1
                   is used. 

                o 'mgf' is the mask generation function. By default, mgf
                   is derived from the provided hash function using the
                   generic MGF1 (see pkcs_mgf1() for details).

                o 'sLen' is the length in octet of the salt. You can overload the
                  default value (the octet length of the hash value for provided
                  algorithm) by providing another one with that parameter.
        """
        if t is None: # RSAVP1
            S = pkcs_os2ip(S)
            n = self.modulus
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
    
class _DecryptAndSignMethods(OSSLHelper):
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
           ciphertext representative, a long between 0 and n-1

        Not intended to be used directly. Please, see encrypt() method.
        """

        n = self.modulus
        if type(c) is int:
            c = long(c)        
        if type(c) is not long or c > n-1:
            warning("Key._rsaep() expects a long between 0 and n-1")
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
            warning("Key._rsaes_pkcs1_v1_5_decrypt() decryption error "
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
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(first byte is not 0x00)")
            return None

        if EM[1] != '\x02':
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(second byte is not 0x02)")
            return None

        tmp = EM[2:].split('\x00', 1)
        if len(tmp) != 2:
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(no 0x00 to separate PS from M)")
            return None

        PS, M = tmp
        if len(PS) < 8:
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
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
                k = 2*hLen + 2 (k denotes the length in octets of the RSA modulus
                and hLen the length in octets of the hash function output)
           h  : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
                'sha256', 'sha384'). 'sha1' is used if none is provided.
           mgf: the mask generation function f : seed, maskLen -> mask
           L  : optional label whose association with the message is to be
                verified; the default value for L, if not provided is the empty
                string.

        Output:
           message, an octet string of length k mLen, where mLen <= k - 2*hLen - 2

        On error, None is returned.
        """
        # The steps below are the one described in Sect. 7.1.2 of RFC 3447.

        # 1) Length Checking
                                                    # 1.a) is not done
        if h is None:
            h = "sha1"
        if not _hashFuncParams.has_key(h):
            warning("Key._rsaes_oaep_decrypt(): unknown hash function %s.", h)
            return None
        hLen = _hashFuncParams[h][0]
        hFun = _hashFuncParams[h][1]
        k = self.modulusLen / 8
        cLen = len(C)
        if cLen != k:                               # 1.b)
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(cLen != k)")
            return None
        if k < 2*hLen + 2:
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
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
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
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
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(0x01 separator not found)")
            return None
        PS, M = tmp
        if PS != '\x00'*len(PS):
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(invalid padding string)")
            return None
        if lHash != lHashPrime:
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
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

        - 'oaep': the ciphertext 'C' is applied the RSAES-OAEP-DECRYPT decryption
                scheme, as described in PKCS#1 v2.1, i.e. RFC 3447 Sect
                7.1.2. In that context,

                o 'h' parameter provides the name of the hash method to use.
                  Possible values are "md2", "md4", "md5", "sha1", "tls",
                  "sha224", "sha256", "sha384" and "sha512". if none is provided,
                  sha1 is used by default.

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
            warning("Key.decrypt(): Unknown decryption type (%s) provided" % t)
            return None

    ### Below are signature related methods. Verification ones are inherited from
    ### PubKey

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
        modBits = self.modulusLen
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
        k = self.modulusLen / 8
        EM = pkcs_emsa_pkcs1_v1_5_encode(M, k, h)
        if EM is None:
            warning("Key._rsassa_pkcs1_v1_5_sign(): unable to encode")
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
                using the private key. Additionnal method parameters are just
                ignored.

        - 'pkcs': the message 'M' is applied RSASSA-PKCS1-v1_5-SIGN signature
                scheme as described in Sect. 8.2.1 of RFC 3447. In that context,
                the hash function name is passed using 'h'. Possible values are
                "md2", "md4", "md5", "sha1", "tls", "sha224", "sha256", "sha384"
                and "sha512". If none is provided, sha1 is used. Other additionnal 
                parameters are ignored.

        - 'pss' : the message 'M' is applied RSASSA-PSS-SIGN signature scheme as
                described in Sect. 8.1.1. of RFC 3447. In that context,

                o 'h' parameter provides the name of the hash method to use.
                   Possible values are "md2", "md4", "md5", "sha1", "tls", "sha224",
                   "sha256", "sha384" and "sha512". if none is provided, sha1
                   is used. 

                o 'mgf' is the mask generation function. By default, mgf
                   is derived from the provided hash function using the
                   generic MGF1 (see pkcs_mgf1() for details).

                o 'sLen' is the length in octet of the salt. You can overload the
                  default value (the octet length of the hash value for provided
                  algorithm) by providing another one with that parameter.
        """

        if t is None: # RSASP1
            M = pkcs_os2ip(M)
            n = self.modulus
            if M > n-1:
                warning("Message to be signed is too long for key modulus")
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
            warning("Key.sign(): Unknown signature type (%s) provided" % t)
            return None


def openssl_parse_RSA(fmt="PEM"):
    return popen3(['openssl', 'rsa', '-text', '-pubin', '-inform', fmt, '-noout'])
def openssl_convert_RSA(infmt="PEM", outfmt="DER"):
    return ['openssl', 'rsa', '-pubin', '-inform', infmt, '-outform', outfmt]

class PubKey(OSSLHelper, _EncryptAndVerify):
    # Below are the fields we recognize in the -text output of openssl
    # and from which we extract information. We expect them in that
    # order. Number of spaces does matter.
    possible_fields = [ "Modulus (",
                        "Exponent:" ]
    possible_fields_count = len(possible_fields)
    
    def __init__(self, keypath):
        error_msg = "Unable to import key."

        # XXX Temporary hack to use PubKey inside Cert
        if type(keypath) is tuple:
            e, m, mLen = keypath
            self.modulus = m
            self.modulusLen = mLen
            self.pubExp = e
            return

        fields_dict = {}
        for k in self.possible_fields:
            fields_dict[k] = None

        self.keypath = None
        rawkey = None

        if (not '\x00' in keypath) and os.path.isfile(keypath): # file
            self.keypath = keypath
            key_size = os.path.getsize(keypath)
            if key_size > MAX_KEY_SIZE:
                raise Exception(error_msg)
            try:
                f = open(keypath)
                rawkey = f.read()
                f.close()
            except:
                raise Exception(error_msg)     
        else:
            rawkey = keypath

        if rawkey is None:
            raise Exception(error_msg)

        self.rawkey = rawkey

        key_header = "-----BEGIN PUBLIC KEY-----"
        key_footer = "-----END PUBLIC KEY-----"
        l = rawkey.split(key_header, 1)
        if len(l) == 2: # looks like PEM
            tmp = l[1]
            l = tmp.split(key_footer, 1)
            if len(l) == 2:
                tmp = l[0]
                rawkey = "%s%s%s\n" % (key_header, tmp, key_footer)
            else:
                raise Exception(error_msg)
            r,w,e = openssl_parse_RSA("PEM")
            w.write(rawkey)
            w.close()
            textkey = r.read()
            r.close()
            res = e.read()
            e.close()
            if res == '':
                self.format = "PEM"
                self.pemkey = rawkey
                self.textkey = textkey
                cmd = openssl_convert_RSA_cmd("PEM", "DER")
                self.derkey = self._apply_ossl_cmd(cmd, rawkey)
            else:
                raise Exception(error_msg)
        else: # not PEM, try DER
            r,w,e = openssl_parse_RSA("DER")
            w.write(rawkey)
            w.close()
            textkey = r.read()
            r.close()
            res = e.read()
            if res == '':
                self.format = "DER"
                self.derkey = rawkey
                self.textkey = textkey
                cmd = openssl_convert_RSA_cmd("DER", "PEM")
                self.pemkey = self._apply_ossl_cmd(cmd, rawkey)
                cmd = openssl_convert_RSA_cmd("DER", "DER")
                self.derkey = self._apply_ossl_cmd(cmd, rawkey)                
            else:
                try: # Perhaps it is a cert
                    c = Cert(keypath)
                except:
                    raise Exception(error_msg)
                # TODO:
                # Reconstruct a key (der and pem) and provide:
                # self.format
                # self.derkey
                # self.pemkey
                # self.textkey
                # self.keypath

        self.osslcmdbase = ['openssl', 'rsa', '-pubin', '-inform',  self.format]

        self.keypath = keypath

        # Parse the -text output of openssl to make things available
        l = self.textkey.split('\n', 1)
        if len(l) != 2:
            raise Exception(error_msg)
        cur, tmp = l
        i = 0
        k = self.possible_fields[i] # Modulus (
        cur = cur[len(k):] + '\n'
        while k:
            l = tmp.split('\n', 1)
            if len(l) != 2: # Over
                fields_dict[k] = cur
                break
            l, tmp = l

            newkey = 0
            # skip fields we have already seen, this is the purpose of 'i'
            for j in range(i, self.possible_fields_count):
                f = self.possible_fields[j]
                if l.startswith(f):
                    fields_dict[k] = cur
                    cur = l[len(f):] + '\n'
                    k = f
                    newkey = 1
                    i = j+1
                    break
            if newkey == 1:
                continue
            cur += l + '\n'

        # modulus and modulus length
        v = fields_dict["Modulus ("]
        self.modulusLen = None
        if v:
            v, rem = v.split(' bit):', 1)
            self.modulusLen = int(v)
            rem = rem.replace('\n','').replace(' ','').replace(':','')
            self.modulus = long(rem, 16)
        if self.modulus is None:
            raise Exception(error_msg)
        
        # public exponent
        v = fields_dict["Exponent:"]
        self.pubExp = None
        if v:
            self.pubExp = long(v.split('(', 1)[0])
        if self.pubExp is None:
            raise Exception(error_msg)

        self.key = RSA.construct((self.modulus, self.pubExp, ))

    def __str__(self):
        return self.derkey


class Key(OSSLHelper, _DecryptAndSignMethods, _EncryptAndVerify):
    # Below are the fields we recognize in the -text output of openssl
    # and from which we extract information. We expect them in that
    # order. Number of spaces does matter.
    possible_fields = [ "Private-Key: (",
                        "modulus:",
                        "publicExponent:",
                        "privateExponent:",
                        "prime1:",
                        "prime2:",
                        "exponent1:",
                        "exponent2:",
                        "coefficient:" ]
    possible_fields_count = len(possible_fields)
    
    def __init__(self, keypath):
        error_msg = "Unable to import key."

        fields_dict = {}
        for k in self.possible_fields:
            fields_dict[k] = None

        self.keypath = None
        rawkey = None

        if (not '\x00' in keypath) and os.path.isfile(keypath):
            self.keypath = keypath
            key_size = os.path.getsize(keypath)
            if key_size > MAX_KEY_SIZE:
                raise Exception(error_msg)
            try:
                f = open(keypath)
                rawkey = f.read()
                f.close()
            except:
                raise Exception(error_msg)     
        else:
            rawkey = keypath

        if rawkey is None:
            raise Exception(error_msg)

        self.rawkey = rawkey

        # Let's try to get file format : PEM or DER.
        fmtstr = 'openssl rsa -text -inform %s -noout'
        convertstr = 'openssl rsa -inform %s -outform %s'
        key_header = "-----BEGIN RSA PRIVATE KEY-----"
        key_footer = "-----END RSA PRIVATE KEY-----"
        l = rawkey.split(key_header, 1)
        if len(l) == 2: # looks like PEM
            tmp = l[1]
            l = tmp.split(key_footer, 1)
            if len(l) == 2:
                tmp = l[0]
                rawkey = "%s%s%s\n" % (key_header, tmp, key_footer)
            else:
                raise Exception(error_msg)
            r,w,e = popen3((fmtstr % "PEM").split(" "))
            w.write(rawkey)
            w.close()
            textkey = r.read()
            r.close()
            res = e.read()
            e.close()
            if res == '':
                self.format = "PEM"
                self.pemkey = rawkey
                self.textkey = textkey
                cmd = (convertstr % ("PEM", "DER")).split(" ")
                self.derkey = self._apply_ossl_cmd(cmd, rawkey)
            else:
                raise Exception(error_msg)
        else: # not PEM, try DER
            r,w,e = popen3((fmtstr % "DER").split(" "))
            w.write(rawkey)
            w.close()
            textkey = r.read()
            r.close()
            res = e.read()
            if res == '':
                self.format = "DER"
                self.derkey = rawkey
                self.textkey = textkey
                cmd = (convertstr % ("DER", "PEM")).split(" ")
                self.pemkey = self._apply_ossl_cmd(cmd, rawkey)
                cmd = (convertstr % ("DER", "DER")).split(" ")
                self.derkey = self._apply_ossl_cmd(cmd, rawkey)
            else:
                raise Exception(error_msg)     

        self.osslcmdbase = ['openssl', 'rsa', '-inform', self.format]

        r,w,e = popen3(["openssl", "asn1parse", "-inform", "DER"])
        w.write(self.derkey)
        w.close()
        self.asn1parsekey = r.read()
        r.close()
        res = e.read()
        e.close()
        if res != '':
            raise Exception(error_msg)

        self.keypath = keypath

        # Parse the -text output of openssl to make things available
        l = self.textkey.split('\n', 1)
        if len(l) != 2:
            raise Exception(error_msg)
        cur, tmp = l
        i = 0
        k = self.possible_fields[i] # Private-Key: (
        cur = cur[len(k):] + '\n'
        while k:
            l = tmp.split('\n', 1)
            if len(l) != 2: # Over
                fields_dict[k] = cur
                break
            l, tmp = l

            newkey = 0
            # skip fields we have already seen, this is the purpose of 'i'
            for j in range(i, self.possible_fields_count):
                f = self.possible_fields[j]
                if l.startswith(f):
                    fields_dict[k] = cur
                    cur = l[len(f):] + '\n'
                    k = f
                    newkey = 1
                    i = j+1
                    break
            if newkey == 1:
                continue
            cur += l + '\n'

        # modulus length
        v = fields_dict["Private-Key: ("]
        self.modulusLen = None
        if v:
            self.modulusLen = int(v.split(' bit', 1)[0])
        if self.modulusLen is None:
            raise Exception(error_msg)
        
        # public exponent
        v = fields_dict["publicExponent:"]
        self.pubExp = None
        if v:
            self.pubExp = long(v.split('(', 1)[0])
        if self.pubExp is None:
            raise Exception(error_msg)

        tmp = {}
        for k in ["modulus:", "privateExponent:", "prime1:", "prime2:",
                  "exponent1:", "exponent2:", "coefficient:"]:
            v = fields_dict[k]
            if v:
                s = v.replace('\n', '').replace(' ', '').replace(':', '')
                tmp[k] = long(s, 16)
            else:
                raise Exception(error_msg)

        self.modulus     = tmp["modulus:"]
        self.privExp     = tmp["privateExponent:"]
        self.prime1      = tmp["prime1:"]
        self.prime2      = tmp["prime2:"] 
        self.exponent1   = tmp["exponent1:"]
        self.exponent2   = tmp["exponent2:"]
        self.coefficient = tmp["coefficient:"]

        self.key = RSA.construct((self.modulus, self.pubExp, self.privExp))

    def __str__(self):
        return self.derkey


# We inherit from PubKey to get access to all encryption and verification
# methods. To have that working, we simply need Cert to provide 
# modulusLen and key attribute.
# XXX Yes, it is a hack.
class Cert(OSSLHelper, _EncryptAndVerify):
    # Below are the fields we recognize in the -text output of openssl
    # and from which we extract information. We expect them in that
    # order. Number of spaces does matter.
    possible_fields = [ "        Version:",
                        "        Serial Number:",
                        "        Signature Algorithm:",
                        "        Issuer:",
                        "            Not Before:",
                        "            Not After :",
                        "        Subject:",
                        "            Public Key Algorithm:",
                        "                Modulus (",
                        "                Exponent:",
                        "            X509v3 Subject Key Identifier:",
                        "            X509v3 Authority Key Identifier:",
                        "                keyid:",
                        "                DirName:",
                        "                serial:",
                        "            X509v3 Basic Constraints:",
                        "            X509v3 Key Usage:",
                        "            X509v3 Extended Key Usage:",
                        "            X509v3 CRL Distribution Points:",
                        "            Authority Information Access:",
                        "    Signature Algorithm:" ]
    possible_fields_count = len(possible_fields)
    
    def __init__(self, certpath):
        error_msg = "Unable to import certificate."

        fields_dict = {}
        for k in self.possible_fields:
            fields_dict[k] = None

        self.certpath = None
        rawcert = None

        if (not '\x00' in certpath) and os.path.isfile(certpath): # file
            self.certpath = certpath
            cert_size = os.path.getsize(certpath)
            if cert_size > MAX_CERT_SIZE:
                raise Exception(error_msg)
            try:
                f = open(certpath)
                rawcert = f.read()
                f.close()
            except:
                raise Exception(error_msg)     
        else:
            rawcert = certpath
            
        if rawcert is None:
            raise Exception(error_msg)

        self.rawcert = rawcert

        # Let's try to get file format : PEM or DER.
        fmtstr = 'openssl x509 -text -inform %s -noout'
        convertstr = 'openssl x509 -inform %s -outform %s'
        cert_header = "-----BEGIN CERTIFICATE-----"
        cert_footer = "-----END CERTIFICATE-----"
        l = rawcert.split(cert_header, 1)
        if len(l) == 2: # looks like PEM
            tmp = l[1]
            l = tmp.split(cert_footer, 1)
            if len(l) == 2:
                tmp = l[0]
                rawcert = "%s%s%s\n" % (cert_header, tmp, cert_footer)
            else:
                raise Exception(error_msg)
            r,w,e = popen3((fmtstr % "PEM").split(" "))
            w.write(rawcert)
            w.close()
            textcert = r.read()
            r.close()
            res = e.read()
            e.close()
            if res == '':
                self.format = "PEM"
                self.pemcert = rawcert
                self.textcert = textcert
                cmd = (convertstr % ("PEM", "DER")).split(" ")
                self.dercert = self._apply_ossl_cmd(cmd, rawcert)
            else:
                raise Exception(error_msg)
        else: # not PEM, try DER
            r,w,e = popen3((fmtstr % "DER").split(" "))
            w.write(rawcert)
            w.close()
            textcert = r.read()
            r.close()
            res = e.read()
            if res == '':
                self.format = "DER"
                self.dercert = rawcert
                self.textcert = textcert
                cmd = (convertstr % ("DER", "PEM")).split(" ")
                self.pemcert = self._apply_ossl_cmd(cmd, rawcert)
                cmd = (convertstr % ("DER", "DER")).split(" ")     
                self.dercert = self._apply_ossl_cmd(cmd, rawcert)
            else:
                raise Exception(error_msg)

        self.osslcmdbase = ['openssl', 'x509', '-inform', self.format]
                                                  
        r,w,e = popen3('openssl asn1parse -inform DER'.split(' '))
        w.write(self.dercert)
        w.close()
        self.asn1parsecert = r.read()
        r.close()
        res = e.read()
        e.close()
        if res != '':
            raise Exception(error_msg)
        
        # Grab _raw_ X509v3 Authority Key Identifier, if any.
        tmp = self.asn1parsecert.split(":X509v3 Authority Key Identifier", 1)
        self.authorityKeyID = None
        if len(tmp) == 2:
            tmp = tmp[1]
            tmp = tmp.split("[HEX DUMP]:", 1)[1]
            self.authorityKeyID=tmp.split('\n',1)[0]

        # Grab _raw_ X509v3 Subject Key Identifier, if any.
        tmp = self.asn1parsecert.split(":X509v3 Subject Key Identifier", 1)
        self.subjectKeyID = None
        if len(tmp) == 2:
            tmp = tmp[1]
            tmp = tmp.split("[HEX DUMP]:", 1)[1]
            self.subjectKeyID=tmp.split('\n',1)[0]            

        # Get tbsCertificate using the worst hack. output of asn1parse
        # looks like that:
        #
        # 0:d=0  hl=4 l=1298 cons: SEQUENCE          
        # 4:d=1  hl=4 l=1018 cons: SEQUENCE          
        # ...
        #
        l1,l2 = self.asn1parsecert.split('\n', 2)[:2]
        hl1 = int(l1.split("hl=",1)[1].split("l=",1)[0])
        rem = l2.split("hl=",1)[1]
        hl2, rem = rem.split("l=",1)
        hl2 = int(hl2)
        l = int(rem.split("cons",1)[0])
        self.tbsCertificate = self.dercert[hl1:hl1+hl2+l]

        # Parse the -text output of openssl to make things available
        tmp = self.textcert.split('\n', 2)[2]
        l = tmp.split('\n', 1)
        if len(l) != 2:
            raise Exception(error_msg)
        cur, tmp = l
        i = 0
        k = self.possible_fields[i] # Version:
        cur = cur[len(k):] + '\n'
        while k:
            l = tmp.split('\n', 1)
            if len(l) != 2: # Over
                fields_dict[k] = cur
                break
            l, tmp = l

            newkey = 0
            # skip fields we have already seen, this is the purpose of 'i'
            for j in range(i, self.possible_fields_count):
                f = self.possible_fields[j]
                if l.startswith(f):
                    fields_dict[k] = cur
                    cur = l[len(f):] + '\n'
                    k = f
                    newkey = 1
                    i = j+1
                    break
            if newkey == 1:
                continue
            cur += l + '\n'

        # version
        v = fields_dict["        Version:"]
        self.version = None
        if v:
            self.version = int(v[1:2])
        if self.version is None:
            raise Exception(error_msg)

        # serial number
        v = fields_dict["        Serial Number:"]
        self.serial = None
        if v:
            v = v.replace('\n', '').strip()
            if "0x" in v:
                v = v.split("0x", 1)[1].split(')', 1)[0]
            v = v.replace(':', '').upper()
            if len(v) % 2:
                v = '0' + v
            self.serial = v
        if self.serial is None:
            raise Exception(error_msg)

        # Signature Algorithm        
        v = fields_dict["        Signature Algorithm:"]
        self.sigAlg = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.sigAlg = v
        if self.sigAlg is None:
            raise Exception(error_msg)
        
        # issuer
        v = fields_dict["        Issuer:"]
        self.issuer = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.issuer = v
        if self.issuer is None:
            raise Exception(error_msg)

        # not before
        v = fields_dict["            Not Before:"]
        self.notBefore_str = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.notBefore_str = v
        if self.notBefore_str is None:
            raise Exception(error_msg)
        try:
            self.notBefore = time.strptime(self.notBefore_str,
                                           "%b %d %H:%M:%S %Y %Z")
        except:
            self.notBefore = time.strptime(self.notBefore_str,
                                           "%b %d %H:%M:%S %Y")
        self.notBefore_str_simple = time.strftime("%x", self.notBefore)
        
        # not after
        v = fields_dict["            Not After :"]
        self.notAfter_str = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.notAfter_str = v
        if self.notAfter_str is None:
            raise Exception(error_msg)
        try:
            self.notAfter = time.strptime(self.notAfter_str,
                                          "%b %d %H:%M:%S %Y %Z")
        except:
            self.notAfter = time.strptime(self.notAfter_str,
                                          "%b %d %H:%M:%S %Y")            
        self.notAfter_str_simple = time.strftime("%x", self.notAfter)
        
        # subject
        v = fields_dict["        Subject:"]
        self.subject = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.subject = v
        if self.subject is None:
            raise Exception(error_msg)
        
        # Public Key Algorithm
        v = fields_dict["            Public Key Algorithm:"]
        self.pubKeyAlg = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.pubKeyAlg = v
        if self.pubKeyAlg is None:
            raise Exception(error_msg)
        
        # Modulus
        v = fields_dict["                Modulus ("]
        self.modulus = None
        if v:
            v,t = v.split(' bit):',1)
            self.modulusLen = int(v)
            t = t.replace(' ', '').replace('\n', ''). replace(':', '')
            self.modulus_hexdump = t
            self.modulus = long(t, 16)
        if self.modulus is None:
            raise Exception(error_msg)

        # Exponent
        v = fields_dict["                Exponent:"]
        self.exponent = None
        if v:
            v = v.split('(',1)[0]
            self.exponent = long(v)
        if self.exponent is None:
            raise Exception(error_msg)

        # Public Key instance
        self.key = RSA.construct((self.modulus, self.exponent, ))
        
        # Subject Key Identifier

        # Authority Key Identifier: keyid, dirname and serial
        self.authorityKeyID_keyid   = None
        self.authorityKeyID_dirname = None
        self.authorityKeyID_serial  = None
        if self.authorityKeyID: # (hex version already done using asn1parse)
            v = fields_dict["                keyid:"]
            if v:
                v = v.split('\n',1)[0]
                v = v.strip().replace(':', '')
                self.authorityKeyID_keyid = v
            v = fields_dict["                DirName:"]
            if v:
                v = v.split('\n',1)[0]
                self.authorityKeyID_dirname = v
            v = fields_dict["                serial:"]
            if v:
                v = v.split('\n',1)[0]
                v = v.strip().replace(':', '')
                self.authorityKeyID_serial = v                

        # Basic constraints
        self.basicConstraintsCritical = False
        self.basicConstraints=None
        v = fields_dict["            X509v3 Basic Constraints:"]
        if v:
            self.basicConstraints = {}
            v,t = v.split('\n',2)[:2]
            if "critical" in v:
                self.basicConstraintsCritical = True
            if "CA:" in t:
                self.basicConstraints["CA"] = t.split('CA:')[1][:4] == "TRUE"
            if "pathlen:" in t:
                self.basicConstraints["pathlen"] = int(t.split('pathlen:')[1])

        # X509v3 Key Usage
        self.keyUsage = []
        v = fields_dict["            X509v3 Key Usage:"]
        if v:   
            # man 5 x509v3_config
            ku_mapping = {"Digital Signature": "digitalSignature",
                          "Non Repudiation": "nonRepudiation",
                          "Key Encipherment": "keyEncipherment",
                          "Data Encipherment": "dataEncipherment",
                          "Key Agreement": "keyAgreement",
                          "Certificate Sign": "keyCertSign",
                          "CRL Sign": "cRLSign",
                          "Encipher Only": "encipherOnly",
                          "Decipher Only": "decipherOnly"}
            v = v.split('\n',2)[1]
            l = map(lambda x: x.strip(), v.split(','))
            while l:
                c = l.pop()
                if ku_mapping.has_key(c):
                    self.keyUsage.append(ku_mapping[c])
                else:
                    self.keyUsage.append(c) # Add it anyway
                    print "Found unknown X509v3 Key Usage: '%s'" % c
                    print "Report it to arno (at) natisbad.org for addition"

        # X509v3 Extended Key Usage
        self.extKeyUsage = []
        v = fields_dict["            X509v3 Extended Key Usage:"]
        if v:   
            # man 5 x509v3_config:
            eku_mapping = {"TLS Web Server Authentication": "serverAuth",
                           "TLS Web Client Authentication": "clientAuth",
                           "Code Signing": "codeSigning",
                           "E-mail Protection": "emailProtection",
                           "Time Stamping": "timeStamping",
                           "Microsoft Individual Code Signing": "msCodeInd",
                           "Microsoft Commercial Code Signing": "msCodeCom",
                           "Microsoft Trust List Signing": "msCTLSign",
                           "Microsoft Encrypted File System": "msEFS",
                           "Microsoft Server Gated Crypto": "msSGC",
                           "Netscape Server Gated Crypto": "nsSGC",
                           "IPSec End System": "iPsecEndSystem",
                           "IPSec Tunnel": "iPsecTunnel",
                           "IPSec User": "iPsecUser"}
            v = v.split('\n',2)[1]
            l = map(lambda x: x.strip(), v.split(','))
            while l:
                c = l.pop()
                if eku_mapping.has_key(c):
                    self.extKeyUsage.append(eku_mapping[c])
                else:
                    self.extKeyUsage.append(c) # Add it anyway
                    print "Found unknown X509v3 Extended Key Usage: '%s'" % c
                    print "Report it to arno (at) natisbad.org for addition"

        # CRL Distribution points
        self.cRLDistributionPoints = []
        v = fields_dict["            X509v3 CRL Distribution Points:"]
        if v:
            v = v.split("\n\n", 1)[0]
            v = v.split("URI:")[1:]
            self.CRLDistributionPoints = map(lambda x: x.strip(), v)
            
        # Authority Information Access: list of tuples ("method", "location")
        self.authorityInfoAccess = []
        v = fields_dict["            Authority Information Access:"]
        if v:
            v = v.split("\n\n", 1)[0]
            v = v.split("\n")[1:]
            for e in v:
                method, location = map(lambda x: x.strip(), e.split(" - ", 1))
                self.authorityInfoAccess.append((method, location))

        # signature field
        v = fields_dict["    Signature Algorithm:" ]
        self.sig = None
        if v:
            v = v.split('\n',1)[1]
            v = v.replace(' ', '').replace('\n', '')
            self.sig = "".join(map(lambda x: chr(int(x, 16)), v.split(':')))
            self.sigLen = len(self.sig)
        if self.sig is None:
            raise Exception(error_msg)

    def isIssuerCert(self, other):
        """
        True if 'other' issued 'self', i.e.:
          - self.issuer == other.subject
          - self is signed by other
        """
        # XXX should be done on raw values, instead of their textual repr
        if self.issuer != other.subject:
            return False

        # Sanity check regarding modulus length and the
        # signature length
        keyLen = (other.modulusLen + 7)/8
        if keyLen != self.sigLen:
            return False

        unenc = other.encrypt(self.sig) # public key encryption, i.e. decrypt

        # XXX Check block type (00 or 01 and type of padding)
        unenc = unenc[1:]
        if not '\x00' in unenc:
            return False
        pos = unenc.index('\x00')
        unenc = unenc[pos+1:]

        found = None
        for k in _hashFuncParams.keys():
            if self.sigAlg.startswith(k):
                found = k
                break
        if not found:
            return False
        hlen, hfunc, digestInfo =  _hashFuncParams[k]
        
        if len(unenc) != (hlen+len(digestInfo)):
            return False

        if not unenc.startswith(digestInfo):
            return False

        h = unenc[-hlen:]
        myh = hfunc(self.tbsCertificate)

        return h == myh

    def chain(self, certlist):
        """
        Construct the chain of certificates leading from 'self' to the
        self signed root using the certificates in 'certlist'. If the
        list does not provide all the required certs to go to the root
        the function returns a incomplete chain starting with the
        certificate. This fact can be tested by tchecking if the last
        certificate of the returned chain is self signed (if c is the
        result, c[-1].isSelfSigned())
        """
        d = {}
        for c in certlist:
            # XXX we should check if we have duplicate
            d[c.subject] = c
        res = [self]
        cur = self
        while not cur.isSelfSigned():
            if d.has_key(cur.issuer):
                possible_issuer = d[cur.issuer]
                if cur.isIssuerCert(possible_issuer):
                    res.append(possible_issuer)
                    cur = possible_issuer
                else:
                    break
        return res

    def remainingDays(self, now=None):
        """
        Based on the value of notBefore field, returns the number of
        days the certificate will still be valid. The date used for the
        comparison is the current and local date, as returned by 
        time.localtime(), except if 'now' argument is provided another
        one. 'now' argument can be given as either a time tuple or a string
        representing the date. Accepted format for the string version
        are:
        
         - '%b %d %H:%M:%S %Y %Z' e.g. 'Jan 30 07:38:59 2008 GMT'
         - '%m/%d/%y' e.g. '01/30/08' (less precise)

        If the certificate is no more valid at the date considered, then,
        a negative value is returned representing the number of days
        since it has expired.
        
        The number of days is returned as a float to deal with the unlikely
        case of certificates that are still just valid.
        """
        if now is None:
            now = time.localtime()
        elif type(now) is str:
            try:
                if '/' in now:
                    now = time.strptime(now, '%m/%d/%y')
                else:
                    now = time.strptime(now, '%b %d %H:%M:%S %Y %Z')
            except:
                warning("Bad time string provided '%s'. Using current time" % now)
                now = time.localtime()

        now = time.mktime(now)
        nft = time.mktime(self.notAfter)
        diff = (nft - now)/(24.*3600)
        return diff


    # return SHA-1 hash of cert embedded public key
    # !! At the moment, the trailing 0 is in the hashed string if any
    def keyHash(self):
        m = self.modulus_hexdump
        res = []
        i = 0
        l = len(m)
        while i<l: # get a string version of modulus
            res.append(struct.pack("B", int(m[i:i+2], 16)))
            i += 2
        return sha.new("".join(res)).digest()    

    def output(self, fmt="DER"):
        if fmt == "DER":
            return self.dercert
        elif fmt == "PEM":
            return self.pemcert
        elif fmt == "TXT":
            return self.textcert

    def export(self, filename, fmt="DER"):
        """
        Export certificate in 'fmt' format (PEM, DER or TXT) to file 'filename'
        """
        f = open(filename, "wb")
        f.write(self.output(fmt))
        f.close()

    def isSelfSigned(self):
        """
        Return True if the certificate is self signed:
          - issuer and subject are the same
          - the signature of the certificate is valid.
        """
        if self.issuer == self.subject:
            return self.isIssuerCert(self)
        return False

    # Print main informations stored in certificate
    def show(self):
        print "Serial: %s" % self.serial
        print "Issuer: " + self.issuer
        print "Subject: " + self.subject
        print "Validity: %s to %s" % (self.notBefore_str_simple,
                                      self.notAfter_str_simple)

    def __repr__(self):
        return "[X.509 Cert. Subject:%s, Issuer:%s]" % (self.subject, self.issuer)

    def __str__(self):
        return self.dercert

    def verifychain(self, anchors, untrusted=None):
        """
        Perform verification of certificate chains for that certificate. The
        behavior of verifychain method is mapped (and also based) on openssl
        verify userland tool (man 1 verify).
        A list of anchors is required. untrusted parameter can be provided 
        a list of untrusted certificates that can be used to reconstruct the
        chain.

        If you have a lot of certificates to verify against the same
        list of anchor, consider constructing this list as a cafile
        and use .verifychain_from_cafile() instead.
        """
        cafile = create_temporary_ca_file(anchors)
        if not cafile:
            return False
        untrusted_file = None
        if untrusted:
            untrusted_file = create_temporary_ca_file(untrusted) # hack
            if not untrusted_file:
                os.unlink(cafile)
                return False
        res = self.verifychain_from_cafile(cafile, 
                                           untrusted_file=untrusted_file)
        os.unlink(cafile)
        if untrusted_file:
            os.unlink(untrusted_file)
        return res

    def verifychain_from_cafile(self, cafile, untrusted_file=None):
        """
        Does the same job as .verifychain() but using the list of anchors
        from the cafile. This is useful (because more efficient) if
        you have a lot of certificates to verify do it that way: it
        avoids the creation of a cafile from anchors at each call.

        As for .verifychain(), a list of untrusted certificates can be
        passed (as a file, this time)
        """
        cmd = ["openssl", "verify", "-CAfile", cafile]
        if untrusted_file:
           cmd += ["-untrusted", untrusted_file]
        try:
            pemcert = self.output(fmt="PEM")
            cmdres = self._apply_ossl_cmd(cmd, pemcert)
        except:
            return False
        return cmdres.endswith("\nOK\n") or cmdres.endswith(": OK\n")

    def verifychain_from_capath(self, capath, untrusted_file=None):
        """
        Does the same job as .verifychain_from_cafile() but using the list
        of anchors in capath directory. The directory should contain
        certificates files in PEM format with associated links as
        created using c_rehash utility (man c_rehash).

        As for .verifychain_from_cafile(), a list of untrusted certificates
        can be passed as a file (concatenation of the certificates in
        PEM format)
        """
        cmd = ["openssl", "verify", "-CApath", capath]
        if untrusted_file:
            cmd += ["-untrusted", untrusted_file]
        try:
            pemcert = self.output(fmt="PEM")
            cmdres = self._apply_ossl_cmd(cmd, pemcert)
        except:
            return False
        return cmdres.endswith("\nOK\n") or cmdres.endswith(": OK\n")

    def is_revoked(self, crl_list):
        """
        Given a list of trusted CRL (their signature has already been
        verified with trusted anchors), this function returns True if
        the certificate is marked as revoked by one of those CRL.

        Note that if the Certificate was on hold in a previous CRL and
        is now valid again in a new CRL and bot are in the list, it
        will be considered revoked: this is because _all_ CRLs are 
        checked (not only the freshest) and revocation status is not
        handled.

        Also note that the check on the issuer is performed on the
        Authority Key Identifier if available in _both_ the CRL and the
        Cert. Otherwise, the issuers are simply compared.
        """
        for c in crl_list:
            if (self.authorityKeyID is not None and 
                c.authorityKeyID is not None and
                self.authorityKeyID == c.authorityKeyID):
                return self.serial in map(lambda x: x[0], c.revoked_cert_serials)
            elif (self.issuer == c.issuer):
                return self.serial in map(lambda x: x[0], c.revoked_cert_serials)
        return False

def print_chain(l):
    llen = len(l) - 1
    if llen < 0:
        return ""
    c = l[llen]
    llen -= 1
    s = "_ "
    if not c.isSelfSigned():
        s = "_ ... [Missing Root]\n"
    else:
        s += "%s [Self Signed]\n" % c.subject
    i = 1
    while (llen != -1):
        c = l[llen]
        s += "%s\_ %s" % (" "*i, c.subject)
        if llen != 0:
            s += "\n"
        i += 2
        llen -= 1
    print s

# import popen2
# a=popen3("openssl crl -text -inform DER -noout ", capturestderr=True)
# a.tochild.write(open("samples/klasa1.crl").read())
# a.tochild.close()
# a.poll()

class CRL(OSSLHelper):
    # Below are the fields we recognize in the -text output of openssl
    # and from which we extract information. We expect them in that
    # order. Number of spaces does matter.
    possible_fields = [ "        Version",
                        "        Signature Algorithm:",
                        "        Issuer:",
                        "        Last Update:",
                        "        Next Update:",
                        "        CRL extensions:",
                        "            X509v3 Issuer Alternative Name:",
                        "            X509v3 Authority Key Identifier:", 
                        "                keyid:",
                        "                DirName:",
                        "                serial:",
                        "            X509v3 CRL Number:", 
                        "Revoked Certificates:",
                        "No Revoked Certificates.",
                        "    Signature Algorithm:" ]
    possible_fields_count = len(possible_fields)

    def __init__(self, crlpath):
        error_msg = "Unable to import CRL."

        fields_dict = {}
        for k in self.possible_fields:
            fields_dict[k] = None

        self.crlpath = None
        rawcrl = None

        if (not '\x00' in crlpath) and os.path.isfile(crlpath):
            self.crlpath = crlpath
            cert_size = os.path.getsize(crlpath)
            if cert_size > MAX_CRL_SIZE:
                raise Exception(error_msg)
            try:
                f = open(crlpath)
                rawcrl = f.read()
                f.close()
            except:
                raise Exception(error_msg)     
        else:
            rawcrl = crlpath

        if rawcrl is None:
            raise Exception(error_msg)

        self.rawcrl = rawcrl

        # Let's try to get file format : PEM or DER.
        fmtstr = 'openssl crl -text -inform %s -noout'
        convertstr = 'openssl crl -inform %s -outform %s'
        crl_header = "-----BEGIN X509 CRL-----"
        crl_footer = "-----END X509 CRL-----"
        l = rawcrl.split(crl_header, 1)
        if len(l) == 2: # looks like PEM
            tmp = l[1]
            l = tmp.split(crl_footer, 1)
            if len(l) == 2:
                tmp = l[0]
                rawcrl = "%s%s%s\n" % (crl_header, tmp, crl_footer)
            else:
                raise Exception(error_msg)
            r,w,e = popen3((fmtstr % "PEM").split(" "))
            w.write(rawcrl)
            w.close()
            textcrl = r.read()
            r.close()
            res = e.read()
            e.close()
            if res == '':
                self.format = "PEM"
                self.pemcrl = rawcrl
                self.textcrl = textcrl
                cmd = (convertstr % ("PEM", "DER")).split(" ")
                self.dercrl = self._apply_ossl_cmd(cmd, rawcrl)
            else:
                raise Exception(error_msg)
        else: # not PEM, try DER
            r,w,e = popen3((fmtstr % "DER").split(' '))
            w.write(rawcrl)
            w.close()
            textcrl = r.read()
            r.close()
            res = e.read()
            if res == '':
                self.format = "DER"
                self.dercrl = rawcrl
                self.textcrl = textcrl
                cmd = (convertstr % ("DER", "PEM")).split(" ")
                self.pemcrl = self._apply_ossl_cmd(cmd, rawcrl)
                cmd = (convertstr % ("DER", "DER")).split(" ")
                self.dercrl = self._apply_ossl_cmd(cmd, rawcrl)
            else:
                raise Exception(error_msg)

        self.osslcmdbase = ['openssl', 'crl', '-inform', self.format]

        r,w,e = popen3(('openssl asn1parse -inform DER').split(" "))
        w.write(self.dercrl)
        w.close()
        self.asn1parsecrl = r.read()
        r.close()
        res = e.read()
        e.close()
        if res != '':
            raise Exception(error_msg)

        # Grab _raw_ X509v3 Authority Key Identifier, if any.
        tmp = self.asn1parsecrl.split(":X509v3 Authority Key Identifier", 1)
        self.authorityKeyID = None
        if len(tmp) == 2:
            tmp = tmp[1]
            tmp = tmp.split("[HEX DUMP]:", 1)[1]
            self.authorityKeyID=tmp.split('\n',1)[0]

        # Parse the -text output of openssl to make things available
        tmp = self.textcrl.split('\n', 1)[1]
        l = tmp.split('\n', 1)
        if len(l) != 2:
            raise Exception(error_msg)
        cur, tmp = l
        i = 0
        k = self.possible_fields[i] # Version
        cur = cur[len(k):] + '\n'
        while k:
            l = tmp.split('\n', 1)
            if len(l) != 2: # Over
                fields_dict[k] = cur
                break
            l, tmp = l

            newkey = 0
            # skip fields we have already seen, this is the purpose of 'i'
            for j in range(i, self.possible_fields_count):
                f = self.possible_fields[j]
                if l.startswith(f):
                    fields_dict[k] = cur
                    cur = l[len(f):] + '\n'
                    k = f
                    newkey = 1
                    i = j+1
                    break
            if newkey == 1:
                continue
            cur += l + '\n'

        # version
        v = fields_dict["        Version"]
        self.version = None
        if v:
            self.version = int(v[1:2])
        if self.version is None:
            raise Exception(error_msg)

        # signature algorithm
        v = fields_dict["        Signature Algorithm:"]
        self.sigAlg = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.sigAlg = v
        if self.sigAlg is None:
            raise Exception(error_msg)

        # issuer
        v = fields_dict["        Issuer:"]
        self.issuer = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.issuer = v
        if self.issuer is None:
            raise Exception(error_msg)

        # last update
        v = fields_dict["        Last Update:"]
        self.lastUpdate_str = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.lastUpdate_str = v
        if self.lastUpdate_str is None:
            raise Exception(error_msg)
        self.lastUpdate = time.strptime(self.lastUpdate_str,
                                       "%b %d %H:%M:%S %Y %Z")
        self.lastUpdate_str_simple = time.strftime("%x", self.lastUpdate)

        # next update
        v = fields_dict["        Next Update:"]
        self.nextUpdate_str = None
        if v:
            v = v.split('\n',1)[0]
            v = v.strip()
            self.nextUpdate_str = v
        if self.nextUpdate_str is None:
            raise Exception(error_msg)
        self.nextUpdate = time.strptime(self.nextUpdate_str,
                                       "%b %d %H:%M:%S %Y %Z")
        self.nextUpdate_str_simple = time.strftime("%x", self.nextUpdate)
        
        # XXX Do something for Issuer Alternative Name

        # Authority Key Identifier: keyid, dirname and serial
        self.authorityKeyID_keyid   = None
        self.authorityKeyID_dirname = None
        self.authorityKeyID_serial  = None
        if self.authorityKeyID: # (hex version already done using asn1parse)
            v = fields_dict["                keyid:"]
            if v:
                v = v.split('\n',1)[0]
                v = v.strip().replace(':', '')
                self.authorityKeyID_keyid = v
            v = fields_dict["                DirName:"]
            if v:
                v = v.split('\n',1)[0]
                self.authorityKeyID_dirname = v
            v = fields_dict["                serial:"]
            if v:
                v = v.split('\n',1)[0]
                v = v.strip().replace(':', '')
                self.authorityKeyID_serial = v

        # number
        v = fields_dict["            X509v3 CRL Number:"]
        self.number = None
        if v:
            v = v.split('\n',2)[1]
            v = v.strip()
            self.number = int(v)

        # Get the list of serial numbers of revoked certificates
        self.revoked_cert_serials = []
        v = fields_dict["Revoked Certificates:"]
        t = fields_dict["No Revoked Certificates."]
        if (t is None and v is not None):
            v = v.split("Serial Number: ")[1:]
            for r in v:
                s,d = r.split('\n', 1)
                s = s.split('\n', 1)[0]
                d = d.split("Revocation Date:", 1)[1]
                d = time.strptime(d.strip(), "%b %d %H:%M:%S %Y %Z")
                self.revoked_cert_serials.append((s,d))

        # signature field
        v = fields_dict["    Signature Algorithm:" ]
        self.sig = None
        if v:
            v = v.split('\n',1)[1]
            v = v.replace(' ', '').replace('\n', '')
            self.sig = "".join(map(lambda x: chr(int(x, 16)), v.split(':')))
            self.sigLen = len(self.sig)
        if self.sig is None:
            raise Exception(error_msg)

    def __str__(self):
        return self.dercrl
        
    # Print main informations stored in CRL
    def show(self):
        print "Version: %d" % self.version
        print "sigAlg: " + self.sigAlg
        print "Issuer: " + self.issuer
        print "lastUpdate: %s" % self.lastUpdate_str_simple
        print "nextUpdate: %s" % self.nextUpdate_str_simple

    def verify(self, anchors):
        """
        Return True if the CRL is signed by one of the provided
        anchors. False on error (invalid signature, missing anchorand, ...)
        """
        cafile = create_temporary_ca_file(anchors)
        if cafile is None:
            return False
        try:
            cmd = self.osslcmdbase + ["-noout", "-CAfile", cafile]
            cmdres = self._apply_ossl_cmd(cmd, self.rawcrl)
        except:
            os.unlink(cafile)
            return False
        os.unlink(cafile)
        return "verify OK" in cmdres


    
