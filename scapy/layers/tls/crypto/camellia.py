## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Pure Python implementation of Camellia based on RFC 3713.
"""

# Note: the only rationales for this implementation are that Camellia is
#       not yet available in python-crypto at the time of writing and
#       the fact that the module is not expected to be used on huge
#       volume of traffic, but mainly for TLS handshakes --arno

from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip


def _left_rot_op(x, xbitlen, bitrot): # left rotation operation, i.e. '<<<'
    """
    Performs left rotation operation of 'xbitrot' bit on 'x' of bit length
    'xbitlen', i.e. if x is taken as 32 bit value, _left_rot_op(x, 32, 12)
    is basically w <<< 12 in the notation of
    """
    bitrot %= xbitlen
    mask = (1 << xbitlen) - 1
    x &= mask
    return ((x << bitrot) |  (x >> (xbitlen - bitrot))) & mask

_MASK8   = 0xff
_MASK32  = 0xffffffff
_MASK64  = 0xffffffffffffffff
_MASK128 = 0xffffffffffffffffffffffffffffffff

_Sigma1 = 0xA09E667F3BCC908B
_Sigma2 = 0xB67AE8584CAA73B2
_Sigma3 = 0xC6EF372FE94F82BE
_Sigma4 = 0x54FF53A5F1D36F1C
_Sigma5 = 0x10E527FADE682D1D
_Sigma6 = 0xB05688C2B3E6C1FD

_SBOX1 = [112, 130,  44, 236, 179,  39, 192, 229,
          228, 133,  87,  53, 234,  12, 174,  65,
           35, 239, 107, 147,  69,  25, 165,  33,
          237,  14,  79,  78,  29, 101, 146, 189,
          134, 184, 175, 143, 124, 235,  31, 206,
           62,  48, 220,  95,  94, 197,  11,  26,
          166, 225,  57, 202, 213,  71,  93,  61,
          217,   1,  90, 214,  81,  86, 108,  77,
          139,  13, 154, 102, 251, 204, 176,  45,
          116,  18,  43,  32, 240, 177, 132, 153,
          223,  76, 203, 194,  52, 126, 118,   5,
          109, 183, 169,  49, 209,  23,   4, 215,
           20,  88,  58,  97, 222,  27,  17,  28,
           50,  15, 156,  22,  83,  24, 242,  34,
          254,  68, 207, 178, 195, 181, 122, 145,
           36,   8, 232, 168,  96, 252, 105,  80,
          170, 208, 160, 125, 161, 137,  98, 151,
           84,  91,  30, 149, 224, 255, 100, 210,
           16, 196,   0,  72, 163, 247, 117, 219,
          138,   3, 230, 218,   9,  63, 221, 148,
          135,  92, 131,   2, 205,  74, 144,  51,
          115, 103, 246, 243, 157, 127, 191, 226,
           82, 155, 216,  38, 200,  55, 198,  59,
          129, 150, 111,  75,  19, 190,  99,  46,
          233, 121, 167, 140, 159, 110, 188, 142,
           41, 245, 249, 182,  47, 253, 180,  89,
          120, 152,   6, 106, 231,  70, 113, 186,
          212,  37, 171,  66, 136, 162, 141, 250,
          114,   7, 185,  85, 248, 238, 172,  10,
           54,  73,  42, 104,  60,  56, 241, 164,
           64,  40, 211, 123, 187, 201,  67, 193,
           21, 227, 173, 244, 119, 199, 128, 158]

_SBOX2 = map(lambda x: _left_rot_op(x,8,1), _SBOX1)

_SBOX3 = map(lambda x: _left_rot_op(x,8,7), _SBOX1)

_SBOX4 = []
for k in range(len(_SBOX1)):
    _SBOX4.append(_SBOX1[_left_rot_op(k,8,1)])

def _F(F_IN, KE): # Section 2.4.1 of RFC 3713
       x  = (F_IN ^ KE) & _MASK64
       t1 =  x >> 56  & _MASK8
       t2 = (x >> 48) & _MASK8
       t3 = (x >> 40) & _MASK8
       t4 = (x >> 32) & _MASK8
       t5 = (x >> 24) & _MASK8
       t6 = (x >> 16) & _MASK8
       t7 = (x >>  8) & _MASK8
       t8 =  x        & _MASK8
       t1 = _SBOX1[t1]
       t2 = _SBOX2[t2]
       t3 = _SBOX3[t3]
       t4 = _SBOX4[t4]
       t5 = _SBOX2[t5]
       t6 = _SBOX3[t6]
       t7 = _SBOX4[t7]
       t8 = _SBOX1[t8]
       y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
       y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
       y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
       y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
       y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
       y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
       y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
       y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
       F_OUT = ((y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) |
                (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8)
       return F_OUT;


def _FL(FL_IN, KE): # Section 2.4.2 of RFC 3713
    x1 = (FL_IN >> 32) & _MASK32
    x2 = FL_IN & _MASK32
    k1 = KE >> 32
    k2 = KE & _MASK32
    x2 = x2 ^ _left_rot_op((x1 & k1), 32, 1)
    x1 = x1 ^ (x2 | k2)
    FL_OUT = (x1 << 32) | x2
    return FL_OUT

def _FLINV(FLINV_IN, KE): # Section 2.4.3 of RFC 3713
    y1 = FLINV_IN >> 32
    y2 = FLINV_IN & _MASK32
    k1 = KE >> 32
    k2 = KE & _MASK32
    y1 = y1 ^ (y2 | k2)
    y2 = y2 ^ _left_rot_op((y1 & k1), 32, 1)
    FLINV_OUT = (y1 << 32) | y2
    return FLINV_OUT

# Key Scheduling Part as described in section 2.2 of RFC 3713
def _scheduling(K): #eats the key as a 16, 24 or 32 bytes string
    l = len(K)
    K = pkcs_os2ip(K)

    if l == 16:
        KL = K
        KR = 0
    elif l == 24:
        KL = K >> 64
        KR = ((K & _MASK64) << 64) | ((~(K & _MASK64)) % (_MASK64+1))
    elif l == 32:
        KL = K >> 128
        KR = K & _MASK128
    else:
        return None

    D1 = (KL ^ KR) >> 64
    D2 = (KL ^ KR) & _MASK64
    D2 = D2 ^ _F(D1, _Sigma1)
    D1 = D1 ^ _F(D2, _Sigma2)
    D1 = D1 ^ (KL >> 64)
    D2 = D2 ^ (KL & _MASK64)
    D2 = D2 ^ _F(D1, _Sigma3)
    D1 = D1 ^ _F(D2, _Sigma4)
    KA = (D1 << 64) | D2
    D1 = (KA ^ KR) >> 64
    D2 = (KA ^ KR) & _MASK64
    D2 = D2 ^ _F(D1, _Sigma5)
    D1 = D1 ^ _F(D2, _Sigma6)

    if l != 16:
        KB = (D1 << 64) | D2

    if l == 16:
        kw1 = _left_rot_op(KL, 128,   0) >> 64
        kw2 = _left_rot_op(KL, 128,   0) & _MASK64
        k1  = _left_rot_op(KA, 128,   0) >> 64
        k2  = _left_rot_op(KA, 128,   0) & _MASK64
        k3  = _left_rot_op(KL, 128,  15) >> 64
        k4  = _left_rot_op(KL, 128,  15) & _MASK64
        k5  = _left_rot_op(KA, 128,  15) >> 64
        k6  = _left_rot_op(KA, 128,  15) & _MASK64
        ke1 = _left_rot_op(KA, 128,  30) >> 64
        ke2 = _left_rot_op(KA, 128,  30) & _MASK64
        k7  = _left_rot_op(KL, 128,  45) >> 64
        k8  = _left_rot_op(KL, 128,  45) & _MASK64
        k9  = _left_rot_op(KA, 128,  45) >> 64
        k10 = _left_rot_op(KL, 128,  60) & _MASK64
        k11 = _left_rot_op(KA, 128,  60) >> 64
        k12 = _left_rot_op(KA, 128,  60) & _MASK64
        ke3 = _left_rot_op(KL, 128,  77) >> 64
        ke4 = _left_rot_op(KL, 128,  77) & _MASK64
        k13 = _left_rot_op(KL, 128,  94) >> 64
        k14 = _left_rot_op(KL, 128,  94) & _MASK64
        k15 = _left_rot_op(KA, 128,  94) >> 64
        k16 = _left_rot_op(KA, 128,  94) & _MASK64
        k17 = _left_rot_op(KL, 128, 111) >> 64
        k18 = _left_rot_op(KL, 128, 111) & _MASK64
        kw3 = _left_rot_op(KA, 128, 111) >> 64
        kw4 = _left_rot_op(KA, 128, 111) & _MASK64
        return [ kw1, kw2, kw3, kw4,
                 k1 ,  k2,  k3,  k4,  k5,  k6,  k7,  k8,  k9,
                 k10, k11, k12, k13, k14, k15, k16, k17, k18,
                 ke1, ke2, ke3, ke4 ]
    else:
        kw1 = _left_rot_op(KL, 128,   0) >> 64
        kw2 = _left_rot_op(KL, 128,   0) & _MASK64
        k1  = _left_rot_op(KB, 128,   0) >> 64
        k2  = _left_rot_op(KB, 128,   0) & _MASK64
        k3  = _left_rot_op(KR, 128,  15) >> 64
        k4  = _left_rot_op(KR, 128,  15) & _MASK64
        k5  = _left_rot_op(KA, 128,  15) >> 64
        k6  = _left_rot_op(KA, 128,  15) & _MASK64
        ke1 = _left_rot_op(KR, 128,  30) >> 64
        ke2 = _left_rot_op(KR, 128,  30) & _MASK64
        k7  = _left_rot_op(KB, 128,  30) >> 64
        k8  = _left_rot_op(KB, 128,  30) & _MASK64
        k9  = _left_rot_op(KL, 128,  45) >> 64
        k10 = _left_rot_op(KL, 128,  45) & _MASK64
        k11 = _left_rot_op(KA, 128,  45) >> 64
        k12 = _left_rot_op(KA, 128,  45) & _MASK64
        ke3 = _left_rot_op(KL, 128,  60) >> 64
        ke4 = _left_rot_op(KL, 128,  60) & _MASK64
        k13 = _left_rot_op(KR, 128,  60) >> 64
        k14 = _left_rot_op(KR, 128,  60) & _MASK64
        k15 = _left_rot_op(KB, 128,  60) >> 64
        k16 = _left_rot_op(KB, 128,  60) & _MASK64
        k17 = _left_rot_op(KL, 128,  77) >> 64
        k18 = _left_rot_op(KL, 128,  77) & _MASK64
        ke5 = _left_rot_op(KA, 128,  77) >> 64
        ke6 = _left_rot_op(KA, 128,  77) & _MASK64
        k19 = _left_rot_op(KR, 128,  94) >> 64
        k20 = _left_rot_op(KR, 128,  94) & _MASK64
        k21 = _left_rot_op(KA, 128,  94) >> 64
        k22 = _left_rot_op(KA, 128,  94) & _MASK64
        k23 = _left_rot_op(KL, 128, 111) >> 64
        k24 = _left_rot_op(KL, 128, 111) & _MASK64
        kw3 = _left_rot_op(KB, 128, 111) >> 64
        kw4 = _left_rot_op(KB, 128, 111) & _MASK64
        return [ kw1, kw2, kw3, kw4,
                 k1 ,  k2,  k3,  k4,  k5,  k6,  k7,  k8,
                 k9 , k10, k11, k12, k13, k14, k15, k16,
                 k17, k18, k19, k20, k21, k22, k23, k24,
                 ke1, ke2, ke3, ke4, ke5, ke6 ]

def _decrypt_encrypt_128(M, K, decrypt=False):
    M = pkcs_os2ip(M)
    D1 = M >> 64
    D2 = M & _MASK64

    l = _scheduling(K)
    (kw1,kw2,kw3,kw4,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,
     k11,k12,k13,k14,k15,k16,k17,k18,ke1,ke2,ke3,ke4) = l
    if decrypt: # Reversing the order of subkeys: See 2.3.3 of RFC 3713
        tmp = kw1; kw1 = kw3; kw3 = tmp
        tmp = kw2; kw2 = kw4; kw4 = tmp
        tmp = k1; k1  = k18; k18 = tmp
        tmp = k2; k2  = k17; k17 = tmp
        tmp = k3; k3  = k16; k16 = tmp
        tmp = k4; k4  = k15; k15 = tmp
        tmp = k5; k5  = k14; k14 = tmp
        tmp = k6; k6  = k13; k13 = tmp
        tmp = k7; k7  = k12; k12 = tmp
        tmp = k8; k8  = k11; k11 = tmp
        tmp = k9; k9  = k10; k10 = tmp
        tmp = ke1; ke1 = ke4; ke4 = tmp
        tmp = ke2; ke2 = ke3; ke3 = tmp

    D1 = D1 ^ kw1           # Prewhitening
    D2 = D2 ^ kw2
    D2 = D2 ^ _F(D1, k1)     # Round 1
    D1 = D1 ^ _F(D2, k2)     # Round 2
    D2 = D2 ^ _F(D1, k3)     # Round 3
    D1 = D1 ^ _F(D2, k4)     # Round 4
    D2 = D2 ^ _F(D1, k5)     # Round 5
    D1 = D1 ^ _F(D2, k6)     # Round 6
    D1 = _FL(D1, ke1)        # FL
    D2 = _FLINV(D2, ke2)     # FLINV
    D2 = D2 ^ _F(D1, k7)     # Round 7
    D1 = D1 ^ _F(D2, k8)     # Round 8
    D2 = D2 ^ _F(D1, k9)     # Round 9
    D1 = D1 ^ _F(D2, k10)    # Round 10
    D2 = D2 ^ _F(D1, k11)    # Round 11
    D1 = D1 ^ _F(D2, k12)    # Round 12
    D1 = _FL(D1, ke3)        # FL
    D2 = _FLINV(D2, ke4)     # FLINV
    D2 = D2 ^ _F(D1, k13)    # Round 13
    D1 = D1 ^ _F(D2, k14)    # Round 14
    D2 = D2 ^ _F(D1, k15)    # Round 15
    D1 = D1 ^ _F(D2, k16)    # Round 16
    D2 = D2 ^ _F(D1, k17)    # Round 17
    D1 = D1 ^ _F(D2, k18)    # Round 18
    D2 = D2 ^ kw3           # Postwhitening
    D1 = D1 ^ kw4

    C = (D2 << 64) | D1
    return pkcs_i2osp(C, 16)

def _decrypt_encrypt_192_256(M, K, decrypt=False):
    M = pkcs_os2ip(M)
    D1 = M >> 64
    D2 = M & _MASK64

    l = _scheduling(K)
    (kw1,kw2,kw3,kw4,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,
     k12,k13,k14,k15,k16,k17,k18,k19,k20,k21,k22,k23,
     k24,ke1,ke2,ke3,ke4,ke5,ke6) = l
    if decrypt: # Reversing the order of subkeys: See 2.3.3 of RFC 3713
        tmp = kw1; kw1 = kw3; kw3 = tmp
        tmp = kw2; kw2 = kw4; kw4 = tmp
        tmp = k1; k1  = k24; k24 = tmp
        tmp = k2; k2  = k23; k23 = tmp
        tmp = k3; k3  = k22; k22 = tmp
        tmp = k4; k4  = k21; k21 = tmp
        tmp = k5; k5  = k20; k20 = tmp
        tmp = k6; k6  = k19; k19 = tmp
        tmp = k7; k7  = k18; k18 = tmp
        tmp = k8; k8  = k17; k17 = tmp
        tmp = k9; k9  = k16; k16 = tmp
        tmp = k10; k10 = k15; k15 = tmp
        tmp = k11; k11 = k14; k14 = tmp
        tmp = k12; k12 = k13; k13 = tmp
        tmp = ke1; ke1 = ke6; ke6 = tmp
        tmp = ke2; ke2 = ke5; ke5 = tmp
        tmp = ke3; ke3 = ke4; ke4 = tmp

    D1 = D1 ^ kw1            # Prewhitening
    D2 = D2 ^ kw2
    D2 = D2 ^ _F(D1, k1)     # Round 1
    D1 = D1 ^ _F(D2, k2)     # Round 2
    D2 = D2 ^ _F(D1, k3)     # Round 3
    D1 = D1 ^ _F(D2, k4)     # Round 4
    D2 = D2 ^ _F(D1, k5)     # Round 5
    D1 = D1 ^ _F(D2, k6)     # Round 6
    D1 = _FL   (D1, ke1)     # _FL
    D2 = _FLINV(D2, ke2)     # _FLINV
    D2 = D2 ^ _F(D1, k7)     # Round 7
    D1 = D1 ^ _F(D2, k8)     # Round 8
    D2 = D2 ^ _F(D1, k9)     # Round 9
    D1 = D1 ^ _F(D2, k10)    # Round 10
    D2 = D2 ^ _F(D1, k11)    # Round 11
    D1 = D1 ^ _F(D2, k12)    # Round 12
    D1 = _FL   (D1, ke3)     # _FL
    D2 = _FLINV(D2, ke4)     # _FLINV
    D2 = D2 ^ _F(D1, k13)    # Round 13
    D1 = D1 ^ _F(D2, k14)    # Round 14
    D2 = D2 ^ _F(D1, k15)    # Round 15
    D1 = D1 ^ _F(D2, k16)    # Round 16
    D2 = D2 ^ _F(D1, k17)    # Round 17
    D1 = D1 ^ _F(D2, k18)    # Round 18
    D1 = _FL   (D1, ke5)     # _FL
    D2 = _FLINV(D2, ke6)     # _FLINV
    D2 = D2 ^ _F(D1, k19)    # Round 19
    D1 = D1 ^ _F(D2, k20)    # Round 20
    D2 = D2 ^ _F(D1, k21)    # Round 21
    D1 = D1 ^ _F(D2, k22)    # Round 22
    D2 = D2 ^ _F(D1, k23)    # Round 23
    D1 = D1 ^ _F(D2, k24)    # Round 24
    D2 = D2 ^ kw3            # Postwhitening
    D1 = D1 ^ kw4
    C = (D2 << 64) | D1

    return pkcs_i2osp(C, 16)


class Camellia(object):
    def _decrypt_encrypt(self, M, K, dec):
        if len(M) != 16:
            raise AttributeError("Camellia has a block size of 128 bits")
        l = len(K)
        if l == 16:
            return _decrypt_encrypt_128(M, K, decrypt=dec)
        elif l == 24 or l == 32:
            return _decrypt_encrypt_192_256(M, K, decrypt=dec)
        else:
            raise AttributeError("Camellia supports only 128, 192 and 256 bits keys")

    def encrypt(self, M, K):
        return self._decrypt_encrypt(M, K, False)

    def decrypt(self, C, K):
        return self._decrypt_encrypt(C, K, True)

