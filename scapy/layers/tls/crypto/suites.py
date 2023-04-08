# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury

"""
TLS cipher suites.

A comprehensive list of specified cipher suites can be consulted at:
https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
"""

from scapy.layers.tls.crypto.kx_algs import _tls_kx_algs
from scapy.layers.tls.crypto.hash import _tls_hash_algs
from scapy.layers.tls.crypto.h_mac import _tls_hmac_algs
from scapy.layers.tls.crypto.ciphers import _tls_cipher_algs


def get_algs_from_ciphersuite_name(ciphersuite_name):
    """
    Return the 3-tuple made of the Key Exchange Algorithm class, the Cipher
    class and the HMAC class, through the parsing of the ciphersuite name.
    """
    tls1_3 = False
    if ciphersuite_name.startswith("TLS"):
        s = ciphersuite_name[4:]

        if s.endswith("CCM") or s.endswith("CCM_8"):
            kx_name, s = s.split("_WITH_")
            kx_alg = _tls_kx_algs.get(kx_name)
            hash_alg = _tls_hash_algs.get("SHA256")
            cipher_alg = _tls_cipher_algs.get(s)
            hmac_alg = None

        else:
            if "WITH" in s:
                kx_name, s = s.split("_WITH_")
                kx_alg = _tls_kx_algs.get(kx_name)
            else:
                tls1_3 = True
                kx_alg = _tls_kx_algs.get("TLS13")

            hash_name = s.split('_')[-1]
            hash_alg = _tls_hash_algs.get(hash_name)

            cipher_name = s[:-(len(hash_name) + 1)]
            if tls1_3:
                cipher_name += "_TLS13"
            cipher_alg = _tls_cipher_algs.get(cipher_name)

            hmac_alg = None
            if cipher_alg is not None and cipher_alg.type != "aead":
                hmac_name = "HMAC-%s" % hash_name
                hmac_alg = _tls_hmac_algs.get(hmac_name)

    elif ciphersuite_name.startswith("SSL"):
        s = ciphersuite_name[7:]
        kx_alg = _tls_kx_algs.get("SSLv2")
        cipher_name, hash_name = s.split("_WITH_")
        cipher_alg = _tls_cipher_algs.get(cipher_name.rstrip("_EXPORT40"))
        kx_alg.export = cipher_name.endswith("_EXPORT40")
        hmac_alg = _tls_hmac_algs.get("HMAC-NULL")
        hash_alg = _tls_hash_algs.get(hash_name)

    return kx_alg, cipher_alg, hmac_alg, hash_alg, tls1_3


_tls_cipher_suites = {}
_tls_cipher_suites_cls = {}


class _GenericCipherSuiteMetaclass(type):
    """
    Cipher suite classes are automatically registered through this metaclass.
    Their name attribute equates their respective class name.

    We also pre-compute every expected length of the key block to be generated,
    which may vary according to the current tls_version. The default is set to
    the TLS 1.2 length, and the value should be set at class instantiation.

    Regarding the AEAD cipher suites, note that the 'hmac_alg' attribute will
    be set to None. Yet, we always need a 'hash_alg' for the PRF.
    """
    def __new__(cls, cs_name, bases, dct):
        cs_val = dct.get("val")

        if cs_name != "_GenericCipherSuite":
            kx, c, hm, h, tls1_3 = get_algs_from_ciphersuite_name(cs_name)

            if c is None or h is None or (kx is None and not tls1_3):
                dct["usable"] = False
            else:
                dct["usable"] = True
                dct["name"] = cs_name
                dct["kx_alg"] = kx
                dct["cipher_alg"] = c
                dct["hmac_alg"] = hm
                dct["hash_alg"] = h

                if not tls1_3:
                    kb_len = 2 * c.key_len

                    if c.type == "stream" or c.type == "block":
                        kb_len += 2 * hm.key_len

                    kb_len_v1_0 = kb_len
                    if c.type == "block":
                        kb_len_v1_0 += 2 * c.block_size
                        # no explicit IVs added for TLS 1.1+
                    elif c.type == "aead":
                        kb_len_v1_0 += 2 * c.fixed_iv_len
                        kb_len += 2 * c.fixed_iv_len

                    dct["_key_block_len_v1_0"] = kb_len_v1_0
                    dct["key_block_len"] = kb_len

            _tls_cipher_suites[cs_val] = cs_name
        the_class = super(_GenericCipherSuiteMetaclass, cls).__new__(cls,
                                                                     cs_name,
                                                                     bases,
                                                                     dct)
        if cs_name != "_GenericCipherSuite":
            _tls_cipher_suites_cls[cs_val] = the_class
        return the_class


class _GenericCipherSuite(metaclass=_GenericCipherSuiteMetaclass):
    def __init__(self, tls_version=0x0303):
        """
        Most of the attributes are fixed and have already been set by the
        metaclass, but we still have to provide tls_version differentiation.

        For now, the key_block_len remains the only application if this.
        Indeed for TLS 1.1+, when using a block cipher, there are no implicit
        IVs derived from the master secret. Note that an overlong key_block_len
        would not affect the secret generation (the trailing bytes would
        simply be discarded), but we still provide this for completeness.
        """
        super(_GenericCipherSuite, self).__init__()
        if tls_version <= 0x301:
            self.key_block_len = self._key_block_len_v1_0


class TLS_NULL_WITH_NULL_NULL(_GenericCipherSuite):
    val = 0x0000


class TLS_RSA_WITH_NULL_MD5(_GenericCipherSuite):
    val = 0x0001


class TLS_RSA_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0x0002


class TLS_RSA_EXPORT_WITH_RC4_40_MD5(_GenericCipherSuite):
    val = 0x0003


class TLS_RSA_WITH_RC4_128_MD5(_GenericCipherSuite):
    val = 0x0004


class TLS_RSA_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0x0005


class TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5(_GenericCipherSuite):
    val = 0x0006


class TLS_RSA_WITH_IDEA_CBC_SHA(_GenericCipherSuite):
    val = 0x0007


class TLS_RSA_EXPORT_WITH_DES40_CBC_SHA(_GenericCipherSuite):
    val = 0x0008


class TLS_RSA_WITH_DES_CBC_SHA(_GenericCipherSuite):
    val = 0x0009


class TLS_RSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x000A


class TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA(_GenericCipherSuite):
    val = 0x000B


class TLS_DH_DSS_WITH_DES_CBC_SHA(_GenericCipherSuite):
    val = 0x000C


class TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x000D


class TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA(_GenericCipherSuite):
    val = 0x000E


class TLS_DH_RSA_WITH_DES_CBC_SHA(_GenericCipherSuite):
    val = 0x000F


class TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x0010


class TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA(_GenericCipherSuite):
    val = 0x0011


class TLS_DHE_DSS_WITH_DES_CBC_SHA(_GenericCipherSuite):
    val = 0x0012


class TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x0013


class TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA(_GenericCipherSuite):
    val = 0x0014


class TLS_DHE_RSA_WITH_DES_CBC_SHA(_GenericCipherSuite):
    val = 0x0015


class TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x0016


class TLS_DH_anon_EXPORT_WITH_RC4_40_MD5(_GenericCipherSuite):
    val = 0x0017


class TLS_DH_anon_WITH_RC4_128_MD5(_GenericCipherSuite):
    val = 0x0018


class TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA(_GenericCipherSuite):
    val = 0x0019


class TLS_DH_anon_WITH_DES_CBC_SHA(_GenericCipherSuite):
    val = 0x001A


class TLS_DH_anon_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x001B


class TLS_KRB5_WITH_DES_CBC_SHA(_GenericCipherSuite):
    val = 0x001E


class TLS_KRB5_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x001F


class TLS_KRB5_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0x0020


class TLS_KRB5_WITH_IDEA_CBC_SHA(_GenericCipherSuite):
    val = 0x0021


class TLS_KRB5_WITH_DES_CBC_MD5(_GenericCipherSuite):
    val = 0x0022


class TLS_KRB5_WITH_3DES_EDE_CBC_MD5(_GenericCipherSuite):
    val = 0x0023


class TLS_KRB5_WITH_RC4_128_MD5(_GenericCipherSuite):
    val = 0x0024


class TLS_KRB5_WITH_IDEA_CBC_MD5(_GenericCipherSuite):
    val = 0x0025


class TLS_KRB5_EXPORT_WITH_DES40_CBC_SHA(_GenericCipherSuite):
    val = 0x0026


class TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA(_GenericCipherSuite):
    val = 0x0027


class TLS_KRB5_EXPORT_WITH_RC4_40_SHA(_GenericCipherSuite):
    val = 0x0028


class TLS_KRB5_EXPORT_WITH_DES40_CBC_MD5(_GenericCipherSuite):
    val = 0x0029


class TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5(_GenericCipherSuite):
    val = 0x002A


class TLS_KRB5_EXPORT_WITH_RC4_40_MD5(_GenericCipherSuite):
    val = 0x002B


class TLS_PSK_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0x002C


class TLS_DHE_PSK_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0x002D


class TLS_RSA_PSK_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0x002E


class TLS_RSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x002F


class TLS_DH_DSS_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0030


class TLS_DH_RSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0031


class TLS_DHE_DSS_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0032


class TLS_DHE_RSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0033


class TLS_DH_anon_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0034


class TLS_RSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0035


class TLS_DH_DSS_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0036


class TLS_DH_RSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0037


class TLS_DHE_DSS_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0038


class TLS_DHE_RSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0039


class TLS_DH_anon_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x003A


class TLS_RSA_WITH_NULL_SHA256(_GenericCipherSuite):
    val = 0x003B


class TLS_RSA_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x003C


class TLS_RSA_WITH_AES_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x003D


class TLS_DH_DSS_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x003E


class TLS_DH_RSA_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x003F


class TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x0040


class TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0041


class TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0042


class TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0043


class TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0044


class TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0045


class TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0046


class TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x0067


class TLS_DH_DSS_WITH_AES_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x0068


class TLS_DH_RSA_WITH_AES_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x0069


class TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x006A


class TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x006B


class TLS_DH_anon_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x006C


class TLS_DH_anon_WITH_AES_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x006D


class TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0084


class TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0085


class TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0086


class TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0087


class TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0088


class TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0089


class TLS_PSK_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0x008A


class TLS_PSK_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x008B


class TLS_PSK_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x008C


class TLS_PSK_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x008D


class TLS_DHE_PSK_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0x008E


class TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x008F


class TLS_DHE_PSK_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0090


class TLS_DHE_PSK_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0091


class TLS_RSA_PSK_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0x0092


class TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0x0093


class TLS_RSA_PSK_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0x0094


class TLS_RSA_PSK_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0x0095


class TLS_RSA_WITH_SEED_CBC_SHA(_GenericCipherSuite):
    val = 0x0096


class TLS_DH_DSS_WITH_SEED_CBC_SHA(_GenericCipherSuite):
    val = 0x0097


class TLS_DH_RSA_WITH_SEED_CBC_SHA(_GenericCipherSuite):
    val = 0x0098


class TLS_DHE_DSS_WITH_SEED_CBC_SHA(_GenericCipherSuite):
    val = 0x0099


class TLS_DHE_RSA_WITH_SEED_CBC_SHA(_GenericCipherSuite):
    val = 0x009A


class TLS_DH_anon_WITH_SEED_CBC_SHA(_GenericCipherSuite):
    val = 0x009B


class TLS_RSA_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x009C


class TLS_RSA_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x009D


class TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x009E


class TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x009F


class TLS_DH_RSA_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x00A0


class TLS_DH_RSA_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x00A1


class TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x00A2


class TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x00A3


class TLS_DH_DSS_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x00A4


class TLS_DH_DSS_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x00A5


class TLS_DH_anon_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x00A6


class TLS_DH_anon_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x00A7


class TLS_PSK_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x00A8


class TLS_PSK_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x00A9


class TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x00AA


class TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x00AB


class TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x00AC


class TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x00AD


class TLS_PSK_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00AE


class TLS_PSK_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0x00AF


class TLS_PSK_WITH_NULL_SHA256(_GenericCipherSuite):
    val = 0x00B0


class TLS_PSK_WITH_NULL_SHA384(_GenericCipherSuite):
    val = 0x00B1


class TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00B2


class TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0x00B3


class TLS_DHE_PSK_WITH_NULL_SHA256(_GenericCipherSuite):
    val = 0x00B4


class TLS_DHE_PSK_WITH_NULL_SHA384(_GenericCipherSuite):
    val = 0x00B5


class TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00B6


class TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0x00B7


class TLS_RSA_PSK_WITH_NULL_SHA256(_GenericCipherSuite):
    val = 0x00B8


class TLS_RSA_PSK_WITH_NULL_SHA384(_GenericCipherSuite):
    val = 0x00B9


class TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00BA


class TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00BB


class TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00BC


class TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00BD


class TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00BE


class TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0x00BF


class TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x00C0


class TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x00C1


class TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x00C2


class TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x00C3


class TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x00C4


class TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256(_GenericCipherSuite):
    val = 0x00C5

# class TLS_EMPTY_RENEGOTIATION_INFO_CSV(_GenericCipherSuite):
#    val = 0x00FF

# class TLS_FALLBACK_SCSV(_GenericCipherSuite):
#    val = 0x5600


class TLS_ECDH_ECDSA_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0xC001


class TLS_ECDH_ECDSA_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0xC002


class TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC003


class TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC004


class TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC005


class TLS_ECDHE_ECDSA_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0xC006


class TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0xC007


class TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC008


class TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC009


class TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC00A


class TLS_ECDH_RSA_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0xC00B


class TLS_ECDH_RSA_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0xC00C


class TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC00D


class TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC00E


class TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC00F


class TLS_ECDHE_RSA_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0xC010


class TLS_ECDHE_RSA_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0xC011


class TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC012


class TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC013


class TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC014


class TLS_ECDH_anon_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0xC015


class TLS_ECDH_anon_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0xC016


class TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC017


class TLS_ECDH_anon_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC018


class TLS_ECDH_anon_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC019


class TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC01A


class TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC01B


class TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC01C


class TLS_SRP_SHA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC01D


class TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC01E


class TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC01F


class TLS_SRP_SHA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC020


class TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC021


class TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC022


class TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC023


class TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC024


class TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC025


class TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC026


class TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC027


class TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC028


class TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC029


class TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC02A


class TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC02B


class TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC02C


class TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC02D


class TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC02E


class TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC02F


class TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC030


class TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC031


class TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC032


class TLS_ECDHE_PSK_WITH_RC4_128_SHA(_GenericCipherSuite):
    val = 0xC033


class TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA(_GenericCipherSuite):
    val = 0xC034


class TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(_GenericCipherSuite):
    val = 0xC035


class TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(_GenericCipherSuite):
    val = 0xC036


class TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC037


class TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC038


class TLS_ECDHE_PSK_WITH_NULL_SHA(_GenericCipherSuite):
    val = 0xC039


class TLS_ECDHE_PSK_WITH_NULL_SHA256(_GenericCipherSuite):
    val = 0xC03A


class TLS_ECDHE_PSK_WITH_NULL_SHA384(_GenericCipherSuite):
    val = 0xC03B

# suites 0xC03C-C071 use ARIA


class TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC072


class TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC073


class TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC074


class TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC075


class TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC076


class TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC077


class TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC078


class TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC079


class TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC07A


class TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC07B


class TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC07C


class TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC07D


class TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC07E


class TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC07F


class TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC080


class TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC081


class TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC082


class TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC083


class TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC084


class TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC085


class TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC086


class TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC087


class TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC088


class TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC089


class TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC08A


class TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC08B


class TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC08C


class TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC08D


class TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC08E


class TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC08F


class TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC090


class TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC091


class TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256(_GenericCipherSuite):
    val = 0xC092


class TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384(_GenericCipherSuite):
    val = 0xC093


class TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC094


class TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC095


class TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC096


class TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC097


class TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC098


class TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC099


class TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(_GenericCipherSuite):
    val = 0xC09A


class TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(_GenericCipherSuite):
    val = 0xC09B


class TLS_RSA_WITH_AES_128_CCM(_GenericCipherSuite):
    val = 0xC09C


class TLS_RSA_WITH_AES_256_CCM(_GenericCipherSuite):
    val = 0xC09D


class TLS_DHE_RSA_WITH_AES_128_CCM(_GenericCipherSuite):
    val = 0xC09E


class TLS_DHE_RSA_WITH_AES_256_CCM(_GenericCipherSuite):
    val = 0xC09F


class TLS_RSA_WITH_AES_128_CCM_8(_GenericCipherSuite):
    val = 0xC0A0


class TLS_RSA_WITH_AES_256_CCM_8(_GenericCipherSuite):
    val = 0xC0A1


class TLS_DHE_RSA_WITH_AES_128_CCM_8(_GenericCipherSuite):
    val = 0xC0A2


class TLS_DHE_RSA_WITH_AES_256_CCM_8(_GenericCipherSuite):
    val = 0xC0A3


class TLS_PSK_WITH_AES_128_CCM(_GenericCipherSuite):
    val = 0xC0A4


class TLS_PSK_WITH_AES_256_CCM(_GenericCipherSuite):
    val = 0xC0A5


class TLS_DHE_PSK_WITH_AES_128_CCM(_GenericCipherSuite):
    val = 0xC0A6


class TLS_DHE_PSK_WITH_AES_256_CCM(_GenericCipherSuite):
    val = 0xC0A7


class TLS_PSK_WITH_AES_128_CCM_8(_GenericCipherSuite):
    val = 0xC0A8


class TLS_PSK_WITH_AES_256_CCM_8(_GenericCipherSuite):
    val = 0xC0A9


class TLS_DHE_PSK_WITH_AES_128_CCM_8(_GenericCipherSuite):
    val = 0xC0AA


class TLS_DHE_PSK_WITH_AES_256_CCM_8(_GenericCipherSuite):
    val = 0xC0AB


class TLS_ECDHE_ECDSA_WITH_AES_128_CCM(_GenericCipherSuite):
    val = 0xC0AC


class TLS_ECDHE_ECDSA_WITH_AES_256_CCM(_GenericCipherSuite):
    val = 0xC0AD


class TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(_GenericCipherSuite):
    val = 0xC0AE


class TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8(_GenericCipherSuite):
    val = 0xC0AF

# the next 3 suites are from draft-agl-tls-chacha20poly1305-04


class TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD(_GenericCipherSuite):
    val = 0xCC13


class TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD(_GenericCipherSuite):
    val = 0xCC14


class TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD(_GenericCipherSuite):
    val = 0xCC15


class TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0xCCA8


class TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0xCCA9


class TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0xCCAA


class TLS_PSK_WITH_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0xCCAB


class TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0xCCAC


class TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0xCCAD


class TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0xCCAE


class TLS_AES_128_GCM_SHA256(_GenericCipherSuite):
    val = 0x1301


class TLS_AES_256_GCM_SHA384(_GenericCipherSuite):
    val = 0x1302


class TLS_CHACHA20_POLY1305_SHA256(_GenericCipherSuite):
    val = 0x1303


class TLS_AES_128_CCM_SHA256(_GenericCipherSuite):
    val = 0x1304


class TLS_AES_128_CCM_8_SHA256(_GenericCipherSuite):
    val = 0x1305


class SSL_CK_RC4_128_WITH_MD5(_GenericCipherSuite):
    val = 0x010080


class SSL_CK_RC4_128_EXPORT40_WITH_MD5(_GenericCipherSuite):
    val = 0x020080


class SSL_CK_RC2_128_CBC_WITH_MD5(_GenericCipherSuite):
    val = 0x030080


class SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5(_GenericCipherSuite):
    val = 0x040080


class SSL_CK_IDEA_128_CBC_WITH_MD5(_GenericCipherSuite):
    val = 0x050080


class SSL_CK_DES_64_CBC_WITH_MD5(_GenericCipherSuite):
    val = 0x060040


class SSL_CK_DES_192_EDE3_CBC_WITH_MD5(_GenericCipherSuite):
    val = 0x0700C0


_tls_cipher_suites[0x00ff] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
_tls_cipher_suites[0x5600] = "TLS_FALLBACK_SCSV"


def get_usable_ciphersuites(li, kx):
    """
    From a list of proposed ciphersuites, this function returns a list of
    usable cipher suites, i.e. for which key exchange, cipher and hash
    algorithms are known to be implemented and usable in current version of the
    TLS extension. The order of the cipher suites in the list returned by the
    function matches the one of the proposal.
    """
    res = []
    for c in li:
        if c in _tls_cipher_suites_cls:
            cipher = _tls_cipher_suites_cls[c]
            if cipher.usable:
                # XXX select among RSA and ECDSA cipher suites
                # according to the key(s) the server was given
                if (cipher.kx_alg.anonymous or
                   kx in cipher.kx_alg.name or
                   cipher.kx_alg.name == "TLS13"):
                    res.append(c)
    return res
