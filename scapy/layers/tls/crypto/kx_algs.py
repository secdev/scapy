# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury

"""
Key Exchange algorithms as listed in appendix C of RFC 4346.

XXX No support yet for PSK (also, no static DH, DSS, SRP or KRB).
"""

from __future__ import absolute_import
from scapy.layers.tls.keyexchange import (ServerDHParams,
                                          ServerRSAParams,
                                          ClientDiffieHellmanPublic,
                                          ClientECDiffieHellmanPublic,
                                          _tls_server_ecdh_cls_guess,
                                          EncryptedPreMasterSecret)
import scapy.libs.six as six


_tls_kx_algs = {}


class _GenericKXMetaclass(type):
    """
    We could try to set server_kx_msg and client_kx_msg while parsing
    the class name... :)
    """
    def __new__(cls, kx_name, bases, dct):
        if kx_name != "_GenericKX":
            dct["name"] = kx_name[3:]       # remove leading "KX_"
        the_class = super(_GenericKXMetaclass, cls).__new__(cls, kx_name,
                                                            bases, dct)
        if kx_name != "_GenericKX":
            the_class.export = kx_name.endswith("_EXPORT")
            the_class.anonymous = "_anon" in kx_name
            the_class.no_ske = not ("DHE" in kx_name or "_anon" in kx_name)
            the_class.no_ske &= not the_class.export
            _tls_kx_algs[kx_name[3:]] = the_class
        return the_class


class _GenericKX(six.with_metaclass(_GenericKXMetaclass)):
    pass


class KX_NULL(_GenericKX):
    descr = "No key exchange"
    server_kx_msg_cls = lambda _, m: None
    client_kx_msg_cls = None


class KX_SSLv2(_GenericKX):
    descr = "SSLv2 dummy key exchange class"
    server_kx_msg_cls = lambda _, m: None
    client_kx_msg_cls = None


class KX_TLS13(_GenericKX):
    descr = "TLS 1.3 dummy key exchange class"
    server_kx_msg_cls = lambda _, m: None
    client_kx_msg_cls = None


# Standard RSA-authenticated key exchange

class KX_RSA(_GenericKX):
    descr = "RSA encryption"
    server_kx_msg_cls = lambda _, m: None
    client_kx_msg_cls = EncryptedPreMasterSecret

# class KX_DH_RSA(_GenericKX):
#    descr = "DH with RSA-based certificates"
#    server_kx_msg_cls = lambda _,m: None
#    client_kx_msg_cls = None


class KX_DHE_RSA(_GenericKX):
    descr = "Ephemeral DH with RSA signature"
    server_kx_msg_cls = lambda _, m: ServerDHParams
    client_kx_msg_cls = ClientDiffieHellmanPublic

# class KX_ECDH_RSA(_GenericKX):
#     descr = "ECDH RSA key exchange"
#     server_kx_msg_cls = lambda _,m: None
#     client_kx_msg_cls = None


class KX_ECDHE_RSA(_GenericKX):
    descr = "Ephemeral ECDH with RSA signature"
    server_kx_msg_cls = lambda _, m: _tls_server_ecdh_cls_guess(m)
    client_kx_msg_cls = ClientECDiffieHellmanPublic


class KX_RSA_EXPORT(KX_RSA):
    descr = "RSA encryption, export version"
    server_kx_msg_cls = lambda _, m: ServerRSAParams

# class KX_DH_RSA_EXPORT(KX_DH_RSA):
#    descr = "DH with RSA-based certificates - Export version"


class KX_DHE_RSA_EXPORT(KX_DHE_RSA):
    descr = "Ephemeral DH with RSA signature, export version"


# Standard ECDSA-authenticated key exchange

# class KX_ECDH_ECDSA(_GenericKX):
#     descr = "ECDH ECDSA key exchange"
#     server_kx_msg_cls = lambda _,m: None
#     client_kx_msg_cls = None

class KX_ECDHE_ECDSA(_GenericKX):
    descr = "Ephemeral ECDH with ECDSA signature"
    server_kx_msg_cls = lambda _, m: _tls_server_ecdh_cls_guess(m)
    client_kx_msg_cls = ClientECDiffieHellmanPublic


# Classes below are offered without any guarantee.
# They may offer some parsing capabilities,
# but surely won't be able to handle a proper TLS negotiation.
# Uncomment them at your own risk.

# Standard DSS-authenticated key exchange

# class KX_DH_DSS(_GenericKX):
#     descr = "DH with DSS-based certificates"
#     server_kx_msg_cls = lambda _,m: ServerDHParams
#     client_kx_msg_cls = ClientDiffieHellmanPublic

# class KX_DHE_DSS(_GenericKX):
#    descr = "Ephemeral DH with DSS signature"
#    server_kx_msg_cls = lambda _,m: ServerDHParams
#    client_kx_msg_cls = ClientDiffieHellmanPublic

# class KX_DH_DSS_EXPORT(KX_DH_DSS):
#     descr = "DH with DSS-based certificates - Export version"

# class KX_DHE_DSS_EXPORT(KX_DHE_DSS):
#    descr = "Ephemeral DH with DSS signature, export version"


# PSK-based key exchange

# class KX_PSK(_GenericKX): # RFC 4279
#     descr = "PSK key exchange"
#     server_kx_msg_cls = lambda _,m: ServerPSKParams
#     client_kx_msg_cls = None

# class KX_RSA_PSK(_GenericKX): # RFC 4279
#     descr = "RSA PSK key exchange"
#     server_kx_msg_cls = lambda _,m: ServerPSKParams
#     client_kx_msg_cls = None

# class KX_DHE_PSK(_GenericKX): # RFC 4279
#     descr = "Ephemeral DH with PSK key exchange"
#     server_kx_msg_cls = lambda _,m: ServerPSKParams
#     client_kx_msg_cls = ClientDiffieHellmanPublic

# class KX_ECDHE_PSK(_GenericKX): # RFC 5489
#     descr = "Ephemeral ECDH PSK key exchange"
#     server_kx_msg_cls = lambda _,m: _tls_server_ecdh_cls_guess(m)
#     client_kx_msg_cls = ClientDiffieHellmanPublic


# SRP-based key exchange

#


# Kerberos-based key exchange

# class KX_KRB5(_GenericKX):
#     descr = "Kerberos 5 key exchange"
#     server_kx_msg_cls = lambda _,m: None  # No SKE with kerberos
#     client_kx_msg_cls = None

# class KX_KRB5_EXPORT(KX_KRB5):
#     descr = "Kerberos 5 key exchange - Export version"


# Unauthenticated key exchange (opportunistic encryption)

class KX_DH_anon(_GenericKX):
    descr = "Anonymous DH, no signatures"
    server_kx_msg_cls = lambda _, m: ServerDHParams
    client_kx_msg_cls = ClientDiffieHellmanPublic


class KX_ECDH_anon(_GenericKX):
    descr = "ECDH anonymous key exchange"
    server_kx_msg_cls = lambda _, m: _tls_server_ecdh_cls_guess(m)
    client_kx_msg_cls = ClientECDiffieHellmanPublic


class KX_DH_anon_EXPORT(KX_DH_anon):
    descr = "Anonymous DH, no signatures - Export version"
