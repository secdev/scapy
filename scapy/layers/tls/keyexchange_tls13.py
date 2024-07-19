# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2017 Maxence Tury
#               2019 Romain Perez

"""
TLS 1.3 key exchange logic.
"""

import struct

from scapy.config import conf, crypto_validator
from scapy.error import log_runtime
from scapy.fields import (
    FieldLenField,
    IntField,
    PacketField,
    PacketLenField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrFixedLenField,
    StrLenField,
    XStrLenField,
)
from scapy.packet import Packet
from scapy.layers.tls.extensions import TLS_Ext_Unknown, _tls_ext
from scapy.layers.tls.cert import PrivKeyECDSA, PrivKeyRSA, PrivKeyEdDSA
from scapy.layers.tls.crypto.groups import (
    _tls_named_curves,
    _tls_named_ffdh_groups,
    _tls_named_groups,
    _tls_named_groups_generate,
    _tls_named_groups_import,
    _tls_named_groups_pubbytes,
)

if conf.crypto_valid:
    from cryptography.hazmat.primitives.asymmetric import ec
if conf.crypto_valid_advanced:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.asymmetric import ed448


class KeyShareEntry(Packet):
    """
    When building from scratch, we create a DH private key, and when
    dissecting, we create a DH public key. Default group is secp256r1.
    """
    __slots__ = ["privkey", "pubkey"]
    name = "Key Share Entry"
    fields_desc = [ShortEnumField("group", None, _tls_named_groups),
                   FieldLenField("kxlen", None, length_of="key_exchange"),
                   XStrLenField("key_exchange", "",
                                length_from=lambda pkt: pkt.kxlen)]

    def __init__(self, *args, **kargs):
        self.privkey = None
        self.pubkey = None
        super(KeyShareEntry, self).__init__(*args, **kargs)

    def do_build(self):
        """
        We need this hack, else 'self' would be replaced by __iter__.next().
        """
        tmp = self.explicit
        self.explicit = True
        b = super(KeyShareEntry, self).do_build()
        self.explicit = tmp
        return b

    @crypto_validator
    def create_privkey(self):
        """
        This is called by post_build() for key creation.
        """
        self.privkey = _tls_named_groups_generate(self.group)
        self.key_exchange = _tls_named_groups_pubbytes(self.privkey)

    def post_build(self, pkt, pay):
        if self.group is None:
            self.group = 23     # secp256r1

        if not self.key_exchange:
            try:
                self.create_privkey()
            except ImportError:
                pass

        if self.kxlen is None:
            self.kxlen = len(self.key_exchange)

        group = struct.pack("!H", self.group)
        kxlen = struct.pack("!H", self.kxlen)
        return group + kxlen + self.key_exchange + pay

    @crypto_validator
    def register_pubkey(self):
        self.pubkey = _tls_named_groups_import(
            self.group,
            self.key_exchange
        )

    def post_dissection(self, r):
        try:
            self.register_pubkey()
        except ImportError:
            pass

    def extract_padding(self, s):
        return "", s


class TLS_Ext_KeyShare_CH(TLS_Ext_Unknown):
    name = "TLS Extension - Key Share (for ClientHello)"
    fields_desc = [ShortEnumField("type", 0x33, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("client_shares_len", None,
                                 length_of="client_shares"),
                   PacketListField("client_shares", [], KeyShareEntry,
                                   length_from=lambda pkt: pkt.client_shares_len)]  # noqa: E501

    def post_build(self, pkt, pay):
        if not self.tls_session.frozen:
            privshares = self.tls_session.tls13_client_privshares
            for kse in self.client_shares:
                if kse.privkey:
                    if _tls_named_groups[kse.group] in privshares:
                        pkt_info = pkt.firstlayer().summary()
                        log_runtime.info("TLS: group %s used twice in the same ClientHello [%s]", kse.group, pkt_info)  # noqa: E501
                        break
                    privshares[_tls_named_groups[kse.group]] = kse.privkey
        return super(TLS_Ext_KeyShare_CH, self).post_build(pkt, pay)

    def post_dissection(self, r):
        if not self.tls_session.frozen:
            for kse in self.client_shares:
                if kse.pubkey:
                    pubshares = self.tls_session.tls13_client_pubshares
                    if _tls_named_groups[kse.group] in pubshares:
                        pkt_info = r.firstlayer().summary()
                        log_runtime.info("TLS: group %s used twice in the same ClientHello [%s]", kse.group, pkt_info)  # noqa: E501
                        break
                    pubshares[_tls_named_groups[kse.group]] = kse.pubkey
        return super(TLS_Ext_KeyShare_CH, self).post_dissection(r)


class TLS_Ext_KeyShare_HRR(TLS_Ext_Unknown):
    name = "TLS Extension - Key Share (for HelloRetryRequest)"
    fields_desc = [ShortEnumField("type", 0x33, _tls_ext),
                   ShortField("len", None),
                   ShortEnumField("selected_group", None, _tls_named_groups)]


class TLS_Ext_KeyShare_SH(TLS_Ext_Unknown):
    name = "TLS Extension - Key Share (for ServerHello)"
    fields_desc = [ShortEnumField("type", 0x33, _tls_ext),
                   ShortField("len", None),
                   PacketField("server_share", None, KeyShareEntry)]

    def post_build(self, pkt, pay):
        if not self.tls_session.frozen and self.server_share.privkey:
            # if there is a privkey, we assume the crypto library is ok
            privshare = self.tls_session.tls13_server_privshare
            if len(privshare) > 0:
                pkt_info = pkt.firstlayer().summary()
                log_runtime.info("TLS: overwriting previous server key share [%s]", pkt_info)  # noqa: E501
            group_name = _tls_named_groups[self.server_share.group]
            privshare[group_name] = self.server_share.privkey

            if group_name in self.tls_session.tls13_client_pubshares:
                privkey = self.server_share.privkey
                pubkey = self.tls_session.tls13_client_pubshares[group_name]
                if group_name in _tls_named_ffdh_groups.values():
                    pms = privkey.exchange(pubkey)
                elif group_name in _tls_named_curves.values():
                    if group_name in ["x25519", "x448"]:
                        pms = privkey.exchange(pubkey)
                    else:
                        pms = privkey.exchange(ec.ECDH(), pubkey)
                self.tls_session.tls13_dhe_secret = pms
                self.tls_session.kx_group = group_name
        return super(TLS_Ext_KeyShare_SH, self).post_build(pkt, pay)

    def post_dissection(self, r):
        if not self.tls_session.frozen and self.server_share.pubkey:
            # if there is a pubkey, we assume the crypto library is ok
            pubshare = self.tls_session.tls13_server_pubshare
            if pubshare:
                pkt_info = r.firstlayer().summary()
                log_runtime.info("TLS: overwriting previous server key share [%s]", pkt_info)  # noqa: E501
            group_name = _tls_named_groups[self.server_share.group]
            pubshare[group_name] = self.server_share.pubkey

            if group_name in self.tls_session.tls13_client_privshares:
                pubkey = self.server_share.pubkey
                privkey = self.tls_session.tls13_client_privshares[group_name]
                if group_name in _tls_named_ffdh_groups.values():
                    pms = privkey.exchange(pubkey)
                elif group_name in _tls_named_curves.values():
                    if group_name in ["x25519", "x448"]:
                        pms = privkey.exchange(pubkey)
                    else:
                        pms = privkey.exchange(ec.ECDH(), pubkey)
                self.tls_session.tls13_dhe_secret = pms
                self.tls_session.kx_group = group_name
            elif group_name in self.tls_session.tls13_server_privshare:
                pubkey = self.tls_session.tls13_client_pubshares[group_name]
                privkey = self.tls_session.tls13_server_privshare[group_name]
                if group_name in _tls_named_ffdh_groups.values():
                    pms = privkey.exchange(pubkey)
                elif group_name in _tls_named_curves.values():
                    if group_name in ["x25519", "x448"]:
                        pms = privkey.exchange(pubkey)
                    else:
                        pms = privkey.exchange(ec.ECDH(), pubkey)
                self.tls_session.tls13_dhe_secret = pms
                self.tls_session.kx_group = group_name
        return super(TLS_Ext_KeyShare_SH, self).post_dissection(r)


_tls_ext_keyshare_cls = {1: TLS_Ext_KeyShare_CH,
                         2: TLS_Ext_KeyShare_SH}

_tls_ext_keyshare_hrr_cls = {2: TLS_Ext_KeyShare_HRR}


class Ticket(Packet):
    name = "Recommended Ticket Construction (from RFC 5077)"
    fields_desc = [StrFixedLenField("key_name", None, 16),
                   StrFixedLenField("iv", None, 16),
                   FieldLenField("encstatelen", None, length_of="encstate"),
                   StrLenField("encstate", "",
                               length_from=lambda pkt: pkt.encstatelen),
                   StrFixedLenField("mac", None, 32)]


class TicketField(PacketLenField):
    def m2i(self, pkt, m):
        if len(m) < 64:
            # Minimum ticket size is 64 bytes
            return conf.raw_layer(m)
        return self.cls(m)


class PSKIdentity(Packet):
    name = "PSK Identity"
    fields_desc = [FieldLenField("identity_len", None,
                                 length_of="identity"),
                   TicketField("identity", "", Ticket,
                               length_from=lambda pkt: pkt.identity_len),
                   IntField("obfuscated_ticket_age", 0)]

    def default_payload_class(self, payload):
        return conf.padding_layer


class PSKBinderEntry(Packet):
    name = "PSK Binder Entry"
    fields_desc = [FieldLenField("binder_len", None, fmt="B",
                                 length_of="binder"),
                   StrLenField("binder", "",
                               length_from=lambda pkt: pkt.binder_len)]

    def default_payload_class(self, payload):
        return conf.padding_layer


class TLS_Ext_PreSharedKey_CH(TLS_Ext_Unknown):
    # XXX define post_build and post_dissection methods
    name = "TLS Extension - Pre Shared Key (for ClientHello)"
    fields_desc = [ShortEnumField("type", 0x29, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("identities_len", None,
                                 length_of="identities"),
                   PacketListField("identities", [], PSKIdentity,
                                   length_from=lambda pkt: pkt.identities_len),
                   FieldLenField("binders_len", None,
                                 length_of="binders"),
                   PacketListField("binders", [], PSKBinderEntry,
                                   length_from=lambda pkt: pkt.binders_len)]


class TLS_Ext_PreSharedKey_SH(TLS_Ext_Unknown):
    name = "TLS Extension - Pre Shared Key (for ServerHello)"
    fields_desc = [ShortEnumField("type", 0x29, _tls_ext),
                   ShortField("len", None),
                   ShortField("selected_identity", None)]


_tls_ext_presharedkey_cls = {1: TLS_Ext_PreSharedKey_CH,
                             2: TLS_Ext_PreSharedKey_SH}


# Util to find usable signature algorithms

# TLS 1.3 SignatureScheme is a subset of _tls_hash_sig
_tls13_usable_certificate_verify_algs = [
    # ECDSA algorithms
    0x0403, 0x0503, 0x0603,
    # RSASSA-PSS algorithms with public key OID rsaEncryption
    0x0804, 0x0805, 0x0806,
    # EdDSA algorithms
    0x0807, 0x0808,
]

_tls13_usable_certificate_signature_algs = [
    # RSASSA-PKCS1-v1_5 algorithms
    0x0401, 0x0501, 0x0601,
    # ECDSA algorithms
    0x0403, 0x0503, 0x0603,
    # EdDSA algorithms
    0x0807, 0x0808,
    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    0x0809, 0x080a, 0x080b,
    # Legacy algorithms
    0x0201, 0x0203,
]


def get_usable_tls13_sigalgs(li, key, location="certificateverify"):
    """
    From a list of proposed signature algorithms, this function returns a list of
    usable signature algorithms.
    The order of the signature algorithms in the list returned by the
    function matches the one of the proposal.
    """
    from scapy.layers.tls.keyexchange import _tls_hash_sig
    res = []
    if isinstance(key, PrivKeyRSA):
        kx = "rsa"
    elif isinstance(key, PrivKeyECDSA):
        kx = "ecdsa"
    elif isinstance(key, PrivKeyEdDSA):
        if isinstance(key.pubkey, ed25519.Ed25519PublicKey):
            kx = "ed25519"
        elif isinstance(key.pubkey, ed448.Ed448PublicKey):
            kx = "ed448"
        else:
            kx = "unknown"
    else:
        return res
    if location == "certificateverify":
        algs = _tls13_usable_certificate_verify_algs
    elif location == "certificatesignature":
        algs = _tls13_usable_certificate_signature_algs
    else:
        return res
    for c in li:
        if c in algs:
            sigalg = _tls_hash_sig[c]
            if "+" in sigalg:
                _, sig = sigalg.split('+')
            else:
                sig = sigalg
            if kx in sig:
                res.append(c)
    return res
