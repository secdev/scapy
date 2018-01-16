## This file is part of Scapy
## Copyright (C) 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS 1.3 key exchange logic.
"""

import math

from scapy.config import conf, crypto_validator
from scapy.error import log_runtime, warning
from scapy.fields import *
from scapy.packet import Packet, Raw, Padding
from scapy.layers.tls.cert import PubKeyRSA, PrivKeyRSA
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.basefields import _tls_version, _TLSClientVersionField
from scapy.layers.tls.extensions import TLS_Ext_Unknown, _tls_ext
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip
from scapy.layers.tls.crypto.groups import (_tls_named_ffdh_groups,
                                            _tls_named_curves, _ffdh_groups,
                                            _tls_named_groups)

if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import dh, ec
if conf.crypto_valid_advanced:
    from cryptography.hazmat.primitives.asymmetric import x25519


class KeyShareEntry(Packet):
    """
    When building from scratch, we create a DH private key, and when
    dissecting, we create a DH public key. Default group is secp256r1.
    """
    __slots__ = ["privkey", "pubkey"]
    name = "Key Share Entry"
    fields_desc = [ShortEnumField("group", None, _tls_named_groups),
                   FieldLenField("kxlen", None, length_of="key_exchange"),
                   StrLenField("key_exchange", "",
                               length_from=lambda pkt: pkt.kxlen) ]

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
        if self.group in _tls_named_ffdh_groups:
            params = _ffdh_groups[_tls_named_ffdh_groups[self.group]][0]
            privkey = params.generate_private_key()
            self.privkey = privkey
            pubkey = privkey.public_key()
            self.key_exchange = pubkey.public_numbers().y
        elif self.group in _tls_named_curves:
            if _tls_named_curves[self.group] == "x25519":
                if conf.crypto_valid_advanced:
                    privkey = x25519.X25519PrivateKey.generate()
                    self.privkey = privkey
                    pubkey = privkey.public_key()
                    self.key_exchange = pubkey.public_bytes()
            elif _tls_named_curves[self.group] != "x448":
                curve = ec._CURVE_TYPES[_tls_named_curves[self.group]]()
                privkey = ec.generate_private_key(curve, default_backend())
                self.privkey = privkey
                pubkey = privkey.public_key()
                self.key_exchange = pubkey.public_numbers().encode_point()

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
        if self.group in _tls_named_ffdh_groups:
            params = _ffdh_groups[_tls_named_ffdh_groups[self.group]][0]
            pn = params.parameter_numbers()
            public_numbers = dh.DHPublicNumbers(self.key_exchange, pn)
            self.pubkey = public_numbers.public_key(default_backend())
        elif self.group in _tls_named_curves:
            if _tls_named_curves[self.group] == "x25519":
                if conf.crypto_valid_advanced:
                    import_point = x25519.X25519PublicKey.from_public_bytes
                    self.pubkey = import_point(self.key_exchange)
            elif _tls_named_curves[self.group] != "x448":
                curve = ec._CURVE_TYPES[_tls_named_curves[self.group]]()
                import_point = ec.EllipticCurvePublicNumbers.from_encoded_point
                public_numbers = import_point(curve, self.key_exchange)
                self.pubkey = public_numbers.public_key(default_backend())

    def post_dissection(self, r):
        try:
            self.register_pubkey()
        except ImportError:
            pass

    def extract_padding(self, s):
        return "", s


class TLS_Ext_KeyShare_CH(TLS_Ext_Unknown):
    name = "TLS Extension - Key Share (for ClientHello)"
    fields_desc = [ShortEnumField("type", 0x28, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("client_shares_len", None,
                                 length_of="client_shares"),
                   PacketListField("client_shares", [], KeyShareEntry,
                            length_from=lambda pkt: pkt.client_shares_len) ]

    def post_build(self, pkt, pay):
        if not self.tls_session.frozen:
            privshares = self.tls_session.tls13_client_privshares
            for kse in self.client_shares:
                if kse.privkey:
                    if _tls_named_curves[kse.group] in privshares:
                        pkt_info = pkt.firstlayer().summary()
                        log_runtime.info("TLS: group %s used twice in the same ClientHello [%s]", kse.group, pkt_info)
                        break
                    privshares[_tls_named_groups[kse.group]] = kse.privkey
        return super(TLS_Ext_KeyShare_CH, self).post_build(pkt, pay)

    def post_dissection(self, r):
        if not self.tls_session.frozen:
            for kse in self.client_shares:
                if kse.pubkey:
                    pubshares = self.tls_session.tls13_client_pubshares
                    if _tls_named_curves[kse.group] in pubshares:
                        pkt_info = r.firstlayer().summary()
                        log_runtime.info("TLS: group %s used twice in the same ClientHello [%s]", kse.group, pkt_info)
                        break
                    pubshares[_tls_named_curves[kse.group]] = kse.pubkey
        return super(TLS_Ext_KeyShare_CH, self).post_dissection(r)


class TLS_Ext_KeyShare_HRR(TLS_Ext_Unknown):
    name = "TLS Extension - Key Share (for HelloRetryRequest)"
    fields_desc = [ShortEnumField("type", 0x28, _tls_ext),
                   ShortField("len", None),
                   ShortEnumField("selected_group", None, _tls_named_groups) ]


class TLS_Ext_KeyShare_SH(TLS_Ext_Unknown):
    name = "TLS Extension - Key Share (for ServerHello)"
    fields_desc = [ShortEnumField("type", 0x28, _tls_ext),
                   ShortField("len", None),
                   PacketField("server_share", None, KeyShareEntry) ]

    def post_build(self, pkt, pay):
        if not self.tls_session.frozen and self.server_share.privkey:
            # if there is a privkey, we assume the crypto library is ok
            privshare = self.tls_session.tls13_server_privshare
            if len(privshare) > 0:
                pkt_info = pkt.firstlayer().summary()
                log_runtime.info("TLS: overwriting previous server key share [%s]", pkt_info)
            group_name = _tls_named_groups[self.server_share.group]
            privshare[group_name] = self.server_share.privkey

            if group_name in self.tls_session.tls13_client_pubshares:
                privkey = self.server_share.privkey
                pubkey = self.tls_session.tls13_client_pubshares[group_name]
                if group_name in six.itervalues(_tls_named_ffdh_groups):
                    pms = privkey.exchange(pubkey)
                elif group_name in six.itervalues(_tls_named_curves):
                    if group_name == "x25519":
                        pms = privkey.exchange(pubkey)
                    else:
                        pms = privkey.exchange(ec.ECDH(), pubkey)
                self.tls_session.tls13_dhe_secret = pms
        return super(TLS_Ext_KeyShare_SH, self).post_build(pkt, pay)

    def post_dissection(self, r):
        if not self.tls_session.frozen and self.server_share.pubkey:
            # if there is a pubkey, we assume the crypto library is ok
            pubshare = self.tls_session.tls13_server_pubshare
            if len(pubshare) > 0:
                pkt_info = r.firstlayer().summary()
                log_runtime.info("TLS: overwriting previous server key share [%s]", pkt_info)
            group_name = _tls_named_groups[self.server_share.group]
            pubshare[group_name] = self.server_share.pubkey

            if group_name in self.tls_session.tls13_client_privshares:
                pubkey = self.server_share.pubkey
                privkey = self.tls_session.tls13_client_privshares[group_name]
                if group_name in six.itervalues(_tls_named_ffdh_groups):
                    pms = privkey.exchange(pubkey)
                elif group_name in six.itervalues(_tls_named_curves):
                    if group_name == "x25519":
                        pms = privkey.exchange(pubkey)
                    else:
                        pms = privkey.exchange(ec.ECDH(), pubkey)
                self.tls_session.tls13_dhe_secret = pms
        return super(TLS_Ext_KeyShare_SH, self).post_dissection(r)


_tls_ext_keyshare_cls  = { 1: TLS_Ext_KeyShare_CH,
                           2: TLS_Ext_KeyShare_SH,
                           6: TLS_Ext_KeyShare_HRR }


class Ticket(Packet):
    name = "Recommended Ticket Construction (from RFC 5077)"
    fields_desc = [ StrFixedLenField("key_name", None, 16),
                    StrFixedLenField("iv", None, 16),
                    FieldLenField("encstatelen", None, length_of="encstate"),
                    StrLenField("encstate", "",
                                length_from=lambda pkt: pkt.encstatelen),
                    StrFixedLenField("mac", None, 32) ]

class TicketField(PacketField):
    __slots__ = ["length_from"]
    def __init__(self, name, default, length_from=None, **kargs):
        self.length_from = length_from
        PacketField.__init__(self, name, default, Ticket, **kargs)

    def m2i(self, pkt, m):
        l = self.length_from(pkt)
        tbd, rem = m[:l], m[l:]
        return self.cls(tbd)/Padding(rem)

class PSKIdentity(Packet):
    name = "PSK Identity"
    fields_desc = [FieldLenField("identity_len", None,
                                 length_of="identity"),
                   TicketField("identity", "",
                               length_from=lambda pkt: pkt.identity_len),
                   IntField("obfuscated_ticket_age", 0) ]

class PSKBinderEntry(Packet):
    name = "PSK Binder Entry"
    fields_desc = [FieldLenField("binder_len", None, fmt="B",
                                 length_of="binder"),
                   StrLenField("binder", "",
                               length_from=lambda pkt: pkt.binder_len) ]

class TLS_Ext_PreSharedKey_CH(TLS_Ext_Unknown):
    #XXX define post_build and post_dissection methods
    name = "TLS Extension - Pre Shared Key (for ClientHello)"
    fields_desc = [ShortEnumField("type", 0x28, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("identities_len", None,
                                 length_of="identities"),
                   PacketListField("identities", [], PSKIdentity,
                            length_from=lambda pkt: pkt.identities_len),
                   FieldLenField("binders_len", None,
                                 length_of="binders"),
                   PacketListField("binders", [], PSKBinderEntry,
                            length_from=lambda pkt: pkt.binders_len) ]


class TLS_Ext_PreSharedKey_SH(TLS_Ext_Unknown):
    name = "TLS Extension - Pre Shared Key (for ServerHello)"
    fields_desc = [ShortEnumField("type", 0x29, _tls_ext),
                   ShortField("len", None),
                   ShortField("selected_identity", None) ]


_tls_ext_presharedkey_cls  = { 1: TLS_Ext_PreSharedKey_CH,
                               2: TLS_Ext_PreSharedKey_SH }

