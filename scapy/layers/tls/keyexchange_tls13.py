## This file is part of Scapy
## Copyright (C) 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS 1.3 key exchange logic.
"""

import math

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec

from scapy.config import conf, crypto_validator
from scapy.error import warning
from scapy.fields import *
from scapy.packet import Packet, Raw, Padding
from scapy.layers.tls.cert import PubKeyRSA, PrivKeyRSA
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.basefields import _tls_version, _TLSClientVersionField
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip
from scapy.layers.tls.crypto.ffdh import _ffdh_groups
from scapy.layers.tls.keyexchange import _tls_named_curves


_tls_ext = {  0: "server_name",             # RFC 4366
              1: "max_fragment_length",     # RFC 4366
              2: "client_certificate_url",  # RFC 4366
              3: "trusted_ca_keys",         # RFC 4366
              4: "truncated_hmac",          # RFC 4366
              5: "status_request",          # RFC 4366
              6: "user_mapping",            # RFC 4681
              7: "client_authz",            # RFC 5878
              8: "server_authz",            # RFC 5878
              9: "cert_type",               # RFC 6091
            #10: "elliptic_curves",         # RFC 4492
             10: "supported_groups",
             11: "ec_point_formats",        # RFC 4492
             13: "signature_algorithms",    # RFC 5246
             0x0f: "heartbeat",             # RFC 6520
             0x10: "alpn",                  # RFC 7301
             0x15: "padding",               # RFC 7685
             0x16: "encrypt_then_mac",      # RFC 7366
             0x17: "extended_master_secret",# RFC 7627
             0x23: "session_ticket",        # RFC 5077
             0x28: "key_share",
             0x29: "pre_shared_key",
             0x2a: "early_data",
             0x2b: "supported_versions",
             0x2c: "cookie",
             0x2d: "psk_key_exchange_modes",
             0x2e: "ticket_early_data_info",
             0x2f: "certificate_authorities",
             0x30: "oid_filters",
             0x3374: "next_protocol_negotiation",
                                            # RFC-draft-agl-tls-nextprotoneg-03
             0xff01: "renegotiation_info"   # RFC 5746
             }


class TLS_Ext_Unknown(_GenericTLSSessionInheritance):
    """
    We put this here rather than in extensions.py in order to avoid
    circular imports...
    """
    name = "TLS Extension - Scapy Unknown"
    fields_desc = [ShortEnumField("type", None, _tls_ext),
                   FieldLenField("len", None, fmt="!H", length_of="val"),
                   StrLenField("val", "",
                               length_from=lambda pkt: pkt.len) ]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p+pay


_tls_named_ffdh_groups = { 256: "ffdhe2048", 257: "ffdhe3072",
                           258: "ffdhe4096", 259: "ffdhe6144",
                           260: "ffdhe8192" }

_tls_named_groups = {}
_tls_named_groups.update(_tls_named_ffdh_groups)
_tls_named_groups.update(_tls_named_curves)


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

    def post_build(self, pkt, pay):
        if self.group is None:
            self.group = 23     # secp256r1

        if self.key_exchange == "":
            if self.group in _tls_named_ffdh_groups:
                params = _ffdh_groups[_tls_named_ffdh_groups[self.group]][0]
                privkey = params.generate_private_key()
                self.privkey = privkey
                pubkey = privkey.public_key()
                self.key_exchange = pubkey.public_numbers().y
            elif self.group in _tls_named_curves:
                if not _tls_named_curves[self.group] in ["x25519", "x448"]:
                    #XXX no support for now :(
                    curve = ec._CURVE_TYPES[_tls_named_curves[self.group]]()
                    privkey = ec.generate_private_key(curve, default_backend())
                    self.privkey = privkey
                    pubkey = privkey.public_key()
                    self.key_exchange = pubkey.public_numbers().encode_point()

        if self.kxlen is None:
            self.kxlen = len(self.key_exchange)

        group = struct.pack("!H", self.group)
        kxlen = struct.pack("!H", self.kxlen)
        return group + kxlen + self.key_exchange + pay

    def post_dissection(self, r):
        if self.key_exchange:
            if self.group in _tls_named_ffdh_groups:
                params = _ffdh_groups[_tls_named_ffdh_groups[self.group]][0]
                pn = params.parameter_numbers()
                public_numbers = dh.DHPublicNumbers(self.key_exchange, pn)
                self.pubkey = public_numbers.public_key(default_backend())
            elif self.group in _tls_named_curves:
                if _tls_named_curves[self.group] in ["x25519", "x448"]:
                    #XXX no support for now :(
                    return
                curve = ec._CURVE_TYPES[_tls_named_curves[self.group]]()
                import_point = ec.EllipticCurvePublicNumbers.from_encoded_point
                public_numbers = import_point(curve, self.key_exchange)
                self.pubkey = public_numbers.public_key(default_backend())


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
                        print "Group %s used twice in the same ClientHello!" % kse.group
                        break
                    privshares[_tls_named_groups[kse.group]] = kse.privkey
        return super(TLS_Ext_KeyShare_CH, self).post_build(pkt, pay)

    def post_dissection(self, r):
        if not self.tls_session.frozen:
            for kse in self.client_shares:
                if kse.pubkey:
                    pubshares = self.tls_session.tls13_client_pubshares
                    if _tls_named_curves[kse.group] in pubshares:
                        print "Group %s used twice in the same ClientHello!" % kse.group
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
            privshare = self.tls_session.tls13_server_privshare
            if len(privshare) > 0:
                print "Server key share was already stored...?"
            group_name = _tls_named_groups[self.server_share.group]
            privshare[group_name] = self.server_share.privkey

            if group_name in self.tls_session.tls13_client_pubshares:
                privkey = self.server_share.privkey
                pubkey = self.tls_session.tls13_client_pubshares[group_name]
                if group_name in _tls_named_ffdh_groups.itervalues():
                    pms = privkey.exchange(pubkey)
                elif group_name in _tls_named_curves.itervalues():
                    pms = privkey.exchange(ec.ECDH(), pubkey)
                self.tls_session.tls13_dhe_secret = pms
        return super(TLS_Ext_KeyShare_SH, self).post_build(pkt, pay)

    def post_dissection(self, r):
        if not self.tls_session.frozen and self.server_share.pubkey:
            pubshare = self.tls_session.tls13_server_pubshare
            if len(pubshare) > 0:
                print "Server key share was already stored...?"
            group_name = _tls_named_groups[self.server_share.group]
            pubshare[group_name] = self.server_share.pubkey

            if group_name in self.tls_session.tls13_client_privshares:
                pubkey = self.server_share.pubkey
                privkey = self.tls_session.tls13_client_privshares[group_name]
                if group_name in _tls_named_ffdh_groups.itervalues():
                    pms = privkey.exchange(pubkey)
                elif group_name in _tls_named_curves.itervalues():
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

