# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2017 Maxence Tury

"""
TLS handshake extensions.
"""

from __future__ import print_function

import os
import struct

from scapy.fields import ByteEnumField, ByteField, EnumField, FieldLenField, \
    FieldListField, IntField, PacketField, PacketListField, ShortEnumField, \
    ShortField, StrFixedLenField, StrLenField, XStrLenField
from scapy.packet import Packet, Raw, Padding
from scapy.layers.x509 import X509_Extensions
from scapy.layers.tls.basefields import _tls_version
from scapy.layers.tls.keyexchange import (SigAndHashAlgsLenField,
                                          SigAndHashAlgsField, _tls_hash_sig)
from scapy.layers.tls.session import _GenericTLSSessionInheritance
from scapy.layers.tls.crypto.groups import _tls_named_groups
from scapy.layers.tls.crypto.suites import _tls_cipher_suites
from scapy.themes import AnsiColorTheme
from scapy.compat import raw
from scapy.config import conf


# Because ServerHello and HelloRetryRequest have the same
# msg_type, the only way to distinguish these message is by
# checking the random_bytes. If the random_bytes are equal to
# SHA256('HelloRetryRequest') then we know this is a
# HelloRetryRequest and the TLS_Ext_KeyShare must be parsed as
# TLS_Ext_KeyShare_HRR and not as TLS_Ext_KeyShare_SH

# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
# digest.update(b"HelloRetryRequest")
# _tls_hello_retry_magic = digest.finalize()

_tls_hello_retry_magic = (
    b'\xcf!\xadt\xe5\x9aa\x11\xbe\x1d\x8c\x02\x1ee\xb8\x91\xc2\xa2\x11'
    b'\x16z\xbb\x8c^\x07\x9e\t\xe2\xc8\xa83\x9c'
)


_tls_ext = {0: "server_name",             # RFC 4366
            1: "max_fragment_length",     # RFC 4366
            2: "client_certificate_url",  # RFC 4366
            3: "trusted_ca_keys",         # RFC 4366
            4: "truncated_hmac",          # RFC 4366
            5: "status_request",          # RFC 4366
            6: "user_mapping",            # RFC 4681
            7: "client_authz",            # RFC 5878
            8: "server_authz",            # RFC 5878
            9: "cert_type",               # RFC 6091
            # 10: "elliptic_curves",         # RFC 4492
            10: "supported_groups",
            11: "ec_point_formats",        # RFC 4492
            13: "signature_algorithms",    # RFC 5246
            0x0f: "heartbeat",             # RFC 6520
            0x10: "alpn",                  # RFC 7301
            0x12: "signed_certificate_timestamp",  # RFC 6962
            0x13: "client_certificate_type",  # RFC 7250
            0x14: "server_certificate_type",  # RFC 7250
            0x15: "padding",               # RFC 7685
            0x16: "encrypt_then_mac",      # RFC 7366
            0x17: "extended_master_secret",  # RFC 7627
            0x1c: "record_size_limit",     # RFC 8449
            0x23: "session_ticket",        # RFC 5077
            0x29: "pre_shared_key",
            0x2a: "early_data_indication",
            0x2b: "supported_versions",
            0x2c: "cookie",
            0x2d: "psk_key_exchange_modes",
            0x2f: "certificate_authorities",
            0x30: "oid_filters",
            0x31: "post_handshake_auth",
            0x32: "signature_algorithms_cert",
            0x33: "key_share",
            0x3374: "next_protocol_negotiation",
            # RFC-draft-agl-tls-nextprotoneg-03
            0xff01: "renegotiation_info",   # RFC 5746
            0xffce: "encrypted_server_name"
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
                               length_from=lambda pkt: pkt.len)]

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) - 4
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p + pay


###############################################################################
#   ClientHello/ServerHello extensions                                        #
###############################################################################

# We provide these extensions mostly for packet manipulation purposes.
# For now, most of them are not considered by our automaton.

class TLS_Ext_PrettyPacketList(TLS_Ext_Unknown):
    """
    Dummy extension used for server_name/ALPN/NPN for a lighter representation:
    the final field is showed as a 1-line list rather than as lots of packets.
    XXX Define a new condition for packet lists in Packet._show_or_dump?
    """

    def _show_or_dump(self, dump=False, indent=3,
                      lvl="", label_lvl="", first_call=True):
        """ Reproduced from packet.py """
        ct = AnsiColorTheme() if dump else conf.color_theme
        s = "%s%s %s %s \n" % (label_lvl, ct.punct("###["),
                               ct.layer_name(self.name), ct.punct("]###"))
        for f in self.fields_desc[:-1]:
            ncol = ct.field_name
            vcol = ct.field_value
            fvalue = self.getfieldval(f.name)
            begn = "%s  %-10s%s " % (label_lvl + lvl, ncol(f.name),
                                     ct.punct("="),)
            reprval = f.i2repr(self, fvalue)
            if isinstance(reprval, str):
                reprval = reprval.replace("\n", "\n" + " " * (len(label_lvl) +
                                                              len(lvl) +
                                                              len(f.name) +
                                                              4))
            s += "%s%s\n" % (begn, vcol(reprval))
        f = self.fields_desc[-1]
        ncol = ct.field_name
        vcol = ct.field_value
        fvalue = self.getfieldval(f.name)
        begn = "%s  %-10s%s " % (label_lvl + lvl, ncol(f.name), ct.punct("="),)
        reprval = f.i2repr(self, fvalue)
        if isinstance(reprval, str):
            reprval = reprval.replace("\n", "\n" + " " * (len(label_lvl) +
                                                          len(lvl) +
                                                          len(f.name) +
                                                          4))
        s += "%s%s\n" % (begn, vcol(reprval))
        if self.payload:
            s += self.payload._show_or_dump(dump=dump, indent=indent,
                                            lvl=lvl + (" " * indent * self.show_indent),  # noqa: E501
                                            label_lvl=label_lvl, first_call=False)  # noqa: E501

        if first_call and not dump:
            print(s)
        else:
            return s


_tls_server_name_types = {0: "host_name"}


class ServerName(Packet):
    name = "HostName"
    fields_desc = [ByteEnumField("nametype", 0, _tls_server_name_types),
                   FieldLenField("namelen", None, length_of="servername"),
                   StrLenField("servername", "",
                               length_from=lambda pkt: pkt.namelen)]

    def guess_payload_class(self, p):
        return Padding


class ServerListField(PacketListField):
    def i2repr(self, pkt, x):
        res = [p.servername for p in x]
        return "[%s]" % ", ".join(repr(x) for x in res)


class ServerLenField(FieldLenField):
    """
    There is no length when there are no servernames (as in a ServerHello).
    """

    def addfield(self, pkt, s, val):
        if not val:
            if not pkt.servernames:
                return s
        return super(ServerLenField, self).addfield(pkt, s, val)


class TLS_Ext_ServerName(TLS_Ext_PrettyPacketList):                 # RFC 4366
    name = "TLS Extension - Server Name"
    fields_desc = [ShortEnumField("type", 0, _tls_ext),
                   FieldLenField("len", None, length_of="servernames",
                                 adjust=lambda pkt, x: x + 2),
                   ServerLenField("servernameslen", None,
                                  length_of="servernames"),
                   ServerListField("servernames", [], ServerName,
                                   length_from=lambda pkt: pkt.servernameslen)]


class TLS_Ext_EncryptedServerName(TLS_Ext_PrettyPacketList):
    name = "TLS Extension - Encrypted Server Name"
    fields_desc = [ShortEnumField("type", 0xffce, _tls_ext),
                   ShortField("len", None),
                   EnumField("cipher", None, _tls_cipher_suites),
                   ShortEnumField("key_exchange_group", None,
                                  _tls_named_groups),
                   FieldLenField("key_exchange_len", None,
                                 length_of="key_exchange", fmt="H"),
                   XStrLenField("key_exchange", "",
                                length_from=lambda pkt: pkt.key_exchange_len),
                   FieldLenField("record_digest_len",
                                 None, length_of="record_digest"),
                   XStrLenField("record_digest", "",
                                length_from=lambda pkt: pkt.record_digest_len),
                   FieldLenField("encrypted_sni_len", None,
                                 length_of="encrypted_sni", fmt="H"),
                   XStrLenField("encrypted_sni", "",
                                length_from=lambda pkt: pkt.encrypted_sni_len)]


class TLS_Ext_MaxFragLen(TLS_Ext_Unknown):                          # RFC 4366
    name = "TLS Extension - Max Fragment Length"
    fields_desc = [ShortEnumField("type", 1, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("maxfraglen", 4, {1: "2^9",
                                                   2: "2^10",
                                                   3: "2^11",
                                                   4: "2^12"})]


class TLS_Ext_ClientCertURL(TLS_Ext_Unknown):                       # RFC 4366
    name = "TLS Extension - Client Certificate URL"
    fields_desc = [ShortEnumField("type", 2, _tls_ext),
                   ShortField("len", None)]


_tls_trusted_authority_types = {0: "pre_agreed",
                                1: "key_sha1_hash",
                                2: "x509_name",
                                3: "cert_sha1_hash"}


class TAPreAgreed(Packet):
    name = "Trusted authority - pre_agreed"
    fields_desc = [ByteEnumField("idtype", 0, _tls_trusted_authority_types)]

    def guess_payload_class(self, p):
        return Padding


class TAKeySHA1Hash(Packet):
    name = "Trusted authority - key_sha1_hash"
    fields_desc = [ByteEnumField("idtype", 1, _tls_trusted_authority_types),
                   StrFixedLenField("id", None, 20)]

    def guess_payload_class(self, p):
        return Padding


class TAX509Name(Packet):
    """
    XXX Section 3.4 of RFC 4366. Implement a more specific DNField
    rather than current StrLenField.
    """
    name = "Trusted authority - x509_name"
    fields_desc = [ByteEnumField("idtype", 2, _tls_trusted_authority_types),
                   FieldLenField("dnlen", None, length_of="dn"),
                   StrLenField("dn", "", length_from=lambda pkt: pkt.dnlen)]

    def guess_payload_class(self, p):
        return Padding


class TACertSHA1Hash(Packet):
    name = "Trusted authority - cert_sha1_hash"
    fields_desc = [ByteEnumField("idtype", 3, _tls_trusted_authority_types),
                   StrFixedLenField("id", None, 20)]

    def guess_payload_class(self, p):
        return Padding


_tls_trusted_authority_cls = {0: TAPreAgreed,
                              1: TAKeySHA1Hash,
                              2: TAX509Name,
                              3: TACertSHA1Hash}


class _TAListField(PacketListField):
    """
    Specific version that selects the right Trusted Authority (previous TA*)
    class to be used for dissection based on idtype.
    """

    def m2i(self, pkt, m):
        idtype = ord(m[0])
        cls = self.cls
        if idtype in _tls_trusted_authority_cls:
            cls = _tls_trusted_authority_cls[idtype]
        return cls(m)


class TLS_Ext_TrustedCAInd(TLS_Ext_Unknown):                        # RFC 4366
    name = "TLS Extension - Trusted CA Indication"
    fields_desc = [ShortEnumField("type", 3, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("talen", None, length_of="ta"),
                   _TAListField("ta", [], Raw,
                                length_from=lambda pkt: pkt.talen)]


class TLS_Ext_TruncatedHMAC(TLS_Ext_Unknown):                       # RFC 4366
    name = "TLS Extension - Truncated HMAC"
    fields_desc = [ShortEnumField("type", 4, _tls_ext),
                   ShortField("len", None)]


class ResponderID(Packet):
    name = "Responder ID structure"
    fields_desc = [FieldLenField("respidlen", None, length_of="respid"),
                   StrLenField("respid", "",
                               length_from=lambda pkt: pkt.respidlen)]

    def guess_payload_class(self, p):
        return Padding


class OCSPStatusRequest(Packet):
    """
    This is the structure defined in RFC 6066, not in RFC 6960!
    """
    name = "OCSPStatusRequest structure"
    fields_desc = [FieldLenField("respidlen", None, length_of="respid"),
                   PacketListField("respid", [], ResponderID,
                                   length_from=lambda pkt: pkt.respidlen),
                   FieldLenField("reqextlen", None, length_of="reqext"),
                   PacketField("reqext", "", X509_Extensions)]

    def guess_payload_class(self, p):
        return Padding


_cert_status_type = {1: "ocsp"}
_cert_status_req_cls = {1: OCSPStatusRequest}


class _StatusReqField(PacketListField):
    def m2i(self, pkt, m):
        idtype = pkt.stype
        cls = self.cls
        if idtype in _cert_status_req_cls:
            cls = _cert_status_req_cls[idtype]
        return cls(m)


class TLS_Ext_CSR(TLS_Ext_Unknown):                                 # RFC 4366
    name = "TLS Extension - Certificate Status Request"
    fields_desc = [ShortEnumField("type", 5, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("stype", None, _cert_status_type),
                   _StatusReqField("req", [], Raw,
                                   length_from=lambda pkt: pkt.len - 1)]


class TLS_Ext_UserMapping(TLS_Ext_Unknown):                         # RFC 4681
    name = "TLS Extension - User Mapping"
    fields_desc = [ShortEnumField("type", 6, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("umlen", None, fmt="B", length_of="um"),
                   FieldListField("um", [],
                                  ByteField("umtype", 0),
                                  length_from=lambda pkt: pkt.umlen)]


class TLS_Ext_ClientAuthz(TLS_Ext_Unknown):                         # RFC 5878
    """ XXX Unsupported """
    name = "TLS Extension - Client Authz"
    fields_desc = [ShortEnumField("type", 7, _tls_ext),
                   ShortField("len", None),
                   ]


class TLS_Ext_ServerAuthz(TLS_Ext_Unknown):                         # RFC 5878
    """ XXX Unsupported """
    name = "TLS Extension - Server Authz"
    fields_desc = [ShortEnumField("type", 8, _tls_ext),
                   ShortField("len", None),
                   ]


_tls_cert_types = {0: "X.509", 1: "OpenPGP"}


class TLS_Ext_ClientCertType(TLS_Ext_Unknown):                      # RFC 5081
    name = "TLS Extension - Certificate Type (client version)"
    fields_desc = [ShortEnumField("type", 9, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("ctypeslen", None, length_of="ctypes"),
                   FieldListField("ctypes", [0, 1],
                                  ByteEnumField("certtypes", None,
                                                _tls_cert_types),
                                  length_from=lambda pkt: pkt.ctypeslen)]


class TLS_Ext_ServerCertType(TLS_Ext_Unknown):                      # RFC 5081
    name = "TLS Extension - Certificate Type (server version)"
    fields_desc = [ShortEnumField("type", 9, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("ctype", None, _tls_cert_types)]


def _TLS_Ext_CertTypeDispatcher(m, *args, **kargs):
    """
    We need to select the correct one on dissection. We use the length for
    that, as 1 for client version would imply an empty list.
    """
    tmp_len = struct.unpack("!H", m[2:4])[0]
    if tmp_len == 1:
        cls = TLS_Ext_ServerCertType
    else:
        cls = TLS_Ext_ClientCertType
    return cls(m, *args, **kargs)


class TLS_Ext_SupportedGroups(TLS_Ext_Unknown):
    """
    This extension was known as 'Supported Elliptic Curves' before TLS 1.3
    merged both group selection mechanisms for ECDH and FFDH.
    """
    name = "TLS Extension - Supported Groups"
    fields_desc = [ShortEnumField("type", 10, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("groupslen", None, length_of="groups"),
                   FieldListField("groups", [],
                                  ShortEnumField("ng", None,
                                                 _tls_named_groups),
                                  length_from=lambda pkt: pkt.groupslen)]


class TLS_Ext_SupportedEllipticCurves(TLS_Ext_SupportedGroups):     # RFC 4492
    pass


_tls_ecpoint_format = {0: "uncompressed",
                       1: "ansiX962_compressed_prime",
                       2: "ansiX962_compressed_char2"}


class TLS_Ext_SupportedPointFormat(TLS_Ext_Unknown):                # RFC 4492
    name = "TLS Extension - Supported Point Format"
    fields_desc = [ShortEnumField("type", 11, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("ecpllen", None, fmt="B", length_of="ecpl"),
                   FieldListField("ecpl", [0],
                                  ByteEnumField("nc", None,
                                                _tls_ecpoint_format),
                                  length_from=lambda pkt: pkt.ecpllen)]


class TLS_Ext_SignatureAlgorithms(TLS_Ext_Unknown):                 # RFC 5246
    name = "TLS Extension - Signature Algorithms"
    fields_desc = [ShortEnumField("type", 13, _tls_ext),
                   ShortField("len", None),
                   SigAndHashAlgsLenField("sig_algs_len", None,
                                          length_of="sig_algs"),
                   SigAndHashAlgsField("sig_algs", [],
                                       EnumField("hash_sig", None,
                                                 _tls_hash_sig),
                                       length_from=lambda pkt: pkt.sig_algs_len)]  # noqa: E501


class TLS_Ext_Heartbeat(TLS_Ext_Unknown):                           # RFC 6520
    name = "TLS Extension - Heartbeat"
    fields_desc = [ShortEnumField("type", 0x0f, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("heartbeat_mode", 2,
                                 {1: "peer_allowed_to_send",
                                  2: "peer_not_allowed_to_send"})]


class ProtocolName(Packet):
    name = "Protocol Name"
    fields_desc = [FieldLenField("len", None, fmt='B', length_of="protocol"),
                   StrLenField("protocol", "",
                               length_from=lambda pkt: pkt.len)]

    def guess_payload_class(self, p):
        return Padding


class ProtocolListField(PacketListField):
    def i2repr(self, pkt, x):
        res = [p.protocol for p in x]
        return "[%s]" % ", ".join(repr(x) for x in res)


class TLS_Ext_ALPN(TLS_Ext_PrettyPacketList):                       # RFC 7301
    name = "TLS Extension - Application Layer Protocol Negotiation"
    fields_desc = [ShortEnumField("type", 0x10, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("protocolslen", None, length_of="protocols"),
                   ProtocolListField("protocols", [], ProtocolName,
                                     length_from=lambda pkt:pkt.protocolslen)]


class TLS_Ext_Padding(TLS_Ext_Unknown):                             # RFC 7685
    name = "TLS Extension - Padding"
    fields_desc = [ShortEnumField("type", 0x15, _tls_ext),
                   FieldLenField("len", None, length_of="padding"),
                   StrLenField("padding", "",
                               length_from=lambda pkt: pkt.len)]


class TLS_Ext_EncryptThenMAC(TLS_Ext_Unknown):                      # RFC 7366
    name = "TLS Extension - Encrypt-then-MAC"
    fields_desc = [ShortEnumField("type", 0x16, _tls_ext),
                   ShortField("len", None)]


class TLS_Ext_ExtendedMasterSecret(TLS_Ext_Unknown):                # RFC 7627
    name = "TLS Extension - Extended Master Secret"
    fields_desc = [ShortEnumField("type", 0x17, _tls_ext),
                   ShortField("len", None)]


class TLS_Ext_SessionTicket(TLS_Ext_Unknown):                       # RFC 5077
    """
    RFC 5077 updates RFC 4507 according to most implementations, which do not
    use another (useless) 'ticketlen' field after the global 'len' field.
    """
    name = "TLS Extension - Session Ticket"
    fields_desc = [ShortEnumField("type", 0x23, _tls_ext),
                   FieldLenField("len", None, length_of="ticket"),
                   StrLenField("ticket", "",
                               length_from=lambda pkt: pkt.len)]


class TLS_Ext_KeyShare(TLS_Ext_Unknown):
    name = "TLS Extension - Key Share (dummy class)"
    fields_desc = [ShortEnumField("type", 0x33, _tls_ext),
                   ShortField("len", None)]


class TLS_Ext_PreSharedKey(TLS_Ext_Unknown):
    name = "TLS Extension - Pre Shared Key (dummy class)"
    fields_desc = [ShortEnumField("type", 0x29, _tls_ext),
                   ShortField("len", None)]


class TLS_Ext_EarlyDataIndication(TLS_Ext_Unknown):
    name = "TLS Extension - Early Data"
    fields_desc = [ShortEnumField("type", 0x2a, _tls_ext),
                   ShortField("len", None)]


class TLS_Ext_EarlyDataIndicationTicket(TLS_Ext_Unknown):
    name = "TLS Extension - Ticket Early Data Info"
    fields_desc = [ShortEnumField("type", 0x2a, _tls_ext),
                   ShortField("len", None),
                   IntField("max_early_data_size", 0)]


_tls_ext_early_data_cls = {1: TLS_Ext_EarlyDataIndication,
                           4: TLS_Ext_EarlyDataIndicationTicket,
                           8: TLS_Ext_EarlyDataIndication}


class TLS_Ext_SupportedVersions(TLS_Ext_Unknown):
    name = "TLS Extension - Supported Versions (dummy class)"
    fields_desc = [ShortEnumField("type", 0x2b, _tls_ext),
                   ShortField("len", None)]


class TLS_Ext_SupportedVersion_CH(TLS_Ext_Unknown):
    name = "TLS Extension - Supported Versions (for ClientHello)"
    fields_desc = [ShortEnumField("type", 0x2b, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("versionslen", None, fmt='B',
                                 length_of="versions"),
                   FieldListField("versions", [],
                                  ShortEnumField("version", None,
                                                 _tls_version),
                                  length_from=lambda pkt: pkt.versionslen)]


class TLS_Ext_SupportedVersion_SH(TLS_Ext_Unknown):
    name = "TLS Extension - Supported Versions (for ServerHello)"
    fields_desc = [ShortEnumField("type", 0x2b, _tls_ext),
                   ShortField("len", None),
                   ShortEnumField("version", None, _tls_version)]


_tls_ext_supported_version_cls = {1: TLS_Ext_SupportedVersion_CH,
                                  2: TLS_Ext_SupportedVersion_SH}


class TLS_Ext_Cookie(TLS_Ext_Unknown):
    name = "TLS Extension - Cookie"
    fields_desc = [ShortEnumField("type", 0x2c, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("cookielen", None, length_of="cookie"),
                   XStrLenField("cookie", "",
                                length_from=lambda pkt: pkt.cookielen)]

    def build(self):
        fval = self.getfieldval("cookie")
        if fval is None or fval == b"":
            self.cookie = os.urandom(32)
        return TLS_Ext_Unknown.build(self)


_tls_psk_kx_modes = {0: "psk_ke", 1: "psk_dhe_ke"}


class TLS_Ext_PSKKeyExchangeModes(TLS_Ext_Unknown):
    name = "TLS Extension - PSK Key Exchange Modes"
    fields_desc = [ShortEnumField("type", 0x2d, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("kxmodeslen", None, fmt='B',
                                 length_of="kxmodes"),
                   FieldListField("kxmodes", [],
                                  ByteEnumField("kxmode", None,
                                                _tls_psk_kx_modes),
                                  length_from=lambda pkt: pkt.kxmodeslen)]


class TLS_Ext_TicketEarlyDataInfo(TLS_Ext_Unknown):
    name = "TLS Extension - Ticket Early Data Info"
    fields_desc = [ShortEnumField("type", 0x2e, _tls_ext),
                   ShortField("len", None),
                   IntField("max_early_data_size", 0)]


class TLS_Ext_NPN(TLS_Ext_PrettyPacketList):
    """
    Defined in RFC-draft-agl-tls-nextprotoneg-03. Deprecated in favour of ALPN.
    """
    name = "TLS Extension - Next Protocol Negotiation"
    fields_desc = [ShortEnumField("type", 0x3374, _tls_ext),
                   FieldLenField("len", None, length_of="protocols"),
                   ProtocolListField("protocols", [], ProtocolName,
                                     length_from=lambda pkt:pkt.len)]


class TLS_Ext_PostHandshakeAuth(TLS_Ext_Unknown):                   # RFC 8446
    name = "TLS Extension - Post Handshake Auth"
    fields_desc = [ShortEnumField("type", 0x31, _tls_ext),
                   ShortField("len", None)]


class TLS_Ext_SignatureAlgorithmsCert(TLS_Ext_Unknown):    # RFC 8446
    name = "TLS Extension - Signature Algorithms Cert"
    fields_desc = [ShortEnumField("type", 0x32, _tls_ext),
                   ShortField("len", None),
                   SigAndHashAlgsLenField("sig_algs_len", None,
                                          length_of="sig_algs"),
                   SigAndHashAlgsField("sig_algs", [],
                                       EnumField("hash_sig", None,
                                                 _tls_hash_sig),
                                       length_from=lambda pkt: pkt.sig_algs_len)]  # noqa: E501


class TLS_Ext_RenegotiationInfo(TLS_Ext_Unknown):                   # RFC 5746
    name = "TLS Extension - Renegotiation Indication"
    fields_desc = [ShortEnumField("type", 0xff01, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("reneg_conn_len", None, fmt='B',
                                 length_of="renegotiated_connection"),
                   StrLenField("renegotiated_connection", "",
                               length_from=lambda pkt: pkt.reneg_conn_len)]


class TLS_Ext_RecordSizeLimit(TLS_Ext_Unknown):  # RFC 8449
    name = "TLS Extension - Record Size Limit"
    fields_desc = [ShortEnumField("type", 0x1c, _tls_ext),
                   ShortField("len", None),
                   ShortField("record_size_limit", None)]


_tls_ext_cls = {0: TLS_Ext_ServerName,
                1: TLS_Ext_MaxFragLen,
                2: TLS_Ext_ClientCertURL,
                3: TLS_Ext_TrustedCAInd,
                4: TLS_Ext_TruncatedHMAC,
                5: TLS_Ext_CSR,
                6: TLS_Ext_UserMapping,
                7: TLS_Ext_ClientAuthz,
                8: TLS_Ext_ServerAuthz,
                9: _TLS_Ext_CertTypeDispatcher,
                # 10: TLS_Ext_SupportedEllipticCurves,
                10: TLS_Ext_SupportedGroups,
                11: TLS_Ext_SupportedPointFormat,
                13: TLS_Ext_SignatureAlgorithms,
                0x0f: TLS_Ext_Heartbeat,
                0x10: TLS_Ext_ALPN,
                0x15: TLS_Ext_Padding,
                0x16: TLS_Ext_EncryptThenMAC,
                0x17: TLS_Ext_ExtendedMasterSecret,
                0x1c: TLS_Ext_RecordSizeLimit,
                0x23: TLS_Ext_SessionTicket,
                # 0x28: TLS_Ext_KeyShare,
                0x29: TLS_Ext_PreSharedKey,
                0x2a: TLS_Ext_EarlyDataIndication,
                0x2b: TLS_Ext_SupportedVersions,
                0x2c: TLS_Ext_Cookie,
                0x2d: TLS_Ext_PSKKeyExchangeModes,
                # 0x2e: TLS_Ext_TicketEarlyDataInfo,
                0x31: TLS_Ext_PostHandshakeAuth,
                0x32: TLS_Ext_SignatureAlgorithmsCert,
                0x33: TLS_Ext_KeyShare,
                # 0x2f: TLS_Ext_CertificateAuthorities,       #XXX
                # 0x30: TLS_Ext_OIDFilters,                   #XXX
                0x3374: TLS_Ext_NPN,
                0xff01: TLS_Ext_RenegotiationInfo,
                0xffce: TLS_Ext_EncryptedServerName
                }


class _ExtensionsLenField(FieldLenField):
    def getfield(self, pkt, s):
        """
        We try to compute a length, usually from a msglen parsed earlier.
        If we can not find any length, we consider 'extensions_present'
        (from RFC 5246) to be False.
        """
        ext = pkt.get_field(self.length_of)
        tmp_len = ext.length_from(pkt)
        if tmp_len is None or tmp_len < 0:
            v = pkt.tls_session.tls_version
            if v is None or v < 0x0304:
                return s, None
        return super(_ExtensionsLenField, self).getfield(pkt, s)

    def addfield(self, pkt, s, i):
        """
        There is a hack with the _ExtensionsField.i2len. It works only because
        we expect _ExtensionsField.i2m to return a string of the same size (if
        not of the same value) upon successive calls (e.g. through i2len here,
        then i2m when directly building the _ExtensionsField).

        XXX A proper way to do this would be to keep the extensions built from
        the i2len call here, instead of rebuilding them later on.
        """
        if i is None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)

                tmp = pkt.tls_session.frozen
                pkt.tls_session.frozen = True
                f = fld.i2len(pkt, fval)
                pkt.tls_session.frozen = tmp

                i = self.adjust(pkt, f)
                if i == 0:  # for correct build if no ext and not explicitly 0
                    v = pkt.tls_session.tls_version
                    # With TLS 1.3, zero lengths are always explicit.
                    if v is None or v < 0x0304:
                        return s
                    else:
                        return s + struct.pack(self.fmt, i)
        return s + struct.pack(self.fmt, i)


class _ExtensionsField(StrLenField):
    islist = 1
    holds_packets = 1

    def i2len(self, pkt, i):
        if i is None:
            return 0
        return len(self.i2m(pkt, i))

    def getfield(self, pkt, s):
        tmp_len = self.length_from(pkt) or 0
        if tmp_len <= 0:
            return s, []
        return s[tmp_len:], self.m2i(pkt, s[:tmp_len])

    def i2m(self, pkt, i):
        if i is None:
            return b""
        if isinstance(pkt, _GenericTLSSessionInheritance):
            if not pkt.tls_session.frozen:
                s = b""
                for ext in i:
                    if isinstance(ext, _GenericTLSSessionInheritance):
                        ext.tls_session = pkt.tls_session
                        s += ext.raw_stateful()
                    else:
                        s += raw(ext)
                return s
        return b"".join(map(raw, i))

    def m2i(self, pkt, m):
        res = []
        while len(m) >= 4:
            t = struct.unpack("!H", m[:2])[0]
            tmp_len = struct.unpack("!H", m[2:4])[0]
            cls = _tls_ext_cls.get(t, TLS_Ext_Unknown)
            if cls is TLS_Ext_KeyShare:
                # TLS_Ext_KeyShare can be :
                #  - TLS_Ext_KeyShare_CH if the message is a ClientHello
                #  - TLS_Ext_KeyShare_SH if the message is a ServerHello
                #    and all parameters are accepted by the serveur
                #  - TLS_Ext_KeyShare_HRR if message is a ServerHello and
                #    the client has not provided a sufficient "key_share"
                #    extension
                from scapy.layers.tls.keyexchange_tls13 import (
                    _tls_ext_keyshare_cls, _tls_ext_keyshare_hrr_cls)
                # If SHA-256("HelloRetryRequest") == server_random,
                # this message is a HelloRetryRequest
                if pkt.random_bytes and \
                        pkt.random_bytes == _tls_hello_retry_magic:
                    cls = _tls_ext_keyshare_hrr_cls.get(pkt.msgtype, TLS_Ext_Unknown)  # noqa: E501
                else:
                    cls = _tls_ext_keyshare_cls.get(pkt.msgtype, TLS_Ext_Unknown)  # noqa: E501
            elif cls is TLS_Ext_PreSharedKey:
                from scapy.layers.tls.keyexchange_tls13 import _tls_ext_presharedkey_cls  # noqa: E501
                cls = _tls_ext_presharedkey_cls.get(pkt.msgtype, TLS_Ext_Unknown)  # noqa: E501
            elif cls is TLS_Ext_SupportedVersions:
                cls = _tls_ext_supported_version_cls.get(pkt.msgtype, TLS_Ext_Unknown)  # noqa: E501
            elif cls is TLS_Ext_EarlyDataIndication:
                cls = _tls_ext_early_data_cls.get(pkt.msgtype, TLS_Ext_Unknown)
            res.append(cls(m[:tmp_len + 4], tls_session=pkt.tls_session))
            m = m[tmp_len + 4:]
        return res
