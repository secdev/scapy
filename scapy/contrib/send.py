# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2009 Adline Stephane <adline.stephane@gmail.com>
# Copyright     2018 Gabriel Potter <gabriel[]potter[]fr>

"""
Secure Neighbor Discovery (SEND) - RFC3971
"""

# scapy.contrib.description = Secure Neighbor Discovery (SEND) (ICMPv6)
# scapy.contrib.status = loads


from scapy.packet import Packet
from scapy.fields import BitField, ByteField, FieldLenField, PacketField, \
    PacketLenField, ShortField, StrFixedLenField, StrLenField, UTCTimeField
from scapy.layers.x509 import X509_SubjectPublicKeyInfo
from scapy.layers.inet6 import icmp6ndoptscls, _ICMPv6NDGuessPayload
from scapy.compat import chb
from scapy.volatile import RandBin


class ICMPv6NDOptNonce(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptNonce"
    fields_desc = [ByteField("type", 14),
                   FieldLenField("len", None, length_of="nonce", fmt="B", adjust=lambda pkt, x: int(round((x + 2) / 8.))),  # noqa: E501
                   StrLenField("nonce", "", length_from=lambda pkt: pkt.len * 8 - 2)]  # noqa: E501


class ICMPv6NDOptTmstp(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptTmstp"
    fields_desc = [ByteField("type", 13),
                   ByteField("len", 2),
                   BitField("reserved", 0, 48),
                   UTCTimeField("timestamp", None)]


class ICMPv6NDOptRsaSig(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptRsaSig"
    fields_desc = [ByteField("type", 12),
                   FieldLenField("len", None, length_of="signature_pad", fmt="B", adjust=lambda pkt, x: (x + 20) // 8),  # noqa: E501
                   ShortField("reserved", 0),
                   StrFixedLenField("key_hash", "", length=16),
                   StrLenField("signature_pad", "", length_from=lambda pkt: pkt.len * 8 - 20)]  # noqa: E501


class CGA_Params(Packet):
    name = "CGA Parameters data structure"
    fields_desc = [StrFixedLenField("modifier", RandBin(size=16), length=16),
                   StrFixedLenField("subprefix", "", length=8),
                   ByteField("cc", 0),
                   PacketField("pubkey", X509_SubjectPublicKeyInfo(),
                               X509_SubjectPublicKeyInfo)]


class ICMPv6NDOptCGA(_ICMPv6NDGuessPayload, Packet):
    name = "ICMPv6NDOptCGA"
    fields_desc = [ByteField("type", 11),
                   FieldLenField("len", None, length_of="CGA_PARAMS", fmt="B", adjust=lambda pkt, x: (x + pkt.padlength + 4) // 8),  # noqa: E501
                   FieldLenField("padlength", 0, length_of="padding", fmt="B"),
                   ByteField("reserved", 0),
                   PacketLenField("CGA_PARAMS", "", CGA_Params, length_from=lambda pkt: pkt.len * 8 - pkt.padlength - 4),  # noqa: E501
                   StrLenField("padding", "", length_from=lambda pkt: pkt.padlength)]  # noqa: E501

    def post_build(self, p, pay):
        l_ = len(self.CGA_PARAMS)
        tmp_len = -(4 + l_) % 8  # Pad to 8 bytes
        p = p[:1] + chb((4 + l_ + tmp_len) // 8) + chb(tmp_len) + p[3:4 + l_]
        p += b"\x00" * tmp_len + pay
        return p


send_icmp6ndoptscls = {11: ICMPv6NDOptCGA,
                       12: ICMPv6NDOptRsaSig,
                       13: ICMPv6NDOptTmstp,
                       14: ICMPv6NDOptNonce
                       }
icmp6ndoptscls.update(send_icmp6ndoptscls)
