# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = ForCES Inter-FE LFB type (IFE)
# scapy.contrib.status = loads

"""
    IFE - ForCES Inter-FE LFB type
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Alexander Aring, aring@mojatatu.com

    :description:

        This module provides Scapy layers for the IFE protocol.

        normative references:
            - RFC 8013
              Forwarding and Control Element Separation (ForCES)
              Inter-FE Logical Functional Block (LFB)
              https://tools.ietf.org/html/rfc8013
"""

import functools

from scapy.data import ETHER_TYPES
from scapy.packet import Packet, bind_layers
from scapy.fields import FieldLenField, PacketListField, IntField, \
    MultipleTypeField, ShortField, ShortEnumField, StrField, PadField
from scapy.layers.l2 import Ether

ETH_P_IFE = 0xed3e
ETHER_TYPES[ETH_P_IFE] = 'IFE'

# The value to set for the skb mark.
IFE_META_SKBMARK = 0x0001
IFE_META_HASHID = 0x0002
# Value to set for priority in the skb structure.
IFE_META_PRIO = 0x0003
IFE_META_QMAP = 0x0004
# Value to set for the traffic control index in the skb structure.
IFE_META_TCINDEX = 0x0005

IFE_META_TYPES = {
    IFE_META_SKBMARK: "SKBMark",
    IFE_META_HASHID: "HashID",
    IFE_META_PRIO: "Prio",
    IFE_META_QMAP: "QMap",
    IFE_META_TCINDEX: "TCIndex"
}

IFE_TYPES_SHORT = [IFE_META_TCINDEX]
IFE_TYPES_INT = [
    IFE_META_SKBMARK,
    IFE_META_PRIO,
]


class IFETlv(Packet):
    """
    Parent Class interhit by all ForCES TLV structures
    """
    name = "IFETlv"

    fields_desc = [
        ShortEnumField("type", 0, IFE_META_TYPES),
        FieldLenField("length", None, length_of="value",
                      adjust=lambda pkt, x: x + 4),
        MultipleTypeField(
            [
                (PadField(ShortField("value", 0), 4, padwith=b'\x00'),
                 lambda pkt: pkt.type in IFE_TYPES_SHORT),
                (PadField(IntField("value", 0), 4, padwith=b'\x00'),
                 lambda pkt: pkt.type in IFE_TYPES_INT),
            ],
            PadField(IntField("value", 0), 4, padwith=b'\x00')
        ),
    ]

    def extract_padding(self, s):
        return "", s


class IFETlvStr(IFETlv):
    """
    A IFE TLV with variable payload
    """
    fields_desc = [
        ShortEnumField("type", 0, IFE_META_TYPES),
        FieldLenField("length", None, length_of="value",
                      adjust=lambda pkt, x: x + 4),
        StrField("value", "")
    ]


class IFE(Packet):
    """
    Main IFE Packet Class
    """
    name = "IFE"

    fields_desc = [
        FieldLenField("mdlen", None, length_of="tlvs",
                      adjust=lambda pkt, x: x + 2),
        PacketListField("tlvs", None, IFETlv),
    ]


IFESKBMark = functools.partial(IFETlv, type=IFE_META_SKBMARK)
IFEHashID = functools.partial(IFETlv, type=IFE_META_HASHID)
IFEPrio = functools.partial(IFETlv, type=IFE_META_PRIO)
IFEQMap = functools.partial(IFETlv, type=IFE_META_QMAP)
IFETCIndex = functools.partial(IFETlv, type=IFE_META_TCINDEX)

bind_layers(Ether, IFE, type=ETH_P_IFE)
