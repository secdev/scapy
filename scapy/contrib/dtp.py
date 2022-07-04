# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Dynamic Trunking Protocol (DTP)
# scapy.contrib.status = loads

"""
    DTP Scapy Extension
    ~~~~~~~~~~~~~~~~~~~

    :version: 2008-12-22
    :author: Jochen Bartl <lobo@c3a.de>

    :Thanks:

    - TLV code derived from the CDP implementation of scapy. (Thanks to Nicolas Bareil and Arnaud Ebalard)  # noqa: E501
"""

from __future__ import absolute_import
from __future__ import print_function
import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, FieldLenField, MACField, PacketListField, \
    ShortField, StrLenField, XShortField
from scapy.layers.l2 import SNAP, Dot3, LLC
from scapy.sendrecv import sendp
from scapy.config import conf
from scapy.volatile import RandMAC


class DtpGenericTlv(Packet):
    name = "DTP Generic TLV"
    fields_desc = [XShortField("type", 0x0001),
                   FieldLenField("length", None, length_of=lambda pkt:pkt.value + 4),  # noqa: E501
                   StrLenField("value", "", length_from=lambda pkt:pkt.length - 4)  # noqa: E501
                   ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            cls = _DTP_TLV_CLS.get(t, "DtpGenericTlv")
        return cls

    def guess_payload_class(self, p):
        return conf.padding_layer


class DTPDomain(DtpGenericTlv):
    name = "DTP Domain"
    fields_desc = [ShortField("type", 1),
                   FieldLenField("length", None, "domain", adjust=lambda pkt, x:x + 4),  # noqa: E501
                   StrLenField("domain", b"\x00", length_from=lambda pkt:pkt.length - 4)  # noqa: E501
                   ]


class DTPStatus(DtpGenericTlv):
    name = "DTP Status"
    fields_desc = [ShortField("type", 2),
                   FieldLenField("length", None, "status", adjust=lambda pkt, x:x + 4),  # noqa: E501
                   StrLenField("status", b"\x03", length_from=lambda pkt:pkt.length - 4)  # noqa: E501
                   ]


class DTPType(DtpGenericTlv):
    name = "DTP Type"
    fields_desc = [ShortField("type", 3),
                   FieldLenField("length", None, "dtptype", adjust=lambda pkt, x:x + 4),  # noqa: E501
                   StrLenField("dtptype", b"\xa5", length_from=lambda pkt:pkt.length - 4)  # noqa: E501
                   ]


class DTPNeighbor(DtpGenericTlv):
    name = "DTP Neighbor"
    fields_desc = [ShortField("type", 4),
                   # FieldLenField("length", None, "neighbor", adjust=lambda pkt,x:x + 4),  # noqa: E501
                   ShortField("len", 10),
                   MACField("neighbor", None)
                   ]


_DTP_TLV_CLS = {
    0x0001: DTPDomain,
    0x0002: DTPStatus,
    0x0003: DTPType,
    0x0004: DTPNeighbor
}


class DTP(Packet):
    name = "DTP"
    fields_desc = [ByteField("ver", 1),
                   PacketListField("tlvlist", [], DtpGenericTlv)]


bind_layers(SNAP, DTP, code=0x2004, OUI=0xc)


def negotiate_trunk(iface=conf.iface, mymac=str(RandMAC())):
    print("Trying to negotiate a trunk on interface %s" % iface)
    p = Dot3(src=mymac, dst="01:00:0c:cc:cc:cc") / LLC()
    p /= SNAP()
    p /= DTP(tlvlist=[DTPDomain(), DTPStatus(), DTPType(), DTPNeighbor(neighbor=mymac)])  # noqa: E501
    sendp(p)
