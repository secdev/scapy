# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Ethernet Synchronization Message Channel (ESMC)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, XByteField, ShortField, XStrFixedLenField  # noqa: E501
from scapy.contrib.slowprot import SlowProtocol
from scapy.compat import orb


class ESMC(Packet):
    name = "ESMC"
    fields_desc = [
        XStrFixedLenField("ituOui", b"\x00\x19\xa7", 3),
        ShortField("ituSubtype", 1),
        BitField("version", 1, 4),
        BitField("event", 0, 1),
        BitField("reserved1", 0, 3),
        XStrFixedLenField("reserved2", b"\x00" * 3, 3),
    ]

    def guess_payload_class(self, payload):
        if orb(payload[0]) == 1:
            return QLTLV
        if orb(payload[0]) == 2:
            return EQLTLV
        return Packet.guess_payload_class(self, payload)


class QLTLV(ESMC):
    name = "QLTLV"
    fields_desc = [
        ByteField("type", 1),
        ShortField("length", 4),
        XByteField("ssmCode", 0xf),
    ]


class EQLTLV(ESMC):
    name = "EQLTLV"
    fields_desc = [
        ByteField("type", 2),
        ShortField("length", 0x14),
        XByteField("enhancedSsmCode", 0xFF),
        XStrFixedLenField("clockIdentity", b"\x00" * 8, 8),
        ByteField("flag", 0),
        ByteField("cascaded_eEEcs", 1),
        ByteField("cascaded_EEcs", 0),
        XStrFixedLenField("reserved", b"\x00" * 5, 5),
    ]


bind_layers(SlowProtocol, ESMC, subtype=10)
