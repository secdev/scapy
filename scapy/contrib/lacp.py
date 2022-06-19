# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Link Aggregation Control Protocol (LACP)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, MACField, ShortField, ByteEnumField, IntField, XStrFixedLenField  # noqa: E501
from scapy.contrib.slowprot import SlowProtocol


class LACP(Packet):
    name = "LACP"
    deprecated_fields = {
        "actor_port_numer": ("actor_port_number", "2.4.4"),
        "partner_port_numer": ("partner_port_number", "2.4.4"),
        "colletctor_reserved": ("collector_reserved", "2.4.4"),
    }
    fields_desc = [
        ByteField("version", 1),
        ByteField("actor_type", 1),
        ByteField("actor_length", 20),
        ShortField("actor_system_priority", 0),
        MACField("actor_system", None),
        ShortField("actor_key", 0),
        ShortField("actor_port_priority", 0),
        ShortField("actor_port_number", 0),
        ByteField("actor_state", 0),
        XStrFixedLenField("actor_reserved", "", 3),
        ByteField("partner_type", 2),
        ByteField("partner_length", 20),
        ShortField("partner_system_priority", 0),
        MACField("partner_system", None),
        ShortField("partner_key", 0),
        ShortField("partner_port_priority", 0),
        ShortField("partner_port_number", 0),
        ByteField("partner_state", 0),
        XStrFixedLenField("partner_reserved", "", 3),
        ByteField("collector_type", 3),
        ByteField("collector_length", 16),
        ShortField("collector_max_delay", 0),
        XStrFixedLenField("collector_reserved", "", 12),
        ByteField("terminator_type", 0),
        ByteField("terminator_length", 0),
        XStrFixedLenField("reserved", "", 50),
    ]


bind_layers(SlowProtocol, LACP, subtype=1)

MARKER_TYPES = {
    'Marker Request': 1,
    'Marker Response': 2,
}


class MarkerProtocol(Packet):
    name = "MarkerProtocol"
    fields_desc = [
        ByteField("version", 1),
        ByteEnumField("marker_type", 1, MARKER_TYPES),
        ByteField("marker_length", 16),
        ShortField("requester_port", 0),
        MACField("requester_system", None),
        IntField("requester_transaction_id", 0),
        XStrFixedLenField("marker_reserved", "", 2),
        ByteField("terminator_type", 0),
        ByteField("terminator_length", 0),
        XStrFixedLenField("reserved", 0, 90),
    ]


bind_layers(SlowProtocol, MarkerProtocol, subtype=2)
