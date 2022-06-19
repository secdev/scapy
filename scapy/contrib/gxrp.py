# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Generic Attribute Register Protocol (GARP)
# scapy.contrib.status = loads

"""
    GARP - Generic Attribute Register Protocol
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Sergey Matsievskiy, matsievskiysv@gmail.com

    :description:

        This module provides Scapy layers for the GARP protocol and its
        two applications: GARP VLAN Registration Protocol (GVRP) and
        GARP Multicast Registration Protocol (GMRP)

        normative references:
            - IEEE 802.1D 2004 - Media Access Control (MAC) Bridges
            - IEEE 802.1Q 1998 - Virtual Bridged Local Area Networks

"""
from scapy.fields import (
    LenField,
    EnumField,
    ByteField,
    PacketListField,
    ShortField,
    MACField,
)
from scapy.packet import Packet, bind_layers, split_layers
from scapy.layers.l2 import LLC, Dot3
from scapy.error import warning


class GVRP(Packet):
    """
    GVRP
    """

    name = "GVRP"

    # IEEE802.1Q-1998 11.2.3.1.3
    fields_desc = [ShortField("vlan", 1)]

    def extract_padding(self, s):
        return b"", s


class GMRP_GROUP(Packet):
    """
    GMRP Group
    """

    name = "GMRP Group"

    # IEEE802.1D-2004 10.3.1.4
    fields_desc = [MACField("addr", None)]

    def extract_padding(self, s):
        return b"", s


class GMRP_SERVICE(Packet):
    """
    GMRP Service
    """

    name = "GMRP Service"

    # IEEE802.1D-2004 10.3.1.4
    fields_desc = [
        EnumField(
            "event",
            0,
            {0x0: "All Groups", 0x1: "All Unregistered Groups"},
            fmt="B",
        )
    ]

    def extract_padding(self, s):
        return b"", s


class GARP_ATTRIBUTE(Packet):
    """
    GARP attribute container
    """

    name = "GARP Attribute"

    # IEEE802.1D-2004 12.10.2.4-5
    fields_desc = [
        LenField("len", None, fmt="B", adjust=lambda l: l + 2),
        EnumField(
            "event",
            0,
            {
                0x0: "LeaveAll",
                0x1: "JoinEmpty",
                0x2: "JoinIn",
                0x3: "LeaveEmpty",
                0x4: "LeaveIn",
                0x5: "Empty",
            },
            fmt="B",
        ),
    ]

    def do_dissect(self, s):
        s = super(GARP_ATTRIBUTE, self).do_dissect(s)
        if self.len is not None and self.event == 0 and self.len > 2:
            warning("Non-empty payload at LeaveAll event")
        return s

    def extract_padding(self, s):
        boundary = self.len - 2
        return s[:boundary], s[boundary:]

    def guess_payload_class(self, payload):
        try:
            garp_message = self.parent
            garp = garp_message.parent
            llc = garp.underlayer
            dot3 = llc.underlayer
            if (
                dot3.dst == "01:80:c2:00:00:21"
            ):  # IEEE802.1D-2004 12.4 Table 12-1
                return GVRP
            elif (
                dot3.dst == "01:80:c2:00:00:20"
            ):  # IEEE802.1D-2004 12.4 Table 12-1
                if garp_message.type == 1:  # IEEE802.1D-2004 10.3.1.3
                    return GMRP_GROUP
                elif garp_message.type == 2:  # IEEE802.1D-2004 10.3.1.3
                    return GMRP_SERVICE
        except AttributeError:
            pass
        return super(GARP_ATTRIBUTE, self).guess_payload_class(payload)


def parse_next_attr(pkt, lst, cur, remain):
    # IEEE802.1D-2004 12.10.2.7
    if not remain or len(remain) == 0 or remain[0:1] == b"\x00":
        return None
    elif ord(remain[0:1]) >= 2:  # minimal attribute size
        return GARP_ATTRIBUTE
    else:
        return None


class GARP_MESSAGE(Packet):
    """
    GARP message container
    """

    name = "GARP Message"
    fields_desc = [
        ByteField("type", 0x01),
        PacketListField("attrs", [], next_cls_cb=parse_next_attr),
        ByteField("end_mark", 0x0),
    ]

    def extract_padding(self, s):
        return b"", s


def parse_next_msg(pkt, lst, cur, remain):
    # IEEE802.1D-2004 12.10.2.7
    if not remain and len(remain) == 0 or remain[0:1] == b"\x00":
        return None
    else:
        return GARP_MESSAGE


class GARP(Packet):
    """
    GARP packet
    """

    name = "GARP"

    fields_desc = [
        ShortField("proto_id", 0x0001),  # IEEE802.1D-2004 12.10.2.1
        PacketListField("msgs", [], next_cls_cb=parse_next_msg),
        ByteField("end_mark", 0x0),
    ]  # IEEE802.1D-2004 12.10.2.7


class LLC_GARP(LLC):
    """
    Dummy class for layer binding
    """

    payload_guess = []


split_layers(Dot3, LLC)
# IEEE802.1D-2004 12.4 Table 12-1
for mac in ["01:80:c2:00:00:20",
            "01:80:c2:00:00:21",
            "01:80:c2:00:00:22",
            "01:80:c2:00:00:23",
            "01:80:c2:00:00:24",
            "01:80:c2:00:00:25",
            "01:80:c2:00:00:26",
            "01:80:c2:00:00:27",
            "01:80:c2:00:00:28",
            "01:80:c2:00:00:29",
            "01:80:c2:00:00:2a",
            "01:80:c2:00:00:2b",
            "01:80:c2:00:00:2c",
            "01:80:c2:00:00:2d",
            "01:80:c2:00:00:2e",
            "01:80:c2:00:00:2f"]:
    bind_layers(Dot3, LLC_GARP, dst=mac)
bind_layers(Dot3, LLC)
bind_layers(LLC_GARP, GARP)
