# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Parag Bhide

"""
BFD - Bidirectional Forwarding Detection - RFC 5880, 5881, 7130, 7881
"""

# scapy.contrib.description = BFD
# scapy.contrib.status = loads


from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import (
    BitField,
    BitEnumField,
    ByteEnumField,
    XNBytesField,
    XByteField,
    MultipleTypeField,
    IntField,
    FieldLenField,
    FlagsField,
    ByteField,
    PacketField,
    ConditionalField,
    StrFixedLenField,
)
from scapy.layers.inet import UDP

_sta_names = {
    0: "AdminDown",
    1: "Down",
    2: "Init",
    3: "Up",
}


# https://www.iana.org/assignments/bfd-parameters/bfd-parameters.xhtml
_diagnostics = {
    0: "No Diagnostic",
    1: "Control Detection Time Expired",
    2: "Echo Function Failed",
    3: "Neighbor Signaled Session Down",
    4: "Forwarding Plane Reset",
    5: "Path Down",
    6: "Concatenated Path Down",
    7: "Administratively Down",
    8: "Reverse Concatenated Path Down",
    9: "Mis-Connectivity Defect",
}


# https://www.rfc-editor.org/rfc/rfc5880 [Page 10]
_authentification_type = {
    0: "Reserved",
    1: "Simple Password",
    2: "Keyed MD5",
    3: "Meticulous Keyed MD5",
    4: "Keyed SHA1",
    5: "Meticulous Keyed SHA1",
}


class OptionalAuth(Packet):
    name = "Optional Auth"
    fields_desc = [
        ByteEnumField("auth_type", 1, _authentification_type),
        FieldLenField(
            "auth_len",
            None,
            fmt="B",
            length_of="auth_key",
            adjust=lambda pkt, x: x + 3 if pkt.auth_type <= 1 else x + 8,
        ),
        ByteField("auth_keyid", 1),
        ConditionalField(
            XByteField("reserved", 0),
            lambda pkt: pkt.auth_type > 1,
        ),
        ConditionalField(
            IntField("sequence_number", 0),
            lambda pkt: pkt.auth_type > 1,
        ),
        MultipleTypeField(
            [
                (
                    StrFixedLenField(
                        "auth_key", "", length_from=lambda pkt: pkt.auth_len
                    ),
                    lambda pkt: pkt.auth_type == 0,
                ),
                (
                    XNBytesField("auth_key", 0x5F4DCC3B5AA765D61D8327DEB882CF99, 16),
                    lambda pkt: pkt.auth_type == 2 or pkt.auth_type == 3,
                ),
                (
                    XNBytesField(
                        "auth_key", 0x5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8, 20
                    ),
                    lambda pkt: pkt.auth_type == 4 or pkt.auth_type == 5,
                ),
            ],
            StrFixedLenField(
                "auth_key", "password", length_from=lambda pkt: pkt.auth_len
            ),
        ),
    ]


class BFD(Packet):
    name = "BFD"
    fields_desc = [
        BitField("version", 1, 3),
        BitEnumField("diag", 0, 5, _diagnostics),
        BitEnumField("sta", 3, 2, _sta_names),
        FlagsField("flags", 0, 6, "MDACFP"),
        ByteField("detect_mult", 3),
        FieldLenField(
            "len",
            None,
            fmt="B",
            length_of="optional_auth",
            adjust=lambda pkt, x: x + 24,
        ),
        BitField("my_discriminator", 0x11111111, 32),
        BitField("your_discriminator", 0x22222222, 32),
        BitField("min_tx_interval", 1000000000, 32),
        BitField("min_rx_interval", 1000000000, 32),
        BitField("echo_rx_interval", 1000000000, 32),
        ConditionalField(
            PacketField("optional_auth", None, OptionalAuth),
            lambda pkt: pkt.flags.names[2] == "A",
        ),
    ]

    def mysummary(self):
        return self.sprintf(
            "BFD (my_disc=%BFD.my_discriminator%,"
            "your_disc=%BFD.your_discriminator%,"
            "state=%BFD.sta%)"
        )


for _bfd_port in [
    3784,  # single-hop BFD
    4784,  # multi-hop BFD
    6784,  # BFD for LAG a.k.a micro-BFD
    7784,  # seamless BFD
]:
    bind_bottom_up(UDP, BFD, dport=_bfd_port)
    bind_bottom_up(UDP, BFD, sport=_bfd_port)
    bind_layers(UDP, BFD, dport=_bfd_port, sport=_bfd_port)
