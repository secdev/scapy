# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
EPT map (EndPoinT mapper)
"""

import uuid

from scapy.config import conf
from scapy.fields import (
    ByteEnumField,
    ConditionalField,
    FieldLenField,
    IPField,
    LEShortField,
    MultipleTypeField,
    PacketListField,
    ShortField,
    StrLenField,
    UUIDEnumField,
)
from scapy.packet import Packet
from scapy.layers.dcerpc import (
    DCE_RPC_INTERFACES_NAMES_rev,
    DCE_RPC_INTERFACES_NAMES,
    DCE_RPC_PROTOCOL_IDENTIFIERS,
    DCE_RPC_TRANSFER_SYNTAXES,
)

from scapy.layers.msrpce.raw.ept import *  # noqa: F401, F403


# [C706] Appendix L

# "For historical reasons, this cannot be done using the standard
# NDR encoding rules for marshalling and unmarshalling.
# A special encoding is required." - Appendix L


class octet_string_t(Packet):
    fields_desc = [
        FieldLenField("count", None, fmt="<H", length_of="value"),
        StrLenField("value", b"", length_from=lambda pkt: pkt.count),
    ]

    def default_payload_class(self, _):
        return conf.padding_layer


def _uuid_res(x):
    # Look in both DCE_RPC_INTERFACES_NAMES and DCE_RPC_TRANSFER_SYNTAXES
    dct = DCE_RPC_INTERFACES_NAMES.copy()
    dct.update(DCE_RPC_TRANSFER_SYNTAXES)
    return dct.get(x)


def _uuid_res_rev(x):
    # Same but reversed
    dct = DCE_RPC_INTERFACES_NAMES_rev.copy()
    dct.update({v: k for k, v in DCE_RPC_TRANSFER_SYNTAXES.items()})
    return dct.get(x)


class prot_and_addr_t(Packet):
    fields_desc = [
        # --- LHS
        LEShortField(
            "lhs_length",
            0,
        ),
        ByteEnumField(
            "protocol_identifier",
            0,
            DCE_RPC_PROTOCOL_IDENTIFIERS,
        ),
        # 0x0
        ConditionalField(
            StrLenField("oid", "", length_from=lambda pkt: pkt.lhs_length - 1),
            lambda pkt: pkt.protocol_identifier == 0x0,
        ),
        # 0xD
        ConditionalField(
            UUIDEnumField(
                "uuid",
                uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860"),
                (
                    # Those are dynamic
                    _uuid_res,
                    _uuid_res_rev,
                ),
                uuid_fmt=UUIDEnumField.FORMAT_LE,
            ),
            lambda pkt: pkt.protocol_identifier == 0xD,
        ),
        ConditionalField(
            LEShortField("version", 0), lambda pkt: pkt.protocol_identifier == 0xD
        ),
        # Other
        ConditionalField(
            StrLenField("lhs", "", length_from=lambda pkt: pkt.lhs_length - 1),
            lambda pkt: pkt.protocol_identifier not in [0x0, 0x7, 0xD],
        ),
        # --- RHS
        LEShortField(
            "rhs_length",
            None,
        ),
        MultipleTypeField(
            [
                (
                    # (big-endian)
                    ShortField("rhs", 0),
                    lambda pkt: pkt.protocol_identifier in [0x7, 0x8, 0x1F],
                    "port",
                ),
                (
                    # (big-endian)
                    IPField("rhs", 0),
                    lambda pkt: pkt.protocol_identifier == 0x9,
                    "addr",
                ),
                (
                    LEShortField("rhs", 5),
                    lambda pkt: pkt.protocol_identifier in [0xA, 0xB, 0xD],
                    "minor version",
                ),
                (
                    StrLenField("rhs", "", length_from=lambda pkt: pkt.rhs_length),
                    lambda pkt: pkt.protocol_identifier == 0xF,
                    "named pipe",
                ),
                (
                    StrLenField("rhs", "", length_from=lambda pkt: pkt.rhs_length),
                    lambda pkt: pkt.protocol_identifier == 0x11,
                    "netbios name",
                ),
            ],
            StrLenField("rhs", "", length_from=lambda pkt: pkt.rhs_length),
        ),
    ]

    def default_payload_class(self, _):
        return conf.padding_layer


class protocol_tower_t(Packet):
    fields_desc = [
        FieldLenField("count", None, fmt="<H", count_of="floors"),
        PacketListField(
            "floors",
            [prot_and_addr_t()],
            prot_and_addr_t,
            count_from=lambda pkt: pkt.count,
        ),
    ]

    def _summary(self):
        if len(self.floors) < 4:
            raise ValueError("Malformed protocol_tower_t (not enough floors)")
        if self.floors[0].protocol_identifier != 0xD:
            raise ValueError("Malformed protocol_tower_t (bad floor 1)")
        if self.floors[1].protocol_identifier != 0xD:
            raise ValueError("Malformed protocol_tower_t (bad floor 2)")
        if self.floors[2].protocol_identifier in [0xA, 0xB]:  # Connection oriented/less
            endpoint = "%s:%s" % (
                self.floors[3].sprintf("%protocol_identifier%"),
                ":".join(
                    x.rhs.decode() if isinstance(x.rhs, bytes) else str(x.rhs)
                    for x in self.floors[3:][::-1]
                ),
            )
        elif self.floors[2].protocol_identifier == 0xC:  # NCALRPC
            endpoint = "%s:%s" % (
                self.floors[2].sprintf("%protocol_identifier%"),
                self.floors[3].rhs.decode(),
            )
        else:
            raise ValueError(
                "Unknown RPC transport: %s" % self.floors[2].protocol_identifier
            )
        return (
            self.floors[0].sprintf("%uuid% (%version%.%r,rhs%)"),
            endpoint,
        )

    def mysummary(self):
        try:
            return "%s %s" % self._summary()
        except ValueError as ex:
            return str(ex)
