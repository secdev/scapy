# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
#
# scapy.contrib.description = Realtek Bluetooth HCI Vendor-Specific Commands
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    LEShortField,
    LEIntField,
    MultipleTypeField,
    XLEIntField,
    XStrLenField,
)

from scapy.layers.bluetooth import (
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)

# Address space selector:
#   0, 1 - direct native CPU load/store RAM/ROM.
#   2    - indirect reg routed to the port for the RF/analog-front-end/baseband/modem.
#   3    - invalid, rejected by the firmware with status 0x12.
_rtk_mem_space = {0: "direct", 1: "direct_alt", 2: "indirect_reg", 3: "invalid"}

# Access width selector for memory read/write operations.
_rtk_mem_width = {0: "byte", 1: "halfword", 2: "word", 3: "word"}


class HCI_Cmd_VSC_Realtek_Read_Mem(Packet):
    """
    Realtek Read Controller Memory (OCF 0x061, opcode 0xFC61).

    Reads ``1 << width`` bytes (1/2/4) from ``address``.
    The ``space`` field selects direct CPU memory (0/1) or the indirect
    RF/PHY register port (2). For ``space=indirect_reg`` only the low 16
    bits of ``address`` are used, as the register offset.
    """
    name = "Realtek Read Controller Memory"
    fields_desc = [
        BitField("reserved1", 0, 2),                       # bits 7-6
        BitEnumField("width", 2, 2, _rtk_mem_width),       # bits 5-4 (default word)
        BitField("reserved2", 0, 2),                       # bits 3-2
        BitEnumField("space", 0, 2, _rtk_mem_space),       # bits 1-0 (default direct)
        XLEIntField("address", 0x80000000),
    ]


class HCI_Cmd_VSC_Realtek_Write_Mem(Packet):
    """
    Realtek Write Controller Memory (OCF 0x062, opcode 0xFC62).

    Writes ``value`` (sized by ``width``: byte/halfword/word) to ``address``.
    ``value`` is a little-endian integer whose width follows the ``width``
    field. ``space`` selects direct CPU memory (0/1) or the indirect RF/PHY
    register port (2); for ``space=indirect_reg`` only the low 16 bits of
    ``address`` are used, as the register offset.
    """
    name = "Realtek Write Controller Memory"
    fields_desc = [
        BitField("reserved1", 0, 2),
        BitEnumField("width", 2, 2, _rtk_mem_width),
        BitField("reserved2", 0, 2),
        BitEnumField("space", 0, 2, _rtk_mem_space),
        XLEIntField("address", 0x80000000),
        MultipleTypeField(
            [
                (ByteField("value", 0), lambda pkt: pkt.width == 0),
                (LEShortField("value", 0), lambda pkt: pkt.width == 1),
            ],
            LEIntField("value", 0),                        # default: word
        ),
    ]


class HCI_Cmd_Complete_VSC_Realtek_Read_Mem(Packet):
    """Read Controller Memory (0xFC61) command complete"""
    name = "Realtek Read Controller Memory complete"
    fields_desc = [
        XStrLenField("data", b"", lambda pkt: pkt.underlayer.underlayer.len - 4)
    ]


bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Read_Mem, ogf=0x3F, ocf=0x061)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Realtek_Write_Mem, ogf=0x3F, ocf=0x062)

bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_VSC_Realtek_Read_Mem,
            opcode=0xFC61)
