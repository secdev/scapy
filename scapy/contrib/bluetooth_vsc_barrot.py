# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
#
# scapy.contrib.description = Barrot Bluetooth HCI Vendor-Specific Commands
# scapy.contrib.status = loads
#
# Information sources:
# - https://github.com/tryger/barrot-tools/

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteField,
    XLEShortField,
    XLEIntField,
    XStrField,
    XStrLenField,
)

from scapy.layers.bluetooth import (
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
)


class HCI_Cmd_VSC_Barrot(Packet):
    """
    Barrot vendor-specific command wrapper (opcode 0xFC80).
    """
    name = "Barrot Vendor Specific Command"
    fields_desc = [XLEShortField("cmd", 0)]


class HCI_Evt_VSC_Barrot_Command_Complete(Packet):
    """
    Barrot vendor-specific Command Complete body (opcode 0xFC80).
    """
    name = "Barrot Vendor Specific Command Complete"
    fields_desc = [XLEShortField("cmd", 0)]


class HCI_Cmd_VSC_Barrot_Flash_Write(Packet):
    """
    Barrot Flash Write (cmd 0x11).

    Writes ``data`` to the flash offset ``address``. On a write-protected device
    the firmware reports success (status 0x00) but does not change the flash.
    """
    name = "Barrot Flash Write"
    fields_desc = [
        XLEIntField("address", 0),
        XStrField("data", b""),
    ]


class HCI_Cmd_VSC_Barrot_Flash_Read(Packet):
    """
    Barrot Flash Read (cmd 0x12).

    Reads ``length`` bytes (1..0xF0) from the flash offset ``address``.
    Only reads the SPI flash storage memory.
    """
    name = "Barrot Flash Read"
    fields_desc = [
        XLEIntField("address", 0),
        ByteField("length", 0),
    ]


class HCI_Cmd_Complete_VSC_Barrot_Flash_Read(Packet):
    """Flash Read (cmd 0x12) command complete: the ``length`` bytes read."""
    name = "Barrot Flash Read complete"
    fields_desc = [
        XStrLenField("data", b"",
                     length_from=lambda p: p.underlayer.underlayer.underlayer.len - 6)
    ]


bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Barrot, ogf=0x3F, ocf=0x080)
bind_layers(HCI_Event_Command_Complete, HCI_Evt_VSC_Barrot_Command_Complete,
            opcode=0xFC80)

bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Flash_Write, cmd=0x11)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Flash_Read, cmd=0x12)
bind_layers(HCI_Evt_VSC_Barrot_Command_Complete,
            HCI_Cmd_Complete_VSC_Barrot_Flash_Read, cmd=0x12)
