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
    ConditionalField,
    LEMACField,
    StrFixedLenField,
    XLEShortField,
    XLEIntField,
    XStrField,
    XStrFixedLenField,
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


class HCI_Cmd_VSC_Barrot_Read_Chip_Version(Packet):
    """
    Barrot Read Chip Version (cmd 0x01).

    Returns the chip model, firmware date, flash id and feature flags.
    """
    name = "Barrot Read Chip Version"


class HCI_Cmd_VSC_Barrot_Read_Signature(Packet):
    """
    Barrot Read Signature (cmd 0x03).

    Returns a 32-byte chip signature.
    """
    name = "Barrot Read Signature"


class HCI_Cmd_VSC_Barrot_Bd_Param(Packet):
    """
    Barrot BD Param (cmd 0x05).

    Sets the device bluetooth address to the 6 bytes ``bd_addr`` field. When
    ``bd_addr`` is left unset, nothing is set. Either way the device responds
    with its bluetooth address.
    """
    name = "Barrot HCI BD Param"
    fields_desc = [
        ConditionalField(
            LEMACField("bd_addr", None),
            lambda p: p.fields.get("bd_addr") is not None or len(p.original) >= 6
        ),
    ]


class HCI_Cmd_VSC_Barrot_Bus_Write(Packet):
    """
    Barrot Bus Write (cmd 0x0E).

    Writes ``data`` to arbitrary memory bus ``address``
    """
    name = "Barrot Bus Write"
    fields_desc = [
        XLEIntField("address", 0),
        XStrField("data", b"")
    ]


class HCI_Cmd_VSC_Barrot_Bus_Read(Packet):
    """
    Barrot Bus Read (cmd 0x0F)

    Reads ``length`` bytes from memory bus ``address``.
    """
    name = "Barrot Bus Read"
    fields_desc = [
        XLEIntField("address", 0),
        ByteField("length", 0)
    ]


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


class HCI_Evt_VSC_Barrot_Command_Complete(Packet):
    """
    Barrot vendor-specific Command Complete body (opcode 0xFC80).
    """
    name = "Barrot Vendor Specific Command Complete"
    fields_desc = [XLEShortField("cmd", 0)]


class HCI_Cmd_Complete_VSC_Barrot_Read_Chip_Version(Packet):
    """
    Read Chip Version (cmd 0x01) command complete.

    ``version`` packs the chip model in hex digits (0x08051A02 -> "BR8051A02").
    """
    name = "Barrot Read Chip Version complete"
    fields_desc = [
        StrFixedLenField("magic", b"BRT", 3),
        ByteField("config_type", 0),
        XLEIntField("version", 0),
        XLEIntField("fw_date", 0),
        XLEIntField("esm_type", 0),
        XLEIntField("run_mode", 0),
        XLEIntField("features", 0),
        XLEShortField("flash_id", 0),
    ]


class HCI_Cmd_Complete_VSC_Barrot_Read_Signature(Packet):
    """Read Signature (cmd 0x03) command complete: the 32-byte signature."""
    name = "Barrot Read Signature complete"
    fields_desc = [XStrFixedLenField("signature", b"\x00" * 32, 32)]


class HCI_Cmd_Complete_VSC_Barrot_Bd_Param(Packet):
    """
    BD Param (cmd 0x05) command complete: the 6 bytes bluetooth address of
    the device in ``bd_addr``.

    When answering an address change, the address reported is the new one, if
    it was set correctly.
    """
    name = "Barrot HCI BD Param complete"
    fields_desc = [LEMACField("bd_addr", None)]


class HCI_Cmd_Complete_VSC_Barrot_Bus_Read(Packet):
    """Bus Read (cmd 0x0F) command complete: the ``length`` bytes read from
    the memory bus."""
    name = "Barrot Bus Read complete"
    fields_desc = [
        XStrLenField("data", b"",
                     length_from=lambda p: p.underlayer.underlayer.underlayer.len - 6)
    ]


class HCI_Cmd_Complete_VSC_Barrot_Flash_Read(Packet):
    """Flash Read (cmd 0x12) command complete: the ``length`` bytes read."""
    name = "Barrot Flash Read complete"
    fields_desc = [
        XStrLenField("data", b"",
                     length_from=lambda p: p.underlayer.underlayer.underlayer.len - 6)
    ]


bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Barrot, ogf=0x3F, ocf=0x080)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Read_Chip_Version, cmd=0x01)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Read_Signature, cmd=0x03)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Bd_Param, cmd=0x05)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Bus_Write, cmd=0x0E)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Bus_Read, cmd=0x0F)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Flash_Write, cmd=0x11)
bind_layers(HCI_Cmd_VSC_Barrot, HCI_Cmd_VSC_Barrot_Flash_Read, cmd=0x12)

bind_layers(HCI_Event_Command_Complete, HCI_Evt_VSC_Barrot_Command_Complete,
            opcode=0xFC80)
bind_layers(HCI_Evt_VSC_Barrot_Command_Complete,
            HCI_Cmd_Complete_VSC_Barrot_Read_Chip_Version, cmd=0x01)
bind_layers(HCI_Evt_VSC_Barrot_Command_Complete,
            HCI_Cmd_Complete_VSC_Barrot_Read_Signature, cmd=0x03)
bind_layers(HCI_Evt_VSC_Barrot_Command_Complete,
            HCI_Cmd_Complete_VSC_Barrot_Bd_Param, cmd=0x05)
bind_layers(HCI_Evt_VSC_Barrot_Command_Complete,
            HCI_Cmd_Complete_VSC_Barrot_Bus_Read, cmd=0x0F)
bind_layers(HCI_Evt_VSC_Barrot_Command_Complete,
            HCI_Cmd_Complete_VSC_Barrot_Flash_Read, cmd=0x12)
