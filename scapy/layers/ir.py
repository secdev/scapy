# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
IrDA infrared data communication.
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import BitEnumField, ByteEnumField, StrField, XBitField, \
    XByteField, XIntField, XShortField
from scapy.layers.l2 import CookedLinux


# IR

class IrLAPHead(Packet):
    name = "IrDA Link Access Protocol Header"
    fields_desc = [XBitField("Address", 0x7f, 7),
                   BitEnumField("Type", 1, 1, {"Response": 0,
                                               "Command": 1})]


class IrLAPCommand(Packet):
    name = "IrDA Link Access Protocol Command"
    fields_desc = [XByteField("Control", 0),
                   XByteField("Format_identifier", 0),
                   XIntField("Source_address", 0),
                   XIntField("Destination_address", 0xffffffff),
                   XByteField("Discovery_flags", 0x1),
                   ByteEnumField("Slot_number", 255, {"final": 255}),
                   XByteField("Version", 0)]


class IrLMP(Packet):
    name = "IrDA Link Management Protocol"
    fields_desc = [XShortField("Service_hints", 0),
                   XByteField("Character_set", 0),
                   StrField("Device_name", "")]


bind_layers(CookedLinux, IrLAPHead, proto=23)
bind_layers(IrLAPHead, IrLAPCommand, Type=1)
bind_layers(IrLAPCommand, IrLMP,)
