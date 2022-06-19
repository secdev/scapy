# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2019 Jose Diogo Monteiro <jdlopes@student.dei.uc.pt>

# scapy.contrib.description = EtherNet/IP
# scapy.contrib.status = loads

"""
EtherNet/IP (Industrial Protocol)

Based on https://github.com/scy-phy/scapy-cip-enip
EtherNet/IP Home: www.odva.org
"""

import struct
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
from scapy.fields import LEShortField, LEShortEnumField, LEIntEnumField, \
    LEIntField, LELongField, FieldLenField, PacketListField, ByteField, \
    PacketField, MultipleTypeField, StrLenField, StrFixedLenField, \
    XLEIntField, XLEStrLenField

_commandIdList = {
    0x0004: "ListServices",  # Request Struct Don't Have Command Spec Data
    0x0063: "ListIdentity",  # Request Struct Don't Have Command Spec Data
    0x0064: "ListInterfaces",  # Request Struct Don't Have Command Spec Data
    0x0065: "RegisterSession",  # Request Structure = Reply Structure
    0x0066: "UnregisterSession",  # Don't Have Command Specific Data
    0x006f: "SendRRData",  # Request Structure = Reply Structure
    0x0070: "SendUnitData",  # There is no reply
    0x0072: "IndicateStatus",
    0x0073: "Cancel"
}

_statusList = {
    0: "success",
    1: "invalid_cmd",
    2: "no_resources",
    3: "incorrect_data",
    100: "invalid_session",
    101: "invalid_length",
    105: "unsupported_prot_rev"
}

_itemID = {
    0x0000: "Null Address Item",
    0x00a1: "Connection-based Address Item",
    0x00b1: "Connected Transport packet Data Item",
    0x00b2: "Unconnected message Data Item",
    0x8000: "Sockaddr Info, originator-to-target Data Item",
    0x8001: "Sockaddr Info, target-to-originator Data Item"
}


class ItemData(Packet):
    """Common Packet Format"""
    name = "Item Data"
    fields_desc = [
        LEShortEnumField("typeId", 0, _itemID),
        LEShortField("length", 0),
        XLEStrLenField("data", "", length_from=lambda pkt: pkt.length),
    ]

    def extract_padding(self, s):
        return '', s


class EncapsulatedPacket(Packet):
    """Encapsulated Packet"""
    name = "Encapsulated Packet"
    fields_desc = [LEShortField("itemCount", 2), PacketListField(
        "item", None, ItemData, count_from=lambda pkt: pkt.itemCount), ]


class BaseSendPacket(Packet):
    """ Abstract Class"""
    fields_desc = [
        LEIntField("interfaceHandle", 0),
        LEShortField("timeout", 0),
        PacketField("encapsulatedPacket", None, EncapsulatedPacket),
    ]


class CommandSpecificData(Packet):
    """Command Specific Data Field Default"""
    pass


class ENIPSendUnitData(BaseSendPacket):
    """Send Unit Data Command Field"""
    name = "ENIPSendUnitData"


class ENIPSendRRData(BaseSendPacket):
    """Send RR Data Command Field"""
    name = "ENIPSendRRData"


class ENIPListInterfacesReplyItems(Packet):
    """List Interfaces Items Field"""
    name = "ENIPListInterfacesReplyItems"
    fields_desc = [
        LEIntField("itemTypeCode", 0),
        FieldLenField("itemLength", 0, length_of="itemData"),
        StrLenField("itemData", "", length_from=lambda pkt: pkt.itemLength),
    ]


class ENIPListInterfacesReply(Packet):
    """List Interfaces Command Field"""
    name = "ENIPListInterfacesReply"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="identityItems"),
        PacketField("identityItems", 0, ENIPListInterfacesReplyItems),
    ]


class ENIPListIdentityReplyItems(Packet):
    """List Identity Items Field"""
    name = "ENIPListIdentityReplyItems"
    fields_desc = [
        LEIntField("itemTypeCode", 0),
        FieldLenField("itemLength", 0, length_of="itemData"),
        StrLenField("itemData", "", length_from=lambda pkt: pkt.item_length),
    ]


class ENIPListIdentityReply(Packet):
    """List Identity Command Field"""
    name = "ENIPListIdentityReply"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="identityItems"),
        PacketField("identityItems", None, ENIPListIdentityReplyItems),
    ]


class ENIPListServicesReplyItems(Packet):
    """List Services Items Field"""
    name = "ENIPListServicesReplyItems"
    fields_desc = [
        LEIntField("itemTypeCode", 0),
        LEIntField("itemLength", 0),
        ByteField("version", 1),
        ByteField("flag", 0),
        StrFixedLenField("serviceName", None, 16 * 4),
    ]


class ENIPListServicesReply(Packet):
    """List Services Command Field"""
    name = "ENIPListServicesReply"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="identityItems"),
        PacketField("targetItems", None, ENIPListServicesReplyItems),
    ]


class ENIPRegisterSession(CommandSpecificData):
    """Register Session Command Field"""
    name = "ENIPRegisterSession"
    fields_desc = [
        LEShortField("protocolVersion", 1),
        LEShortField("options", 0)
    ]


class ENIPTCP(Packet):
    """Ethernet/IP packet over TCP"""
    name = "ENIPTCP"
    fields_desc = [
        LEShortEnumField("commandId", None, _commandIdList),
        LEShortField("length", 0),
        XLEIntField("session", 0),
        LEIntEnumField("status", None, _statusList),
        LELongField("senderContext", 0),
        LEIntField("options", 0),
        MultipleTypeField(
            [
                # List Services Reply
                (PacketField("commandSpecificData", ENIPListServicesReply,
                             ENIPListServicesReply),
                 lambda pkt: pkt.commandId == 0x4),
                # List Identity Reply
                (PacketField("commandSpecificData", ENIPListIdentityReply,
                             ENIPListIdentityReply),
                 lambda pkt: pkt.commandId == 0x63),
                # List Interfaces Reply
                (PacketField("commandSpecificData", ENIPListInterfacesReply,
                             ENIPListInterfacesReply),
                 lambda pkt: pkt.commandId == 0x64),
                # Register Session
                (PacketField("commandSpecificData", ENIPRegisterSession,
                             ENIPRegisterSession),
                 lambda pkt: pkt.commandId == 0x65),
                # Send RR Data
                (PacketField("commandSpecificData", ENIPSendRRData,
                             ENIPSendRRData),
                 lambda pkt: pkt.commandId == 0x6f),
                # Send Unit Data
                (PacketField("commandSpecificData", ENIPSendUnitData,
                             ENIPSendUnitData),
                 lambda pkt: pkt.commandId == 0x70),
            ],
            PacketField(
                "commandSpecificData",
                None,
                CommandSpecificData)  # By default
        ),
    ]

    def post_build(self, pkt, pay):
        if self.length is None and pay:
            pkt = pkt[:2] + struct.pack("<H", len(pay)) + pkt[4:]
        return pkt + pay


bind_layers(TCP, ENIPTCP, dport=44818)
bind_layers(TCP, ENIPTCP, sport=44818)
