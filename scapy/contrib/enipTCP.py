# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2019 Jose Diogo Monteiro <jdlopes@student.dei.uc.pt>
# Updated (C) 2023 Claire Vacherot <clairelex@pm.me>

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
    StrLenField, StrFixedLenField, XLEIntField, XLEStrLenField, \
    LEFieldLenField, ShortField, IPField, LongField, XLEShortField

_commandIdList = {
    0x0001: "UnknownCommand",
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

_typeIdList = {
    0x0000: "Null Address Item",
    0x000c: "CIP Identity",
    0x0086: "CIP Security Information",
    0x0087: "EtherNet/IP Capability",
    0x0088: "EtherNet/IP Usage",
    0x00a1: "Connected Address Item",
    0x00B1: "Connected Data Item",
    0x00B2: "Unconnected Data Item",
    0x0100: "List Services Response",
    0x8000: "Socket Address Info O->T",
    0x8001: "Socket Address Info T->O",
    0x8002: "Sequenced Address Item",
    0x8003: "Unconnected Message over UDP"
}

_deviceTypeList = {
    0x0000: "Generic Device (deprecated)",
    0x0002: "AC Drive",
    0x0003: "Motor Overload",
    0x0004: "Limit Switch",
    0x0005: "Inductive Proximity Switch",
    0x0006: "Photoelectric Sensor",
    0x0007: "General Purpose Discrete I/O",
    0x0009: "Resolver",
    0x000C: "Communications Adapter",
    0x000E: "Programmable Logic Controller",
    0x0010: "Position Controller",
    0x0013: "DC Drive",
    0x0015: "Contactor",
    0x0016: "Motor Starter",
    0x0017: "Soft Start",
    0x0018: "Human-Machine Interface",
    0x001A: "Mass Flow Controller",
    0x001B: "Pneumatic Valve",
    0x001C: "Vacuum Pressure Gauge",
    0x001D: "Process Control Value",
    0x001E: "Residual Gas Analyzer",
    0x001F: "DC Power Generator",
    0x0020: "RF Power Generator",
    0x0021: "Turbomolecular Vacuum Pump",
    0x0022: "Encoder",
    0x0023: "Safety Discrete I/O Device",
    0x0024: "Fluid Flow Controller",
    0x0025: "CIP Motion Drive",
    0x0026: "CompoNet Repeater",
    0x0027: "Mass Flow Controller, Enhanced",
    0x0028: "CIP Modbus Device",
    0x0029: "CIP Modbus Translator",
    0x002A: "Safety Analog I/O Device",
    0x002B: "Generic Device (keyable)",
    0x002C: "Managed Ethernet Switch",
    0x002D: "CIP Motion Safety Drive Device",
    0x002E: "Safety Drive Device",
    0x002F: "CIP Motion Encoder",
    0x0030: "CIP Motion Converter",
    0x0031: "CIP Motion I/O",
    0x0032: "ControlNet Physical Layer Component",
    0x0033: "Circuit Breaker",
    0x0034: "HART Device",
    0x0035: "CIP-HART Translator",
    0x00C8: "Embedded Component",
}

_interfaceList = {
    0x00: "CIP"
}


class ItemData(Packet):
    """Common Packet Format"""
    name = "Item Data"
    fields_desc = [
        LEShortEnumField("typeId", 0, _typeIdList),
        LEShortField("length", 0),
        XLEStrLenField("data", "", length_from=lambda pkt: pkt.length),
    ]

    def extract_padding(self, s):
        return '', s


# Unknown command (0x0001)


class ENIPUnknownCommand(Packet):
    """Unknown Command reply"""
    name = "ENIPUnknownCommand"
    pass


# List services (0x0004)


class ENIPListServicesItem(Packet):
    """List Services Item Field"""
    name = "ENIPListServicesItem"
    fields_desc = [
        LEShortEnumField("itemTypeCode", 0, _typeIdList),
        LEFieldLenField("itemLength", 0),
        LEShortField("protocolVersion", 0),
        XLEShortField("flag", 0),  # TODO: detail with BitFields
        StrFixedLenField("serviceName", None, 16),
    ]


class ENIPListServices(Packet):
    """List Services Command Field"""
    name = "ENIPListServices"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="items"),
        PacketListField("items", None, ENIPListServicesItem),
    ]


# List identity (0x0063)


class ENIPListIdentityItem(Packet):
    """List Identity Item Fields"""
    name = "ENIPListIdentityReplyItem"
    fields_desc = [
        LEShortEnumField("itemTypeCode", 0, _typeIdList),
        LEFieldLenField("itemLength", 0),
        LEShortField("protocolVersion", 0),
        # Socket address
        ShortField("sinFamily", 0),
        ShortField("sinPort", 0),
        IPField("sinAddress", None),
        LongField("sinZero", 0),
        # End socket address
        LEShortField("vendorId", 0),  # Vendor list could be added (long list)
        LEShortEnumField("deviceType", 0, _deviceTypeList),
        LEShortField("productCode", 0),
        ByteField("revisionMajor", 0),
        ByteField("revisionMinor", 0),
        LEShortField("status", 0),
        XLEIntField("serialNumber", 0),
        ByteField("productNameLength", 0),
        StrLenField("productName", None,
                    length_from=lambda pkt: pkt.productNameLength),
        ByteField("state", 0)
    ]


class ENIPListIdentity(Packet):
    """List identity request and response"""
    name = "ENIPListIdentity"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="items"),
        PacketListField("items", None, ENIPListIdentityItem)
    ]


# List Interfaces (0x0064)


class ENIPListInterfacesItem(Packet):
    """List Interfaces Item Fields"""
    name = "ENIPListInterfacesItem"
    fields_desc = [
        LEShortEnumField("itemTypeCode", 0, _typeIdList),
        FieldLenField("itemLength", 0, length_of="itemData"),
        # TODO: Could be detailed
        StrLenField("itemData", "", length_from=lambda pkt: pkt.itemLength),
    ]


class ENIPListInterfaces(Packet):
    """List Interfaces Command Field"""
    name = "ENIPListInterfaces"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="items"),
        PacketListField("items", None, ENIPListInterfacesItem),
    ]


# Register Session (0x0065)


class ENIPRegisterSession(Packet):
    """Register Session Command Field"""
    name = "ENIPRegisterSession"
    fields_desc = [
        LEShortField("protocolVersion", 1),
        LEShortField("options", 0)
    ]


# Unregister Session (0x0066) -- Requires further testing


class ENIPUnregisterSession(Packet):
    """Unregister Session Command Field"""
    name = "ENIPUnregisterSession"
    pass


# Send RR Data (0x006f)


class ENIPSendRRData(Packet):
    """Send RR Data Command Field"""
    name = "ENIPSendRRData"
    fields_desc = [
        LEIntEnumField("interface", 0, _interfaceList),
        LEShortField("timeout", 0xff),
        LEFieldLenField("itemCount", 0, count_of="items"),
        PacketListField("items", None, ItemData)
        # TODO: Send RR Data is usually followed by a CIP packet
    ]


# Send Unit Data (0x006f)


class ENIPSendUnitData(Packet):
    """Send Unit Data Command Field"""
    name = "ENIPSendUnitData"
    fields_desc = [
        LEIntEnumField("interface", 0, _interfaceList),
        LEShortField("timeout", 0xff),
        LEFieldLenField("itemCount", 0, count_of="items"),
        PacketListField("items", None, ItemData)
    ]


# Main Ethernet/IP packet structure with header


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
    ]

    def post_build(self, pkt, pay):
        if self.length is None and pay:
            pkt = pkt[:2] + struct.pack("<H", len(pay)) + pkt[4:]
        return pkt + pay


bind_layers(TCP, ENIPTCP, dport=44818)
bind_layers(TCP, ENIPTCP, sport=44818)

bind_layers(ENIPTCP, ENIPUnknownCommand, commandId=0x0001)
bind_layers(ENIPTCP, ENIPListServices, commandId=0x0004)
bind_layers(ENIPTCP, ENIPListIdentity, commandId=0x0063)
bind_layers(ENIPTCP, ENIPListInterfaces, commandId=0x0064)
bind_layers(ENIPTCP, ENIPRegisterSession, commandId=0x0065)
bind_layers(ENIPTCP, ENIPUnregisterSession, commandId=0x0066)
bind_layers(ENIPTCP, ENIPSendRRData, commandId=0x006f)
bind_layers(ENIPTCP, ENIPSendUnitData, commandId=0x0070)
