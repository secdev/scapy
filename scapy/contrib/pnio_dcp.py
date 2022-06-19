# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2019 Stefan Mehner (stefan.mehner@b-tu.de)

# scapy.contrib.description = Profinet DCP layer
# scapy.contrib.status = loads

from scapy.compat import orb
from scapy.all import Packet, bind_layers, Padding
from scapy.fields import (
    ByteEnumField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    IPField,
    LenField,
    MACField,
    MultiEnumField,
    MultipleTypeField,
    PacketListField,
    PadField,
    ShortEnumField,
    ShortField,
    StrLenField,
    XByteField,
    XIntField,
    XShortField,
)

# minimum packet is 60 bytes.. 14 bytes are Ether()
MIN_PACKET_LENGTH = 44

#####################################################
#                     Constants                     #
#####################################################

DCP_GET_SET_FRAME_ID = 0xFEFD
DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF

DCP_REQUEST = 0x00
DCP_RESPONSE = 0x01

DCP_SERVICE_ID_GET = 0x03
DCP_SERVICE_ID_SET = 0x04
DCP_SERVICE_ID_IDENTIFY = 0x05

DCP_SERVICE_ID = {
    0x00: "reserved",
    0x01: "Manufacturer specific",
    0x02: "Manufacturer specific",
    0x03: "Get",
    0x04: "Set",
    0x05: "Identify",
    0x06: "Hello",
}

DCP_SERVICE_TYPE = {
    0x00: "Request",
    0x01: "Response Success",
    0x05: "Response - Request not supported",
}

DCP_DEVICE_ROLES = {
    0x00: "IO Supervisor",
    0x01: "IO Device",
    0x02: "IO Controller",

}

DCP_OPTIONS = {
    0x00: "reserved",
    0x01: "IP",
    0x02: "Device properties",
    0x03: "DHCP",
    0x04: "Reserved",
    0x05: "Control",
    0x06: "Device Initiative",
    0xff: "All Selector"
}
DCP_OPTIONS.update({i: "reserved" for i in range(0x07, 0x7f)})
DCP_OPTIONS.update({i: "Manufacturer specific" for i in range(0x80, 0xfe)})

DCP_SUBOPTIONS = {
    # ip
    0x01: {
        0x00: "Reserved",
        0x01: "MAC Address",
        0x02: "IP Parameter",
        0x03: "Full IP Suite",
    },
    # device properties
    0x02: {
        0x00: "Reserved",
        0x01: "Manufacturer specific (Type of Station)",
        0x02: "Name of Station",
        0x03: "Device ID",
        0x04: "Device Role",
        0x05: "Device Options",
        0x06: "Alias Name",
        0x07: "Device Instance",
        0x08: "OEM Device ID",
    },
    # dhcp
    0x03: {
        0x0c: "Host name",
        0x2b: "Vendor specific",
        0x36: "Server identifier",
        0x37: "Parameter request list",
        0x3c: "Class identifier",
        0x3d: "DHCP client identifier",
        0x51: "FQDN, Fully Qualified Domain Name",
        0x61: "UUID/GUID-based Client",
        0xff: "Control DHCP for address resolution"
    },
    # control
    0x05: {
        0x00: "Reserved",
        0x01: "Start Transaction",
        0x02: "End Transaction",
        0x03: "Signal",
        0x04: "Response",
        0x05: "Reset Factory Settings",
        0x06: "Reset to Factory"
    },
    # device initiative
    0x06: {
        0x00: "Reserved",
        0x01: "Device Initiative"
    },
    0xff: {
        0xff: "ALL Selector"
    }
}

BLOCK_INFOS = {
    0x00: "Reserved",
}
BLOCK_INFOS.update({i: "reserved" for i in range(0x01, 0xff)})


IP_BLOCK_INFOS = {
    0x0000: "IP not set",
    0x0001: "IP set",
    0x0002: "IP set by DHCP",
    0x0080: "IP not set (address conflict detected)",
    0x0081: "IP set (address conflict detected)",
    0x0082: "IP set by DHCP (address conflict detected)",
}
IP_BLOCK_INFOS.update({i: "reserved" for i in range(0x0003, 0x007f)})

BLOCK_ERRORS = {
    0x00: "Ok",
    0x01: "Option unsupp.",
    0x02: "Suboption unsupp. or no DataSet avail.",
    0x03: "Suboption not set",
    0x04: "Resource Error",
    0x05: "SET not possible by local reasons",
    0x06: "In operation, SET not possible",
}

BLOCK_QUALIFIERS = {
    0x0000: "Use the value temporary",
    0x0001: "Save the value permanent",
}
BLOCK_QUALIFIERS.update({i: "reserved" for i in range(0x0002, 0x00ff)})


#####################################################
#                     DCP Blocks                    #
#####################################################

# GENERIC DCP BLOCK

# DCP RESPONSE BLOCKS

class DCPBaseBlock(Packet):
    """
        base class for all DCP Blocks
    """
    fields_desc = [
        ByteEnumField("option", 1, DCP_OPTIONS),
        MultiEnumField("sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        FieldLenField("dcp_block_length", None, length_of="data"),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        StrLenField("data", "", length_from=lambda x: x.dcp_block_length),
    ]

    def extract_padding(self, s):
        return '', s


# OPTION: IP

class DCPIPBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 1, DCP_OPTIONS),
        MultiEnumField("sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None),
        ShortEnumField("block_info", 1, IP_BLOCK_INFOS),
        IPField("ip", "192.168.0.2"),
        IPField("netmask", "255.255.255.0"),
        IPField("gateway", "192.168.0.1"),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPFullIPBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 1, DCP_OPTIONS),
        MultiEnumField("sub_option", 3, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None),
        ShortEnumField("block_info", 1, IP_BLOCK_INFOS),
        IPField("ip", "192.168.0.2"),
        IPField("netmask", "255.255.255.0"),
        IPField("gateway", "192.168.0.1"),
        FieldListField("dnsaddr", [], IPField("", "0.0.0.0"),
                       count_from=lambda x: 4),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPMACBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 1, DCP_OPTIONS),
        MultiEnumField("sub_option", 1, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        FieldLenField("dcp_block_length", None),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        MACField("mac", "00:00:00:00:00:00"),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


# OPTION: Device Properties

class DCPManufacturerSpecificBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 1, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        FieldLenField("dcp_block_length", None),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        StrLenField("device_vendor_value", "et200sp",
                    length_from=lambda x: x.dcp_block_length - 2),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPNameOfStationBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        FieldLenField("dcp_block_length", None, length_of="name_of_station",
                      adjust=lambda p, x: x + 2),

        ShortEnumField("block_info", 0, BLOCK_INFOS),
        StrLenField("name_of_station", "et200sp",
                    length_from=lambda x: x.dcp_block_length - 2),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPDeviceIDBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 3, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        XShortField("vendor_id", 0x002a),
        XShortField("device_id", 0x0313),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPDeviceRoleBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 4, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", 4),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        ByteEnumField("device_role_details", 1, DCP_DEVICE_ROLES),
        XByteField("reserved", 0x00),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


# one DeviceOptionsBlock can contain 1..n different options
class DeviceOption(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 5, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
    ]

    def extract_padding(self, s):
        return '', s


class DCPDeviceOptionsBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 5, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None),
        ShortEnumField("block_info", 0, BLOCK_INFOS),

        PacketListField("device_options", [], DeviceOption,
                        length_from=lambda p: p.dcp_block_length - 2),

        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPAliasNameBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 6, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        FieldLenField("dcp_block_length", None, length_of="alias_name",
                      adjust=lambda p, x: x + 2),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        StrLenField("alias_name", "et200sp",
                    length_from=lambda x: x.dcp_block_length - 2),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPDeviceInstanceBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 7, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", 4),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        XByteField("device_instance_high", 0x00),
        XByteField("device_instance_low", 0x01),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPOEMIDBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 2, DCP_OPTIONS),
        MultiEnumField("sub_option", 8, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", None),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        XShortField("vendor_id", 0x002a),
        XShortField("device_id", 0x0313),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPControlBlock(Packet):
    fields_desc = [
        ByteEnumField("option", 5, DCP_OPTIONS),
        MultiEnumField("sub_option", 4, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        LenField("dcp_block_length", 3),
        ByteEnumField("response", 2, DCP_OPTIONS),
        MultiEnumField("response_sub_option", 2, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        ByteEnumField("block_error", 0, BLOCK_ERRORS),
        PadField(StrLenField("padding", b"\x00",
                             length_from=lambda p: p.dcp_block_length % 2), 1,
                 padwith=b"\x00")
    ]

    def extract_padding(self, s):
        return '', s


class DCPDeviceInitiativeBlock(Packet):
    """
        device initiative DCP block
    """
    fields_desc = [
        ByteEnumField("option", 6, DCP_OPTIONS),
        MultiEnumField("sub_option", 1, DCP_SUBOPTIONS, fmt='B',
                       depends_on=lambda p: p.option),
        FieldLenField("dcp_block_length", None, length_of="device_initiative"),
        ShortEnumField("block_info", 0, BLOCK_INFOS),
        ShortField("device_initiative", 1),
    ]

    def extract_padding(self, s):
        return '', s


def guess_dcp_block_class(packet, **kargs):
    """
    returns the correct dcp block class needed to dissect the current tag
    if nothing can be found -> dcp base block will be used

    :param packet: the current packet
    :return: dcp block class
    """
    # packet = unicode(packet, "utf-8")
    option = orb(packet[0])
    suboption = orb(packet[1])

    # NOTE implement the other functions if needed

    class_switch_case = {
        # IP
        0x01:
            {
                0x01: "DCPMACBlock",
                0x02: "DCPIPBlock"
            },
        # Device Properties
        0x02:
            {
                0x01: "DCPManufacturerSpecificBlock",
                0x02: "DCPNameOfStationBlock",
                0x03: "DCPDeviceIDBlock",
                0x04: "DCPDeviceRoleBlock",
                0x05: "DCPDeviceOptionsBlock",
                0x06: "DCPAliasNameBlock",
                0x07: "DCPDeviceInstanceBlock",
                0x08: "DCPOEMIDBlock"
            },
        # DHCP
        0x03:
            {
                0x0c: "Host name",
                0x2b: "Vendor specific",
                0x36: "Server identifier",
                0x37: "Parameter request list",
                0x3c: "Class identifier",
                0x3d: "DHCP client identifier",
                0x51: "FQDN, Fully Qualified Domain Name",
                0x61: "UUID/GUID-based Client",
                0xff: "Control DHCP for address resolution"
            },
        # Control
        0x05:
            {
                0x00: "Reserved (0x00)",
                0x01: "Start Transaction (0x01)",
                0x02: "End Transaction (0x02)",
                0x03: "Signal (0x03)",
                0x04: "DCPControlBlock",
                0x05: "Reset Factory Settings (0x05)",
                0x06: "Reset to Factory (0x06)"
            },
        # Device Inactive
        0x06:
            {
                0x00: "Reserved (0x00)",
                0x01: "DCPDeviceInitiativeBlock"
            },
        # ALL Selector
        0xff:
            {
                0xff: "ALL Selector (0xff)"
            }
    }

    try:
        c = class_switch_case[option][suboption]
    except KeyError:
        c = "DCPBaseBlock"

    cls = globals()[c]
    return cls(packet, **kargs)


# GENERIC DCP PACKET

class ProfinetDCP(Packet):
    """
    Profinet DCP Packet

    Requests are handled via ConditionalField because here only 1 Block is used
    every time.

    Response can contain 1..n Blocks, for that you have to use one ProfinetDCP
    Layer with one or multiple DCP*Block Layers::

        ProfinetDCP / DCPNameOfStationBlock / DCPDeviceIDBlock ...

    Example for a DCP Identify All Request::

        Ether(dst="01:0e:cf:00:00:00") /
        ProfinetIO(frameID=DCP_IDENTIFY_REQUEST_FRAME_ID) /
        ProfinetDCP(service_id=DCP_SERVICE_ID_IDENTIFY,
            service_type=DCP_REQUEST, option=255, sub_option=255,
            dcp_data_length=4)

    Example for a DCP Identify Response::

        Ether(dst=dst_mac) /
        ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID) /
        ProfinetDCP(
            service_id=DCP_SERVICE_ID_IDENTIFY,
            service_type=DCP_RESPONSE) /
        DCPNameOfStationBlock(name_of_station="device1")

    Example for a DCP Set Request::

        Ether(dst=mac) /
        ProfinetIO(frameID=DCP_GET_SET_FRAME_ID) /
        ProfinetDCP(service_id=DCP_SERVICE_ID_SET, service_type=DCP_REQUEST,
            option=2, sub_option=2, dcp_data_length=14, dcp_block_length=10,
            name_of_station=name, reserved=0)

    """

    name = "Profinet DCP"
    # a DCP PDU consists of some fields and 1..n DCP Blocks
    fields_desc = [
        ByteEnumField("service_id", 5, DCP_SERVICE_ID),
        ByteEnumField("service_type", 0, DCP_SERVICE_TYPE),
        XIntField("xid", 0x01000001),
        # XShortField('reserved', 0),

        ShortField('reserved', 0),
        LenField("dcp_data_length", None),

        # DCP REQUEST specific
        ConditionalField(ByteEnumField("option", 2, DCP_OPTIONS),
                         lambda pkt: pkt.service_type == 0),
        ConditionalField(
            MultiEnumField("sub_option", 3, DCP_SUBOPTIONS, fmt='B',
                           depends_on=lambda p: p.option),
            lambda pkt: pkt.service_type == 0),

        # calculate the len fields - workaround
        ConditionalField(LenField("dcp_block_length", 0),
                         lambda pkt: pkt.service_type == 0),

        # DCP SET REQUEST #
        ConditionalField(ShortEnumField("block_qualifier", 1,
                                        BLOCK_QUALIFIERS),
                         lambda pkt: pkt.service_id == 4 and
                         pkt.service_type == 0),
        # (Common) Name Of Station
        ConditionalField(
            MultipleTypeField(
                [
                    (StrLenField("name_of_station", "et200sp",
                                 length_from=lambda x: x.dcp_block_length - 2),
                     lambda pkt: pkt.service_id == 4),
                ],
                StrLenField("name_of_station", "et200sp",
                            length_from=lambda x: x.dcp_block_length),
            ),
            lambda pkt: pkt.service_type == 0 and pkt.option == 2 and
            pkt.sub_option == 2
        ),
        # DCP SET REQUEST #
        # MAC
        ConditionalField(MACField("mac", "00:00:00:00:00:00"),
                         lambda pkt: pkt.service_id == 4 and
                         pkt.service_type == 0 and pkt.option == 1 and
                         pkt.sub_option == 1),
        # IP
        ConditionalField(IPField("ip", "192.168.0.2"),
                         lambda pkt: pkt.service_id == 4 and
                         pkt.service_type == 0 and pkt.option == 1 and
                         pkt.sub_option in [2, 3]),
        ConditionalField(IPField("netmask", "255.255.255.0"),
                         lambda pkt: pkt.service_id == 4 and
                         pkt.service_type == 0 and pkt.option == 1 and
                         pkt.sub_option in [2, 3]),
        ConditionalField(IPField("gateway", "192.168.0.1"),
                         lambda pkt: pkt.service_id == 4 and
                         pkt.service_type == 0 and pkt.option == 1 and
                         pkt.sub_option in [2, 3]),

        # Full IP
        ConditionalField(FieldListField("dnsaddr", [], IPField("", "0.0.0.0"),
                                        count_from=lambda x: 4),
                         lambda pkt: pkt.service_id == 4 and
                         pkt.service_type == 0 and pkt.option == 1 and
                         pkt.sub_option == 3),

        # DCP IDENTIFY REQUEST #
        # Name of station (handled above)

        # Alias name
        ConditionalField(StrLenField("alias_name", "et200sp",
                                     length_from=lambda x: x.dcp_block_length),
                         lambda pkt: pkt.service_id == 5 and
                         pkt.service_type == 0 and pkt.option == 2 and
                         pkt.sub_option == 6),

        # implement further REQUEST fields if needed ....

        # DCP RESPONSE BLOCKS #
        ConditionalField(
            PacketListField("dcp_blocks", [], guess_dcp_block_class,
                            length_from=lambda p: p.dcp_data_length),
            lambda pkt: pkt.service_type == 1),
    ]

    def post_build(self, pkt, pay):
        # add padding to ensure min packet length

        padding = MIN_PACKET_LENGTH - (len(pkt + pay))
        pay += b"\0" * padding

        return Packet.post_build(self, pkt, pay)


bind_layers(ProfinetDCP, Padding)
