#! /usr/bin/env python

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = HomePlugAV Layer
# scapy.contrib.status = loads

from __future__ import absolute_import
import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteEnumField, ByteField, \
    ConditionalField, EnumField, FieldLenField, IntField, LEIntField, \
    LELongField, LEShortField, MACField, PacketListField, ShortField, \
    StrFixedLenField, StrLenField, X3BytesField, XByteField, XIntField, \
    XLongField, XShortField
from scapy.layers.l2 import Ether
from scapy.modules.six.moves import range

"""
    Copyright (C) HomePlugAV Layer for Scapy by FlUxIuS (Sebastien Dudek)
"""

"""
    HomePlugAV Management Message Type
    Key (type value) : Description
"""
HPAVTypeList = {0xA000: "'Get Device/sw version Request'",
                0xA001: "'Get Device/sw version Confirmation'",
                0xA008: "'Read MAC Memory Request'",
                0xA009: "'Read MAC Memory Confirmation'",
                0xA00C: "'Start MAC Request'",
                0xA00D: "'Start MAC Confirmation'",
                0xA010: "'Get NVM Parameters Request'",
                0xA011: "'Get NVM Parameters Confirmation'",
                0xA01C: "'Reset Device Request'",
                0xA01D: "'Reset Device Confirmation'",
                0xA020: "'Write Module Data Request'",
                0xA024: "'Read Module Data Request'",
                0xA025: "'Read Module Data Confirmation'",
                0xA028: "'Write Module Data to NVM Request'",
                0xA029: "'Write Module Data to NVM Confirmation'",
                0xA034: "'Sniffer Request'",
                0xA035: "'Sniffer Confirmation'",
                0xA036: "'Sniffer Indicates'",
                0xA038: "'Network Information Request'",
                0xA039: "'Network Information Confirmation'",
                0xA048: "'Loopback Request'",
                0xA049: "'Loopback Request Confirmation'",
                0xA050: "'Set Encryption Key Request'",
                0xA051: "'Set Encryption Key Request Confirmation'",
                0xA058: "'Read Configuration Block Request'",
                0xA059: "'Read Configuration Block Confirmation'",
                0xA062: "'Embedded Host Action Required Indication'"}

HPAVversionList = {0x00: "1.0",
                   0x01: "1.1"}

HPAVDeviceIDList = {0x00: "Unknown",
                    0x01: "'INT6000'",
                    0x02: "'INT6300'",
                    0x03: "'INT6400'",
                    0x04: "'AR7400'",
                    0x05: "'AR6405'",
                    0x20: "'QCA7450/QCA7420'",
                    0x21: "'QCA6410/QCA6411'",
                    0x22: "'QCA7000'"}

StationRole = {0x00: "'Station'",
               0x01: "'Proxy coordinator'",
               0x02: "'Central coordinator'"}

StatusCodes = {0x00: "'Success'",
               0x10: "'Invalid Address'",
               0x14: "'Invalid Length'"}

DefaultVendor = "Qualcomm"

#########################################################################
# Qualcomm Vendor Specific Management Message Types;                    #
# from https://github.com/qca/open-plc-utils/blob/master/mme/qualcomm.h #
#########################################################################
# Commented commands are already in HPAVTypeList, the other have to be implemted  # noqa: E501
QualcommTypeList = {  # 0xA000 : "VS_SW_VER",
    0xA004: "VS_WR_MEM",
    # 0xA008 : "VS_RD_MEM",
    # 0xA00C : "VS_ST_MAC",
    # 0xA010 : "VS_GET_NVM",
    0xA014: "VS_RSVD_1",
    0xA018: "VS_RSVD_2",
    # 0xA01C : "VS_RS_DEV",
    # 0xA020 : "VS_WR_MOD",
    # 0xA024 : "VS_RD_MOD",
    # 0xA028 : "VS_MOD_NVM",
    0xA02C: "VS_WD_RPT",
    0xA030: "VS_LNK_STATS",
    # 0xA034 : "VS_SNIFFER",
    # 0xA038 : "VS_NW_INFO",
    0xA03C: "VS_RSVD_3",
    0xA040: "VS_CP_RPT",
    0xA044: "VS_ARPC",
    # 0xA050 : "VS_SET_KEY",
    0xA054: "VS_MFG_STRING",
    # 0xA058 : "VS_RD_CBLOCK",
    0xA05C: "VS_SET_SDRAM",
    0xA060: "VS_HOST_ACTION",
    0xA068: "VS_OP_ATTRIBUTES",
    0xA06C: "VS_ENET_SETTINGS",
    0xA070: "VS_TONE_MAP_CHAR",
    0xA074: "VS_NW_INFO_STATS",
    0xA078: "VS_SLAVE_MEM",
    0xA07C: "VS_FAC_DEFAULTS",
    0xA07D: "VS_FAC_DEFAULTS_CONFIRM",
    0xA084: "VS_MULTICAST_INFO",
    0xA088: "VS_CLASSIFICATION",
    0xA090: "VS_RX_TONE_MAP_CHAR",
    0xA094: "VS_SET_LED_BEHAVIOR",
    0xA098: "VS_WRITE_AND_EXECUTE_APPLET",
    0xA09C: "VS_MDIO_COMMAND",
    0xA0A0: "VS_SLAVE_REG",
    0xA0A4: "VS_BANDWIDTH_LIMITING",
    0xA0A8: "VS_SNID_OPERATION",
    0xA0AC: "VS_NN_MITIGATE",
    0xA0B0: "VS_MODULE_OPERATION",
    0xA0B4: "VS_DIAG_NETWORK_PROBE",
    0xA0B8: "VS_PL_LINK_STATUS",
    0xA0BC: "VS_GPIO_STATE_CHANGE",
    0xA0C0: "VS_CONN_ADD",
    0xA0C4: "VS_CONN_MOD",
    0xA0C8: "VS_CONN_REL",
    0xA0CC: "VS_CONN_INFO",
    0xA0D0: "VS_MULTIPORT_LNK_STA",
    0xA0DC: "VS_EM_ID_TABLE",
    0xA0E0: "VS_STANDBY",
    0xA0E4: "VS_SLEEPSCHEDULE",
    0xA0E8: "VS_SLEEPSCHEDULE_NOTIFICATION",
    0xA0F0: "VS_MICROCONTROLLER_DIAG",
    0xA0F8: "VS_GET_PROPERTY",
    0xA100: "VS_SET_PROPERTY",
    0xA104: "VS_PHYSWITCH_MDIO",
    0xA10C: "VS_SELFTEST_ONETIME_CONFIG",
    0xA110: "VS_SELFTEST_RESULTS",
    0xA114: "VS_MDU_TRAFFIC_STATS",
    0xA118: "VS_FORWARD_CONFIG",
    0xA200: "VS_HYBRID_INFO"}
#          END OF Qualcomm commands                          #

EofPadList = [0xA000, 0xA038]  # TODO: The complete list of Padding can help to improve the condition in VendorMME Class  # noqa: E501


def FragmentCond(pkt):
    """
        A fragmentation field condition
        TODO: To complete
    """
    fragTypeTable = [0xA038, 0xA039]
    return ((pkt.version == 0x01) and (pkt.HPtype in fragTypeTable))


class MACManagementHeader(Packet):
    name = "MACManagementHeader "
    if DefaultVendor == "Qualcomm":
        HPAVTypeList.update(QualcommTypeList)
    fields_desc = [ByteEnumField("version", 0, HPAVversionList),
                   EnumField("HPtype", 0xA000, HPAVTypeList, "<H")]


class VendorMME(Packet):
    name = "VendorMME "
    fields_desc = [X3BytesField("OUI", 0x00b052)]


class GetDeviceVersion(Packet):
    name = "GetDeviceVersion"
    fields_desc = [ByteEnumField("Status", 0x0, StatusCodes),
                   ByteEnumField("DeviceID", 0x20, HPAVDeviceIDList),
                   FieldLenField("VersionLen", None, count_of="DeviceVersion", fmt="B"),  # noqa: E501
                   StrLenField("DeviceVersion", b"NoVersion\x00", length_from=lambda pkt: pkt.VersionLen),  # noqa: E501
                   StrLenField("DeviceVersion_pad", b"\xcc\xcc\xcc\xcc\xcc" + b"\x00" * 59, length_from=lambda pkt: 64 - pkt.VersionLen),  # noqa: E501
                   ByteEnumField("Upgradable", 0, {0: "False", 1: "True"})]


class NetworkInformationRequest(Packet):
    name = "NetworkInformationRequest"
    fields_desc = []

###############################################################################
#   Networks & Stations information for MAC Management V1.0
###############################################################################


class NetworkInfoV10(Packet):
    """
        Network Information Element
    """
    name = "NetworkInfo"
    fields_desc = [StrFixedLenField("NetworkID", b"\x00\x00\x00\x00\x00\x00\x00", 7),  # noqa: E501
                   XByteField("ShortNetworkID", 0x00),
                   XByteField("TerminalEID", 0x01),
                   ByteEnumField("StationRole", 0x00, StationRole),
                   MACField("CCoMACAdress", "00:00:00:00:00:00"),
                   XByteField("CCoTerminalEID", 0x01)]

    def extract_padding(self, p):
        return b"", p


class StationInfoV10(Packet):
    """
        Station Information Element
    """
    name = "StationInfo"
    fields_desc = [MACField("StationMAC", "00:00:00:00:00:00"),
                   XByteField("StationTerminalEID", 0x01),
                   MACField("firstnodeMAC", "ff:ff:ff:ff:ff:ff"),
                   XByteField("TXaverage", 0x00),
                   XByteField("RXaverage", 0x00)]

    def extract_padding(self, p):
        return b"", p

###############################################################################
#   Networks & Stations information for MAC Management V1.1
###############################################################################


class NetworkInfoV11(Packet):
    """
        Network Information Element
    """
    name = "NetworkInfo"
    fields_desc = [StrFixedLenField("NetworkID", b"\x00\x00\x00\x00\x00\x00\x00", 7),  # noqa: E501
                   ShortField("reserved_1", 0x0000),
                   XByteField("ShortNetworkID", 0x00),
                   XByteField("TerminalEID", 0x01),
                   IntField("reserved_2", 0x00000000),
                   ByteEnumField("StationRole", 0x00, StationRole),
                   MACField("CCoMACAdress", "00:00:00:00:00:00"),
                   XByteField("CCoTerminalEID", 0x01),
                   X3BytesField("reserved_3", 0x000000)]

    def extract_padding(self, p):
        return b"", p


class StationInfoV11(Packet):
    """
        Station Information Element
    """
    name = "StationInfo"
    fields_desc = [MACField("StationMAC", "00:00:00:00:00:00"),
                   XByteField("StationTerminalEID", 0x01),
                   X3BytesField("reserved_s2", 0x000000),
                   MACField("firstnodeMAC", "ff:ff:ff:ff:ff:ff"),
                   LEShortField("TXaverage", 0x0000),
                   BitField("RxCoupling", 0, 4),
                   BitField("TxCoupling", 0, 4),
                   XByteField("reserved_s3", 0x00),
                   LEShortField("RXaverage", 0x0000),
                   XByteField("reserved_s4", 0x00)]

    def extract_padding(self, p):
        return b"", p

#                          END                                                          #  # noqa: E501


class NetworkInfoConfirmationV10(Packet):
    """
        Network Information Confirmation following the MAC Management version 1.0  # noqa: E501
    """
    name = "NetworkInfoConfirmation"
    fields_desc = [XByteField("LogicalNetworksNumber", 0x01),
                   PacketListField("NetworksInfos", "", NetworkInfoV10, length_from=lambda pkt: pkt.LogicalNetworksNumber * 17),  # noqa: E501
                   XByteField("StationsNumber", 0x01),
                   PacketListField("StationsInfos", "", StationInfoV10, length_from=lambda pkt: pkt.StationsNumber * 21)]  # noqa: E501


class NetworkInfoConfirmationV11(Packet):
    """
        Network Information Confirmation following the MAC Management version 1.1  # noqa: E501
        This introduce few 'crazy' reserved bytes -> have fun!
    """
    name = "NetworkInfoConfirmation"
    fields_desc = [StrFixedLenField("reserved_n1", b"\x00\x00\x3a\x00\x00", 5),
                   XByteField("LogicalNetworksNumber", 0x01),
                   PacketListField("NetworksInfos", "", NetworkInfoV11, length_from=lambda pkt: pkt.LogicalNetworksNumber * 26),  # noqa: E501
                   XByteField("StationsNumber", 0x01),
                   StrFixedLenField("reserverd_s1", b"\x00\x00\x00\x00\x00", 5),  # noqa: E501
                   PacketListField("StationsInfos", "", StationInfoV11, length_from=lambda pkt: pkt.StationsNumber * 23)]  # noqa: E501


# Description of Embedded Host Action Required Indice
ActionsList = {0x02: "'PIB Update Ready'",
               0x04: "'Loader (Bootloader)'"}


class HostActionRequired(Packet):
    """
        Embedded Host Action Required Indice
    """
    name = "HostActionRequired"
    fields_desc = [ByteEnumField("ActionRequired", 0x02, ActionsList)]


class LoopbackRequest(Packet):
    name = "LoopbackRequest"
    fields_desc = [ByteField("Duration", 0x01),
                   ByteField("reserved_l1", 0x01),
                   ShortField("LRlength", 0x0000)]
    # TODO: Test all possibles data to complete it


class LoopbackConfirmation(Packet):
    name = "LoopbackConfirmation"
    fields_desc = [ByteEnumField("Status", 0x0, StatusCodes),
                   ByteField("Duration", 0x01),
                   ShortField("LRlength", 0x0000)]

################################################################
# Encryption Key Packets
################################################################


class SetEncryptionKeyRequest(Packet):
    name = "SetEncryptionKeyRequest"
    fields_desc = [XByteField("EKS", 0x00),
                   StrFixedLenField("NMK",
                                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # noqa: E501
                                    16),
                   XByteField("PayloadEncKeySelect", 0x00),
                   MACField("DestinationMAC", "ff:ff:ff:ff:ff:ff"),
                   StrFixedLenField("DAK",
                                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # noqa: E501
                                    16)]


SetEncKey_Status = {0x00: "Success",
                    0x10: "Invalid EKS",
                    0x11: "Invalid PKS"}


class SetEncryptionKeyConfirmation(Packet):
    name = "SetEncryptionKeyConfirmation"
    fields_desc = [ByteEnumField("Status", 0x0, SetEncKey_Status)]

################################################################
# Default config Packet
################################################################


class QUAResetFactoryConfirm(Packet):
    name = "QUAResetFactoryConfirm"
    fields_desc = [ByteEnumField("Status", 0x0, StatusCodes)]  # TODO : Probably a Status bytefield?  # noqa: E501

######################################################################
# NVM Parameters Packets
######################################################################


class GetNVMParametersRequest(Packet):
    name = "Get NVM Parameters Request"
    fields_desc = []


class GetNVMParametersConfirmation(Packet):
    name = "Get NVM Parameters Confirmation"
    fields_desc = [ByteEnumField("Status", 0x0, StatusCodes),
                   LEIntField("NVMType", 0x00000013),
                   LEIntField("NVMPageSize", 0x00000100),
                   LEIntField("NVMBlockSize", 0x00010000),
                   LEIntField("NVMMemorySize", 0x00100000)]

######################################################################
# Sniffer Packets
######################################################################


SnifferControlList = {0x0: "'Disabled'",
                      0x1: "'Enabled'"}

SnifferTypeCodes = {0x00: "'Regular'"}


class SnifferRequest(Packet):
    name = "SnifferRequest"
    fields_desc = [ByteEnumField("SnifferControl", 0x0, SnifferControlList)]


SnifferCodes = {0x00: "'Success'",
                0x10: "'Invalid Control'"}


class SnifferConfirmation(Packet):
    name = "SnifferConfirmation"
    fields_desc = [ByteEnumField("Status", 0x0, StatusCodes)]


DirectionCodes = {0x00: "'Tx'",
                  0x01: "'Rx'"}

ANCodes = {0x00: "'In-home'",
           0x01: "'Access'"}


class SnifferIndicate(Packet):
    # TODO: Some bitfield have been regrouped for the moment => need more work on it  # noqa: E501
    name = "SnifferIndicate"
    fields_desc = [ByteEnumField("SnifferType", 0x0, SnifferTypeCodes),
                   ByteEnumField("Direction", 0x0, DirectionCodes),
                   LELongField("SystemTime", 0x0),
                   LEIntField("BeaconTime", 0x0),
                   XByteField("ShortNetworkID", 0x0),
                   ByteField("SourceTermEqID", 0),
                   ByteField("DestTermEqID", 0),
                   ByteField("LinkID", 0),
                   XByteField("PayloadEncrKeySelect", 0x0f),
                   ByteField("PendingPHYblock", 0),
                   ByteField("BitLoadingEstim", 0),
                   BitField("ToneMapIndex", 0, size=5),
                   BitField("NumberofSymbols", 0, size=2),
                   BitField("PHYblockSize", 0, size=1),
                   XShortField("FrameLength", 0x0000),
                   XByteField("ReversegrandLength", 0x0),
                   BitField("RequestSACKtrans", 0, size=1),
                   BitField("DataMACstreamCMD", 0, size=3),
                   BitField("ManNACFrameStreamCMD", 0, size=3),
                   BitField("reserved_1", 0, size=6),
                   BitField("MultinetBroadcast", 0, size=1),
                   BitField("DifferentCPPHYclock", 0, size=1),
                   BitField("Multicast", 0, size=1),
                   X3BytesField("FrameControlCheckSeq", 0x000000),
                   XByteField("ShortNetworkID_", 0x0),
                   IntField("BeaconTimestamp", 0),
                   XShortField("BeaconTransOffset_0", 0x0000),
                   XShortField("BeaconTransOffset_1", 0x0000),
                   XShortField("BeaconTransOffset_2", 0x0000),
                   XShortField("BeaconTransOffset_3", 0x0000),
                   X3BytesField("FrameContrchkSeq", 0x000000)]

######################################################################
# Read MAC Memory
#####################################################################


class ReadMACMemoryRequest(Packet):
    name = "ReadMACMemoryRequest"
    fields_desc = [LEIntField("Address", 0x00000000),
                   LEIntField("Length", 0x00000400),
                   ]


ReadMACStatus = {0x00: "Success",
                 0x10: "Invalid Address",
                 0x14: "Invalid Length"}


class ReadMACMemoryConfirmation(Packet):
    name = "ReadMACMemoryConfirmation"

    fields_desc = [ByteEnumField("Status", 0x00, ReadMACStatus),
                   LEIntField("Address", 0),
                   FieldLenField("MACLen", None, length_of="MACData", fmt="<H"),  # noqa: E501
                   StrLenField("MACData", b"\x00", length_from=lambda pkt: pkt.MACLen),  # noqa: E501
                   ]

######################################################################
# Read Module Datas
######################################################################


ModuleIDList = {0x00: "MAC Soft-Loader Image",
                0x01: "MAC Software Image",
                0x02: "PIB",
                0x10: "Write Alternate Flash Location"}


def chksum32(data):
    cksum = 0
    for i in range(0, len(data), 4):
        cksum = (cksum ^ struct.unpack('<I', data[i:i + 4])[0]) & 0xffffffff
    return (~cksum) & 0xffffffff


class ReadModuleDataRequest(Packet):
    name = "ReadModuleDataRequest"
    fields_desc = [ByteEnumField("ModuleID", 0x02, ModuleIDList),
                   XByteField("reserved", 0x00),
                   LEShortField("Length", 0x0400),
                   LEIntField("Offset", 0x00000000)]


class ReadModuleDataConfirmation(Packet):
    name = "ReadModuleDataConfirmation"
    fields_desc = [ByteEnumField("Status", 0x0, StatusCodes),
                   X3BytesField("reserved_1", 0x000000),
                   ByteEnumField("ModuleID", 0x02, ModuleIDList),
                   XByteField("reserved_2", 0x00),
                   FieldLenField("DataLen", None, count_of="ModuleData", fmt="<H"),  # noqa: E501
                   LEIntField("Offset", 0x00000000),
                   LEIntField("checksum", None),
                   StrLenField("ModuleData", b"\x00", length_from=lambda pkt: pkt.DataLen),  # noqa: E501
                   ]

    def post_build(self, p, pay):
        if self.DataLen is None:
            _len = len(self.ModuleData)
            p = p[:6] + struct.pack('h', _len) + p[8:]
        if self.checksum is None and p:
            ck = chksum32(self.ModuleData)
            p = p[:12] + struct.pack('I', ck) + p[16:]
        return p + pay

######################################################################
# Write Module Datas
######################################################################


class WriteModuleDataRequest(Packet):
    name = "WriteModuleDataRequest"
    fields_desc = [ByteEnumField("ModuleID", 0x02, ModuleIDList),
                   XByteField("reserved_1", 0x00),
                   FieldLenField("DataLen", None, count_of="ModuleData", fmt="<H"),  # noqa: E501
                   LEIntField("Offset", 0x00000000),
                   LEIntField("checksum", None),
                   StrLenField("ModuleData", b"\x00", length_from=lambda pkt: pkt.DataLen),  # noqa: E501
                   ]

    def post_build(self, p, pay):
        if self.DataLen is None:
            _len = len(self.ModuleData)
            p = p[:2] + struct.pack('h', _len) + p[4:]
        if self.checksum is None and p:
            ck = chksum32(self.ModuleData)
            p = p[:8] + struct.pack('I', ck) + p[12:]
        return p + pay

######################################
# Parse PIB                          #
######################################


class ClassifierPriorityMap(Packet):
    name = "ClassifierPriorityMap"
    fields_desc = [LEIntField("Priority", 0),
                   LEIntField("PID", 0),
                   LEIntField("IndividualOperand", 0),
                   StrFixedLenField("ClassifierValue",
                                    b"\x00" * 16,
                                    16),
                   ]

    def extract_padding(self, p):
        return b"", p


class ClassifierObj(Packet):
    name = "ClassifierObj"

    fields_desc = [LEIntField("ClassifierPID", 0),
                   LEIntField("IndividualOperand", 0),
                   StrFixedLenField("ClassifierValue",
                                    b"\x00" * 16,
                                    16),
                   ]

    def extract_padding(self, p):
        return b"", p


class AutoConnection(Packet):
    name = "AutoConnection"

    fields_desc = [XByteField("Action", 0x00),
                   XByteField("ClassificationOperand", 0x00),
                   XShortField("NumClassifiers", 0x0000),
                   PacketListField("ClassifierObjs", "", ClassifierObj, length_from=lambda x: 24),  # noqa: E501
                   XShortField("CSPECversion", 0x0000),
                   XByteField("ConnCAP", 0x00),
                   XByteField("ConnCoQoSPrio", 0x00),
                   ShortField("ConnRate", 0),
                   LEIntField("ConnTTL", 0),
                   ShortField("CSPECversion", 0),
                   StrFixedLenField("VlanTag",
                                    b"\x00" * 4,
                                    4),
                   XIntField("reserved_1", 0),
                   StrFixedLenField("reserved_2",
                                    b"\x00" * 14,
                                    14),
                   ]

    def extract_padding(self, p):
        return b"", p


class PeerNode(Packet):
    name = "PeerNodes"
    fields_desc = [XByteField("PeerTEI", 0x0),
                   MACField("PIBMACAddr", "00:00:00:00:00:00"),
                   ]

    def extract_padding(self, p):
        return b"", p


class AggregateConfigEntrie(Packet):
    name = "AggregateConfigEntrie"
    fields_desc = [XByteField("TrafficTypeID", 0x0),
                   XByteField("AggregationConfigID", 0x0),
                   ]

    def extract_padding(self, p):
        return b"", p


class RSVD_CustomAggregationParameter(Packet):
    name = "RSVD_CustomAggregationParameter"
    fields_desc = [XIntField("CustomAggregationParameter", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class PrescalerValue(Packet):
    name = "PrescalerValue"
    fields_desc = [XIntField("prescaler", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class GPIOMap(Packet):
    name = "GPIOMap"
    fields_desc = [XByteField("GPIOvalue", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class ReservedPercentageForCap(Packet):
    name = "ReservedPercentageForCap"
    fields_desc = [XByteField("CAPpercent", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class ConfigBit(Packet):
    name = "ConfigBit"
    fields_desc = [BitField("OverrideSoundCap", 0, 1),
                   BitField("OverrideFailHoldDefaults", 0, 1),
                   BitField("OverrideResourceDefaults", 0, 1),
                   BitField("OverrideContentionWindowDefaults", 0, 1),
                   BitField("OverrideUnplugDetectionDefaults", 0, 1),
                   BitField("OverrideResoundDefaults", 0, 1),
                   BitField("OverrideExpiryDefaults", 0, 1),
                   BitField("DisableWorseChannelTrigger", 0, 1),
                   BitField("DisableBetterChannelTrigger", 0, 1),
                   BitField("DisableNetworkEventTrigger", 0, 1),
                   BitField("rsv1", 0, 6),
                   ]


class ContentionWindowTable(Packet):
    name = "ContentionWindowTable"
    fields_desc = [XShortField("element", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class BackoffDeferalCountTable(Packet):
    name = "BackoffDeferalCountTable"
    fields_desc = [XByteField("element", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class BehaviorBlockArray(Packet):
    name = "BehaviorBlockArray"
    fields_desc = [XByteField("BehId", 0),
                   XByteField("NoOfSteps", 0),
                   XByteField("DurationInMs", 0),
                   XShortField("GPIOMaskBits_1", 0),
                   XShortField("GPIOMaskBits_2", 0),
                   XShortField("GPIOMaskBits_3", 0),
                   XShortField("GPIOMaskBits_4", 0),
                   XShortField("GPIOMaskBits_5", 0),
                   XShortField("GPIOMaskBits_6", 0),
                   XIntField("reserved_beh", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class EventBlockArray(Packet):
    name = "EventBlockArray"
    fields_desc = [XByteField("EventPriorityID", 0),
                   XByteField("EventID", 0),
                   XByteField("BehID_1", 0),
                   XByteField("BehID_2", 0),
                   XByteField("BehID_3", 0),
                   XShortField("ParticipatingGPIOs", 0),
                   XByteField("EventAttributes", 0),
                   XShortField("reserved_evb", 0),
                   ]

    def extract_padding(self, p):
        return b"", p


class ModulePIB(Packet):
    """
        Simple Module PIB Decoder.
            /!/ A wrong slice would produce 'bad' results
    """
    name = "ModulePIB"
    __slots__ = ["_ModulePIB__offset", "_ModulePIB__length"]
    fields_desc = [
        ConditionalField(XByteField("FirmwareMajorVersion", 0x00),
                         lambda pkt:(0x0 == pkt.__offset and 0x1 <= pkt.__offset + pkt.__length)),  # The following conditional fields just check if the current field fits in the data range  # noqa: E501
        ConditionalField(XByteField("PIBMinorVersion", 0x00),
                         lambda pkt:(0x1 >= pkt.__offset and 0x2 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("reserved_1", 0x0000),
                         lambda pkt:(0x2 >= pkt.__offset and 0x4 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("PIBLength", 0x0000),
                         lambda pkt:(0x4 >= pkt.__offset and 0x6 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("reserved_2", 0x0000),
                         lambda pkt:(0x6 >= pkt.__offset and 0x8 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("checksumPIB", None),
                         lambda pkt:(0x8 >= pkt.__offset and 0xC <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(MACField("PIBMACAddr", "00:00:00:00:00:00"),
                         lambda pkt:(0xC >= pkt.__offset and 0x12 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("DAK",
                                          b"\x00" * 16,
                                          16),
                         lambda pkt:(0x12 >= pkt.__offset and 0x22 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("reserved_3", 0x0000),
                         lambda pkt:(0x22 >= pkt.__offset and 0x24 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("ManufactorID",
                                          b"\x00" * 64,
                                          64),
                         lambda pkt:(0x24 >= pkt.__offset and 0x64 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("NMK",
                                          b"\x00" * 16,
                                          16),
                         lambda pkt:(0x64 >= pkt.__offset and 0x74 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("UserID",
                                          b"\x00" * 64,
                                          64),
                         lambda pkt:(0x74 >= pkt.__offset and 0xB4 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("AVLN_ID",
                                          b"\x00" * 64,
                                          64),
                         lambda pkt:(0xB4 >= pkt.__offset and 0xF4 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("CCoSelection", 0x00),
                         lambda pkt:(0xF4 >= pkt.__offset and 0xF5 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("CoExistSelection", 0x00),
                         lambda pkt:(0xF5 >= pkt.__offset and 0xF6 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PLFreqSelection", 0x00),
                         lambda pkt:(0xF6 >= pkt.__offset and 0xF7 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("H3CDowngradeShld", 0x00),
                         lambda pkt:(0xF7 >= pkt.__offset and 0xF8 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("PreferredNID",
                                          b"\x00" * 7,
                                          7),
                         lambda pkt:(0xF8 >= pkt.__offset and 0xFF <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("AutoFWUpgradeable", 0x00),
                         lambda pkt:(0xFF >= pkt.__offset and 0x100 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("MDUConfiguration", 0x00),
                         lambda pkt:(0x100 >= pkt.__offset and 0x101 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("MDURole", 0x00),
                         lambda pkt:(0x101 >= pkt.__offset and 0x102 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("SnifferEnabled", 0x00),
                         lambda pkt:(0x102 >= pkt.__offset and 0x103 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(MACField("SnifferMACAddrRetrn", "00:00:00:00:00:00"),
                         lambda pkt:(0x103 >= pkt.__offset and 0x109 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("WireTapEnable", 0x00),
                         lambda pkt:(0x109 >= pkt.__offset and 0x10A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("reserved_4", 0x0000),
                         lambda pkt:(0x10A >= pkt.__offset and 0x10C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("StaticNetworkEnabled", 0x00),
                         lambda pkt:(0x10C >= pkt.__offset and 0x10D <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("LD_TEI", 0x00),
                         lambda pkt:(0x10D >= pkt.__offset and 0x10E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(MACField("CCo_MACAdd", "00:00:00:00:00:00"),
                         lambda pkt:(0x10E >= pkt.__offset and 0x114 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("SNID", 0x00),
                         lambda pkt:(0x114 >= pkt.__offset and 0x115 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("NumOfPeerNodes", 0x00),
                         lambda pkt:(0x115 >= pkt.__offset and 0x116 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("PeerNodes", "", PeerNode, length_from=lambda x: 56),  # noqa: E501
                         lambda pkt:(0x116 >= pkt.__offset and 0x11C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_5",
                                          b"\x00" * 62,
                                          62),
                         lambda pkt:(0x146 >= pkt.__offset and 0x14e <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OverideModeDefaults", 0x00),
                         lambda pkt:(0x18C >= pkt.__offset and 0x18D <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("DisableFlowControl", 0x00),
                         lambda pkt:(0x18D >= pkt.__offset and 0x18E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("AdvertisementCapabilities", 0x00),
                         lambda pkt:(0x18E >= pkt.__offset and 0x18F <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OverrideMeteringDefaults", 0x00),
                         lambda pkt:(0x18F >= pkt.__offset and 0x190 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("MaxFramesPerSec", 0),
                         lambda pkt:(0x190 >= pkt.__offset and 0x194 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("DisableAutoNegotiation", 0x00),
                         lambda pkt:(0x194 >= pkt.__offset and 0x195 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnetSpeedSetting", 0x00),
                         lambda pkt:(0x195 >= pkt.__offset and 0x196 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnetDuplexSetting", 0x00),
                         lambda pkt:(0x196 >= pkt.__offset and 0x197 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("DisableTxFlowControl", 0x00),
                         lambda pkt:(0x197 >= pkt.__offset and 0x198 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("DisableRxFlowControl", 0x00),
                         lambda pkt:(0x198 >= pkt.__offset and 0x199 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PhyAddressSelection", 0x00),
                         lambda pkt:(0x199 >= pkt.__offset and 0x19A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PhyAddressSelection_Data", 0x00),
                         lambda pkt:(0x19A >= pkt.__offset and 0x19B <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("reserved_6", 0x00),
                         lambda pkt:(0x19B >= pkt.__offset and 0x19C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("Force33MHz", 0x00),
                         lambda pkt:(0x19C >= pkt.__offset and 0x19D <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("LinkStatusOnPowerline", 0x00),
                         lambda pkt:(0x19D >= pkt.__offset and 0x19E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OverrideIdDefaults", 0x00),
                         lambda pkt:(0x19E >= pkt.__offset and 0x19F <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OverrideSubIdDefaults", 0x00),
                         lambda pkt:(0x19F >= pkt.__offset and 0x1A0 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("PCIDeviceID", 0x0000),
                         lambda pkt:(0x1A0 >= pkt.__offset and 0x1A2 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("PCIVendorID", 0x0000),
                         lambda pkt:(0x1A2 >= pkt.__offset and 0x1A4 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("reserved_7", 0x00),
                         lambda pkt:(0x1A4 >= pkt.__offset and 0x1A5 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PCIClassCode", 0x00),
                         lambda pkt:(0x1A5 >= pkt.__offset and 0x1A6 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PCIClassCodeSubClass", 0x00),
                         lambda pkt:(0x1A6 >= pkt.__offset and 0x1A7 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PCIRevisionID", 0x00),
                         lambda pkt:(0x1A7 >= pkt.__offset and 0x1A8 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("PCISubsystemID", 0x0000),
                         lambda pkt:(0x1A8 >= pkt.__offset and 0x1AA <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("PCISybsystemVendorID", 0x0000),
                         lambda pkt:(0x1AA >= pkt.__offset and 0x1AC <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_8",
                                          b"\x00" * 64,
                                          64),
                         lambda pkt:(0x1AC >= pkt.__offset and 0x1EC <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OverrideIGMPDefaults", 0x00),
                         lambda pkt:(0x1EC >= pkt.__offset and 0x1ED <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ConfigFlags", 0x00),
                         lambda pkt:(0x1ED >= pkt.__offset and 0x1EE <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("NumCpToSend_PLFrames", 0x00),
                         lambda pkt:(0x1EE >= pkt.__offset and 0x1EF <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_9",
                                          b"\x00" * 29,
                                          29),
                         lambda pkt:(0x1EF >= pkt.__offset and 0x20C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("UniCastPriority", 0x00),
                         lambda pkt:(0x20C >= pkt.__offset and 0x20D <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("McastPriority", 0x00),
                         lambda pkt:(0x20D >= pkt.__offset and 0x20E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("IGMPPriority", 0x00),
                         lambda pkt:(0x20E >= pkt.__offset and 0x20F <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("AVStreamPriority", 0x00),
                         lambda pkt:(0x20F >= pkt.__offset and 0x210 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("PriorityTTL_0", 0),
                         lambda pkt:(0x210 >= pkt.__offset and 0x214 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("PriorityTTL_1", 0),
                         lambda pkt:(0x214 >= pkt.__offset and 0x218 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("PriorityTTL_2", 0),
                         lambda pkt:(0x218 >= pkt.__offset and 0x21C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("PriorityTTL_3", 0),
                         lambda pkt:(0x21C >= pkt.__offset and 0x220 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnableVLANOver", 0x00),
                         lambda pkt:(0x220 >= pkt.__offset and 0x221 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnableTOSOver", 0x00),
                         lambda pkt:(0x221 >= pkt.__offset and 0x222 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("reserved_10", 0x0000),
                         lambda pkt:(0x222 >= pkt.__offset and 0x224 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("VLANPrioTOSPrecMatrix", 0),
                         lambda pkt:(0x224 >= pkt.__offset and 0x228 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("NumClassifierPriorityMaps", 0),
                         lambda pkt:(0x228 >= pkt.__offset and 0x22C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("NumAutoConnections", 0),
                         lambda pkt:(0x22C >= pkt.__offset and 0x230 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("ClassifierPriorityMaps", "", ClassifierPriorityMap, length_from=lambda x: 224),  # noqa: E501
                         lambda pkt:(0x230 >= pkt.__offset and 0x244 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("AutoConnections", "", AutoConnection, length_from=lambda x: 1600),  # noqa: E501
                         lambda pkt:(0x310 >= pkt.__offset and 0x36e <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("NumberOfConfigEntries", 0x00),
                         lambda pkt:(0x950 >= pkt.__offset and 0x951 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("AggregateConfigEntries", "", AggregateConfigEntrie, length_from=lambda x: 16),  # noqa: E501
                         lambda pkt:(0x951 >= pkt.__offset and 0x961 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("RSVD_CustomAggregationParameters", "", RSVD_CustomAggregationParameter, length_from=lambda x: 48),  # noqa: E501
                         lambda pkt:(0x961 >= pkt.__offset and 0x991 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_11",
                                          b"\x00" * 123,
                                          123),
                         lambda pkt:(0x991 >= pkt.__offset and 0xA0C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("ToneMaskType", 0),
                         lambda pkt:(0xA0C >= pkt.__offset and 0xA10 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("ToneMaskEnabled", 0),
                         lambda pkt:(0xA10 >= pkt.__offset and 0xA14 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("StartTone", 0),
                         lambda pkt:(0xA14 >= pkt.__offset and 0xA18 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("EndTone", 0),
                         lambda pkt:(0xA18 >= pkt.__offset and 0xA1C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_12",
                                          b"\x00" * 12,
                                          12),
                         lambda pkt:(0xA1C >= pkt.__offset and 0xA28 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("PsdIndex", 0),
                         lambda pkt:(0xA28 >= pkt.__offset and 0xA2C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("TxPrescalerType", 0),
                         lambda pkt:(0xA2C >= pkt.__offset and 0xA30 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("PrescalerValues", "", PrescalerValue, length_from=lambda x: 3600),  # noqa: E501
                         lambda pkt:(0xA30 >= pkt.__offset and 0xA34 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_13",
                                          b"\x00" * 1484,
                                          1484),
                         lambda pkt:(0x1840 >= pkt.__offset and 0x1E0C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("AllowNEKRotation", 0),
                         lambda pkt:(0x1E0C >= pkt.__offset and 0x1E10 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("OverrideLocalNEK", 0),
                         lambda pkt:(0x1E10 >= pkt.__offset and 0x1E14 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("LocalNEKToUse",
                                          b"\x00" * 16,
                                          16),
                         lambda pkt:(0x1E14 >= pkt.__offset and 0x1E24 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("OverrideNEKRotationTimer", 0),
                         lambda pkt:(0x1E24 >= pkt.__offset and 0x1E28 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("NEKRotationTime_Min", 0),
                         lambda pkt:(0x1E28 >= pkt.__offset and 0x1E2C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_14",
                                          b"\x00" * 96,
                                          96),
                         lambda pkt:(0x1E2C >= pkt.__offset and 0x1E8C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("AVLNMembership", 0),
                         lambda pkt:(0x1E8C >= pkt.__offset and 0x1E90 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("SimpleConnectTimeout", 0),
                         lambda pkt:(0x1E90 >= pkt.__offset and 0x1E94 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnableLEDThroughputIndicate", 0),
                         lambda pkt:(0x1E94 >= pkt.__offset and 0x1E95 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("MidLEDThroughputThreshold_Mbps", 0),
                         lambda pkt:(0x1E95 >= pkt.__offset and 0x1E96 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("HighLEDThroughputThreshold_Mbps", 0),
                         lambda pkt:(0x1E96 >= pkt.__offset and 0x1E97 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("reserved_15", 0),
                         lambda pkt:(0x1E97 >= pkt.__offset and 0x1E98 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnableUnicastQuieriesToMember", 0),
                         lambda pkt:(0x1E98 >= pkt.__offset and 0x1E99 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("DisableMLDGroupIDCheckInMAC", 0),
                         lambda pkt:(0x1E99 >= pkt.__offset and 0x1E9A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("EnableReportsToNonQuerierHosts", 0),
                         lambda pkt:(0x1E9A >= pkt.__offset and 0x1E9C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("DisableExpireGroupMembershipInterval", 0),
                         lambda pkt:(0x1E9C >= pkt.__offset and 0x1EA0 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("DisableLEDTestLights", 0),
                         lambda pkt:(0x1EA0 >= pkt.__offset and 0x1EA4 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("GPIOMaps", "", GPIOMap, length_from=lambda x: 12),  # noqa: E501
                         lambda pkt:(0x1EA4 >= pkt.__offset and 0x1EB0 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XLongField("reserved_16", 0),
                         lambda pkt:(0x1EB0 >= pkt.__offset and 0x1EB8 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnableTrafficClass_DSCPOver", 0),
                         lambda pkt:(0x1EB8 >= pkt.__offset and 0x1EB9 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("TrafficClass_DSCPMatrices",
                                          b"\x00" * 64,
                                          64),
                         lambda pkt:(0x1EB9 >= pkt.__offset and 0x1EF9 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("GPIOControl", 0),
                         lambda pkt:(0x1EF9 >= pkt.__offset and 0x1EFA <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("LEDControl",
                                          b"\x00" * 32,
                                          32),
                         lambda pkt:(0x1EFA >= pkt.__offset and 0x1F1A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("OverrideMinButtonPressHoldTime", 0),
                         lambda pkt:(0x1F1A >= pkt.__offset and 0x1F1E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("MinButtonPressHoldTime", 0),
                         lambda pkt:(0x1F1E >= pkt.__offset and 0x1F22 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_17",
                                          b"\x00" * 22,
                                          22),
                         lambda pkt:(0x1F22 >= pkt.__offset and 0x1F38 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("MemoryProfile", 0),
                         lambda pkt:(0x1F38 >= pkt.__offset and 0x1F3C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("DisableAllLEDFlashOnWarmReboot", 0),
                         lambda pkt:(0x1F3C >= pkt.__offset and 0x1F40 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("UplinkLimit_bps", 0),
                         lambda pkt:(0x1F40 >= pkt.__offset and 0x1F44 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("DownlinkLimit_bps", 0),
                         lambda pkt:(0x1F44 >= pkt.__offset and 0x1F48 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("MDUStaticSNID", 0),
                         lambda pkt:(0x1F48 >= pkt.__offset and 0x1F4C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("MitigateEnabled", 0),
                         lambda pkt:(0x1F4C >= pkt.__offset and 0x1F4D <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("CorrelThreshold", 0),
                         lambda pkt:(0x1F4D >= pkt.__offset and 0x1F51 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("ScaledTxGain", 0),
                         lambda pkt:(0x1F51 >= pkt.__offset and 0x1F55 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ResourceThresholdEnabled", 0),
                         lambda pkt:(0x1F55 >= pkt.__offset and 0x1F56 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("ReservedPercentageForCaps", "", ReservedPercentageForCap, length_from=lambda x: 4),  # noqa: E501
                         lambda pkt:(0x1F56 >= pkt.__offset and 0x1F5A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PowerSavingMode", 0),
                         lambda pkt:(0x1F5A >= pkt.__offset and 0x1F5B <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PowerLEDDutyCycle", 0),
                         lambda pkt:(0x1F5B >= pkt.__offset and 0x1F5C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("reserved_18", 0),
                         lambda pkt:(0x1F5C >= pkt.__offset and 0x1F5E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("LinkUpDurationBeforeReset_ms", 0),
                         lambda pkt:(0x1F5E >= pkt.__offset and 0x1F62 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("PowerLEDPeriod_ms", 0),
                         lambda pkt:(0x1F62 >= pkt.__offset and 0x1F66 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("LinkDownDurationBeforeLowPowerMode_ms", 0),  # noqa: E501
                         lambda pkt:(0x1F66 >= pkt.__offset and 0x1F6A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("reserved_19", 0),
                         lambda pkt:(0x1F6A >= pkt.__offset and 0x1F6E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("AfeGainBusMode", 0),
                         lambda pkt:(0x1F6E >= pkt.__offset and 0x1F6F <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("EnableDynamicPsd", 0),
                         lambda pkt:(0x1F6F >= pkt.__offset and 0x1F70 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ReservedPercentageForTxStreams", 0),
                         lambda pkt:(0x1F70 >= pkt.__offset and 0x1F71 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ReservedPercentageForRxStreams", 0),
                         lambda pkt:(0x1F71 >= pkt.__offset and 0x1F72 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_20",
                                          b"\x00" * 22,
                                          22),
                         lambda pkt:(0x1F72 >= pkt.__offset and 0x1F88 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("LegacyNetworkUpgradeEnable", 0),
                         lambda pkt:(0x1F88 >= pkt.__offset and 0x1F8C <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("unknown", 0),
                         lambda pkt:(0x1F8C >= pkt.__offset and 0x1F90 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("MMETTL_us", 0),
                         lambda pkt:(0x1F90 >= pkt.__offset and 0x1F94 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("ConfigBits", "", ConfigBit, length_from=lambda x: 2),  # noqa: E501
                         lambda pkt:(0x1F94 >= pkt.__offset and 0x1F96 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("TxToneMapExpiry_ms", 0),
                         lambda pkt:(0x1F96 >= pkt.__offset and 0x1F9A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("RxToneMapExpiry_ms", 0),
                         lambda pkt:(0x1F9A >= pkt.__offset and 0x1F9E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("TimeoutToResound_ms", 0),
                         lambda pkt:(0x1F9E >= pkt.__offset and 0x1FA2 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("MissingSackThresholdForUnplugDetection", 0),  # noqa: E501
                         lambda pkt:(0x1FA2 >= pkt.__offset and 0x1FA6 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(LEIntField("UnplugTimeout_ms", 0),
                         lambda pkt:(0x1FA6 >= pkt.__offset and 0x1FAA <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("ContentionWindowTableES", "", ContentionWindowTable, length_from=lambda x: 8),  # noqa: E501
                         lambda pkt:(0x1FAA >= pkt.__offset and 0x1FB2 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("BackoffDeferalCountTableES", "", BackoffDeferalCountTable, length_from=lambda x: 4),  # noqa: E501
                         lambda pkt:(0x1FB2 >= pkt.__offset and 0x1FB6 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("GoodSoundCountThreshold", 0),
                         lambda pkt:(0x1FB6 >= pkt.__offset and 0x1FB7 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("SoundCountThreshold_GoodSoundCountPass", 0),  # noqa: E501
                         lambda pkt:(0x1FB7 >= pkt.__offset and 0x1FB8 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("SoundCountThreshold_GoodSoundCountFail", 0),  # noqa: E501
                         lambda pkt:(0x1FB8 >= pkt.__offset and 0x1FB9 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("reserved_21", 0),
                         lambda pkt:(0x1FB9 >= pkt.__offset and 0x1FBB <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ExclusiveTxPbs_percentage", 0),
                         lambda pkt:(0x1FBB >= pkt.__offset and 0x1FBC <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ExclusiveRxPbs_percentage", 0),
                         lambda pkt:(0x1FBC >= pkt.__offset and 0x1FBD <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OptimizationBackwardCompatible", 0),
                         lambda pkt:(0x1FBD >= pkt.__offset and 0x1FBE <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("reserved_21", 0),
                         lambda pkt:(0x1FBE >= pkt.__offset and 0x1FBF <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("MaxPbsPerSymbol", 0),
                         lambda pkt:(0x1FBF >= pkt.__offset and 0x1FC0 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("MaxModulation", 0),
                         lambda pkt:(0x1FC0 >= pkt.__offset and 0x1FC1 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ContinuousRx", 0),
                         lambda pkt:(0x1FC1 >= pkt.__offset and 0x1FC2 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_22",
                                          b"\x00" * 6,
                                          6),
                         lambda pkt:(0x1FC2 >= pkt.__offset and 0x1FC8 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("PBControlStatus", 0),
                         lambda pkt:(0x1FC8 >= pkt.__offset and 0x1FC9 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("STAMembershipMaskEnabled", 0),
                         lambda pkt:(0x1FC9 >= pkt.__offset and 0x1FCA <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ExitDefaultEnabled", 0),
                         lambda pkt:(0x1FCA >= pkt.__offset and 0x1FCB <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("RejectDefaultEnabled", 0),
                         lambda pkt:(0x1FCB >= pkt.__offset and 0x1FCC <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ChainingEnabled", 0),
                         lambda pkt:(0x1FCC >= pkt.__offset and 0x1FCD <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("VendorSpecificNMK",
                                          b"\x00" * 16,
                                          16),
                         lambda pkt:(0x1FCD >= pkt.__offset and 0x1FDD <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("LocalMACAddressLimit", 0),
                         lambda pkt:(0x1FDD >= pkt.__offset and 0x1FDE <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OverrideBridgeTableAgingTime", 0),
                         lambda pkt:(0x1FDE >= pkt.__offset and 0x1FDF <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("LocalBridgeTableAgingTime_min", 0),
                         lambda pkt:(0x1FDF >= pkt.__offset and 0x1FE1 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XShortField("RemoteBridgeTableAgingTime_min", 0),
                         lambda pkt:(0x1FE1 >= pkt.__offset and 0x1FE3 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("PhySyncReference", 0),
                         lambda pkt:(0x1FE3 >= pkt.__offset and 0x1FE7 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("reserved_23", 0),
                         lambda pkt:(0x1FE7 >= pkt.__offset and 0x1FE8 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("reserved_24", 0),
                         lambda pkt:(0x1FE8 >= pkt.__offset and 0x1FEC <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XIntField("reserved_25", 0),
                         lambda pkt:(0x1FEC >= pkt.__offset and 0x1FF0 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(StrFixedLenField("reserved_26",
                                          b"\x00" * 24,
                                          24),
                         lambda pkt:(0x1FF0 >= pkt.__offset and 0x2008 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("OverrideDefaultLedEventBehavior", 0x80),
                         lambda pkt:(0x2008 >= pkt.__offset and 0x2009 <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("ReportToHostInfo", 0),
                         lambda pkt:(0x2009 >= pkt.__offset and 0x200A <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(X3BytesField("reserved_27", 0),
                         lambda pkt:(0x200A >= pkt.__offset and 0x200D <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("NumBehaviors", 0),
                         lambda pkt:(0x200D >= pkt.__offset and 0x200E <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("BehaviorBlockArrayES", "", BehaviorBlockArray, length_from=lambda x: 1200),  # noqa: E501
                         lambda pkt:(0x200E >= pkt.__offset and 0x24BE <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(XByteField("NumEvents", 0),
                         lambda pkt:(0x24BE >= pkt.__offset and 0x24BF <= pkt.__offset + pkt.__length)),  # noqa: E501
        ConditionalField(PacketListField("EventBlockArrayES", "", EventBlockArray, length_from=lambda x: 550),  # noqa: E501
                         lambda pkt:(0x24BF >= pkt.__offset and 0x26E5 <= pkt.__offset + pkt.__length)),  # noqa: E501
    ]

    def __init__(self, packet="", offset=0x0, length=0x400):
        self.__offset = offset
        self.__length = length
        return super(ModulePIB, self).__init__(packet)


######################################################################
# Read MAC Memory
#####################################################################

StartMACCodes = {0x00: "Success"}


class StartMACRequest(Packet):
    name = "StartMACRequest"
    fields_desc = [ByteEnumField("ModuleID", 0x00, StartMACCodes),
                   X3BytesField("reserver_1", 0x000000),
                   LEIntField("ImgLoadStartAddr", 0x00000000),
                   LEIntField("ImgLength", 0x00000000),
                   LEIntField("ImgCheckSum", 0x00000000),
                   LEIntField("ImgStartAddr", 0x00000000),
                   ]


class StartMACConfirmation(Packet):
    name = "StartMACConfirmation"
    fields_desc = [ByteEnumField("Status", 0x00, StartMACCodes),
                   XByteField("ModuleID", 0x00),
                   ]

######################################################################
# Reset Device
######################################################################


ResetDeviceCodes = {0x00: "Success"}


class ResetDeviceRequest(Packet):
    name = "ResetDeviceRequest"
    fields_desc = []


class ResetDeviceConfirmation(Packet):
    name = "ResetDeviceConfirmation"
    fields_desc = [ByteEnumField("Status", 0x00, ResetDeviceCodes)]

######################################################################
# Read Configuration Block
######################################################################


ReadConfBlockCodes = {0x00: "Success"}


class ReadConfBlockRequest(Packet):
    name = "ReadConfBlockRequest"
    fields_desc = []


CBImgTCodes = {0x00: "Generic Image",
               0x01: "Synopsis configuration",
               0x02: "Denali configuration",
               0x03: "Denali applet",
               0x04: "Runtime firmware",
               0x05: "OAS client",
               0x06: "Custom image",
               0x07: "Memory control applet",
               0x08: "Power management applet",
               0x09: "OAS client IP stack",
               0x0A: "OAS client TR069",
               0x0B: "SoftLoader",
               0x0C: "Flash layout",
               0x0D: "Unknown",
               0x0E: "Chain manifest",
               0x0F: "Runtime parameters",
               0x10: "Custom module in scratch",
               0x11: "Custom module update applet"}


class ConfBlock(Packet):
    name = "ConfBlock"
    fields_desc = [LEIntField("HeaderVersionNum", 0),
                   LEIntField("ImgAddrNVM", 0),
                   LEIntField("ImgAddrSDRAM", 0),
                   LEIntField("ImgLength", 0),
                   LEIntField("ImgCheckSum", 0),
                   LEIntField("EntryPoint", 0),
                   XByteField("HeaderMinVersion", 0x00),
                   ByteEnumField("HeaderImgType", 0x00, CBImgTCodes),
                   XShortField("HeaderIgnoreMask", 0x0000),
                   LEIntField("HeaderModuleID", 0),
                   LEIntField("HeaderModuleSubID", 0),
                   LEIntField("AddrNextHeaderNVM", 0),
                   LEIntField("HeaderChecksum", 0),
                   LEIntField("SDRAMsize", 0),
                   LEIntField("SDRAMConfRegister", 0),
                   LEIntField("SDRAMTimingRegister_0", 0),
                   LEIntField("SDRAMTimingRegister_1", 0),
                   LEIntField("SDRAMControlRegister", 0),
                   LEIntField("SDRAMRefreshRegister", 0),
                   LEIntField("MACClockRegister", 0),
                   LEIntField("reserved_1", 0), ]


class ReadConfBlockConfirmation(Packet):
    name = "ReadConfBlockConfirmation"
    fields_desc = [ByteEnumField("Status", 0x00, ReadConfBlockCodes),
                   FieldLenField("BlockLen", None, count_of="ConfigurationBlock", fmt="B"),  # noqa: E501
                   PacketListField("ConfigurationBlock", None, ConfBlock, length_from=lambda pkt:pkt.BlockLen)]  # noqa: E501


######################################################################
# Write Module Data to NVM
######################################################################

class WriteModuleData2NVMRequest(Packet):
    name = "WriteModuleData2NVMRequest"
    fields_desc = [ByteEnumField("ModuleID", 0x02, ModuleIDList)]


class WriteModuleData2NVMConfirmation(Packet):
    name = "WriteModuleData2NVMConfirmation"
    fields_desc = [ByteEnumField("Status", 0x0, StatusCodes),
                   ByteEnumField("ModuleID", 0x02, ModuleIDList)]

#                            END                                      #


class HomePlugAV(Packet):
    """
        HomePlugAV Packet - by default => gets devices information
    """
    name = "HomePlugAV "
    fields_desc = [MACManagementHeader,
                   ConditionalField(XShortField("FragmentInfo", 0x0), FragmentCond),  # Fragmentation Field  # noqa: E501
                   VendorMME]

    def answers(self, other):
        return (isinstance(self, HomePlugAV))


bind_layers(Ether, HomePlugAV, {"type": 0x88e1})

#   +----------+------------+--------------------+
#   | Ethernet | HomePlugAV | Elements + Payload |
#   +----------+------------+--------------------+
bind_layers(HomePlugAV, GetDeviceVersion, {"HPtype": 0xA001})
bind_layers(HomePlugAV, StartMACRequest, {"HPtype": 0xA00C})
bind_layers(HomePlugAV, StartMACConfirmation, {"HPtype": 0xA00D})
bind_layers(HomePlugAV, ResetDeviceRequest, {"HPtype": 0xA01C})
bind_layers(HomePlugAV, ResetDeviceConfirmation, {"HPtype": 0xA01D})
bind_layers(HomePlugAV, NetworkInformationRequest, {"HPtype": 0xA038})
bind_layers(HomePlugAV, ReadMACMemoryRequest, {"HPtype": 0xA008})
bind_layers(HomePlugAV, ReadMACMemoryConfirmation, {"HPtype": 0xA009})
bind_layers(HomePlugAV, ReadModuleDataRequest, {"HPtype": 0xA024})
bind_layers(HomePlugAV, ReadModuleDataConfirmation, {"HPtype": 0xA025})
bind_layers(HomePlugAV, WriteModuleDataRequest, {"HPtype": 0xA020})
bind_layers(HomePlugAV, WriteModuleData2NVMRequest, {"HPtype": 0xA028})
bind_layers(HomePlugAV, WriteModuleData2NVMConfirmation, {"HPtype": 0xA029})
bind_layers(HomePlugAV, NetworkInfoConfirmationV10, {"HPtype": 0xA039, "version": 0x00})  # noqa: E501
bind_layers(HomePlugAV, NetworkInfoConfirmationV11, {"HPtype": 0xA039, "version": 0x01})  # noqa: E501
bind_layers(NetworkInfoConfirmationV10, NetworkInfoV10, {"HPtype": 0xA039, "version": 0x00})  # noqa: E501
bind_layers(NetworkInfoConfirmationV11, NetworkInfoV11, {"HPtype": 0xA039, "version": 0x01})  # noqa: E501
bind_layers(HomePlugAV, HostActionRequired, {"HPtype": 0xA062})
bind_layers(HomePlugAV, LoopbackRequest, {"HPtype": 0xA048})
bind_layers(HomePlugAV, LoopbackConfirmation, {"HPtype": 0xA049})
bind_layers(HomePlugAV, SetEncryptionKeyRequest, {"HPtype": 0xA050})
bind_layers(HomePlugAV, SetEncryptionKeyConfirmation, {"HPtype": 0xA051})
bind_layers(HomePlugAV, ReadConfBlockRequest, {"HPtype": 0xA058})
bind_layers(HomePlugAV, ReadConfBlockConfirmation, {"HPtype": 0xA059})
bind_layers(HomePlugAV, QUAResetFactoryConfirm, {"HPtype": 0xA07D})
bind_layers(HomePlugAV, GetNVMParametersRequest, {"HPtype": 0xA010})
bind_layers(HomePlugAV, GetNVMParametersConfirmation, {"HPtype": 0xA011})
bind_layers(HomePlugAV, SnifferRequest, {"HPtype": 0xA034})
bind_layers(HomePlugAV, SnifferConfirmation, {"HPtype": 0xA035})
bind_layers(HomePlugAV, SnifferIndicate, {"HPtype": 0xA036})

"""
    Credit song : "Western Spaguetti - We are terrorists"
"""
