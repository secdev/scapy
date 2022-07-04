# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2020  Sebastien Dudek (@FlUxIuS)

# scapy.contrib.description = LoRa PHY to WAN Layer
# scapy.contrib.status = loads

"""
LoRa PHY to WAN Layer

Initially developed @PentHertz
and improved at @Trend Micro

Spec: lorawantm_specification v1.1
"""

from scapy.packet import Packet
from scapy.fields import BitField, ByteEnumField, ByteField, \
    ConditionalField, IntField, LEShortField, PacketListField, \
    StrFixedLenField, X3BytesField, XByteField, XIntField, \
    XShortField, BitFieldLenField, LEX3BytesField, XBitField, \
    BitEnumField, XLEIntField, StrField, PacketField, \
    MultipleTypeField


class FCtrl_DownLink(Packet):
    name = "FCtrl_DownLink"
    fields_desc = [BitField("ADR", 0, 1),
                   BitField("ADRACKReq", 0, 1),
                   BitField("ACK", 0, 1),
                   BitField("FPending", 0, 1),
                   BitFieldLenField("FOptsLen", 0, 4)]

    def extract_padding(self, p):
        return "", p


class FCtrl_Link(Packet):
    name = "FCtrl_UpLink"
    fields_desc = [BitField("ADR", 0, 1),
                   BitField("ADRACKReq", 0, 1),
                   BitField("ACK", 0, 1),
                   BitField("UpClassB_DownFPending", 0, 1),
                   BitFieldLenField("FOptsLen", 0, 4)]

    def extract_padding(self, p):
        return "", p


class FCtrl_UpLink(Packet):
    name = "FCtrl_UpLink"
    fields_desc = [BitField("ADR", 0, 1),
                   BitField("ADRACKReq", 0, 1),
                   BitField("ACK", 0, 1),
                   BitField("ClassB", 0, 1),
                   BitFieldLenField("FOptsLen", 0, 4)]

    def extract_padding(self, p):
        return "", p


class DevAddrElem(Packet):
    name = "DevAddrElem"
    fields_desc = [XByteField("NwkID", 0x0),
                   LEX3BytesField("NwkAddr", b"\x00" * 3)]


CIDs_up = {0x01: "ResetInd",
           0x02: "LinkCheckReq",
           0x03: "LinkADRReq",
           0x04: "DutyCycleReq",
           0x05: "RXParamSetupReq",
           0x06: "DevStatusReq",
           0x07: "NewChannelReq",
           0x08: "RXTimingSetupReq",
           0x09: "TxParamSetupReq",  # LoRa 1.1 specs
           0x0A: "DlChannelReq",
           0x0B: "RekeyInd",
           0x0C: "ADRParamSetupReq",
           0x0D: "DeviceTimeReq",
           0x0E: "ForceRejoinReq",
           0x0F: "RejoinParamSetupReq"}  # end of LoRa 1.1 specs


CIDs_down = {0x01: "ResetConf",
             0x02: "LinkCheckAns",
             0x03: "LinkADRAns",
             0x04: "DutyCycleAns",
             0x05: "RXParamSetupAns",
             0x06: "DevStatusAns",
             0x07: "NewChannelAns",
             0x08: "RXTimingSetupAns",
             0x09: "TxParamSetupAns",  # LoRa 1.1 specs here
             0x0A: "DlChannelAns",
             0x0B: "RekeyConf",
             0x0C: "ADRParamSetupAns",
             0x0D: "DeviceTimeAns",
             0x0F: "RejoinParamSetupAns"}  # end of LoRa 1.1 specs


class ResetInd(Packet):
    name = "ResetInd"
    fields_desc = [ByteField("Dev_version", 0)]


class ResetConf(Packet):
    name = "ResetConf"
    fields_desc = [ByteField("Serv_version", 0)]


class LinkCheckReq(Packet):
    name = "LinkCheckReq"


class LinkCheckAns(Packet):
    name = "LinkCheckAns"
    fields_desc = [ByteField("Margin", 0),
                   ByteField("GwCnt", 0)]


class DataRate_TXPower(Packet):
    name = "DataRate_TXPower"
    fields_desc = [XBitField("DataRate", 0, 4),
                   XBitField("TXPower", 0, 4)]


class Redundancy(Packet):
    name = "Redundancy"
    fields_desc = [XBitField("RFU", 0, 1),
                   XBitField("ChMaskCntl", 0, 3),
                   XBitField("NbTrans", 0, 4)]


class LinkADRReq(Packet):
    name = "LinkADRReq"
    fields_desc = [DataRate_TXPower,
                   XShortField("ChMask", 0),
                   Redundancy]


class LinkADRAns_Status(Packet):
    name = "LinkADRAns_Status"
    fields_desc = [BitField("RFU", 0, 5),
                   BitField("PowerACK", 0, 1),
                   BitField("DataRate", 0, 1),
                   BitField("ChannelMaskACK", 0, 1)]


class LinkADRAns(Packet):
    name = "LinkADRAns"
    fields_desc = [PacketField("status",
                               LinkADRAns_Status(),
                               LinkADRAns_Status)]


class DutyCyclePL(Packet):
    name = "DutyCyclePL"
    fields_desc = [BitField("MaxDCycle", 0, 4)]


class DutyCycleReq(Packet):
    name = "DutyCycleReq"
    fields_desc = [DutyCyclePL]


class DutyCycleAns(Packet):
    name = "DutyCycleAns"
    fields_desc = []


class DLsettings(Packet):
    name = "DLsettings"
    fields_desc = [BitField("OptNeg", 0, 1),
                   XBitField("RX1DRoffset", 0, 3),
                   XBitField("RX2_Data_rate", 0, 4)]


class RXParamSetupReq(Packet):
    name = "RXParamSetupReq"
    fields_desc = [DLsettings,
                   X3BytesField("Frequency", 0)]


class RXParamSetupAns_Status(Packet):
    name = "RXParamSetupAns_Status"
    fields_desc = [XBitField("RFU", 0, 5),
                   BitField("RX1DRoffsetACK", 0, 1),
                   BitField("RX2DatarateACK", 0, 1),
                   BitField("ChannelACK", 0, 1)]


class RXParamSetupAns(Packet):
    name = "RXParamSetupAns"
    fields_desc = [RXParamSetupAns_Status]


Battery_state = {0: "End-device connected to external source",
                 255: "Battery level unknown"}


class DevStatusReq(Packet):
    name = "DevStatusReq"
    fields_desc = [ByteEnumField("Battery", 0, Battery_state),
                   ByteField("Margin", 0)]


class DevStatusAns_Status(Packet):
    name = "DevStatusAns_Status"
    fields_desc = [XBitField("RFU", 0, 2),
                   XBitField("Margin", 0, 6)]


class DevStatusAns(Packet):
    name = "DevStatusAns"
    fields_desc = [DevStatusAns_Status]


class DrRange(Packet):
    name = "DrRange"
    fields_desc = [XBitField("MaxDR", 0, 4),
                   XBitField("MinDR", 0, 4)]


class NewChannelReq(Packet):
    name = "NewChannelReq"
    fields_desc = [ByteField("ChIndex", 0),
                   X3BytesField("Freq", 0),
                   DrRange]


class NewChannelAns_Status(Packet):
    name = "NewChannelAns_Status"
    fields_desc = [XBitField("RFU", 0, 6),
                   BitField("Dataraterangeok", 0, 1),
                   BitField("Channelfrequencyok", 0, 1)]


class NewChannelAns(Packet):
    name = "NewChannelAns"
    fields_desc = [NewChannelAns_Status]


class RXTimingSetupReq_Settings(Packet):
    name = "RXTimingSetupReq_Settings"
    fields_desc = [XBitField("RFU", 0, 4),
                   XBitField("Del", 0, 4)]


class RXTimingSetupReq(Packet):
    name = "RXTimingSetupReq"
    fields_desc = [RXTimingSetupReq_Settings]


class RXTimingSetupAns(Packet):
    name = "RXTimingSetupAns"
    fields_desc = []


# Specific commands for LoRa 1.1 here

MaxEIRPs = {0: "8 dbm",
            1: "10 dbm",
            2: "12 dbm",
            3: "13 dbm",
            4: "14 dbm",
            5: "16 dbm",
            6: "18 dbm",
            7: "20 dbm",
            8: "21 dbm",
            9: "24 dbm",
            10: "26 dbm",
            11: "27 dbm",
            12: "29 dbm",
            13: "30 dbm",
            14: "33 dbm",
            15: "36 dbm"}


DwellTimes = {0: "No limit",
              1: "400 ms"}


class EIRP_DwellTime(Packet):
    name = "EIRP_DwellTime"
    fields_desc = [BitField("RFU", 0b0, 2),
                   BitEnumField("DownlinkDwellTime", 0b0, 1, DwellTimes),
                   BitEnumField("UplinkDwellTime", 0b0, 1, DwellTimes),
                   BitEnumField("MaxEIRP", 0b0000, 4, MaxEIRPs)]


class TxParamSetupReq(Packet):
    name = "TxParamSetupReq"
    fields_desc = [EIRP_DwellTime]


class TxParamSetupAns(Packet):
    name = "TxParamSetupAns"
    fields_desc = []


class DlChannelReq(Packet):
    name = "DlChannelReq"
    fields_desc = [ByteField("ChIndex", 0),
                   X3BytesField("Freq", 0)]


class DlChannelAns(Packet):
    name = "DlChannelAns"
    fields_desc = [ByteField("Status", 0)]


class DevLoraWANversion(Packet):
    name = "DevLoraWANversion"
    fields_desc = [BitField("RFU", 0b0000, 4),
                   BitField("Minor", 0b0001, 4)]


class RekeyInd(Packet):
    name = "RekeyInd"
    fields_desc = [PacketListField("LoRaWANversion", b"",
                   DevLoraWANversion, length_from=lambda pkt:1)]


class RekeyConf(Packet):
    name = "RekeyConf"
    fields_desc = [ByteField("ServerVersion", 0)]


class ADRparam(Packet):
    name = "ADRparam"
    fields_desc = [BitField("Limit_exp", 0b0000, 4),
                   BitField("Delay_exp", 0b0000, 4)]


class ADRParamSetupReq(Packet):
    name = "ADRParamSetupReq"
    fields_desc = [ADRparam]


class ADRParamSetupAns(Packet):
    name = "ADRParamSetupReq"
    fields_desc = []


class DeviceTimeReq(Packet):
    name = "DeviceTimeReq"
    fields_desc = []


class DeviceTimeAns(Packet):
    name = "DeviceTimeAns"
    fields_desc = [IntField("SecondsSinceEpoch", 0),
                   ByteField("FracSecond", 0x00)]


class ForceRejoinReq(Packet):
    name = "ForceRejoinReq"
    fields_desc = [BitField("RFU", 0, 2),
                   BitField("Period", 0, 3),
                   BitField("Max_Retries", 0, 3),
                   BitField("RFU2", 0, 1),
                   BitField("RejoinType", 0, 3),
                   BitField("DR", 0, 4)]


class RejoinParamSetupReq(Packet):
    name = "RejoinParamSetupReq"
    fields_desc = [BitField("MaxTimeN", 0, 4),
                   BitField("MaxCountN", 0, 4)]


class RejoinParamSetupAns(Packet):
    name = "RejoinParamSetupAns"
    fields_desc = [BitField("RFU", 0, 7),
                   BitField("TimeOK", 0, 1)]


# End of specific 1.1 commands


class MACCommand_up(Packet):
    name = "MACCommand_up"
    fields_desc = [ByteEnumField("CID", 0, CIDs_up),
                   ConditionalField(PacketListField("Reset", b"",
                                                    ResetInd,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x01)),
                   ConditionalField(PacketListField("LinkCheck", b"",
                                                    LinkCheckReq,
                                                    length_from=lambda pkt:0),
                                    lambda pkt:(pkt.CID == 0x02)),
                   ConditionalField(PacketListField("LinkADR", b"",
                                                    LinkADRReq,
                                                    length_from=lambda pkt:4),
                                    lambda pkt:(pkt.CID == 0x03)),
                   ConditionalField(PacketListField("DutyCycle", b"",
                                                    DutyCycleReq,
                                                    length_from=lambda pkt:4),
                                    lambda pkt:(pkt.CID == 0x04)),
                   ConditionalField(PacketListField("RXParamSetup", b"",
                                                    RXParamSetupReq,
                                                    length_from=lambda pkt:4),
                                    lambda pkt:(pkt.CID == 0x05)),
                   ConditionalField(PacketListField("DevStatus", b"",
                                                    DevStatusReq,
                                                    length_from=lambda pkt:2),
                                    lambda pkt:(pkt.CID == 0x06)),
                   ConditionalField(PacketListField("NewChannel", b"",
                                                    NewChannelReq,
                                                    length_from=lambda pkt:5),
                                    lambda pkt:(pkt.CID == 0x07)),
                   ConditionalField(PacketListField("RXTimingSetup", b"",
                                                    RXTimingSetupReq,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x08)),
                   # specific to 1.1 from here
                   ConditionalField(PacketListField("TxParamSetup", b"",
                                                    TxParamSetupReq,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x09)),
                   ConditionalField(PacketListField("DlChannel", b"",
                                                    DlChannelReq,
                                                    length_from=lambda pkt:4),
                                    lambda pkt:(pkt.CID == 0x0A)),
                   ConditionalField(PacketListField("Rekey", b"",
                                                    RekeyInd,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x0B)),
                   ConditionalField(PacketListField("ADRParamSetup", b"",
                                                    ADRParamSetupReq,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x0C)),
                   ConditionalField(PacketListField("DeviceTime", b"",
                                                    DeviceTimeReq,
                                                    length_from=lambda pkt:0),
                                    lambda pkt:(pkt.CID == 0x0D)),
                   ConditionalField(PacketListField("ForceRejoin", b"",
                                                    ForceRejoinReq,
                                                    length_from=lambda pkt:2),
                                    lambda pkt:(pkt.CID == 0x0E)),
                   ConditionalField(PacketListField("RejoinParamSetup", b"",
                                                    RejoinParamSetupReq,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x0F))]

    # pylint: disable=R0201
    def extract_padding(self, p):
        return "", p


class MACCommand_down(Packet):
    name = "MACCommand_down"
    fields_desc = [ByteEnumField("CID", 0, CIDs_up),
                   ConditionalField(PacketListField("Reset", b"",
                                                    ResetConf,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x01)),
                   ConditionalField(PacketListField("LinkCheck", b"",
                                                    LinkCheckAns,
                                                    length_from=lambda pkt:2),
                                    lambda pkt:(pkt.CID == 0x02)),
                   ConditionalField(PacketListField("LinkADR", b"",
                                                    LinkADRAns,
                                                    length_from=lambda pkt:0),
                                    lambda pkt:(pkt.CID == 0x03)),
                   ConditionalField(PacketListField("DutyCycle", b"",
                                                    DutyCycleAns,
                                                    length_from=lambda pkt:4),
                                    lambda pkt:(pkt.CID == 0x04)),
                   ConditionalField(PacketListField("RXParamSetup", b"",
                                                    RXParamSetupAns,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x05)),
                   ConditionalField(PacketListField("DevStatusAns", b"",
                                                    RXParamSetupAns,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x06)),
                   ConditionalField(PacketListField("NewChannel", b"",
                                                    NewChannelAns,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x07)),
                   ConditionalField(PacketListField("RXTimingSetup", b"",
                                                    RXTimingSetupAns,
                                                    length_from=lambda pkt:0),
                                    lambda pkt:(pkt.CID == 0x08)),
                   ConditionalField(PacketListField("TxParamSetup", b"",
                                                    TxParamSetupAns,
                                                    length_from=lambda pkt:0),
                                    lambda pkt:(pkt.CID == 0x09)),
                   ConditionalField(PacketListField("DlChannel", b"",
                                                    DlChannelAns,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x0A)),
                   ConditionalField(PacketListField("Rekey", b"",
                                                    RekeyConf,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x0B)),
                   ConditionalField(PacketListField("ADRParamSetup", b"",
                                                    ADRParamSetupAns,
                                                    length_from=lambda pkt:0),
                                    lambda pkt:(pkt.CID == 0x0C)),
                   ConditionalField(PacketListField("DeviceTime", b"",
                                                    DeviceTimeAns,
                                                    length_from=lambda pkt:5),
                                    lambda pkt:(pkt.CID == 0x0D)),
                   ConditionalField(PacketListField("RejoinParamSetup", b"",
                                                    RejoinParamSetupAns,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:(pkt.CID == 0x0F))]


class FOpts(Packet):
    name = "FOpts"
    fields_desc = [ConditionalField(PacketListField("FOpts_up", b"",
                                                    # UL piggy MAC Command
                                                    MACCommand_up,
                                                    length_from=lambda pkt:pkt.FCtrl[0].FOptsLen),  # noqa: E501
                                    lambda pkt:(pkt.FCtrl[0].FOptsLen > 0 and
                                                pkt.MType & 0b1 == 0 and
                                                pkt.MType >= 0b010)),
                   ConditionalField(PacketListField("FOpts_down", b"",
                                                    # DL piggy MAC Command
                                                    MACCommand_down,
                                                    length_from=lambda pkt:pkt.FCtrl[0].FOptsLen),  # noqa: E501
                                    lambda pkt:(pkt.FCtrl[0].FOptsLen > 0 and
                                                pkt.MType & 0b1 == 1 and
                                                pkt.MType <= 0b101))]


def FOptsDownShow(pkt):
    try:
        if pkt.FCtrl[0].FOptsLen > 0 and pkt.MType & 0b1 == 1 and pkt.MType <= 0b101 and (pkt.MType & 0b101 > 0):  # noqa: E501
            return True
        return False
    except Exception:
        return False


def FOptsUpShow(pkt):
    try:
        if pkt.FCtrl[0].FOptsLen > 0 and pkt.MType & 0b1 == 0 and pkt.MType >= 0b010 and (pkt.MType & 0b110 > 0):  # noqa: E501
            return True
        return False
    except Exception:
        return False


class FHDR(Packet):
    name = "FHDR"
    fields_desc = [ConditionalField(PacketListField("DevAddr", b"", DevAddrElem,  # noqa: E501
                                                    length_from=lambda pkt:4),
                                    lambda pkt:(pkt.MType >= 0b010 and
                                                pkt.MType <= 0b101)),
                   ConditionalField(PacketListField("FCtrl", b"",
                                                    FCtrl_Link,
                                                    length_from=lambda pkt:1),
                                    lambda pkt:((pkt.MType & 0b1 == 1 and
                                                pkt.MType <= 0b101 and
                                                (pkt.MType & 0b10 > 0)) or
                                                (pkt.MType & 0b1 == 0 and
                                                pkt.MType >= 0b010))),
                   ConditionalField(LEShortField("FCnt", 0),
                                    lambda pkt:(pkt.MType >= 0b010 and
                                                pkt.MType <= 0b101)),
                   ConditionalField(PacketListField("FOpts_up", b"",
                                                    MACCommand_up,
                                                    length_from=lambda pkt:pkt.FCtrl[0].FOptsLen),  # noqa: E501
                                    FOptsUpShow),
                   ConditionalField(PacketListField("FOpts_down", b"",
                                                    MACCommand_down,
                                                    length_from=lambda pkt:pkt.FCtrl[0].FOptsLen),  # noqa: E501
                                    FOptsDownShow)]


FPorts = {0: "NwkSKey"}  # anything else is AppSKey


JoinReqTypes = {0xFF: "Join-request",
                0x00: "Rejoin-request type 0",
                0x01: "Rejoin-request type 1",
                0x02: "Rejoin-request type 2"}


class Join_Request(Packet):
    name = "Join_Request"
    fields_desc = [StrFixedLenField("AppEUI", b"\x00" * 8, 8),
                   StrFixedLenField("DevEUI", b"\00" * 8, 8),
                   LEShortField("DevNonce", 0x0000)]


class Join_Accept(Packet):
    name = "Join_Accept"
    dcflist = False
    fields_desc = [LEX3BytesField("JoinAppNonce", 0),
                   LEX3BytesField("NetID", 0),
                   XLEIntField("DevAddr", 0),
                   DLsettings,
                   XByteField("RxDelay", 0),
                   ConditionalField(StrFixedLenField("CFList", b"\x00" * 16, 16),  # noqa: E501
                                    lambda pkt:(Join_Accept.dcflist is True))]

    def extract_padding(self, p):
        return "", p

    def __init__(self, packet=""):  # CFList calculated with rest of packet len
        if len(packet) > 18:
            Join_Accept.dcflist = True
        super(Join_Accept, self).__init__(packet)


RejoinType = {0: "NetID+DevEUI",
              1: "JoinEUI+DevEUI",
              2: "NetID+DevEUI"}


class RejoinReq(Packet):  # LoRa 1.1 specs
    name = "RejoinReq"
    fields_desc = [ByteField("Type", 0),
                   X3BytesField("NetID", 0),
                   StrFixedLenField("DevEUI", b"\x00" * 8),
                   XShortField("RJcount0", 0)]


def dpload_type(pkt):
    if (pkt.MType == 0b101 or pkt.MType == 0b011):
        return 0  # downlink
    elif (pkt.MType == 0b100 or pkt.MType == 0b010):
        return 1  # uplink
    return None


datapayload_list = [(StrField("DataPayload", "", remain=4),
                     lambda pkt:(dpload_type(pkt) == 0)),
                    (StrField("DataPayload", "", remain=6),
                     lambda pkt:(dpload_type(pkt) == 1))]


class FRMPayload(Packet):
    name = "FRMPayload"
    fields_desc = [ConditionalField(MultipleTypeField(datapayload_list,
                                                      StrField("DataPayload",
                                                               "", remain=4)),
                                    lambda pkt:(dpload_type(pkt) is not None)),
                   ConditionalField(PacketListField("Join_Request_Field", b"",
                                                    Join_Request,
                                                    length_from=lambda pkt:18),
                                    lambda pkt:(pkt.MType == 0b000)),
                   ConditionalField(PacketListField("Join_Accept_Field", b"",
                                                    Join_Accept,
                                                    count_from=lambda pkt:1),
                                    lambda pkt:(pkt.MType == 0b001 and
                                                LoRa.encrypted is False)),
                   ConditionalField(StrField("Join_Accept_Encrypted", 0),
                                    lambda pkt:(pkt.MType == 0b001 and LoRa.encrypted is True)),  # noqa: E501
                   ConditionalField(PacketListField("ReJoin_Request_Field", b"",  # noqa: E501
                                                    RejoinReq,
                                                    length_from=lambda pkt:14),
                                    lambda pkt:(pkt.MType == 0b111))]


class MACPayload(Packet):
    name = "MACPayload"
    eFPort = False
    fields_desc = [FHDR,
                   ConditionalField(ByteEnumField("FPort", 0, FPorts),
                                    lambda pkt:(pkt.MType >= 0b010 and
                                                pkt.MType <= 0b101 and
                                                pkt.FCtrl[0].FOptsLen == 0)),
                   FRMPayload]


MTypes = {0b000: "Join-request",
          0b001: "Join-accept",
          0b010: "Unconfirmed Data Up",
          0b011: "Unconfirmed Data Down",
          0b100: "Confirmed Data Up",
          0b101: "Confirmed Data Down",
          0b110: "Rejoin-request",  # Only in LoRa 1.1 specs
          0b111: "Proprietary"}


class MHDR(Packet):  # Same for 1.0 as for 1.1
    name = "MHDR"

    fields_desc = [BitEnumField("MType", 0b000, 3, MTypes),
                   BitField("RFU", 0b000, 3),
                   BitField("Major", 0b00, 2)]


class PHYPayload(Packet):
    name = "PHYPayload"
    fields_desc = [MHDR,
                   MACPayload,
                   ConditionalField(XIntField("MIC", 0),
                                    lambda pkt:(pkt.MType != 0b001 or
                                                LoRa.encrypted is False))]


class LoRa(Packet):  # default frame (unclear specs => taken from https://www.ncbi.nlm.nih.gov/pmc/articles/PMC5677147/)  # noqa: E501
    name = "LoRa"
    version = "1.1"  # default version to parse
    encrypted = True

    fields_desc = [XBitField("Preamble", 0, 4),
                   XBitField("PHDR", 0, 16),
                   XBitField("PHDR_CRC", 0, 4),
                   PHYPayload,
                   ConditionalField(XShortField("CRC", 0),
                                    lambda pkt:(pkt.MType & 0b1 == 0))]
