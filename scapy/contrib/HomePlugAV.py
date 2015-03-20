from scapy.all import *
"""
    Copyright (C) HomePlugAV Layer for Scapy by FlUxIuS (Sebastien Dudek)
"""

"""
    HomePlugAV Management Message Type
    Key (type value) : Description
"""
HPAVTypeList = { 0xA000 : "'Get Device/sw version Request'",
                0xA001 : "'Get Device/sw version Confirmation'",
                0xA008 : "'Read MAC Memory Request'",
                0xA009 : "'Read MAC Memory Confirmation'",
                0xA00C : "'Start MAC Request'",
                0xA00D : "'Start MAC Confirmation'",
                0xA010 : "'Get NVM Parameters Request'",
                0xA011 : "'Get NVM Parameters Confirmation'",
                0xA01C : "'Reset Device Request'",
                0xA01D : "'Reset Device Confirmation'",
                0xA020 : "'Write Module Data Request'",
                0xA024 : "'Read Module Data Request'",
                0xA025 : "'Read Module Data Confirmation'",
                0xA028 : "'Write Module Data to NVM Request'",
                0xA028 : "'Write Module Data to NVM Confirmation'",
                0xA034 : "'Sniffer Request'",
                0xA035 : "'Sniffer Confirmation'",
                0xA036 : "'Sniffer Indicates'",
                0xA038 : "'Network Information Request'",
                0xA039 : "'Network Information Confirmation'",
                0xA048 : "'Loopback Request'",
                0xA049 : "'Loopback Request Confirmation'",
                0xA050 : "'Set Encryption Key Request'",
                0xA051 : "'Set Encryption Key Request Confirmation'",
                0xA058 : "'Read Configuration Block Request'",
                0xA058 : "'Read Configuration Block Confirmation'",
                0xA062 : "'Embedded Host Action Required Indication'" }

HPAVversionList = { 0x00 : "1.0",
                    0x01 : "1.1" }

HPAVDeviceIDList = {    0x00 : "Unknown",
                        0x01 : "'INT6000'",
                        0x02 : "'INT6300'",
                        0x03 : "'INT6400'",
                        0x04 : "'AR7400'",
                        0x05 : "'AR6405'",
                        0x20 : "'QCA7450/QCA7420'",
                        0x21 : "'QCA6410/QCA6411'",
                        0x22 : "'QCA7000'" }

StationRole = { 0x00 : "'Station'",
                0x01 : "'Proxy coordinator'",
                0x02 : "'Central coordinator'" }

StatusCodes = { 0x00 : "'Success'",
                0x10 : "'Invalid Address'",
                0x14 : "'Invalid Length'" }

DefaultVendor = "Qualcomm"

#########################################################################
# Qualcomm Vendor Specific Management Message Types;                    #
# from https://github.com/qca/open-plc-utils/blob/master/mme/qualcomm.h #
#########################################################################
# Commented commands are already in HPAVTypeList, the other have to be implemted 
QualcommTypeList = {  #0xA000 : "VS_SW_VER",
                    0xA004 : "VS_WR_MEM",
                    #0xA008 : "VS_RD_MEM",
                    #0xA00C : "VS_ST_MAC",
                    #0xA010 : "VS_GET_NVM",
                    0xA014 : "VS_RSVD_1",
                    0xA018 : "VS_RSVD_2",
                    #0xA01C : "VS_RS_DEV",
                    #0xA020 : "VS_WR_MOD",
                    #0xA024 : "VS_RD_MOD",
                    #0xA028 : "VS_MOD_NVM",
                    0xA02C : "VS_WD_RPT",
                    0xA030 : "VS_LNK_STATS",
                    #0xA034 : "VS_SNIFFER",
                    #0xA038 : "VS_NW_INFO",
                    0xA03C : "VS_RSVD_3",
                    0xA040 : "VS_CP_RPT",
                    0xA044 : "VS_ARPC",
                    #0xA050 : "VS_SET_KEY",
                    0xA054 : "VS_MFG_STRING",
                    #0xA058 : "VS_RD_CBLOCK",
                    0xA05C : "VS_SET_SDRAM",
                    0xA060 : "VS_HOST_ACTION",
                    0xA068 : "VS_OP_ATTRIBUTES",
                    0xA06C : "VS_ENET_SETTINGS",
                    0xA070 : "VS_TONE_MAP_CHAR",
                    0xA074 : "VS_NW_INFO_STATS",
                    0xA078 : "VS_SLAVE_MEM",
                    0xA07C : "VS_FAC_DEFAULTS",
                    0xA07D : "VS_FAC_DEFAULTS_CONFIRM",
                    0xA084 : "VS_MULTICAST_INFO",
                    0xA088 : "VS_CLASSIFICATION",
                    0xA090 : "VS_RX_TONE_MAP_CHAR",
                    0xA094 : "VS_SET_LED_BEHAVIOR",
                    0xA098 : "VS_WRITE_AND_EXECUTE_APPLET",
                    0xA09C : "VS_MDIO_COMMAND",
                    0xA0A0 : "VS_SLAVE_REG",
                    0xA0A4 : "VS_BANDWIDTH_LIMITING",
                    0xA0A8 : "VS_SNID_OPERATION",
                    0xA0AC : "VS_NN_MITIGATE",
                    0xA0B0 : "VS_MODULE_OPERATION",
                    0xA0B4 : "VS_DIAG_NETWORK_PROBE",
                    0xA0B8 : "VS_PL_LINK_STATUS",
                    0xA0BC : "VS_GPIO_STATE_CHANGE",
                    0xA0C0 : "VS_CONN_ADD",
                    0xA0C4 : "VS_CONN_MOD",
                    0xA0C8 : "VS_CONN_REL",
                    0xA0CC : "VS_CONN_INFO",
                    0xA0D0 : "VS_MULTIPORT_LNK_STA",
                    0xA0DC : "VS_EM_ID_TABLE",
                    0xA0E0 : "VS_STANDBY",
                    0xA0E4 : "VS_SLEEPSCHEDULE",
                    0xA0E8 : "VS_SLEEPSCHEDULE_NOTIFICATION",
                    0xA0F0 : "VS_MICROCONTROLLER_DIAG",
                    0xA0F8 : "VS_GET_PROPERTY",
                    0xA100 : "VS_SET_PROPERTY",
                    0xA104 : "VS_PHYSWITCH_MDIO",
                    0xA10C : "VS_SELFTEST_ONETIME_CONFIG",
                    0xA110 : "VS_SELFTEST_RESULTS",
                    0xA114 : "VS_MDU_TRAFFIC_STATS",
                    0xA118 : "VS_FORWARD_CONFIG",
                    0xA200 : "VS_HYBRID_INFO"}
########## END OF Qualcomm commands ##########################

EofPadList = [ 0xA000, 0xA038 ] # TODO: The complete list of Padding can help to improve the condition in VendorMME Class

def FragmentCond(pkt):
    """
        A fragementation field condition
        TODO: To complete
    """
    fragTypeTable = [ 0xA038, 0xA039 ]
    return ((pkt.version == 0x01 )  and ( pkt.HPtype in fragTypeTable ))

class MACManagementHeader(Packet):
    name = "MACManagementHeader "
    if DefaultVendor == "Qualcomm":
        HPAVTypeList.update(QualcommTypeList) 
    fields_desc=[ ByteEnumField("version",0, HPAVversionList),
                EnumField("HPtype" , 0xA000, HPAVTypeList, "<H") ]

class VendorMME(Packet):
    name = "VendorMME "
    fields_desc=[ X3BytesField("OUI", 0x00b052) ]

class GetDeviceVersion(Packet):
    name = "GetDeviceVersion"
    fields_desc=[ ByteEnumField("Status", 0x0, StatusCodes),
                ByteEnumField("DeviceID",0x20, HPAVDeviceIDList),
                FieldLenField("VersionLen", None, count_of="DeviceVersion", fmt="B"),
                StrLenField("DeviceVersion", "NoVersion\x00", length_from = lambda pkt: pkt.VersionLen),
                StrLenField("DeviceVersion_pad", "\xcc\xcc\xcc\xcc\xcc"+"\x00"*59, length_from = lambda pkt: 64-pkt.VersionLen), 
                ByteEnumField("Upgradable", 0, {0:"False",1:"True"}) ]

class NetworkInformationRequest(Packet):
    name = "NetworkInformationRequest"
    fields_desc=[ ]

#""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
#   Networks & Stations informations for MAC Management V1.0
#""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
class NetworkInfoV10(Packet):
    """
        Network Information Element
    """
    name = "NetworkInfo"
    fields_desc = [ StrFixedLenField("NetworkID", "\x00\x00\x00\x00\x00\x00\x00", 7),
                    XByteField("ShortNetworkID", 0x00),
                    XByteField("TerminalEID", 0x01),
                    ByteEnumField("StationRole", 0x00, StationRole),
                    MACField("CCoMACAdress", "00:00:00:00:00:00"),
                    XByteField("CCoTerminalEID", 0x01) ]

    def extract_padding(self, p):
        return "", p

class StationInfoV10(Packet):
    """
        Station Information Element
    """
    name = "StationInfo"
    fields_desc=[ MACField("StationMAC", "00:00:00:00:00:00"),
                XByteField("StationTerminalEID", 0x01), 
                MACField("firstnodeMAC", "ff:ff:ff:ff:ff:ff"),
                XByteField("TXaverage", 0x00),
                XByteField("RXaverage", 0x00) ]

    def extract_padding(self, p):
        return "", p

#""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
#   Networks & Stations informations for MAC Management V1.1 
#""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
class NetworkInfoV11(Packet):
    """
        Network Information Element
    """
    name = "NetworkInfo"
    fields_desc = [ StrFixedLenField("NetworkID", "\x00\x00\x00\x00\x00\x00\x00", 7),
                    ShortField("reserved_1", 0x0000),
                    XByteField("ShortNetworkID", 0x00),
                    XByteField("TerminalEID", 0x01),
                    IntField("reserved_2", 0x00000000),
                    ByteEnumField("StationRole", 0x00, StationRole),
                    MACField("CCoMACAdress", "00:00:00:00:00:00"),
                    XByteField("CCoTerminalEID", 0x01),
                    X3BytesField("reserved_3", 0x000000) ]
    
    def extract_padding(self, p):
        return "", p


class StationInfoV11(Packet):
    """
        Station Information Element
    """
    name = "StationInfo"
    fields_desc=[ MACField("StationMAC", "00:00:00:00:00:00"),
                XByteField("StationTerminalEID", 0x01),
                X3BytesField("reserved_s2", 0x000000),
                MACField("firstnodeMAC", "ff:ff:ff:ff:ff:ff"),
                LEShortField("TXaverage", 0x0000),
                BitField("RxCoupling", 0b0000, 4),
                BitField("TxCoupling", 0b0000, 4),
                XByteField("reserved_s3", 0x00),
                LEShortField("RXaverage", 0x0000),
                XByteField("reserved_s4", 0x00) ]
    
    def extract_padding(self, p):
        return "", p

#""""""""""""""""""""""""" END """"""""""""""""""""""""""""""""""""""""""""""""""""""""""

class NetworkInfoConfirmationV10(Packet):
    """
        Network Information Confirmation following the MAC Management version 1.0
    """
    name = "NetworkInfoConfirmation"
    fields_desc=[ XByteField("LogicalNetworksNumber", 0x01),
                PacketListField("NetworksInfos", "", NetworkInfoV10, length_from=lambda pkt: pkt.LogicalNetworksNumber * 17),
                XByteField("StationsNumber", 0x01),
                PacketListField("StationsInfos", "", StationInfoV10, length_from=lambda pkt: pkt.StationsNumber * 21) ]

class NetworkInfoConfirmationV11(Packet):
    """
        Network Information Confirmation following the MAC Management version 1.1
        This introduce few 'crazy' reserved bytes -> have fun!
    """
    name = "NetworkInfoConfirmation"
    fields_desc= [ StrFixedLenField("reserved_n1", "\x00\x00\x3a\x00\x00", 5),
                XByteField("LogicalNetworksNumber", 0x01),
                PacketListField("NetworksInfos", "", NetworkInfoV11, length_from=lambda pkt: pkt.LogicalNetworksNumber * 26),
                XByteField("StationsNumber", 0x01),
                StrFixedLenField("reserverd_s1", "\x00\x00\x00\x00\x00", 5),
                PacketListField("StationsInfos", "", StationInfoV11, length_from=lambda pkt: pkt.StationsNumber * 23) ]


# Description of Embedded Host Action Required Indice
ActionsList = { 0x02 : "'PIB Update Ready'",
                0x04 : "'Loader (Bootloader)'" }

class HostActionRequired(Packet):
    """
        Embedded Host Action Required Indice
    """
    name = "HostActionRequired"
    fields_desc=[ ByteEnumField("ActionRequired", 0x02, ActionsList) ]

class LoopbackRequest(Packet):
    name = "LoopbackRequest"
    fields_desc=[ ByteField("Duration", 0x01),
                ByteField("reserved_l1", 0x01),
                ShortField("LRlength", 0x0000) ]
                # TODO: Test all possibles data to complete it

class LoopbackConfirmation(Packet):
    name = "LoopbackConfirmation"
    fields_desc=[ ByteEnumField("Status", 0x0, StatusCodes), 
                ByteField("Duration", 0x01),
                ShortField("LRlength", 0x0000) ]

################################################################
# Encryption Key Packets
################################################################

class SetEncryptionKeyRequest(Packet):
    name = "SetEncryptionKeyRequest"
    fields_desc=[ XByteField("EKS", 0x00),
                StrFixedLenField("NMK", 
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                16),
                XByteField("PayloadEncKeySelect", 0x00),
                MACField("DestinationMAC", "ff:ff:ff:ff:ff:ff"),
                StrFixedLenField("DAK", 
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 
                                16) ]

SetEncKey_Status = {    0x00 : "Success",
                        0x10 : "Invalid EKS",
                        0x11 : "Invalid PKS" }

class SetEncryptionKeyConfirmation(Packet):
    name = "SetEncryptionKeyConfirmation"
    fields_desc=[ ByteEnumField("Status", 0x0, SetEncKey_Status) ]

################################################################
# Default config Packet
################################################################

class QUAResetFactoryConfirm(Packet):
    name = "QUAResetFactoryConfirm"
    fields_desc=[ ByteEnumField("Status", 0x0, StatusCodes) ] #TODO : Probably a Status bytefield?

######################################################################
# NVM Parameters Packets
######################################################################

class GetNVMParametersRequest(Packet):
    name = "Get NVM Parameters Request"
    fields_desc=[ ]

class GetNVMParametersConfirmation(Packet):
    name = "Get NVM Parameters Confirmation"
    fields_desc=[ ByteEnumField("Status", 0x0, StatusCodes),
                LEIntField("NVMType", 0x00000013),
                LEIntField("NVMPageSize", 0x00000100),
                LEIntField("NVMBlockSize", 0x00010000),
                LEIntField("NVMMemorySize", 0x00100000) ]

######################################################################
# Sniffer Packets
######################################################################

SnifferControlList = { 0x0 : "'Disabled'",
                       0x1 : "'Enabled'" }

SnifferTypeCodes = { 0x00 : "'Regular'" }

class SnifferRequest(Packet):
    name = "SnifferRequest"
    fields_desc=[ ByteEnumField("SnifferControl", 0x0, SnifferControlList) ]

SnifferCodes = { 0x00 : "'Success'",
                 0x10 : "'Invalid Control'" }

class SnifferConfirmation(Packet):
    name = "SnifferConfirmation"
    fields_desc=[ ByteEnumField("Status", 0x0, StatusCodes) ]

DirectionCodes = { 0x00 : "'Tx'",
                   0x01 : "'Rx'" }

ANCodes = { 0x00 : "'In-home'",
            0x01 : "'Access'" }

class SnifferIndicate(Packet):
    # TODO: Some bitfield have been regrouped for the moment => need more work on it
    name = "SnifferIndicate"
    fields_desc=[ ByteEnumField("SnifferType", 0x0, SnifferTypeCodes), 
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
                  X3BytesField("FrameContrchkSeq", 0x000000) ]

######################################################################
# Read MAC Memory
#####################################################################

class ReadMACMemoryRequest(Packet):
    name = "ReadMACMemoryRequest"
    fields_desc=[ LEIntField("Address" , 0x00000000),
                  LEIntField("Length", 0x00000400), 
                ]

ReadMACStatus = { 0x00 : "Success",
                  0x10 : "Invalid Address",
                  0x14 : "Invalid Length" }

class ReadMACMemoryConfirmation(Packet):
    name = "ReadMACMemoryConfirmation"

    fields_desc=[ ByteEnumField("Status", 0x00 , ReadMACStatus),
                  LEIntField("Address" , 0),
                  FieldLenField("MACLen", None, length_of="MACData", fmt="<H"),
                  StrLenField("MACData", "\x00", length_from = lambda pkt: pkt.MACLen),
                ]

######################################################################
# Read Module Datas
######################################################################

ModuleIDList = {    0x00 : "MAC Soft-Loader Image",
                    0x01 : "MAC Software Image",
                    0x02 : "PIB",
                    0x10 : "Write Alternate Flash Location" }

def chksum32(data):
    cksum = 0
    for i in range(0, len(data), 4):
        cksum = (cksum ^ struct.unpack('<I', data[i:i+4])[0]) & 0xffffffff   
    return (~cksum) & 0xffffffff

class ReadModuleDataRequest(Packet):
    name = "ReadModuleDataRequest"
    fields_desc=[ ByteEnumField("ModuleID", 0x02, ModuleIDList),
                  XByteField("reserved", 0x00),
                  LEShortField("Length" , 0x0400),
                  LEIntField("Offset", 0x00000000) ]

class ReadModuleDataConfirmation(Packet):
    name = "ReadModuleDataConfirmation"
    fields_desc=[ ByteEnumField("Status", 0x0, StatusCodes),
                  X3BytesField("reserved_1", 0x000000),
                  ByteEnumField("ModuleID", 0x02, ModuleIDList),
                  XByteField("reserved_2", 0x00),
                  FieldLenField("DataLen", None, count_of="ModuleData", fmt="<H"),
                  LEIntField("Offset", 0x00000000),
                  LEIntField("checksum", None), 
                  StrLenField("ModuleData", "\x00", length_from = lambda pkt: pkt.DataLen),
                ]

    def post_build(self, p, pay):
        import binascii
        if self.DataLen is None:
            _len = len(self.ModuleData)
            p = p[:6] + struct.pack('h', _len) + p[8:]
        if self.checksum is None and p:
            ck = chksum32(self.ModuleData)
            p = p[:12] + struct.pack('I', ck) + p[16:]
        return p+pay

######################################################################
# Write Module Datas
######################################################################

class WriteModuleDataRequest(Packet):
    name = "WriteModuleDataRequest"
    fields_desc=[ ByteEnumField("ModuleID", 0x02, ModuleIDList),
                  XByteField("reserved_1", 0x00),
                  FieldLenField("DataLen", None, count_of="ModuleData", fmt="<H"),
                  LEIntField("Offset", 0x00000000),
                  LEIntField("checksum", None),
                  StrLenField("ModuleData", "\x00", length_from = lambda pkt: pkt.DataLen),
                ]

    def post_build(self, p, pay):
        import binascii
        if self.DataLen is None:
            _len = len(self.ModuleData)
            p = p[:2] + struct.pack('h', _len) + p[4:]
        if self.checksum is None and p:
            ck = chksum32(self.ModuleData)
            p = p[:8] + struct.pack('I', ck) + p[12:]
        return p+pay

######################################
# Parse PIB                          #
######################################

class ClassifierPriorityMap(Packet):
    name = "ClassifierPriorityMap"
    fields_desc=[ LEIntField("Priority" , 0),
                  LEIntField("PID" , 0),
                  LEIntField("IndividualOperand" , 0),
                  StrFixedLenField("ClassifierValue",
                                "\x00"*16,
                                16),
                ]
 
    def extract_padding(self, p):
        return "", p

class ClassifierObj(Packet):
    name = "ClassifierObj"
    
    fields_desc=[ LEIntField("ClassifierPID", 0),
                  LEIntField("IndividualOperand", 0),
                  StrFixedLenField("ClassifierValue",
                                "\x00"*16,
                                16), 
                ]

    def extract_padding(self, p):
        return "", p

class AutoConnection(Packet):
    name = "AutoConnection"

    fields_desc=[ XByteField("Action", 0x00), 
                  XByteField("ClassificationOperand", 0x00),
                  XShortField("NumClassifiers", 0x0000),
                  PacketListField("ClassifierObjs", "", ClassifierObj, length_from=lambda x: 24),
                  XShortField("CSPECversion", 0x0000),
                  XByteField("ConnCAP", 0x00),
                  XByteField("ConnCoQoSPrio", 0x00),
                  ShortField("ConnRate", 0),
                  LEIntField("ConnTTL", 0),
                  ShortField("CSPECversion", 0),
                  StrFixedLenField("VlanTag",
                                "\x00"*4,
                                4),
                  XIntField("reserved_1", 0),
                  StrFixedLenField("reserved_2",
                                "\x00"*14,
                                14),
                ]

    def extract_padding(self, p):
        return "", p

class PeerNode(Packet):
    name = "PeerNodes"
    fields_desc=[ XByteField("PeerTEI", 0x0),
                  MACField("PIBMACAddr", "00:00:00:00:00:00"),
                ]

    def extract_padding(self, p):
        return "", p

class AggregateConfigEntrie(Packet):
    name = "AggregateConfigEntrie"
    fields_desc=[ XByteField("TrafficTypeID", 0x0),
                  XByteField("AggregationConfigID", 0x0),
                ]

    def extract_padding(self, p):
        return "", p

class RSVD_CustomAggregationParameter(Packet):
    name = "RSVD_CustomAggregationParameter"
    fields_desc=[ XIntField("CustomAggregationParameter", 0),
                ]

    def extract_padding(self, p):
        return "", p

class PrescalerValue(Packet):
    name = "PrescalerValue"
    fields_desc=[ XIntField("prescaler", 0),
                ]

    def extract_padding(self, p):
        return "", p

class GPIOMap(Packet):
    name = "GPIOMap"
    fields_desc=[ XByteField("GPIOvalue", 0),
                ]

    def extract_padding(self, p):
        return "", p

class ReservedPercentageForCap(Packet):
    name = "ReservedPercentageForCap"
    fields_desc=[ XByteField("CAPpercent", 0),
                ]

    def extract_padding(self, p):
        return "", p

class ConfigBit(Packet):
    name = "ConfigBit"
    fields_desc=[ BitField("OverrideSoundCap", 0, 1),
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
    fields_desc=[ XShortField("element", 0), 
                ]

    def extract_padding(self, p):
        return "", p

class BackoffDeferalCountTable(Packet):
    name = "BackoffDeferalCountTable"
    fields_desc=[ XByteField("element", 0),
                ]

    def extract_padding(self, p):
        return "", p

class BehaviorBlockArray(Packet):
    name = "BehaviorBlockArray"
    fields_desc=[ XByteField("BehId", 0),
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
        return "", p

class EventBlockArray(Packet):
    name = "EventBlockArray"
    fields_desc=[ XByteField("EventPriorityID", 0),
                  XByteField("EventID", 0),
                  XByteField("BehID_1", 0),
                  XByteField("BehID_2", 0),
                  XByteField("BehID_3", 0),
                  XShortField("ParticipatingGPIOs", 0),
                  XByteField("EventAttributes", 0),
                  XShortField("reserved_evb", 0),
                ]

    def extract_padding(self, p):
        return "", p

class ModulePIB(Packet):
    """
        Simple Module PIB Decoder.
            /!\ A wrong slice would produce 'bad' results
    """
    name = "ModulePIB"
    def __init__(self, packet="", offset = 0x0, length = 0x400):
        self.__offset = offset
        self.__length = length
        self.fields_desc=[ ConditionalField( XByteField("FirmwareMajorVersion", 0x00),
                        lambda pkt:(0x0 == self.__offset and 0x1 <= self.__offset+self.__length) ), # The following conditional fiels just check if the current field fits in the data range
                  ConditionalField( XByteField("PIBMinorVersion", 0x00),
                        lambda pkt:(0x1 >= self.__offset and 0x2 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("reserved_1" , 0x0000),
                        lambda pkt:(0x2 >= self.__offset and 0x4 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("PIBLength" , 0x0000),
                        lambda pkt:(0x4 >= self.__offset and 0x6 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("reserved_2" , 0x0000),
                        lambda pkt:(0x6 >= self.__offset and 0x8 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("checksumPIB", None),
                        lambda pkt:(0x8 >= self.__offset and 0xC <= self.__offset+self.__length) ),
                  ConditionalField( MACField("PIBMACAddr", "00:00:00:00:00:00"),
                        lambda pkt:(0xC >= self.__offset and 0x12 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("DAK",
                                "\x00"*16,
                                16),
                        lambda pkt:(0x12 >= self.__offset and 0x22 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("reserved_3" , 0x0000),
                        lambda pkt:(0x22 >= self.__offset and 0x24 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("ManufactorID",
                                "\x00"*64,
                                64),
                        lambda pkt:(0x24 >= self.__offset and 0x64 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("NMK",
                                "\x00"*16,
                                16),
                        lambda pkt:(0x64 >= self.__offset and 0x74 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("UserID",
                                "\x00"*64,
                                64),
                        lambda pkt:(0x74 >= self.__offset and 0xB4 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("AVLN_ID",
                                "\x00"*64,
                                64),
                        lambda pkt:(0xB4 >= self.__offset and 0xF4 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("CCoSelection", 0x00),
                        lambda pkt:(0xF4 >= self.__offset and 0xF5 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("CoExistSelection", 0x00),
                        lambda pkt:(0xF5 >= self.__offset and 0xF6 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PLFreqSelection", 0x00),
                        lambda pkt:(0xF6 >= self.__offset and 0xF7 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("H3CDowngradeShld", 0x00),
                        lambda pkt:(0xF7 >= self.__offset and 0xF8 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("PreferredNID",
                                "\x00"*7,
                                7),
                        lambda pkt:(0xF8 >= self.__offset and 0xFF <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("AutoFWUpgradeable", 0x00),
                        lambda pkt:(0xFF >= self.__offset and 0x100 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("MDUConfiguration", 0x00),
                        lambda pkt:(0x100 >= self.__offset and 0x101 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("MDURole", 0x00),
                        lambda pkt:(0x101 >= self.__offset and 0x102 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("SnifferEnabled", 0x00),
                        lambda pkt:(0x102 >= self.__offset and 0x103 <= self.__offset+self.__length) ),
                  ConditionalField( MACField("SnifferMACAddrRetrn", "00:00:00:00:00:00"),
                        lambda pkt:(0x103 >= self.__offset and 0x109 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("WireTapEnable", 0x00),
                        lambda pkt:(0x109 >= self.__offset and 0x10A <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("reserved_4" , 0x0000),
                        lambda pkt:(0x10A >= self.__offset and 0x10C <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("StaticNetworkEnabled" , 0x00),
                        lambda pkt:(0x10C >= self.__offset and 0x10D <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("LD_TEI" , 0x00),
                        lambda pkt:(0x10D >= self.__offset and 0x10E <= self.__offset+self.__length) ),
                  ConditionalField( MACField("CCo_MACAdd", "00:00:00:00:00:00"),
                        lambda pkt:(0x10E >= self.__offset and 0x114 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("SNID", 0x00),
                        lambda pkt:(0x114 >= self.__offset and 0x115 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("NumOfPeerNodes", 0x00),
                        lambda pkt:(0x115 >= self.__offset and 0x116 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("PeerNodes", "", PeerNode, length_from=lambda x: 56),
                        lambda pkt:(0x116 >= self.__offset and 0x11C <= self.__offset+self.__length) ), 
                  ConditionalField( StrFixedLenField("reserved_5",
                                "\x00"*62,
                                62),
                        lambda pkt:(0x146 >= self.__offset and 0x14e <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OverideModeDefaults" , 0x00),
                        lambda pkt:(0x18C >= self.__offset and 0x18D <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("DisableFlowControl" , 0x00),
                        lambda pkt:(0x18D >= self.__offset and 0x18E <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("AdvertisementCapabilities" , 0x00),
                        lambda pkt:(0x18E >= self.__offset and 0x18F <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OverrideMeteringDefaults" , 0x00),
                        lambda pkt:(0x18F >= self.__offset and 0x190 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("MaxFramesPerSec" , 0),
                        lambda pkt:(0x190 >= self.__offset and 0x194 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("DisableAutoNegotiation" , 0x00),
                        lambda pkt:(0x194 >= self.__offset and 0x195 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnetSpeedSetting" , 0x00),
                        lambda pkt:(0x195 >= self.__offset and 0x196 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnetDuplexSetting" , 0x00),
                        lambda pkt:(0x196 >= self.__offset and 0x197 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("DisableTxFlowControl" , 0x00),
                        lambda pkt:(0x197 >= self.__offset and 0x198 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("DisableRxFlowControl" , 0x00),
                        lambda pkt:(0x198 >= self.__offset and 0x199 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PhyAddressSelection" , 0x00),
                        lambda pkt:(0x199 >= self.__offset and 0x19A <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PhyAddressSelection_Data" , 0x00),
                        lambda pkt:(0x19A >= self.__offset and 0x19B <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("reserved_6" , 0x00),
                        lambda pkt:(0x19B >= self.__offset and 0x19C <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("Force33MHz" , 0x00),
                        lambda pkt:(0x19C >= self.__offset and 0x19D <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("LinkStatusOnPowerline" , 0x00),
                        lambda pkt:(0x19D >= self.__offset and 0x19E <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OverrideIdDefaults" , 0x00),
                        lambda pkt:(0x19E >= self.__offset and 0x19F <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OverrideSubIdDefaults" , 0x00),
                        lambda pkt:(0x19F >= self.__offset and 0x1A0 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("PCIDeviceID" , 0x0000),
                        lambda pkt:(0x1A0 >= self.__offset and 0x1A2 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("PCIVendorID" , 0x0000),
                        lambda pkt:(0x1A2 >= self.__offset and 0x1A4 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("reserved_7" , 0x00),
                        lambda pkt:(0x1A4 >= self.__offset and 0x1A5 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PCIClassCode" , 0x00),
                        lambda pkt:(0x1A5 >= self.__offset and 0x1A6 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PCIClassCodeSubClass" , 0x00),
                        lambda pkt:(0x1A6 >= self.__offset and 0x1A7 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PCIRevisionID" , 0x00),
                        lambda pkt:(0x1A7 >= self.__offset and 0x1A8 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("PCISubsystemID" , 0x0000),
                        lambda pkt:(0x1A8 >= self.__offset and 0x1AA <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("PCISybsystemVendorID" , 0x0000),
                        lambda pkt:(0x1AA >= self.__offset and 0x1AC <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_8",
                                "\x00"*64,
                                64),
                        lambda pkt:(0x1AC >= self.__offset and 0x1EC <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OverrideIGMPDefaults" , 0x00),
                        lambda pkt:(0x1EC >= self.__offset and 0x1ED <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ConfigFlags" , 0x00),
                        lambda pkt:(0x1ED >= self.__offset and 0x1EE <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("NumCpToSend_PLFrames" , 0x00),
                        lambda pkt:(0x1EE >= self.__offset and 0x1EF <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_9",
                                "\x00"*29,
                                29),
                        lambda pkt:(0x1EF >= self.__offset and 0x20C <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("UniCastPriority" , 0x00),
                        lambda pkt:(0x20C >= self.__offset and 0x20D <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("McastPriority" , 0x00),
                        lambda pkt:(0x20D >= self.__offset and 0x20E <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("IGMPPriority" , 0x00),
                        lambda pkt:(0x20E >= self.__offset and 0x20F <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("AVStreamPriority" , 0x00),
                        lambda pkt:(0x20F >= self.__offset and 0x210 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("PriorityTTL_0" , 0),
                        lambda pkt:(0x210 >= self.__offset and 0x214 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("PriorityTTL_1" , 0),
                        lambda pkt:(0x214 >= self.__offset and 0x218 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("PriorityTTL_2" , 0),
                        lambda pkt:(0x218 >= self.__offset and 0x21C <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("PriorityTTL_3" , 0),
                        lambda pkt:(0x21C >= self.__offset and 0x220 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnableVLANOver" , 0x00),
                        lambda pkt:(0x220 >= self.__offset and 0x221 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnableTOSOver" , 0x00),
                        lambda pkt:(0x221 >= self.__offset and 0x222 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("reserved_10" , 0x0000),
                        lambda pkt:(0x222 >= self.__offset and 0x224 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("VLANPrioTOSPrecMatrix" , 0),
                        lambda pkt:(0x224 >= self.__offset and 0x228 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("NumClassifierPriorityMaps" , 0),
                        lambda pkt:(0x228 >= self.__offset and 0x22C <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("NumAutoConnections" , 0),
                        lambda pkt:(0x22C >= self.__offset and 0x230 <= self.__offset+self.__length) ), 
                  ConditionalField( PacketListField("ClassifierPriorityMaps", "", ClassifierPriorityMap, length_from=lambda x: 224),
                        lambda pkt:(0x230 >= self.__offset and 0x244 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("AutoConnections", "", AutoConnection, length_from=lambda x: 1600),
                        lambda pkt:(0x310 >= self.__offset and 0x36e <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("NumberOfConfigEntries" , 0x00),
                        lambda pkt:(0x950 >= self.__offset and 0x951 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("AggregateConfigEntries", "", AggregateConfigEntrie, length_from=lambda x: 16),
                        lambda pkt:(0x951 >= self.__offset and 0x961 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("RSVD_CustomAggregationParameters", "", RSVD_CustomAggregationParameter, length_from=lambda x: 48),
                        lambda pkt:(0x961 >= self.__offset and 0x991 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_11",
                                "\x00"*123,
                                123),
                        lambda pkt:(0x991 >= self.__offset and 0xA0C <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("ToneMaskType" , 0),
                        lambda pkt:(0xA0C >= self.__offset and 0xA10 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("ToneMaskEnabled" , 0),
                        lambda pkt:(0xA10 >= self.__offset and 0xA14 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("StartTone" , 0),
                        lambda pkt:(0xA14 >= self.__offset and 0xA18 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("EndTone" , 0),
                        lambda pkt:(0xA18 >= self.__offset and 0xA1C <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_12",
                                "\x00"*12,
                                12),
                        lambda pkt:(0xA1C >= self.__offset and 0xA28 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("PsdIndex" , 0),
                        lambda pkt:(0xA28 >= self.__offset and 0xA2C <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("TxPrescalerType" , 0),
                        lambda pkt:(0xA2C >= self.__offset and 0xA30 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("PrescalerValues", "", PrescalerValue, length_from=lambda x: 3600),
                        lambda pkt:(0xA30 >= self.__offset and 0xA34 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_13",
                                "\x00"*1484,
                                1484),
                        lambda pkt:(0x1840 >= self.__offset and 0x1E0C <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("AllowNEKRotation" , 0),
                        lambda pkt:(0x1E0C >= self.__offset and 0x1E10 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("OverrideLocalNEK" , 0),
                        lambda pkt:(0x1E10 >= self.__offset and 0x1E14 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("LocalNEKToUse",
                                "\x00"*16,
                                16),
                        lambda pkt:(0x1E14 >= self.__offset and 0x1E24 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("OverrideNEKRotationTimer" , 0),
                        lambda pkt:(0x1E24 >= self.__offset and 0x1E28 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("NEKRotationTime_Min" , 0),
                        lambda pkt:(0x1E28 >= self.__offset and 0x1E2C <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_14",
                                "\x00"*96,
                                96),
                        lambda pkt:(0x1E2C >= self.__offset and 0x1E8C <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("AVLNMembership" , 0),
                        lambda pkt:(0x1E8C >= self.__offset and 0x1E90 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("SimpleConnectTimeout" , 0),
                        lambda pkt:(0x1E90 >= self.__offset and 0x1E94 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnableLEDThroughputIndicate" , 0),
                        lambda pkt:(0x1E94 >= self.__offset and 0x1E95 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("MidLEDThroughputThreshold_Mbps" , 0),
                        lambda pkt:(0x1E95 >= self.__offset and 0x1E96 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("HighLEDThroughputThreshold_Mbps" , 0),
                        lambda pkt:(0x1E96 >= self.__offset and 0x1E97 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("reserved_15" , 0),
                        lambda pkt:(0x1E97 >= self.__offset and 0x1E98 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnableUnicastQuieriesToMember" , 0),
                        lambda pkt:(0x1E98 >= self.__offset and 0x1E99 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("DisableMLDGroupIDCheckInMAC" , 0),          
                        lambda pkt:(0x1E99 >= self.__offset and 0x1E9A <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("EnableReportsToNonQuerierHosts" , 0),
                        lambda pkt:(0x1E9A >= self.__offset and 0x1E9C <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("DisableExpireGroupMembershipInterval" , 0),
                        lambda pkt:(0x1E9C >= self.__offset and 0x1EA0 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("DisableLEDTestLights" , 0),
                        lambda pkt:(0x1EA0 >= self.__offset and 0x1EA4 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("GPIOMaps", "", GPIOMap, length_from=lambda x: 12),
                        lambda pkt:(0x1EA4 >= self.__offset and 0x1EB0 <= self.__offset+self.__length) ),
                  ConditionalField( XLongField("reserved_16" , 0),
                        lambda pkt:(0x1EB0 >= self.__offset and 0x1EB8 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnableTrafficClass_DSCPOver" , 0),
                        lambda pkt:(0x1EB8 >= self.__offset and 0x1EB9 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("TrafficClass_DSCPMatrices",
                                "\x00"*64,
                                64),
                        lambda pkt:(0x1EB9 >= self.__offset and 0x1EF9 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("GPIOControl" , 0),
                        lambda pkt:(0x1EF9 >= self.__offset and 0x1EFA <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("LEDControl",
                                "\x00"*32,
                                32),
                        lambda pkt:(0x1EFA >= self.__offset and 0x1F1A <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("OverrideMinButtonPressHoldTime" , 0),
                        lambda pkt:(0x1F1A >= self.__offset and 0x1F1E <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("MinButtonPressHoldTime" , 0),
                        lambda pkt:(0x1F1E >= self.__offset and 0x1F22 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_17",
                                "\x00"*22,
                                22),
                        lambda pkt:(0x1F22 >= self.__offset and 0x1F38 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("MemoryProfile" , 0),
                        lambda pkt:(0x1F38 >= self.__offset and 0x1F3C <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("DisableAllLEDFlashOnWarmReboot" , 0),
                        lambda pkt:(0x1F3C >= self.__offset and 0x1F40 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("UplinkLimit_bps" , 0),
                        lambda pkt:(0x1F40 >= self.__offset and 0x1F44 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("DownlinkLimit_bps" , 0),
                        lambda pkt:(0x1F44 >= self.__offset and 0x1F48 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("MDUStaticSNID" , 0),
                        lambda pkt:(0x1F48 >= self.__offset and 0x1F4C <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("MitigateEnabled" , 0),
                        lambda pkt:(0x1F4C >= self.__offset and 0x1F4D <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("CorrelThreshold" , 0),
                        lambda pkt:(0x1F4D >= self.__offset and 0x1F51 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("ScaledTxGain" , 0),
                        lambda pkt:(0x1F51 >= self.__offset and 0x1F55 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ResourceThresholdEnabled" , 0),
                        lambda pkt:(0x1F55 >= self.__offset and 0x1F56 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("ReservedPercentageForCaps", "", ReservedPercentageForCap, length_from=lambda x: 4),
                        lambda pkt:(0x1F56 >= self.__offset and 0x1F5A <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PowerSavingMode" , 0),
                        lambda pkt:(0x1F5A >= self.__offset and 0x1F5B <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PowerLEDDutyCycle" , 0),
                        lambda pkt:(0x1F5B >= self.__offset and 0x1F5C <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("reserved_18" , 0),
                        lambda pkt:(0x1F5C >= self.__offset and 0x1F5E <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("LinkUpDurationBeforeReset_ms" , 0),
                        lambda pkt:(0x1F5E >= self.__offset and 0x1F62 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("PowerLEDPeriod_ms" , 0),
                        lambda pkt:(0x1F62 >= self.__offset and 0x1F66 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("LinkDownDurationBeforeLowPowerMode_ms" , 0),
                        lambda pkt:(0x1F66 >= self.__offset and 0x1F6A <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("reserved_19" , 0),
                        lambda pkt:(0x1F6A >= self.__offset and 0x1F6E <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("AfeGainBusMode" , 0),
                        lambda pkt:(0x1F6E >= self.__offset and 0x1F6F <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("EnableDynamicPsd" , 0),
                        lambda pkt:(0x1F6F >= self.__offset and 0x1F70 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ReservedPercentageForTxStreams" , 0),
                        lambda pkt:(0x1F70 >= self.__offset and 0x1F71 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ReservedPercentageForRxStreams" , 0),
                        lambda pkt:(0x1F71 >= self.__offset and 0x1F72 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_20",
                                "\x00"*22,
                                22),
                        lambda pkt:(0x1F72 >= self.__offset and 0x1F88 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("LegacyNetworkUpgradeEnable" , 0),
                        lambda pkt:(0x1F88 >= self.__offset and 0x1F8C <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("unknown" , 0),
                        lambda pkt:(0x1F8C >= self.__offset and 0x1F90 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("MMETTL_us" , 0),
                        lambda pkt:(0x1F90 >= self.__offset and 0x1F94 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("ConfigBits", "", ConfigBit, length_from=lambda x: 2),
                        lambda pkt:(0x1F94 >= self.__offset and 0x1F96 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("TxToneMapExpiry_ms" , 0),
                        lambda pkt:(0x1F96 >= self.__offset and 0x1F9A <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("RxToneMapExpiry_ms" , 0),
                        lambda pkt:(0x1F9A >= self.__offset and 0x1F9E <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("TimeoutToResound_ms" , 0),
                        lambda pkt:(0x1F9E >= self.__offset and 0x1FA2 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("MissingSackThresholdForUnplugDetection" , 0),
                        lambda pkt:(0x1FA2 >= self.__offset and 0x1FA6 <= self.__offset+self.__length) ),
                  ConditionalField( LEIntField("UnplugTimeout_ms" , 0),
                        lambda pkt:(0x1FA6 >= self.__offset and 0x1FAA <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("ContentionWindowTableES", "", ContentionWindowTable, length_from=lambda x: 8),
                        lambda pkt:(0x1FAA >= self.__offset and 0x1FB2 <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("BackoffDeferalCountTableES", "", BackoffDeferalCountTable, length_from=lambda x: 4),
                        lambda pkt:(0x1FB2 >= self.__offset and 0x1FB6 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("GoodSoundCountThreshold" , 0),
                        lambda pkt:(0x1FB6 >= self.__offset and 0x1FB7 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("SoundCountThreshold_GoodSoundCountPass" , 0),
                        lambda pkt:(0x1FB7 >= self.__offset and 0x1FB8 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("SoundCountThreshold_GoodSoundCountFail" , 0),
                        lambda pkt:(0x1FB8 >= self.__offset and 0x1FB9 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("reserved_21" , 0),
                        lambda pkt:(0x1FB9 >= self.__offset and 0x1FBB <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ExclusiveTxPbs_percentage" , 0),
                        lambda pkt:(0x1FBB >= self.__offset and 0x1FBC <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ExclusiveRxPbs_percentage" , 0),
                        lambda pkt:(0x1FBC >= self.__offset and 0x1FBD <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OptimizationBackwardCompatible" , 0),
                        lambda pkt:(0x1FBD >= self.__offset and 0x1FBE <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("reserved_21" , 0),
                        lambda pkt:(0x1FBE >= self.__offset and 0x1FBF <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("MaxPbsPerSymbol" , 0),
                        lambda pkt:(0x1FBF >= self.__offset and 0x1FC0 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("MaxModulation" , 0),                      
                        lambda pkt:(0x1FC0 >= self.__offset and 0x1FC1 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ContinuousRx" , 0),
                        lambda pkt:(0x1FC1 >= self.__offset and 0x1FC2 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_22",
                                "\x00"*6,
                                6),
                        lambda pkt:(0x1FC2 >= self.__offset and 0x1FC8 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("PBControlStatus" , 0),
                        lambda pkt:(0x1FC8 >= self.__offset and 0x1FC9 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("STAMembershipMaskEnabled" , 0),
                        lambda pkt:(0x1FC9 >= self.__offset and 0x1FCA <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ExitDefaultEnabled" , 0),               
                        lambda pkt:(0x1FCA >= self.__offset and 0x1FCB <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("RejectDefaultEnabled" , 0),     
                        lambda pkt:(0x1FCB >= self.__offset and 0x1FCC <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ChainingEnabled" , 0),   
                        lambda pkt:(0x1FCC >= self.__offset and 0x1FCD <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("VendorSpecificNMK",
                                "\x00"*16,
                                16),
                        lambda pkt:(0x1FCD >= self.__offset and 0x1FDD <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("LocalMACAddressLimit" , 0),
                        lambda pkt:(0x1FDD >= self.__offset and 0x1FDE <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OverrideBridgeTableAgingTime" , 0),
                        lambda pkt:(0x1FDE >= self.__offset and 0x1FDF <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("LocalBridgeTableAgingTime_min" , 0),
                        lambda pkt:(0x1FDF >= self.__offset and 0x1FE1 <= self.__offset+self.__length) ),
                  ConditionalField( XShortField("RemoteBridgeTableAgingTime_min" , 0),
                        lambda pkt:(0x1FE1 >= self.__offset and 0x1FE3 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("PhySyncReference" , 0),
                        lambda pkt:(0x1FE3 >= self.__offset and 0x1FE7 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("reserved_23" , 0),
                        lambda pkt:(0x1FE7 >= self.__offset and 0x1FE8 <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("reserved_24" , 0),
                        lambda pkt:(0x1FE8 >= self.__offset and 0x1FEC <= self.__offset+self.__length) ),
                  ConditionalField( XIntField("reserved_25" , 0),
                        lambda pkt:(0x1FEC >= self.__offset and 0x1FF0 <= self.__offset+self.__length) ),
                  ConditionalField( StrFixedLenField("reserved_26",
                                "\x00"*24,
                                24),
                        lambda pkt:(0x1FF0 >= self.__offset and 0x2008 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("OverrideDefaultLedEventBehavior" , 0x80),
                        lambda pkt:(0x2008 >= self.__offset and 0x2009 <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("ReportToHostInfo" , 0),
                        lambda pkt:(0x2009 >= self.__offset and 0x200A <= self.__offset+self.__length) ),
                  ConditionalField( X3BytesField("reserved_27" , 0),
                        lambda pkt:(0x200A >= self.__offset and 0x200D <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("NumBehaviors" , 0),
                        lambda pkt:(0x200D >= self.__offset and 0x200E <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("BehaviorBlockArrayES", "", BehaviorBlockArray, length_from=lambda x: 1200),
                        lambda pkt:(0x200E >= self.__offset and 0x24BE <= self.__offset+self.__length) ),
                  ConditionalField( XByteField("NumEvents" , 0),
                        lambda pkt:(0x24BE >= self.__offset and 0x24BF <= self.__offset+self.__length) ),
                  ConditionalField( PacketListField("EventBlockArrayES", "", EventBlockArray, length_from=lambda x: 550),
                        lambda pkt:(0x24BF >= self.__offset and 0x26E5 <= self.__offset+self.__length) ),
                ]

        return super(ModulePIB,self).__init__(packet)


######################################################################
# Read MAC Memory
#####################################################################

StartMACCodes = { 0x00 : "Success" } 

class StartMACRequest(Packet):
    name = "StartMACRequest"
    fields_desc=[ ByteEnumField("ModuleID", 0x00, StartMACCodes),
                  X3BytesField("reserver_1", 0x000000),
                  LEIntField("ImgLoadStartAddr" , 0x00000000),
                  LEIntField("ImgLength", 0x00000000),
                  LEIntField("ImgCheckSum", 0x00000000),
                  LEIntField("ImgStartAddr", 0x00000000),
                ]

class StartMACConfirmation(Packet):
    name = "StartMACConfirmation"
    fields_desc=[ ByteEnumField("Status", 0x00, StartMACCodes),
                  XByteField("ModuleID", 0x00),
                ]

######################################################################
# Reset Device
######################################################################

ResetDeviceCodes = { 0x00 : "Success" }

class ResetDeviceRequest(Packet):
    name = "ResetDeviceRequest"
    fields_desc=[ ]

class ResetDeviceConfirmation(Packet):
    name = "ResetDeviceConfirmation"
    fields_desc=[ ByteEnumField("Status", 0x00, ResetDeviceCodes) ]

######################################################################
# Read Configuration Block
######################################################################

ReadConfBlockCodes = { 0x00 : "Success" }

class ReadConfBlockRequest(Packet):
    name = "ReadConfBlockRequest"
    fields_desc=[ ]

CBImgTCodes = { 0x00 : "Generic Image",
                0x01 : "Synopsis configuration",
                0x02 : "Denali configuration",
                0x03 : "Denali applet",
                0x04 : "Runtime firmware",
                0x05 : "OAS client",
                0x06 : "Custom image",
                0x07 : "Memory control applet",
                0x08 : "Power management applet",
                0x09 : "OAS client IP stack",
                0x0A : "OAS client TR069",
                0x0B : "SoftLoader",
                0x0C : "Flash layout",
                0x0D : "Unknown",
                0x0E : "Chain manifest",
                0x0F : "Runtime parameters",
                0x10 : "Custom module in scratch",
                0x11 : "Custom module update applet" }

class ConfBlock(Packet):
    name = "ConfBlock"
    fields_desc=[ LEIntField("HeaderVersionNum", 0),
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
    fields_desc=[ ByteEnumField("Status", 0x00, ReadConfBlockCodes),
                  FieldLenField("BlockLen", None, count_of="ConfigurationBlock", fmt="B"),
                  PacketListField("ConfigurationBlock", None, ConfBlock, length_from=lambda pkt:pkt.BlockLen) ]


######################################################################
# Write Module Data to NVM
######################################################################

class WriteModuleData2NVMRequest(Packet):
    name = "WriteModuleData2NVMRequest"
    fields_desc=[ ByteEnumField("ModuleID", 0x02, ModuleIDList) ]

class WriteModuleData2NVMConfirmation(Packet):
    name = "WriteModuleData2NVMConfirmation"
    fields_desc=[ ByteEnumField("Status", 0x0, StatusCodes),
                  ByteEnumField("ModuleID", 0x02, ModuleIDList) ]

############################ END ######################################

class HomePlugAV(Packet):
    """
        HomePlugAV Packet - by default => gets devices informations
    """
    name = "HomePlugAV "
    fields_desc=[ MACManagementHeader,
                ConditionalField(XShortField("FragmentInfo", 0x0), FragmentCond), # Fragmentation Field
                VendorMME ]

    def answers(self, other):
        return ( isinstance(self, HomePlugAV ) )

bind_layers( Ether, HomePlugAV, { "type":0x88e1 } )

#   +----------+------------+--------------------+
#   | Ethernet | HomePlugAV | Elements + Payload |
#   +----------+------------+--------------------+
bind_layers( HomePlugAV, GetDeviceVersion, { "HPtype" : 0xA001 } )
bind_layers( HomePlugAV, StartMACRequest, { "HPtype" : 0xA00C } )
bind_layers( HomePlugAV, StartMACConfirmation, { "HPtype" : 0xA00D } )
bind_layers( HomePlugAV, ResetDeviceRequest, { "HPtype" : 0xA01C } )
bind_layers( HomePlugAV, ResetDeviceConfirmation, { "HPtype" : 0xA01D } )
bind_layers( HomePlugAV, NetworkInformationRequest, { "HPtype" : 0xA038 } )
bind_layers( HomePlugAV, ReadMACMemoryRequest, { "HPtype" : 0xA008 } )
bind_layers( HomePlugAV, ReadMACMemoryConfirmation, { "HPtype" : 0xA009 } )
bind_layers( HomePlugAV, ReadModuleDataRequest, { "HPtype" : 0xA024 } )
bind_layers( HomePlugAV, ReadModuleDataConfirmation, { "HPtype" : 0xA025 } )
bind_layers( HomePlugAV, WriteModuleDataRequest, { "HPtype" : 0xA020 } ) 
bind_layers( HomePlugAV, WriteModuleData2NVMRequest, { "HPtype" : 0xA028 } ) 
bind_layers( HomePlugAV, WriteModuleData2NVMConfirmation, { "HPtype" : 0xA029 } )
bind_layers( HomePlugAV, NetworkInfoConfirmationV10, { "HPtype" : 0xA039, "version" : 0x00 } )
bind_layers( HomePlugAV, NetworkInfoConfirmationV11, { "HPtype" : 0xA039, "version" : 0x01 } )
bind_layers( NetworkInfoConfirmationV10, NetworkInfoV10, { "HPtype" : 0xA039, "version" : 0x00 } )
bind_layers( NetworkInfoConfirmationV11, NetworkInfoV11, { "HPtype" : 0xA039, "version" : 0x01 } )
bind_layers( HomePlugAV, HostActionRequired, { "HPtype" : 0xA062 } )
bind_layers( HomePlugAV, LoopbackRequest, { "HPtype" : 0xA048 } )
bind_layers( HomePlugAV, LoopbackConfirmation, { "HPtype" : 0xA049 } )
bind_layers( HomePlugAV, SetEncryptionKeyRequest, { "HPtype" : 0xA050 } )
bind_layers( HomePlugAV, SetEncryptionKeyConfirmation, { "HPtype" : 0xA051 } )
bind_layers( HomePlugAV, ReadConfBlockRequest, { "HPtype" : 0xA058 } )
bind_layers( HomePlugAV, ReadConfBlockConfirmation, { "HPtype" : 0xA059 } ) 
bind_layers( HomePlugAV, QUAResetFactoryConfirm, { "HPtype" : 0xA07D } )
bind_layers( HomePlugAV, GetNVMParametersRequest, { "HPtype" : 0xA010 } )
bind_layers( HomePlugAV, GetNVMParametersConfirmation, { "HPtype" : 0xA011 } )
bind_layers( HomePlugAV, SnifferRequest,  { "HPtype" : 0xA034 } )
bind_layers( HomePlugAV, SnifferConfirmation,  { "HPtype" : 0xA035 } )
bind_layers( HomePlugAV, SnifferIndicate,  { "HPtype" : 0xA036 } )

"""
    Credit song : "Western Spaguetti - We are terrorists"
""" 
