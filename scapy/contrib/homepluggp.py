# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = HomePlugGP Layer
# scapy.contrib.status = loads

from __future__ import absolute_import

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, FieldLenField, \
    MACField, PacketListField, ShortField, \
    StrFixedLenField, XIntField, PacketField \

# This layer extends HomePlug AV one
from scapy.contrib.homeplugav import HomePlugAV, QualcommTypeList

# Copyright (C) HomePlugGP Layer for Scapy by FlUxIuS (Sebastien Dudek)
# As HomePlug GreenPHY is a subset of HomePlug AV, that is why we use
# HomePlugAV layer as a base here.

HomePlugGPTypes = {0x6008: "CM_SET_KEY_REQ",
                   0x6009: "CM_SET_KEY_CNF",
                   0x6064: "CM_SLAC_PARM_REQ",
                   0x6065: "CM_SLAC_PARM_CNF",
                   0x606e: "CM_ATTEN_CHAR_IN",
                   0x606a: "CM_START_ATTEN_CHAR_IND",
                   0x606f: "CM_ATTEN_CHAR_RSP",
                   0x6076: "CM_MNBC_SOUND_IND",
                   0x607c: "CM_SLAC_MATCH_REQ",
                   0x607d: "CM_SLAC_MATCH_CNF",
                   0x6086: "CM_ATTENUATION_CHARACTERISTICS_MME"}

QualcommTypeList.update(HomePlugGPTypes)

HPGP_codes = {0x0: "Success"}

KeyType_list = {0x01: "NMK (AES-128)"}

######################################################################
# SLAC operations
######################################################################


class CM_SLAC_PARM_REQ(Packet):
    name = "CM_SLAC_PARM_REQ"
    fields_desc = [ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   StrFixedLenField("RunID", b"\x00" * 8, 8)]


class CM_SLAC_PARM_CNF(Packet):
    name = "CM_SLAC_PARM_CNF"
    fields_desc = [MACField("MSoundTargetMAC", "00:00:00:00:00:00"),
                   ByteField("NumberMSounds", 0x0),
                   ByteField("TimeOut", 0x0),
                   ByteField("ResponseType", 0x0),
                   MACField("ForwardingSTA", "00:00:00:00:00:00"),
                   ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   StrFixedLenField("RunID", b"\x00" * 8, 8)]


class HPGP_GROUP(Packet):
    name = "HPGP_GROUP"
    fields_desc = [ByteField("group", 0x0)]

    def extract_padding(self, p):
        return "", p


class VS_ATTENUATION_CHARACTERISTICS_MME(Packet):
    name = "VS_ATTENUATION_CHARACTERISTICS_MME"
    fields_desc = [MACField("EVMACAddress", "00:00:00:00:00:00"),
                   FieldLenField("NumberOfGroups", None,
                                 count_of="Groups", fmt="B"),
                   ByteField("NumberOfCarrierPerGroupe", 0),
                   StrFixedLenField("Reserved", b"\x00" * 7, 7),
                   PacketListField("Groups", "", HPGP_GROUP,
                                   length_from=lambda pkt: pkt.NumberOfGroups)]


class CM_ATTENUATION_CHARACTERISTICS_MME(Packet):
    name = "CM_ATTENUATION_CHARACTERISTICS_MME"
    fields_desc = [MACField("EVMACAddress", "00:00:00:00:00:00"),
                   FieldLenField("NumberOfGroups", None, count_of="Groups",
                                 fmt="B"),
                   ByteField("NumberOfCarrierPerGroupe", 0),
                   PacketListField("Groups", "", HPGP_GROUP,
                                   length_from=lambda pkt: pkt.NumberOfGroups)]


class CM_ATTEN_CHAR_IND(Packet):
    name = "CM_ATTEN_CHAR_IND"
    fields_desc = [ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   MACField("SourceAdress", "00:00:00:00:00:00"),
                   StrFixedLenField("RunID", b"\x00" * 8, 8),
                   StrFixedLenField("SourceID", b"\x00" * 17, 17),
                   StrFixedLenField("ResponseID", b"\x00" * 17, 17),
                   ByteField("NumberOfSounds", 0x0),
                   FieldLenField("NumberOfGroups", None, count_of="Groups",
                                 fmt="B"),
                   PacketListField("Groups", "", HPGP_GROUP,
                                   length_from=lambda pkt: pkt.NumberOfGroups)]


class CM_ATTEN_CHAR_RSP(Packet):
    name = "CM_ATTEN_CHAR_RSP"
    fields_desc = [ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   MACField("SourceAdress", "00:00:00:00:00:00"),
                   StrFixedLenField("RunID", b"\x00" * 8, 8),
                   StrFixedLenField("SourceID", b"\x00" * 17, 17),
                   StrFixedLenField("ResponseID", b"\x00" * 17, 17),
                   ByteEnumField("Result", 0x0, HPGP_codes)]


class SLAC_varfield(Packet):
    name = "SLAC_varfield"
    fields_desc = [StrFixedLenField("EVID", b"\x00" * 17, 17),
                   MACField("EVMAC", "00:00:00:00:00:00"),
                   StrFixedLenField("EVSEID", b"\x00" * 17, 17),
                   MACField("EVSEMAC", "00:00:00:00:00:00"),
                   StrFixedLenField("RunID", b"\x00" * 8, 8),
                   StrFixedLenField("RSVD", b"\x00" * 8, 8)]


class CM_SLAC_MATCH_REQ(Packet):
    name = "CM_SLAC_MATCH_REQ"
    fields_desc = [ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   FieldLenField("MatchVariableFieldLen", None,
                                 length_of="VariableField", fmt="<H"),
                   PacketField("VariableField",
                               SLAC_varfield(),
                               SLAC_varfield)]


class SLAC_varfield_cnf(Packet):
    name = "SLAC_varfield"
    fields_desc = [StrFixedLenField("EVID", b"\x00" * 17, 17),
                   MACField("EVMAC", "00:00:00:00:00:00"),
                   StrFixedLenField("EVSEID", b"\x00" * 17, 17),
                   MACField("EVSEMAC", "00:00:00:00:00:00"),
                   StrFixedLenField("RunID", b"\x00" * 8, 8),
                   StrFixedLenField("RSVD", b"\x00" * 8, 8),
                   StrFixedLenField("NetworkID", b"\x00" * 7, 7),
                   ByteField("Reserved", 0x0),
                   StrFixedLenField("NMK", b"\x00" * 16, 16)]


class CM_SLAC_MATCH_CNF(Packet):
    name = "CM_SLAC_MATCH_CNF"
    fields_desc = [ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   FieldLenField("MatchVariableFieldLen", None,
                                 length_of="VariableField", fmt="<H"),
                   PacketField("VariableField",
                               SLAC_varfield_cnf(),
                               SLAC_varfield_cnf)]


class CM_START_ATTEN_CHAR_IND(Packet):
    name = "CM_START_ATTEN_CHAR_IND"
    fields_desc = [ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   ByteField("NumberOfSounds", 0x0),
                   ByteField("TimeOut", 0x0),
                   ByteField("ResponseType", 0x0),
                   MACField("ForwardingSTA", "00:00:00:00:00:00"),
                   StrFixedLenField("RunID", b"\x00" * 8, 8)]


class CM_MNBC_SOUND_IND(Packet):
    name = "CM_MNBC_SOUND_IND"
    fields_desc = [ByteField("ApplicationType", 0x0),
                   ByteField("SecurityType", 0x0),
                   StrFixedLenField("SenderID", b"\x00" * 17, 17),
                   ByteField("Countdown", 0x0),
                   StrFixedLenField("RunID", b"\x00" * 8, 8),
                   StrFixedLenField("RSVD", b"\x00" * 8, 8),
                   StrFixedLenField("RandomValue", b"\x00" * 16, 16)]


######################################################################
# Set keys for GP
######################################################################


class CM_SET_KEY_REQ(Packet):
    name = "CM_SET_KEY_REQ"
    fields_desc = [ByteEnumField("KeyType", 0x0, KeyType_list),
                   XIntField("MyNonce", 0),
                   XIntField("YourNonce", 0),
                   ByteField("PID", 0),
                   ShortField("ProtoRunNumber", 0),
                   ByteField("ProtoMessNumber", 0),
                   ByteField("CCoCapability", 0),
                   StrFixedLenField("NetworkID", b"\x00" * 7, 7),
                   ByteField("NewEncKeySelect", 0),
                   StrFixedLenField("NewKey", b"\x00" * 16, 16)]


class CM_SET_KEY_CNF(Packet):
    name = "CM_SET_KEY_CNF"
    fields_desc = [ByteEnumField("Result", 0x0, HPGP_codes),
                   XIntField("MyNonce", 0),
                   XIntField("YourNonce", 0),
                   ByteField("PID", 0),
                   ShortField("ProtoRunNumber", 0),
                   ByteField("ProtoMessNumber", 0),
                   ByteField("CCoCapability", 0)]


# END #


bind_layers(HomePlugAV, VS_ATTENUATION_CHARACTERISTICS_MME, HPtype=0xA14E)
bind_layers(HomePlugAV, CM_SLAC_PARM_REQ, HPtype=0x6064)
bind_layers(HomePlugAV, CM_SLAC_PARM_CNF, HPtype=0x6065)
bind_layers(HomePlugAV, CM_START_ATTEN_CHAR_IND, HPtype=0x606a)
bind_layers(HomePlugAV, CM_ATTEN_CHAR_IND, HPtype=0x606e)
bind_layers(HomePlugAV, CM_ATTEN_CHAR_RSP, HPtype=0x606f)
bind_layers(HomePlugAV, CM_MNBC_SOUND_IND, HPtype=0x6076)
bind_layers(HomePlugAV, CM_SLAC_MATCH_REQ, HPtype=0x607c)
bind_layers(HomePlugAV, CM_SLAC_MATCH_CNF, HPtype=0x607d)
bind_layers(HomePlugAV, CM_SET_KEY_REQ, HPtype=0x6008)
bind_layers(HomePlugAV, CM_SET_KEY_CNF, HPtype=0x6009)
bind_layers(HomePlugAV, CM_ATTENUATION_CHARACTERISTICS_MME, HPtype=0x6086)
