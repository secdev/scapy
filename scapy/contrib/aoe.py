#! /usr/bin/env python

# Copyright (C) 2018 antoine.torre <torreantoine1@gmail.com>
##
# This program is published under a GPLv2 license


# scapy.contrib.description = ATA Over Internet
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import FlagsField, XByteField, ByteField, XShortField, \
    ShortField, StrLenField, BitField, BitEnumField, ByteEnumField, \
    FieldLenField, PacketListField, FieldListField, MACField, PacketField, \
    ConditionalField, XIntField
from scapy.layers.l2 import Ether
from scapy.data import ETHER_ANY


class IssueATACommand(Packet):
    name = "Issue ATA Command"
    fields_desc = [FlagsField("flags", 0, 8, "zezdzzaw"),
                   XByteField("err_feature", 0),
                   ByteField("sector_count", 1),
                   XByteField("cmd_status", 0xec),
                   XByteField("lba0", 0),
                   XByteField("lba1", 0),
                   XByteField("lba2", 0),
                   XByteField("lba3", 0),
                   XByteField("lba4", 0),
                   XByteField("lba5", 0),
                   XShortField("reserved", 0),
                   StrLenField("data", "",
                               length_from=lambda x: x.sector_count * 512)]

    def extract_padding(self, s):
        return "", s


class QueryConfigInformation(Packet):
    name = "Query Config Information"
    fields_desc = [ShortField("buffer_count", 0),
                   ShortField("firmware", 0),
                   ByteField("sector_count", 0),
                   BitField("aoe", 0, 4),
                   BitEnumField("ccmd", 0, 4, {0: "Read config string",
                                               1: "Test config string",
                                               2: "Test config string prefix",
                                               3: "Set config string",
                                               4: "Force set config string"}),
                   FieldLenField("config_length", None, length_of="config"),
                   StrLenField("config", None,
                               length_from=lambda x: x.config_length)]

    def extract_padding(self, s):
        return "", s


class Directive(Packet):
    name = "Directive"
    fields_desc = [ByteField("reserved", 0),
                   ByteEnumField("dcmd", 0,
                                 {0: "No directive",
                                  1: "Add mac address to mask list",
                                  2: "Delete mac address from mask list"}),
                   MACField("mac_addr", ETHER_ANY)]


class MacMaskList(Packet):
    name = "Mac Mask List"
    fields_desc = [ByteField("reserved", 0),
                   ByteEnumField("mcmd", 0, {0: "Read Mac Mask List",
                                             1: "Edit Mac Mask List"}),
                   ByteEnumField("merror", 0, {0: "",
                                               1: "Unspecified error",
                                               2: "Bad dcmd directive",
                                               3: "Mask List Full"}),
                   FieldLenField("dir_count", None, count_of="directives"),
                   PacketListField("directives", None, Directive,
                                   count_from=lambda pkt: pkt.dir_count)]

    def extract_padding(self, s):
        return "", s


class ReserveRelease(Packet):
    name = "Reserve / Release"
    fields_desc = [ByteEnumField("rcmd", 0, {0: "Read Reserve List",
                                             1: "Set Reserve List",
                                             2: "Force Set Reserve List"}),
                   FieldLenField("nb_mac", None, count_of="mac_addrs"),
                   FieldListField("mac_addrs", None, MACField("", ETHER_ANY),
                                  count_from=lambda pkt: pkt.nb_mac)]

    def extract_padding(self, s):
        return "", s


class AOE(Packet):
    name = "ATA over Ethernet"
    fields_desc = [BitField("version", 1, 4),
                   FlagsField("flags", 0, 4, ["Response", "Error",
                                              "r1", "r2"]),
                   ByteEnumField("error", 0, {1: "Unrecognized command code",
                                              2: "Bad argument parameter",
                                              3: "Device unavailable",
                                              4: "Config string present",
                                              5: "Unsupported exception",
                                              6: "Target is reserved"}),
                   XShortField("major", 0xFFFF),
                   XByteField("minor", 0xFF),
                   ByteEnumField("cmd", 1, {0: "Issue ATA Command",
                                            1: "Query Config Information",
                                            2: "Mac Mask List",
                                            3: "Reserve / Release"}),
                   XIntField("tag", 0),
                   ConditionalField(PacketField("i_ata_cmd", IssueATACommand(),
                                                IssueATACommand),
                                    lambda x: x.cmd == 0),
                   ConditionalField(PacketField("q_conf_info",
                                                QueryConfigInformation(),
                                                QueryConfigInformation),
                                    lambda x: x.cmd == 1),
                   ConditionalField(PacketField("mac_m_list", MacMaskList(),
                                                MacMaskList),
                                    lambda x: x.cmd == 2),
                   ConditionalField(PacketField("res_rel", ReserveRelease(),
                                                ReserveRelease),
                                    lambda x: x.cmd == 3)]

    def extract_padding(self, s):
        return "", s


bind_layers(Ether, AOE, type=0x88A2)
bind_layers(AOE, IssueATACommand, cmd=0)
bind_layers(AOE, QueryConfigInformation, cmd=1)
bind_layers(AOE, MacMaskList, cmd=2)
bind_layers(AOE, ReserveRelease, cmd=3)
