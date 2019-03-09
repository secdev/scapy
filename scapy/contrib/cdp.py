#! /usr/bin/env python

# scapy.contrib.description = Cisco Discovery Protocol (CDP)
# scapy.contrib.status = loads

#############################################################################
#                                                                           #
#  cdp.py --- Cisco Discovery Protocol (CDP) extension for Scapy            #
#                                                                           #
#  Copyright (C) 2006    Nicolas Bareil  <nicolas.bareil AT eads DOT net>   #
#                        Arnaud Ebalard  <arnaud.ebalard AT eads DOT net>   #
#                        EADS/CRC security team                             #
#                                                                           #
#  This file is part of Scapy                                               #
#  Scapy is free software: you can redistribute it and/or modify it         #
#  under the terms of the GNU General Public License version 2 as           #
#  published by the Free Software Foundation; version 2.                    #
#                                                                           #
#  This program is distributed in the hope that it will be useful, but      #
#  WITHOUT ANY WARRANTY; without even the implied warranty of               #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU        #
#  General Public License for more details.                                 #
#                                                                           #
#############################################################################

from __future__ import absolute_import
import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, FieldLenField, FlagsField, \
    IP6Field, IPField, PacketListField, ShortField, StrLenField, \
    X3BytesField, XByteField, XShortEnumField, XShortField
from scapy.layers.inet import checksum
from scapy.layers.l2 import SNAP
from scapy.compat import orb, chb
from scapy.modules.six.moves import range
from scapy.config import conf


#####################################################################
# Helpers and constants
#####################################################################

# CDP TLV classes keyed by type
_cdp_tlv_cls = {0x0001: "CDPMsgDeviceID",
                0x0002: "CDPMsgAddr",
                0x0003: "CDPMsgPortID",
                0x0004: "CDPMsgCapabilities",
                0x0005: "CDPMsgSoftwareVersion",
                0x0006: "CDPMsgPlatform",
                0x0007: "CDPMsgIPPrefix",
                0x0008: "CDPMsgProtoHello",
                0x0009: "CDPMsgVTPMgmtDomain",  # CDPv2
                0x000a: "CDPMsgNativeVLAN",    # CDPv2
                0x000b: "CDPMsgDuplex",        #
                #                 0x000c: "CDPMsgGeneric",
                #                 0x000d: "CDPMsgGeneric",
                0x000e: "CDPMsgVoIPVLANReply",
                0x000f: "CDPMsgVoIPVLANQuery",
                0x0010: "CDPMsgPower",
                0x0011: "CDPMsgMTU",
                0x0012: "CDPMsgTrustBitmap",
                0x0013: "CDPMsgUntrustedPortCoS",
                #                 0x0014: "CDPMsgSystemName",
                #                 0x0015: "CDPMsgSystemOID",
                0x0016: "CDPMsgMgmtAddr",
                #                 0x0017: "CDPMsgLocation",
                0x0019: "CDPMsgUnknown19",
                #                 0x001a: "CDPPowerAvailable"
                }

_cdp_tlv_types = {0x0001: "Device ID",
                  0x0002: "Addresses",
                  0x0003: "Port ID",
                  0x0004: "Capabilities",
                  0x0005: "Software Version",
                  0x0006: "Platform",
                  0x0007: "IP Prefix",
                  0x0008: "Protocol Hello",
                  0x0009: "VTP Management Domain",  # CDPv2
                  0x000a: "Native VLAN",    # CDPv2
                  0x000b: "Duplex",        #
                  0x000c: "CDP Unknown command (send us a pcap file)",
                  0x000d: "CDP Unknown command (send us a pcap file)",
                  0x000e: "VoIP VLAN Reply",
                  0x000f: "VoIP VLAN Query",
                  0x0010: "Power",
                  0x0011: "MTU",
                  0x0012: "Trust Bitmap",
                  0x0013: "Untrusted Port CoS",
                  0x0014: "System Name",
                  0x0015: "System OID",
                  0x0016: "Management Address",
                  0x0017: "Location",
                  0x0018: "CDP Unknown command (send us a pcap file)",
                  0x0019: "CDP Unknown command (send us a pcap file)",
                  0x001a: "Power Available"}


def _CDPGuessPayloadClass(p, **kargs):
    cls = conf.raw_layer
    if len(p) >= 2:
        t = struct.unpack("!H", p[:2])[0]
        clsname = _cdp_tlv_cls.get(t, "CDPMsgGeneric")
        cls = globals()[clsname]

    return cls(p, **kargs)


class CDPMsgGeneric(Packet):
    name = "CDP Generic Message"
    fields_desc = [XShortEnumField("type", None, _cdp_tlv_types),
                   FieldLenField("len", None, "val", "!H",
                                 adjust=lambda pkt, x: x + 4),
                   StrLenField("val", "", length_from=lambda x:x.len - 4,
                               max_length=65531)]

    def guess_payload_class(self, p):
        return conf.padding_layer  # _CDPGuessPayloadClass


class CDPMsgDeviceID(CDPMsgGeneric):
    name = "Device ID"
    type = 0x0001


_cdp_addr_record_ptype = {0x01: "NLPID", 0x02: "802.2"}
_cdp_addrrecord_proto_ip = b"\xcc"
_cdp_addrrecord_proto_ipv6 = b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"


class CDPAddrRecord(Packet):
    name = "CDP Address"
    fields_desc = [ByteEnumField("ptype", 0x01, _cdp_addr_record_ptype),
                   FieldLenField("plen", None, "proto", "B"),
                   StrLenField("proto", None, length_from=lambda x:x.plen,
                               max_length=255),
                   FieldLenField("addrlen", None, length_of=lambda x:x.addr),
                   StrLenField("addr", None, length_from=lambda x:x.addrlen,
                               max_length=65535)]

    def guess_payload_class(self, p):
        return conf.padding_layer


class CDPAddrRecordIPv4(CDPAddrRecord):
    name = "CDP Address IPv4"
    fields_desc = [ByteEnumField("ptype", 0x01, _cdp_addr_record_ptype),
                   FieldLenField("plen", 1, "proto", "B"),
                   StrLenField("proto", _cdp_addrrecord_proto_ip,
                               length_from=lambda x: x.plen, max_length=255),
                   ShortField("addrlen", 4),
                   IPField("addr", "0.0.0.0")]


class CDPAddrRecordIPv6(CDPAddrRecord):
    name = "CDP Address IPv6"
    fields_desc = [ByteEnumField("ptype", 0x02, _cdp_addr_record_ptype),
                   FieldLenField("plen", 8, "proto", "B"),
                   StrLenField("proto", _cdp_addrrecord_proto_ipv6,
                               length_from=lambda x:x.plen, max_length=255),
                   ShortField("addrlen", 16),
                   IP6Field("addr", "::1")]


def _CDPGuessAddrRecord(p, **kargs):
    cls = conf.raw_layer
    if len(p) >= 2:
        plen = orb(p[1])
        proto = p[2:plen + 2]

        if proto == _cdp_addrrecord_proto_ip:
            clsname = "CDPAddrRecordIPv4"
        elif proto == _cdp_addrrecord_proto_ipv6:
            clsname = "CDPAddrRecordIPv6"
        else:
            clsname = "CDPAddrRecord"

        cls = globals()[clsname]

    return cls(p, **kargs)


class CDPMsgAddr(CDPMsgGeneric):
    name = "Addresses"
    fields_desc = [XShortEnumField("type", 0x0002, _cdp_tlv_types),
                   ShortField("len", None),
                   FieldLenField("naddr", None, "addr", "!I"),
                   PacketListField("addr", [], _CDPGuessAddrRecord, count_from=lambda x:x.naddr)]  # noqa: E501

    def post_build(self, pkt, pay):
        if self.len is None:
            tmp_len = 8 + len(self.addr) * 9
            pkt = pkt[:2] + struct.pack("!H", tmp_len) + pkt[4:]
        p = pkt + pay
        return p


class CDPMsgPortID(CDPMsgGeneric):
    name = "Port ID"
    fields_desc = [XShortEnumField("type", 0x0003, _cdp_tlv_types),
                   FieldLenField("len", None, "iface", "!H",
                                 adjust=lambda pkt, x: x + 4),
                   StrLenField("iface", "Port 1", length_from=lambda x:x.len - 4)]  # noqa: E501


_cdp_capabilities = ["Router",
                     "TransparentBridge",
                     "SourceRouteBridge",
                     "Switch",
                     "Host",
                     "IGMPCapable",
                     "Repeater"] + ["Bit%d" % x for x in range(25, 0, -1)]


class CDPMsgCapabilities(CDPMsgGeneric):
    name = "Capabilities"
    fields_desc = [XShortEnumField("type", 0x0004, _cdp_tlv_types),
                   ShortField("len", 8),
                   FlagsField("cap", 0, 32, _cdp_capabilities)]


class CDPMsgSoftwareVersion(CDPMsgGeneric):
    name = "Software Version"
    type = 0x0005


class CDPMsgPlatform(CDPMsgGeneric):
    name = "Platform"
    type = 0x0006


_cdp_duplex = {0x00: "Half", 0x01: "Full"}

# ODR Routing


class CDPMsgIPPrefix(CDPMsgGeneric):
    name = "IP Prefix"
    type = 0x0007
    fields_desc = [XShortEnumField("type", 0x0007, _cdp_tlv_types),
                   ShortField("len", 8),
                   IPField("defaultgw", "192.168.0.1")]


class CDPMsgProtoHello(CDPMsgGeneric):
    name = "Protocol Hello"
    type = 0x0008
    fields_desc = [XShortEnumField("type", 0x0008, _cdp_tlv_types),
                   ShortField("len", 32),
                   X3BytesField("oui", 0x00000c),
                   XShortField("protocol_id", 0x0),
                   # TLV length (len) - 2 (type) - 2 (len) - 3 (OUI) - 2
                   # (Protocol ID)
                   StrLenField("data", "", length_from=lambda p: p.len - 9)]


class CDPMsgVTPMgmtDomain(CDPMsgGeneric):
    name = "VTP Management Domain"
    type = 0x0009


class CDPMsgNativeVLAN(CDPMsgGeneric):
    name = "Native VLAN"
    fields_desc = [XShortEnumField("type", 0x000a, _cdp_tlv_types),
                   ShortField("len", 6),
                   ShortField("vlan", 1)]


class CDPMsgDuplex(CDPMsgGeneric):
    name = "Duplex"
    fields_desc = [XShortEnumField("type", 0x000b, _cdp_tlv_types),
                   ShortField("len", 5),
                   ByteEnumField("duplex", 0x00, _cdp_duplex)]


class CDPMsgVoIPVLANReply(CDPMsgGeneric):
    name = "VoIP VLAN Reply"
    fields_desc = [XShortEnumField("type", 0x000e, _cdp_tlv_types),
                   ShortField("len", 7),
                   ByteField("status?", 1),
                   ShortField("vlan", 1)]


class CDPMsgVoIPVLANQuery(CDPMsgGeneric):
    name = "VoIP VLAN Query"
    type = 0x000f
    fields_desc = [XShortEnumField("type", 0x000f, _cdp_tlv_types),
                   FieldLenField("len", None, "unknown2", fmt="!H",
                                 adjust=lambda pkt, x: x + 7),
                   XByteField("unknown1", 0),
                   ShortField("vlan", 1),
                   # TLV length (len) - 2 (type) - 2 (len) - 1 (unknown1) - 2 (vlan)  # noqa: E501
                   StrLenField("unknown2", "", length_from=lambda p: p.len - 7,
                               max_length=65528)]


class _CDPPowerField(ShortField):
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return "%d mW" % x


class CDPMsgPower(CDPMsgGeneric):
    name = "Power"
    # Check if field length is fixed (2 bytes)
    fields_desc = [XShortEnumField("type", 0x0010, _cdp_tlv_types),
                   ShortField("len", 6),
                   _CDPPowerField("power", 1337)]


class CDPMsgMTU(CDPMsgGeneric):
    name = "MTU"
    # Check if field length is fixed (2 bytes)
    fields_desc = [XShortEnumField("type", 0x0011, _cdp_tlv_types),
                   ShortField("len", 6),
                   ShortField("mtu", 1500)]


class CDPMsgTrustBitmap(CDPMsgGeneric):
    name = "Trust Bitmap"
    fields_desc = [XShortEnumField("type", 0x0012, _cdp_tlv_types),
                   ShortField("len", 5),
                   XByteField("trust_bitmap", 0x0)]


class CDPMsgUntrustedPortCoS(CDPMsgGeneric):
    name = "Untrusted Port CoS"
    fields_desc = [XShortEnumField("type", 0x0013, _cdp_tlv_types),
                   ShortField("len", 5),
                   XByteField("untrusted_port_cos", 0x0)]


class CDPMsgMgmtAddr(CDPMsgAddr):
    name = "Management Address"
    type = 0x0016


class CDPMsgUnknown19(CDPMsgGeneric):
    name = "Unknown CDP Message"
    type = 0x0019


class CDPMsg(CDPMsgGeneric):
    name = "CDP "
    fields_desc = [XShortEnumField("type", None, _cdp_tlv_types),
                   FieldLenField("len", None, "val", fmt="!H",
                                 adjust=lambda pkt, x: x + 4),
                   StrLenField("val", "", length_from=lambda x:x.len - 4,
                               max_length=65531)]


class _CDPChecksum:
    def _check_len(self, pkt):
        """Check for odd packet length and pad according to Cisco spec.
        This padding is only used for checksum computation.  The original
        packet should not be altered."""
        if len(pkt) % 2:
            last_chr = pkt[-1]
            if last_chr <= b'\x80':
                return pkt[:-1] + b'\x00' + last_chr
            else:
                return pkt[:-1] + b'\xff' + chb(orb(last_chr) - 1)
        else:
            return pkt

    def post_build(self, pkt, pay):
        p = pkt + pay
        if self.cksum is None:
            cksum = checksum(self._check_len(p))
            p = p[:2] + struct.pack("!H", cksum) + p[4:]
        return p


class CDPv2_HDR(_CDPChecksum, CDPMsgGeneric):
    name = "Cisco Discovery Protocol version 2"
    fields_desc = [ByteField("vers", 2),
                   ByteField("ttl", 180),
                   XShortField("cksum", None),
                   PacketListField("msg", [], _CDPGuessPayloadClass)]


bind_layers(SNAP, CDPv2_HDR, {"code": 0x2000, "OUI": 0xC})
