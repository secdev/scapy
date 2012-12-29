#!/usr/bin/env python

# scapy.contrib.description = VLAN Trunking Protocol (VTP)
# scapy.contrib.status = loads

"""
    VTP Scapy Extension
    ~~~~~~~~~~~~~~~~~~~~~

    :version:   2009-02-15
    :copyright: 2009 by Jochen Bartl
    :e-mail:    lobo@c3a.de / jochen.bartl@gmail.com
    :license:   GPL v2

        This program is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

    :TODO

        - Join messages
        - RE MD5 hash calculation
        - Have a closer look at 8 byte padding in summary adv.
            "debug sw-vlan vtp packets" sais the TLV length is invalid,
            when I change the values
            '\x00\x00\x00\x01\x06\x01\x00\x02'
                * \x00\x00 ?
                * \x00\x01 tlvtype?
                * \x06 length?
                * \x00\x02 value?
        - h2i function for VTPTimeStampField

    :References:

        - Understanding VLAN Trunk Protocol (VTP)
        http://www.cisco.com/en/US/tech/tk389/tk689/technologies_tech_note09186a0080094c52.shtml
"""

from scapy.all import *

_VTP_VLAN_TYPE = {
            1 : 'Ethernet',
            2 : 'FDDI',
            3 : 'TrCRF',
            4 : 'FDDI-net',
            5 : 'TrBRF'
        }

_VTP_VLANINFO_TLV_TYPE = {
            0x01 : 'Source-Routing Ring Number',
            0x02 : 'Source-Routing Bridge Number',
            0x03 : 'Spanning-Tree Protocol Type',
            0x04 : 'Parent VLAN',
            0x05 : 'Translationally Bridged VLANs',
            0x06 : 'Pruning',
            0x07 : 'Bridge Type',
            0x08 : 'Max ARE Hop Count',
            0x09 : 'Max STE Hop Count',
            0x0A : 'Backup CRF Mode'
        }


class VTPVlanInfoTlv(Packet):
    name = "VTP VLAN Info TLV"
    fields_desc = [
            ByteEnumField("type", 0, _VTP_VLANINFO_TLV_TYPE),
            ByteField("length", 0),
            StrLenField("value", None, length_from=lambda pkt : pkt.length + 1)
            ]

    def guess_payload_class(self, p):
        return conf.padding_layer

class VTPVlanInfo(Packet):
    name = "VTP VLAN Info"
    fields_desc = [
                    ByteField("len", None), # FIXME: compute length
                    ByteEnumField("status", 0, {0 : "active", 1 : "suspended"}),
                    ByteEnumField("type", 1, _VTP_VLAN_TYPE),
                    FieldLenField("vlannamelen", None, "vlanname", "B"),
                    ShortField("vlanid", 1),
                    ShortField("mtu", 1500),
                    XIntField("dot10index", None),
                    StrLenField("vlanname", "default", length_from=lambda pkt:4 * ((pkt.vlannamelen + 3) / 4)),
                    ConditionalField(PacketListField("tlvlist", [], VTPVlanInfoTlv,
                            length_from=lambda pkt:pkt.len - 12 - (4 * ((pkt.vlannamelen + 3) / 4))),
                            lambda pkt:pkt.type not in [1, 2])
            ]

    def post_build(self, p, pay):
        vlannamelen = 4 * ((len(self.vlanname) + 3) / 4)

        if self.len == None:
            l = vlannamelen + 12
            p = chr(l & 0xff) + p[1:]

        # Pad vlan name with zeros if vlannamelen > len(vlanname)
        l = vlannamelen - len(self.vlanname)
        if l != 0:
            p += "\x00" * l

        p += pay

        return p

    def guess_payload_class(self, p):
        return conf.padding_layer

_VTP_Types = {
            1 : 'Summary Advertisement',
            2 : 'Subset Advertisements',
            3 : 'Advertisement Request',
            4 : 'Join'
            }

class VTPTimeStampField(StrFixedLenField):
    def __init__(self, name, default):
        StrFixedLenField.__init__(self, name, default, 12)

    def i2repr(self, pkt, x):
        return "%s-%s-%s %s:%s:%s" % (x[:2], x[2:4], x[4:6], x[6:8], x[8:10], x[10:12])

class VTP(Packet):
    name = "VTP"
    fields_desc = [
                    ByteField("ver", 2),
                    ByteEnumField("code", 1, _VTP_Types),
                    ConditionalField(ByteField("followers", 1),
                                        lambda pkt:pkt.code == 1),
                    ConditionalField(ByteField("seq", 1),
                                        lambda pkt:pkt.code == 2),
                    ConditionalField(ByteField("reserved", 0),
                                        lambda pkt:pkt.code == 3),
                    ByteField("domnamelen", None),
                    StrFixedLenField("domname", "manbearpig", 32),
                    ConditionalField(SignedIntField("rev", 0),
                                        lambda pkt:pkt.code == 1 or
                                                   pkt.code == 2),
                    # updater identity
                    ConditionalField(IPField("uid", "192.168.0.1"),
                                        lambda pkt:pkt.code == 1),
                    ConditionalField(VTPTimeStampField("timestamp", '930301000000'),
                                        lambda pkt:pkt.code == 1),
                    ConditionalField(StrFixedLenField("md5", "\x00" * 16, 16),
                                        lambda pkt:pkt.code == 1),
                    ConditionalField(
                        PacketListField("vlaninfo", [], VTPVlanInfo),
                        lambda pkt: pkt.code == 2),
                    ConditionalField(ShortField("startvalue", 0),
                                        lambda pkt:pkt.code == 3)
                    ]

    def post_build(self, p, pay):
        if self.domnamelen == None:
            domnamelen = len(self.domname.strip("\x00"))
            p = p[:3] + chr(domnamelen & 0xff) + p[4:]

        p += pay

        return p

bind_layers(SNAP, VTP, code=0x2003)

if __name__ == '__main__':
    interact(mydict=globals(), mybanner="VTP")
