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

# scapy.contrib.description = ICMP Extensions
# scapy.contrib.status = loads

from __future__ import absolute_import
import struct

import scapy
from scapy.compat import chb
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, ConditionalField, \
    FieldLenField, IPField, IntField, PacketListField, ShortField, \
    StrLenField
from scapy.layers.inet import IP, ICMP, checksum
from scapy.layers.inet6 import IP6Field
from scapy.error import warning
from scapy.contrib.mpls import MPLS
import scapy.modules.six as six
from scapy.config import conf


class ICMPExtensionObject(Packet):
    name = 'ICMP Extension Object'
    fields_desc = [ShortField('len', None),
                   ByteField('classnum', 0),
                   ByteField('classtype', 0)]

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = struct.pack('!H', tmp_len) + p[2:]
        return p + pay


class ICMPExtensionHeader(Packet):
    name = 'ICMP Extension Header (RFC4884)'
    fields_desc = [BitField('version', 2, 4),
                   BitField('reserved', 0, 12),
                   BitField('chksum', None, 16)]

    _min_ieo_len = len(ICMPExtensionObject())

    def post_build(self, p, pay):
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2] + chb(ck >> 8) + chb(ck & 0xff) + p[4:]
        return p + pay

    def guess_payload_class(self, payload):
        if len(payload) < self._min_ieo_len:
            return Packet.guess_payload_class(self, payload)

        # Look at fields of the generic ICMPExtensionObject to determine which
        # bound extension type to use.
        ieo = ICMPExtensionObject(payload)
        if ieo.len < self._min_ieo_len:
            return Packet.guess_payload_class(self, payload)

        for fval, cls in self.payload_guess:
            if all(hasattr(ieo, k) and v == ieo.getfieldval(k)
                   for k, v in six.iteritems(fval)):
                return cls
        return ICMPExtensionObject


def ICMPExtension_post_dissection(self, pkt):
    # RFC4884 section 5.2 says if the ICMP packet length
    # is >144 then ICMP extensions start at byte 137.

    lastlayer = pkt.lastlayer()
    if not isinstance(lastlayer, conf.padding_layer):
        return

    if IP in pkt:
        if (ICMP in pkt and
            pkt[ICMP].type in [3, 11, 12] and
                pkt.len > 144):
            bytes = pkt[ICMP].build()[136:]
        else:
            return
    elif scapy.layers.inet6.IPv6 in pkt:
        if ((scapy.layers.inet6.ICMPv6TimeExceeded in pkt or
             scapy.layers.inet6.ICMPv6DestUnreach in pkt) and
                pkt.plen > 144):
            bytes = pkt[scapy.layers.inet6.ICMPv6TimeExceeded].build()[136:]
        else:
            return
    else:
        return

    # validate checksum
    ieh = ICMPExtensionHeader(bytes)
    if checksum(ieh.build()):
        return  # failed

    lastlayer.load = lastlayer.load[:-len(ieh)]
    lastlayer.add_payload(ieh)


class ICMPExtensionMPLS(ICMPExtensionObject):
    name = 'ICMP Extension Object - MPLS (RFC4950)'

    fields_desc = [ShortField('len', None),
                   ByteField('classnum', 1),
                   ByteField('classtype', 1),
                   PacketListField('stack', [], MPLS,
                                   length_from=lambda pkt: pkt.len - 4)]


class ICMPExtensionInterfaceInformation(ICMPExtensionObject):
    name = 'ICMP Extension Object - Interface Information Object (RFC5837)'

    fields_desc = [ShortField('len', None),
                   ByteField('classnum', 2),
                   BitField('interface_role', 0, 2),
                   BitField('reserved', 0, 2),
                   BitField('has_ifindex', 0, 1),
                   BitField('has_ipaddr', 0, 1),
                   BitField('has_ifname', 0, 1),
                   BitField('has_mtu', 0, 1),

                   ConditionalField(
        IntField('ifindex', None),
        lambda pkt: pkt.has_ifindex == 1),

        ConditionalField(
        ShortField('afi', None),
        lambda pkt: pkt.has_ipaddr == 1),
        ConditionalField(
        ShortField('reserved2', 0),
        lambda pkt: pkt.has_ipaddr == 1),
        ConditionalField(
        IPField('ip4', None),
        lambda pkt: pkt.afi == 1),
        ConditionalField(
        IP6Field('ip6', None),
        lambda pkt: pkt.afi == 2),

        ConditionalField(
        FieldLenField('ifname_len', None, fmt='B',
                      length_of='ifname'),
        lambda pkt: pkt.has_ifname == 1),
        ConditionalField(
        StrLenField('ifname', None,
                    length_from=lambda pkt: pkt.ifname_len),
        lambda pkt: pkt.has_ifname == 1),

        ConditionalField(
        IntField('mtu', None),
        lambda pkt: pkt.has_mtu == 1)]

    def self_build(self, **kwargs):
        if self.afi is None:
            if self.ip4 is not None:
                self.afi = 1
            elif self.ip6 is not None:
                self.afi = 2

        if self.has_ifindex and self.ifindex is None:
            warning('has_ifindex set but ifindex is not set.')
        if self.has_ipaddr and self.afi is None:
            warning('has_ipaddr set but afi is not set.')
        if self.has_ipaddr and self.ip4 is None and self.ip6 is None:
            warning('has_ipaddr set but ip4 or ip6 is not set.')
        if self.has_ifname and self.ifname is None:
            warning('has_ifname set but ifname is not set.')
        if self.has_mtu and self.mtu is None:
            warning('has_mtu set but mtu is not set.')

        return ICMPExtensionObject.self_build(self, **kwargs)


# Add the post_dissection() method to the existing ICMPv4 and
# ICMPv6 error messages
scapy.layers.inet.ICMPerror.post_dissection = ICMPExtension_post_dissection
scapy.layers.inet.TCPerror.post_dissection = ICMPExtension_post_dissection
scapy.layers.inet.UDPerror.post_dissection = ICMPExtension_post_dissection

scapy.layers.inet6.ICMPv6DestUnreach.post_dissection = ICMPExtension_post_dissection  # noqa: E501
scapy.layers.inet6.ICMPv6TimeExceeded.post_dissection = ICMPExtension_post_dissection  # noqa: E501


# ICMPExtensionHeader looks at fields from the upper layer object when
# determining which upper layer to use.
bind_layers(ICMPExtensionHeader, ICMPExtensionMPLS, classnum=1, classtype=1)
bind_layers(ICMPExtensionHeader, ICMPExtensionInterfaceInformation, classnum=2)
