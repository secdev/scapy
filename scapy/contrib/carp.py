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

# scapy.contrib.description = Common Address Redundancy Protocol (CARP)
# scapy.contrib.status = loads

import struct
import hmac
import hashlib

from scapy.packet import Packet, split_layers, bind_layers
from scapy.layers.inet import IP
from scapy.fields import BitField, ByteField, XShortField, XIntField
from scapy.layers.vrrp import IPPROTO_VRRP, VRRP, VRRPv3
from scapy.utils import checksum, inet_aton
from scapy.error import warning


class CARP(Packet):
    name = "CARP"
    fields_desc = [BitField("version", 4, 4),
                   BitField("type", 4, 4),
                   ByteField("vhid", 1),
                   ByteField("advskew", 0),
                   ByteField("authlen", 0),
                   ByteField("demotion", 0),
                   ByteField("advbase", 0),
                   XShortField("chksum", None),
                   XIntField("counter1", 0),
                   XIntField("counter2", 0),
                   XIntField("hmac1", 0),
                   XIntField("hmac2", 0),
                   XIntField("hmac3", 0),
                   XIntField("hmac4", 0),
                   XIntField("hmac5", 0)
                   ]

    def post_build(self, pkt, pay):
        if self.chksum is None:
            pkt = pkt[:6] + struct.pack("!H", checksum(pkt)) + pkt[8:]

        return pkt

    def build_hmac_sha1(self, pw=b'\x00' * 20, ip4l=[], ip6l=[]):
        h = hmac.new(pw, digestmod=hashlib.sha1)
        # XXX: this is a dirty hack. it needs to pack version and type into a single 8bit field  # noqa: E501
        h.update(b'\x21')
        # XXX: mac addy if different from special link layer. comes before vhid
        h.update(struct.pack('!B', self.vhid))

        sl = []
        for i in ip4l:
            # sort ips from smallest to largest
            sl.append(inet_aton(i))
        sl.sort()

        for i in sl:
            h.update(i)

        # XXX: do ip6l sorting

        return h.digest()


warning("CARP overwrites VRRP !")
# This cancel the bindings done in vrrp.py
split_layers(IP, VRRP, proto=IPPROTO_VRRP)
split_layers(IP, VRRPv3, proto=IPPROTO_VRRP)
# CARP bindings
bind_layers(IP, CARP, proto=112, dst='224.0.0.18')
