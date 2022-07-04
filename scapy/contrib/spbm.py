# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Shorest Path Bridging Mac-in-mac (SBPM)
# scapy.contrib.status = loads

"""
IEEE 802.1aq - Shorest Path Bridging Mac-in-mac (SPBM):

Ethernet based link state protocol that enables
- Layer 2 Unicast
- Layer 2 Multicast
- Layer 3 Unicast
- Layer 3 Multicast virtualized services

https://en.wikipedia.org/wiki/IEEE_802.1aq
Modeled after the scapy VXLAN contribution

Example SPB Frame Creation
__________________________

Note the outer Dot1Q Ethertype marking (0x88e7)

::
    backboneEther     = Ether(dst='00:bb:00:00:90:00', src='00:bb:00:00:40:00', type=0x8100)  # noqa: E501
    backboneDot1Q     = Dot1Q(vlan=4051,type=0x88e7)
    backboneServiceID = SPBM(prio=1,isid=20011)
    customerEther     = Ether(dst='00:1b:4f:5e:ca:00',src='00:00:00:00:00:01',type=0x8100)  # noqa: E501
    customerDot1Q     = Dot1Q(prio=1,vlan=11,type=0x0800)
    customerIP        = IP(src='10.100.11.10',dst='10.100.12.10',id=0x0629,len=106)  # noqa: E501
    customerUDP       = UDP(sport=1024,dport=1025,chksum=0,len=86)

    spb_example = backboneEther/backboneDot1Q/backboneServiceID/customerEther/customerDot1Q/customerIP/customerUDP/"Payload"  # noqa: E501
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ThreeBytesField
from scapy.layers.l2 import Ether, Dot1Q, Dot1AD


class SPBM(Packet):
    name = "SPBM"
    fields_desc = [BitField("prio", 0, 3),
                   BitField("dei", 0, 1),
                   BitField("nca", 0, 1),
                   BitField("res1", 0, 1),
                   BitField("res2", 0, 2),
                   ThreeBytesField("isid", 0)]

    def mysummary(self):
        return self.sprintf("SPBM (isid=%SPBM.isid%")


bind_layers(Ether, SPBM, type=0x88e7)
bind_layers(Dot1Q, SPBM, type=0x88e7)
bind_layers(Dot1AD, SPBM, type=0x88e7)
bind_layers(SPBM, Ether)
