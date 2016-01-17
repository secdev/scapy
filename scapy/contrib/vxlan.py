# RFC 7348 - Virtual eXtensible Local Area Network (VXLAN):
# A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks
# http://tools.ietf.org/html/rfc7348

# scapy.contrib.description = VXLAN
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from scapy.fields import FlagsField, XByteField, ThreeBytesField

_VXLAN_FLAGS = ['R' for _ in xrange(0, 24)] + ['R', 'R', 'R', 'I', 'R', 'R', 'R', 'R', 'R'] 


class VXLAN(Packet):
    name = "VXLAN"
    fields_desc = [FlagsField("flags", 0x08000000, 32, _VXLAN_FLAGS),
                   ThreeBytesField("vni", 0),
                   XByteField("reserved", 0x00)]

    def mysummary(self):
        return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)
bind_layers(VXLAN, Ether)
