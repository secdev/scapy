# RFC 7348 - Virtual eXtensible Local Area Network (VXLAN):
# A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks
# http://tools.ietf.org/html/rfc7348
#
# VXLAN Group Policy Option:
# http://tools.ietf.org/html/draft-smith-vxlan-group-policy-00

from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from scapy.fields import FlagsField, XByteField, ThreeBytesField, \
        ConditionalField, ShortField

_VXLAN_FLAGS = ["R", "R", "R", "I", "R", "R", "R", "G"]
_GP_FLAGS = ["R", "R", "R", "A", "R", "R", "D", "R"]

class VXLAN(Packet):
    name = "VXLAN"

    fields_desc = [
        FlagsField("flags", 0x8, 8, _VXLAN_FLAGS),
        ConditionalField(
            ThreeBytesField("reserved1", 0x000000),
            lambda pkt: not pkt.flags & 0x80,
        ),
        ConditionalField(
            FlagsField("gpflags", 0x0, 8, _GP_FLAGS),
            lambda pkt: pkt.flags & 0x80,
        ),
        ConditionalField(
            ShortField("gpid", 0),
            lambda pkt: pkt.flags & 0x80,
        ),
        ThreeBytesField("vni", 0),
        XByteField("reserved2", 0x00),
    ]

    # Use default linux implementation port
    overload_fields = {
        UDP: {'dport': 8472},
    }

    def mysummary(self):
        if self.flags & 0x80:
            return self.sprintf("VXLAN (vni=%VXLAN.vni% gpid=%VXLAN.gpid%)")
        else:
            return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)  # RFC standard port
bind_layers(UDP, VXLAN, dport=8472)  # Linux implementation port
bind_layers(VXLAN, Ether)
