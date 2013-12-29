# Virtual eXtensible Local Area Network (VXLAN)
# https://tools.ietf.org/html/draft-mahalingam-dutt-dcops-vxlan-06

# scapy.contrib.description = VXLAN
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *

class VXLAN(Packet):
    name = "VXLAN"
    fields_desc = [ FlagsField("flags", 0x08, 8, ['R', 'R', 'R', 'I', 'R', 'R', 'R', 'R']),
                    X3BytesField("reserved1", 0x000000),
                    ThreeBytesField("vni", 0),
                    XByteField("reserved2", 0x00)]

    def mysummary(self):
        return self.sprintf("VXLAN (vni=%VXLAN.vni%)")

bind_layers(UDP, VXLAN, dport=4789)
bind_layers(VXLAN, Ether)
