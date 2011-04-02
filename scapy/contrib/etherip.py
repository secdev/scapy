
# http://trac.secdev.org/scapy/ticket/297

# scapy.contrib.description = EtherIP
# scapy.contrib.status = loads

from scapy.fields import BitField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

class EtherIP(Packet):
    name = "EtherIP / RFC 3378"
    fields_desc = [ BitField("version", 3, 4),
                    BitField("reserved", 0, 12)]

bind_layers( IP,            EtherIP,       frag=0, proto=0x61)
bind_layers( EtherIP,       Ether)

