## This file is (hopefully) part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## <jellch@harris.com>
## This program is published under a GPLv2 license
"""
PPI (Per-Packet Information).
"""
import logging,struct
from scapy.config import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import Ether
from scapy.layers.dot11 import Dot11

# Dictionary to map the TLV type to the class name of a sub-packet
_ppi_types = {}
def addPPIType(id, value):
    _ppi_types[id] = value
def getPPIType(id, default="default"):
    return _ppi_types.get(id, _ppi_types.get(default, None))


# Default PPI Field Header
class PPIGenericFldHdr(Packet):
    name = "PPI Field Header"
    fields_desc = [ LEShortField('pfh_type', 0),
                    FieldLenField('pfh_length', None, length_of="value", fmt='<H', adjust=lambda p,x:x+4),
                    StrLenField("value", "", length_from=lambda p:p.length) ]

    def extract_padding(self, p):
        return "",p

def _PPIGuessPayloadClass(p, **kargs):
    """ This function tells the PacketListField, how it should extract the TLVs from the payload """
    if len(p) >= 4:
        t,l = struct.unpack("<HH", p[:4])
        # Find out if the value t is in the dict _ppi_types.  if not, return the default TLV class
        cls = getPPIType(t, "default")
    else:
        cls = Raw
    return cls(p, **kargs)


class PPI(Packet):
    name = "PPI Packet Header"
    fields_desc = [ ByteField('pph_version', 0),
                    ByteField('pph_flags', 0),
                    FieldLenField('pph_len', None, length_of="PPIFieldHeaders", fmt="<H", adjust=lambda p,x:x+8 ),
                    LEIntField('dlt', None),
                    PacketListField("PPIFieldHeaders", [],  _PPIGuessPayloadClass, length_from=lambda p:p.pph_len-8,) ]
    def guess_payload_class(self,payload):
        return conf.l2types.get(self.dlt, Packet.guess_payload_class(self, payload))

#Register PPI
addPPIType("default", PPIGenericFldHdr)

conf.l2types.register(192, PPI)
conf.l2types.register_num2layer(192, PPI)

bind_layers(PPI, Dot11, dlt=conf.l2types.get(Dot11))
bind_layers(Dot11, PPI)
bind_layers(PPI, Ether, dlt=conf.l2types.get(Ether))
bind_layers(Dot11, Ether)
