# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
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

# Original PPI author: <jellch@harris.com>

# scapy.contrib.description = Parallel Peripheral Interface (PPI)
# scapy.contrib.status = loads


"""
Per-Packet Information (PPI) Protocol
"""

import struct

from scapy.config import conf
from scapy.data import DLT_EN10MB, DLT_IEEE802_11, DLT_PPI
from scapy.packet import bind_layers, Packet
from scapy.fields import ByteField, FieldLenField, LEIntField, \
    LEShortField, PacketListField, StrLenField
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
    fields_desc = [LEShortField('pfh_type', 0),
                   FieldLenField('pfh_length', None, length_of="value", fmt='<H', adjust=lambda p, x:x + 4),  # noqa: E501
                   StrLenField("value", "", length_from=lambda p:p.pfh_length)]

    def extract_padding(self, p):
        return b"", p


def _PPIGuessPayloadClass(p, **kargs):
    """ This function tells the PacketListField how it should extract the
        TLVs from the payload.  We pass cls only the length string
        pfh_len says it needs.  If a payload is returned, that means
        part of the string was unused.  This converts to a Raw layer, and
        the remainder of p is added as Raw's payload.  If there is no
        payload, the remainder of p is added as out's payload.
    """
    if len(p) >= 4:
        t, pfh_len = struct.unpack("<HH", p[:4])
        # Find out if the value t is in the dict _ppi_types.
        # If not, return the default TLV class
        cls = getPPIType(t, "default")
        pfh_len += 4
        out = cls(p[:pfh_len], **kargs)
        if (out.payload):
            out.payload = conf.raw_layer(out.payload.load)
            out.payload.underlayer = out
            if (len(p) > pfh_len):
                out.payload.payload = conf.padding_layer(p[pfh_len:])
                out.payload.payload.underlayer = out.payload
        elif (len(p) > pfh_len):
            out.payload = conf.padding_layer(p[pfh_len:])
            out.payload.underlayer = out
    else:
        out = conf.raw_layer(p, **kargs)
    return out


class PPI(Packet):
    name = "Per-Packet Information header (PPI)"
    fields_desc = [ByteField('version', 0),
                   ByteField('flags', 0),
                   FieldLenField('len', None, length_of="PPIFieldHeaders", fmt="<H", adjust=lambda p, x: x + 8),  # noqa: E501
                   LEIntField('dlt', 1),
                   PacketListField("PPIFieldHeaders", [], _PPIGuessPayloadClass, length_from=lambda p: p.len - 8,)]  # noqa: E501

    def guess_payload_class(self, payload):
        return conf.l2types.get(self.dlt, Packet.guess_payload_class(self, payload))  # noqa: E501


# Register PPI
addPPIType("default", PPIGenericFldHdr)

conf.l2types.register(DLT_PPI, PPI)

bind_layers(PPI, Dot11, dlt=DLT_IEEE802_11)
bind_layers(PPI, Ether, dlt=DLT_EN10MB)
