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

# scapy.contrib.description = Link Aggregation Control Protocol (LACP)
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, MACField, ShortField, ByteEnumField, IntField, XStrFixedLenField  # noqa: E501
from scapy.layers.l2 import Ether
from scapy.data import ETHER_TYPES


ETHER_TYPES['SlowProtocol'] = 0x8809
SLOW_SUB_TYPES = {
    'Unused': 0,
    'LACP': 1,
    'Marker Protocol': 2,
}


class SlowProtocol(Packet):
    name = "SlowProtocol"
    fields_desc = [ByteEnumField("subtype", 0, SLOW_SUB_TYPES)]


bind_layers(Ether, SlowProtocol, type=0x8809, dst='01:80:c2:00:00:02')


class LACP(Packet):
    name = "LACP"
    fields_desc = [
        ByteField("version", 1),
        ByteField("actor_type", 1),
        ByteField("actor_length", 20),
        ShortField("actor_system_priority", 0),
        MACField("actor_system", None),
        ShortField("actor_key", 0),
        ShortField("actor_port_priority", 0),
        ShortField("actor_port_numer", 0),
        ByteField("actor_state", 0),
        XStrFixedLenField("actor_reserved", 0, 3),
        ByteField("partner_type", 2),
        ByteField("partner_length", 20),
        ShortField("partner_system_priority", 0),
        MACField("partner_system", None),
        ShortField("partner_key", 0),
        ShortField("partner_port_priority", 0),
        ShortField("partner_port_numer", 0),
        ByteField("partner_state", 0),
        XStrFixedLenField("partner_reserved", 0, 3),
        ByteField("collector_type", 3),
        ByteField("collector_length", 16),
        ShortField("collector_max_delay", 0),
        XStrFixedLenField("colletctor_reserved", 0, 12),
        ByteField("terminator_type", 0),
        ByteField("terminator_length", 0),
        XStrFixedLenField("reserved", 0, 50),
    ]


bind_layers(SlowProtocol, LACP, subtype=1)

MARKER_TYPES = {
    'Marker Request': 1,
    'Marker Response': 2,
}


class MarkerProtocol(Packet):
    name = "MarkerProtocol"
    fields_desc = [
        ByteField("version", 1),
        ByteEnumField("marker_type", 1, MARKER_TYPES),
        ByteField("marker_length", 16),
        ShortField("requester_port", 0),
        MACField("requester_system", None),
        IntField("requester_transaction_id", 0),
        XStrFixedLenField("marker_reserved", 0, 2),
        ByteField("terminator_type", 0),
        ByteField("terminator_length", 0),
        XStrFixedLenField("reserved", 0, 90),
    ]


bind_layers(SlowProtocol, MarkerProtocol, subtype=2)
