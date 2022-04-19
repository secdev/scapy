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


# scapy.contrib.description = Postgres PSQL Binary Protocol
# scapy.contrib.status = loads



from typing import Dict
from scapy.packet import Packet
from scapy.fields import ByteField, CharEnumField, IntField, FieldLenField, PadField, StrField, StrLenField, XNBytesField


BASE_PACKET_TAGS = {
    b'E': 'Error',
    b'R': 'Authentication',
    b'S': 'Parameter Status',
    b'Q': 'Query',
}

class Startup(Packet):
    name = 'Startup Request Packet'
    fields_desc = [
        FieldLenField("length", None, length_of="options", fmt="I", adjust=lambda pkt, x: x + 9),
        XNBytesField("protocol_version_major", 0x3, 2),
        XNBytesField("protocol_version_minor", 0x0, 2),
        StrLenField("options", "", length_from = lambda pkt: pkt.length - 9),
        ByteField("padding", 0x00)
    ]

class BasePacket(Packet):
    name = 'Regular packet'
    fields_desc = [
        CharEnumField("tag", b'R', BASE_PACKET_TAGS),
        FieldLenField("len", None, count_of="options", fmt="I"),
        StrLenField("payload", "\0", length_from = lambda pkt: pkt.len)
    ]
