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


# scapy.contrib.description = WireGuard
# scapy.contrib.status = loads

"""WireGuard Module
Implements the WireGuard network tunnel protocol.
Based on the whitepaper: https://www.wireguard.com/papers/wireguard.pdf
"""

from scapy.fields import ByteEnumField, ThreeBytesField, XIntField, \
    XStrFixedLenField, LongField, XStrField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers


class Wireguard(Packet):
    """
    Wrapper that only contains the message type.
    """
    name = "Wireguard"

    fields_desc = [
        ByteEnumField(
            "type", 1,
            {
                1: "initiate",
                2: "respond",
                3: "cookie reply",
                4: "transport"
            }
        ),
        ThreeBytesField("reserved", 0)
    ]

    def guess_payload_class(self, payload):
        wireguard_types = {
            1: WireguardInitiation,
            2: WireguardResponse,
            3: WireguardCookieReply,
            4: WireguardTransport
        }

        try:
            return wireguard_types[self.type]
        except KeyError:
            return Packet.guess_payload_class(self, payload)


class WireguardInitiation(Packet):
    name = "Wireguard Initiation"

    overload_fields = {Wireguard: {"type": 1}}

    fields_desc = [
        XIntField("sender", 0),
        XStrFixedLenField("ephemeral", 0, 32),
        XStrFixedLenField("static", 0, 48),
        XStrFixedLenField("tstamp", 0, 28),
        XStrFixedLenField("mac1", 0, 16),
        XStrFixedLenField("mac2", 0, 16),
    ]


class WireguardResponse(Packet):
    name = "Wireguard Response"

    overload_fields = {Wireguard: {"type": 2}}

    fields_desc = [
        XIntField("sender", 0),
        XIntField("receiver", 0),
        XStrFixedLenField("ephemeral", 0, 32),
        XStrFixedLenField("empty", 0, 16),
        XStrFixedLenField("mac1", 0, 16),
        XStrFixedLenField("mac2", 0, 16),
    ]


class WireguardTransport(Packet):
    name = "Wireguard Transport"

    overload_fields = {Wireguard: {"type": 4}}

    fields_desc = [
        XIntField("receiver", 0),
        LongField("counter", 0),
        XStrField("data", None)
    ]


class WireguardCookieReply(Packet):
    name = "Wireguard Cookie Reply"

    overload_fields = {Wireguard: {"type": 3}}

    fields_desc = [
        XIntField("receiver", 0),
        XStrFixedLenField("nonce", 0, 24),
        XStrFixedLenField("cookie", 0, 16),
        XStrFixedLenField("cookie_tag", 0, 16)
    ]


bind_layers(UDP, Wireguard, dport=51820)
bind_layers(UDP, Wireguard, sport=51820)
