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

from scapy.fields import ByteEnumField, ThreeBytesField, XLEIntField, \
    XStrFixedLenField, XLELongField, XStrField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers


class Wireguard(Packet):
    """
    Wrapper that only contains the message type.
    """
    name = "Wireguard"

    fields_desc = [
        ByteEnumField(
            "message_type", 1,
            {
                1: "initiate",
                2: "respond",
                3: "cookie reply",
                4: "transport"
            }
        ),
        ThreeBytesField("reserved_zero", 0)
    ]


class WireguardInitiation(Packet):
    name = "Wireguard Initiation"

    fields_desc = [
        XLEIntField("sender_index", 0),
        XStrFixedLenField("unencrypted_ephemeral", 0, 32),
        XStrFixedLenField("encrypted_static", 0, 48),
        XStrFixedLenField("encrypted_timestamp", 0, 28),
        XStrFixedLenField("mac1", 0, 16),
        XStrFixedLenField("mac2", 0, 16),
    ]


class WireguardResponse(Packet):
    name = "Wireguard Response"

    fields_desc = [
        XLEIntField("sender_index", 0),
        XLEIntField("receiver_index", 0),
        XStrFixedLenField("unencrypted_ephemeral", 0, 32),
        XStrFixedLenField("encrypted_nothing", 0, 16),
        XStrFixedLenField("mac1", 0, 16),
        XStrFixedLenField("mac2", 0, 16),
    ]


class WireguardTransport(Packet):
    name = "Wireguard Transport"

    fields_desc = [
        XLEIntField("receiver_index", 0),
        XLELongField("counter", 0),
        XStrField("encrypted_encapsulated_packet", None)
    ]


class WireguardCookieReply(Packet):
    name = "Wireguard Cookie Reply"

    fields_desc = [
        XLEIntField("receiver_index", 0),
        XStrFixedLenField("nonce", 0, 24),
        XStrFixedLenField("encrypted_cookie", 0, 32),
    ]


bind_layers(Wireguard, WireguardInitiation, message_type=1)
bind_layers(Wireguard, WireguardResponse, message_type=2)
bind_layers(Wireguard, WireguardCookieReply, message_type=3)
bind_layers(Wireguard, WireguardTransport, message_type=4)
bind_layers(UDP, Wireguard, dport=51820)
bind_layers(UDP, Wireguard, sport=51820)
