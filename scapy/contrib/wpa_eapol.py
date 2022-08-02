# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = WPA EAPOL-KEY
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, LenField, ShortField, StrFixedLenField, \
    StrLenField
from scapy.layers.eap import EAPOL


class WPA_key(Packet):
    name = "WPA_key"
    fields_desc = [ByteField("descriptor_type", 1),
                   ShortField("key_info", 0),
                   LenField("len", None, "H"),
                   StrFixedLenField("replay_counter", "", 8),
                   StrFixedLenField("nonce", "", 32),
                   StrFixedLenField("key_iv", "", 16),
                   StrFixedLenField("wpa_key_rsc", "", 8),
                   StrFixedLenField("wpa_key_id", "", 8),
                   StrFixedLenField("wpa_key_mic", "", 16),
                   LenField("wpa_key_length", None, "H"),
                   StrLenField("wpa_key", "", length_from=lambda pkt:pkt.wpa_key_length)]  # noqa: E501

    def extract_padding(self, s):
        tmp_len = self.len
        return s[:tmp_len], s[tmp_len:]

    def hashret(self):
        return chr(self.type) + self.payload.hashret()

    def answers(self, other):
        if isinstance(other, WPA_key):
            return 1
        return 0


bind_layers(EAPOL, WPA_key, type=3)
