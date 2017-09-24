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

# scapy.contrib.description = WPA EAPOL dissector
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import *
from scapy.layers.eap import EAPOL

class WPA_key(Packet):
    name = "WPA_key"
    fields_desc = [ ByteField("descriptor_type", 1),
                    ShortField("key_info",0),
                    LenField("len", None, "H"),
                    StrFixedLenField("replay_counter", "", 8),
                    StrFixedLenField("nonce", "", 32),
                    StrFixedLenField("key_iv", "", 16),
                    StrFixedLenField("wpa_key_rsc", "", 8), 
                    StrFixedLenField("wpa_key_id", "", 8),
                    StrFixedLenField("wpa_key_mic", "", 16),
                    LenField("wpa_key_length", None, "H"),
                    StrLenField("wpa_key", "", length_from=lambda pkt:pkt.wpa_key_length) ]
    def extract_padding(self, s):
        l = self.len
        return s[:l],s[l:]
    def hashret(self):
        return chr(self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,WPA_key):
               return 1
        return 0
             

bind_layers( EAPOL,         WPA_key,       type=3)
