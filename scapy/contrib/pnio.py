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

# Copyright (C) 2016 Gauthier Sebaux

# scapy.contrib.description = ProfinetIO base layer
# scapy.contrib.status = loads

"""
A simple and non exhaustive Profinet IO layer for scapy
"""

# Scapy imports
from __future__ import absolute_import
from scapy.all import Packet, bind_layers, Ether, UDP
from scapy.fields import XShortEnumField
from scapy.modules.six.moves import range

# Some constants
PNIO_FRAME_IDS = {
    0x0020:"PTCP-RTSyncPDU-followup",
    0x0080:"PTCP-RTSyncPDU",
    0xFC01:"Alarm High",
    0xFE01:"Alarm Low",
    0xFEFC:"DCP-Hello-Req",
    0xFEFD:"DCP-Get-Set",
    0xFEFE:"DCP-Identify-ReqPDU",
    0xFEFF:"DCP-Identify-ResPDU",
    0xFF00:"PTCP-AnnouncePDU",
    0xFF20:"PTCP-FollowUpPDU",
    0xFF40:"PTCP-DelayReqPDU",
    0xFF41:"PTCP-DelayResPDU-followup",
    0xFF42:"PTCP-DelayFuResPDU",
    0xFF43:"PTCP-DelayResPDU",
    }
for i in range(0x0100, 0x1000):
    PNIO_FRAME_IDS[i] = "RT_CLASS_3"
for i in range(0x8000, 0xC000):
    PNIO_FRAME_IDS[i] = "RT_CLASS_1"
for i in range(0xC000, 0xFC00):
    PNIO_FRAME_IDS[i] = "RT_CLASS_UDP"
for i in range(0xFF80, 0xFF90):
    PNIO_FRAME_IDS[i] = "FragmentationFrameID"

#################
## PROFINET IO ##
#################

class ProfinetIO(Packet):
    """Basic PROFINET IO dispatcher"""
    fields_desc = [XShortEnumField("frameID", 0, PNIO_FRAME_IDS)]
    overload_fields = {
        Ether: {"type": 0x8892},
        UDP: {"dport": 0x8892},
        }

    def guess_payload_class(self, payload):
        # For frameID in the RT_CLASS_* range, use the RTC packet as payload
        if (self.frameID >= 0x0100 and self.frameID < 0x1000) or \
                (self.frameID >= 0x8000 and self.frameID < 0xFC00):
            from scapy.contrib.pnio_rtc import PNIORealTime
            return PNIORealTime
        else:
            return Packet.guess_payload_class(self, payload)

bind_layers(Ether, ProfinetIO, type=0x8892)
bind_layers(UDP, ProfinetIO, dport=0x8892)

