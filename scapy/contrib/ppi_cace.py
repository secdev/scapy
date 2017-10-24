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

# author: <jellch@harris.com>

# scapy.contrib.description = PPI CACE
# scapy.contrib.status = loads

"""
CACE PPI types 
"""
import logging,struct
from scapy.config import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import Ether
from scapy.layers.dot11 import Dot11
from scapy.contrib.ppi import *

PPI_DOT11COMMON  = 2
PPI_DOT11NMAC    = 3
PPI_DOT11NMACPHY = 4
PPI_SPECTRUMMAP  = 5
PPI_PROCESSINFO  = 6
PPI_CAPTUREINFO  = 7
PPI_AGGREGATION  = 8
PPI_DOT3         = 9

# PPI 802.11 Common Field Header Fields
class dBmByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "b")
    def i2repr(self, pkt, val):
        if (val != None):
            val = "%4d dBm" % val
        return val

class PPITSFTField(LELongField):
    def i2h(self, pkt, val):
        flags = 0
        if (pkt):
            flags = pkt.getfieldval("Pkt_Flags")
        if not flags:
            flags = 0
        if (flags & 0x02):
            scale = 1e-3
        else:
            scale = 1e-6
        tout = scale * float(val)
        return tout
    def h2i(self, pkt, val):
        scale = 1e6
        if pkt:
            flags = pkt.getfieldval("Pkt_Flags")
            if flags:
                if (flags & 0x02):
                    scale = 1e3
        tout = int((scale * val) + 0.5)
        return tout

_PPIDot11CommonChFlags = ['','','','','Turbo','CCK','OFDM','2GHz','5GHz',
                          'PassiveOnly','Dynamic CCK-OFDM','GSFK']

_PPIDot11CommonPktFlags = ['FCS','TSFT_ms','FCS_Invalid','PHY_Error']

# PPI 802.11 Common Field Header
class Dot11Common(Packet):
    name = "PPI 802.11-Common"
    fields_desc = [ LEShortField('pfh_type',PPI_DOT11COMMON),
                    LEShortField('pfh_length', 20),
                    PPITSFTField('TSF_Timer', 0),
                    FlagsField('Pkt_Flags',0, -16, _PPIDot11CommonPktFlags),
                    LEShortField('Rate',0),
                    LEShortField('Ch_Freq',0),
                    FlagsField('Ch_Flags', 0, -16, _PPIDot11CommonChFlags),
                    ByteField('FHSS_Hop',0),
                    ByteField('FHSS_Pat',0),
                    dBmByteField('Antsignal',-128),
                    dBmByteField('Antnoise',-128)]

    def extract_padding(self, p):
        return b"",p
#Hopefully other CACE defined types will be added here.

#Add the dot11common layer to the PPI array
addPPIType(PPI_DOT11COMMON, Dot11Common)

