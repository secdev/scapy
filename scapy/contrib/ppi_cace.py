## This file is (hopefully) part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## <jellch@harris.com>
## This program is published under a GPLv2 license

"""
CACE PPI tags 
"""
import logging
import struct

from scapy.packet import *
from scapy.fields import *
from scapy.all import conf, bind_layers
from scapy.layers.l2 import Ether, Raw
from scapy.layers.dot11 import Dot11
from ppi import *

DOT11COMMON_TAG = 000002
# more tags here soon

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

_PPIDot11CommonChFlags = ['b0','b1','b2','b3','Turbo','CCK','OFDM','2GHz','5GHz',
                          'PassiveOnly','Dynamic CCK-OFDM','GSFK','b12','b13','b14','b15']

_PPIDot11CommonPktFlags = ['FCS','TSFT_ms','FCS_Invalid','PHY_Error','b4','b5','b6','b7',
                           'b8','b9','b10','b11','b12','b13','b14','b15']

# PPI 802.11 Common Field Header
class Dot11Common(Packet):
    name = "PPI 802.11-Common"
    fields_desc = [ LEShortField('pfh_type',DOT11COMMON_TAG),
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
        return "",p
#Hopefully other CACE defined tags will be added here.

#Add the dot11common layer to the PPI array
addPPIType(DOT11COMMON_TAG, Dot11Common)

