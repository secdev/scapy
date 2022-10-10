# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# author: <jellch@harris.com>

# scapy.contrib.description = CACE Per-Packet Information (PPI)
# scapy.contrib.status = loads

"""
CACE PPI types
"""

from scapy.data import PPI_DOT11COMMON
from scapy.packet import bind_layers
from scapy.fields import ByteField, Field, FlagsField, LELongField, \
    LEShortField
from scapy.layers.ppi import PPI_Hdr, PPI_Element


# PPI 802.11 Common Field Header Fields
class dBmByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "b")

    def i2repr(self, pkt, x):
        if x is not None:
            x = "%4d dBm" % x
        return x


class PPITSFTField(LELongField):
    def i2h(self, pkt, x):
        flags = 0
        if pkt:
            flags = pkt.getfieldval("Pkt_Flags")
        if not flags:
            flags = 0
        if flags & 0x02:
            scale = 1e-3
        else:
            scale = 1e-6
        tout = scale * float(x)
        return tout

    def h2i(self, pkt, x):
        scale = 1e6
        if pkt:
            flags = pkt.getfieldval("Pkt_Flags")
            if flags and (flags & 0x02):
                scale = 1e3
        tout = int((scale * x) + 0.5)
        return tout


_PPIDot11CommonChFlags = [
    '', '', '', '', 'Turbo', 'CCK', 'OFDM', '2GHz', '5GHz',
    'PassiveOnly', 'Dynamic CCK-OFDM', 'GSFK']

_PPIDot11CommonPktFlags = ['FCS', 'TSFT_ms', 'FCS_Invalid', 'PHY_Error']


# PPI 802.11 Common Field Header
class PPI_Dot11Common(PPI_Element):
    name = "PPI 802.11-Common"
    fields_desc = [PPITSFTField('TSF_Timer', 0),
                   FlagsField('Pkt_Flags', 0, -16, _PPIDot11CommonPktFlags),
                   LEShortField('Rate', 0),
                   LEShortField('Ch_Freq', 0),
                   FlagsField('Ch_Flags', 0, -16, _PPIDot11CommonChFlags),
                   ByteField('FHSS_Hop', 0),
                   ByteField('FHSS_Pat', 0),
                   dBmByteField('Antsignal', -128),
                   dBmByteField('Antnoise', -128)]

    def extract_padding(self, s):
        return b'', s


# Hopefully other CACE defined types will be added here.


# Add the dot11common layer to the PPI array
bind_layers(PPI_Hdr, PPI_Dot11Common, pfh_type=PPI_DOT11COMMON)
