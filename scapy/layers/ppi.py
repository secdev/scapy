# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Original PPI author: <jellch@harris.com>

# scapy.contrib.description = CACE Per-Packet Information (PPI) header
# scapy.contrib.status = loads

"""
CACE Per-Packet Information (PPI) header.

A method for adding metadata to link-layer packets.

For example, one can tag an 802.11 packet with GPS coordinates of where it
was captured, and include it in the PCAP file.

New PPI types should:

 * Make their packet a subclass of ``PPI_Element``
 * Call ``bind_layers(PPI_Hdr, ExamplePPI, pfh_type=0xffff)``

See ``layers/contrib/ppi_cace.py`` for an example.
"""

from scapy.config import conf
from scapy.data import DLT_PPI, PPI_TYPES
from scapy.error import warning
from scapy.packet import Packet
from scapy.fields import ByteField, FieldLenField, LEIntField, \
    PacketListField, LEShortEnumField, LenField


class PPI_Hdr(Packet):
    name = 'PPI Header'
    fields_desc = [
        LEShortEnumField('pfh_type', 0, PPI_TYPES),
        LenField('pfh_length', None, fmt='<H'),
    ]

    def mysummary(self):
        return self.sprintf('PPI %pfh_type%')


class PPI_Element(Packet):
    """Superclass for all PPI types."""
    name = 'PPI Element'

    def extract_padding(self, s):
        return b'', s

    @staticmethod
    def length_from(pkt):
        if not pkt.underlayer:
            warning('Missing under-layer')
            return 0

        return pkt.underlayer.len


class PPI(Packet):
    name = 'Per-Packet Information header (PPI)'
    fields_desc = [
        ByteField('version', 0),
        ByteField('flags', 0),
        FieldLenField('len', None, length_of='headers', fmt='<H',
                      adjust=lambda p, x: x + 8),  # length of this packet
        LEIntField('dlt', None),
        PacketListField('headers', [], PPI_Hdr,
                        length_from=lambda p: p.len - 8),
    ]

    def add_payload(self, payload):
        Packet.add_payload(self, payload)

        # Update the DLT if not set
        if self.getfieldval('dlt') is None and isinstance(payload, Packet):
            self.setfieldval('dlt', conf.l2types.get(payload.__class__))

    def guess_payload_class(self, payload):
        # Pass DLT handling to conf.l2types.
        return conf.l2types.get(
            self.getfieldval('dlt'), Packet.guess_payload_class(self, payload))


conf.l2types.register(DLT_PPI, PPI)
