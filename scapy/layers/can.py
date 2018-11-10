# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license


"""A minimal implementation of the CANopen protocol, based on
Wireshark dissectors. See https://wiki.wireshark.org/CANopen

"""

import struct
import binascii
import scapy.modules.six as six
from scapy.config import conf
from scapy.data import DLT_CAN_SOCKETCAN
from scapy.fields import FieldLenField, FlagsField, StrLenField, \
    ThreeBytesField, XBitField
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import CookedLinux

__all__ = ["CAN", "rdcandump"]

# Mimics the Wireshark CAN dissector parameter 'Byte-swap the CAN ID/flags field'  # noqa: E501
#   set to True when working with PF_CAN sockets
conf.contribs['CAN'] = {'swap-bytes': False}


class CAN(Packet):
    """A minimal implementation of the CANopen protocol, based on
    Wireshark dissectors. See https://wiki.wireshark.org/CANopen

    """
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        FieldLenField('length', None, length_of='data', fmt='B'),
        ThreeBytesField('reserved', 0),
        StrLenField('data', '', length_from=lambda pkt: pkt.length),
    ]

    @staticmethod
    def inv_endianness(pkt):
        """ Invert the order of the first four bytes of a CAN packet

        This method is meant to be used specifically to convert a CAN packet
        between the pcap format and the socketCAN format

        :param pkt: str of the CAN packet
        :return: packet str with the first four bytes swapped
        """
        len_partial = len(pkt) - 4  # len of the packet, CAN ID excluded
        return struct.pack('<I{}s'.format(len_partial),
                           *struct.unpack('>I{}s'.format(len_partial), pkt))

    def pre_dissect(self, s):
        """ Implements the swap-bytes functionality when dissecting """
        if conf.contribs['CAN']['swap-bytes']:
            return CAN.inv_endianness(s)
        return s

    def post_dissect(self, s):
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def post_build(self, pkt, pay):
        """ Implements the swap-bytes functionality when building

        this is based on a copy of the Packet.self_build default method.
        The goal is to affect only the CAN layer data and keep
        under layers (e.g LinuxCooked) unchanged
        """
        if conf.contribs['CAN']['swap-bytes']:
            return CAN.inv_endianness(pkt) + pay
        return pkt + pay

    def extract_padding(self, p):
        return b'', p


conf.l2types.register(DLT_CAN_SOCKETCAN, CAN)
bind_layers(CookedLinux, CAN, proto=12)


def rdcandump(filename, count=None,
              is_not_log_file_format=False,
              interface=None):
    """Read a candump log file and return a packet list

count: read only <count> packets
is_not_log_file_format: read input with candumps stdout format
interfaces: return only packets from a specified interface

    """
    try:
        if isinstance(filename, six.string_types):
            file = open(filename, "rb")
        else:
            file = filename

        pkts = list()
        ifilter = None
        if interface is not None:
            if isinstance(interface, six.string_types):
                ifilter = [interface]
            else:
                ifilter = interface

        for l in file.readlines():
            if is_not_log_file_format:
                h, data = l.split(b']')
                intf, idn, le = h.split()
                t = None
            else:
                t, intf, f = l.split()
                idn, data = f.split(b'#')
                le = None
                t = float(t[1:-1])

            if ifilter is not None and intf.decode('ASCII') not in ifilter:
                continue

            data = data.replace(b' ', b'')
            data = data.strip()

            pkt = CAN(identifier=int(idn, 16), data=binascii.unhexlify(data))
            if le is not None:
                pkt.length = int(le[1:])
            else:
                pkt.length = len(pkt.data)

            if pkt.identifier > 0x7ff:
                pkt.flags = 0b100

            if t is not None:
                pkt.time = t

            pkts.append(pkt)
            if count is not None and len(pkts) >= count:
                break

    finally:
        file.close()

    return pkts
