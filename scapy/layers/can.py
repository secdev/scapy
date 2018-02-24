# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license


"""A minimal implementation of the CANopen protocol, based on
Wireshark dissectors. See https://wiki.wireshark.org/CANopen

"""

import struct
import scapy.modules.six as six
from scapy.compat import *
from scapy.config import conf
from scapy.data import DLT_CAN_SOCKETCAN
from scapy.fields import BitField, FieldLenField, FlagsField, StrLenField, \
    ThreeBytesField, XBitField
from scapy.packet import Packet, bind_layers, RawVal
from scapy.layers.l2 import CookedLinux


# Mimics the Wireshark CAN dissector parameter 'Byte-swap the CAN ID/flags field'
#   set to True when working with PF_CAN sockets
conf.contribs['CAN'] = {'swap-bytes': False}


class CAN(Packet):
    """A minimal implementation of the CANopen protocol, based on
    Wireshark dissectors. See https://wiki.wireshark.org/CANopen

    """
    fields_desc = [
        FlagsField('flags', 0, 3, ['error', 'remote_transmission_request', 'extended']),
        XBitField('identifier', 0, 29),
        FieldLenField('length', None, length_of='data', fmt='B'),
        ThreeBytesField('reserved', 0),
        StrLenField('data', '', length_from=lambda pkt: pkt.length),
        StrLenField('padding', '', length_from=lambda pkt: 8 - pkt.length),
    ]

    def pre_dissect(self, s):
        """ Implements the swap-bytes functionality when dissecting """
        if conf.contribs['CAN']['swap-bytes']:
            return struct.pack('<I12s', *struct.unpack('>I12s', s))
        return s

    def self_build(self, field_pos_list=None):
        """ Implements the swap-bytes functionality when building

        this is based on a copy of the Packet.self_build default method.
        The goal is to affect only the CAN layer data and keep
        under layers (e.g LinuxCooked) unchanged
        """
        if self.raw_packet_cache is not None:
            for fname, fval in six.iteritems(self.raw_packet_cache_fields):
                if self.getfieldval(fname) != fval:
                    self.raw_packet_cache = None
                    self.raw_packet_cache_fields = None
                    break
            if self.raw_packet_cache is not None:
                if conf.contribs['CAN']['swap-bytes']:
                    return struct.pack('<I12s', *struct.unpack('>I12s', self.raw_packet_cache))
                return self.raw_packet_cache
        p = b""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            if isinstance(val, RawVal):
                sval = raw(val)
                p += sval
                if field_pos_list is not None:
                    field_pos_list.append((f.name, sval.encode('string_escape'), len(p), len(sval)))
            else:
                p = f.addfield(self, p, val)
        if conf.contribs['CAN']['swap-bytes']:
            return struct.pack('<I12s', *struct.unpack('>I12s', p))
        return p


conf.l2types.register(DLT_CAN_SOCKETCAN, CAN)
bind_layers(CookedLinux, CAN, proto=12)
