# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Thomas Tannhaeuser <hecke@naberius.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = IEC-60870-5-104 layer specific fields
# scapy.contrib.status = loads

"""
    field type definitions used by iec 60870-5-104 layer (iec104)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :description:

        This file provides field definitions used by the IEC-60870-5-104
        implementation. Some of those fields are used exclusively by iec104
        (e.g. IEC104SequenceNumber) while others (LESignedShortField) are
        more common an may be moved to fields.py.

        normative references:
            - EN 60870-5-104:2006
            - EN 60870-5-4:1993
            - EN 60870-5-4:1994
"""
import struct

from scapy.compat import orb
from scapy.fields import Field, ThreeBytesField, BitField
from scapy.volatile import RandSShort


class LESignedShortField(Field):
    """
    little endian signed short field
    """
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<h")


class IEC60870_5_4_NormalizedFixPoint(LESignedShortField):
    """
    defined as typ 4.1 in EN 60870-5-4:1993, sec. 5.4.1 (p. 10)
    """

    def i2repr(self, pkt, x):
        """
        show the fixed fp-number and its signed short representation
        """

        return '{} ({})'.format(self.i2h(pkt, x), x)

    def i2h(self, pkt, x):
        return x / 32768.

    def randval(self):
        # ToDo: this could also be implemented by adding fmt h+RandSShort to
        # randval@class Field - should we ?!?
        return RandSShort()


class LEIEEEFloatField(Field):
    """
    little endian IEEE float field
    """
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<f")


class LEThreeBytesField(ThreeBytesField):
    """
    little endian three bytes field
    """
    def __init__(self, name, default):
        ThreeBytesField.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        data = struct.pack(self.fmt, self.i2m(pkt, val))[1:4][::-1]
        return s + data

    def getfield(self, pkt, s):
        data = s[:3][::-1]
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, b"\x00" + data)[0])


class IEC104SequenceNumber(Field):
    """

    IEC 60870-5-104 uses the following encoding for sequence numbers
    (see EN 60870-5-104:2006, p. 13):

      bit ->7   6   5   4   3   2   1   0
          +---+---+---+---+---+---+---+---+
          |   |   |   |   |   |   |LSB| 0 |  byte 0
          +---+---+---+---+---+---+---+---+
          |MSB|   |   |   |   |   |   |   |  byte 1
          +---+---+---+---+---+---+---+---+

    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "!I")

    def addfield(self, pkt, s, val):
        b0 = (val << 1) & 0xfe
        b1 = val >> 7

        return s + bytes(bytearray([b0, b1]))

    def getfield(self, pkt, s):
        b0 = (orb(s[0]) & 0xfe) >> 1
        b1 = orb(s[1])

        seq_num = b0 + (b1 << 7)

        return s[2:], seq_num


class IEC104SignedSevenBitValue(BitField):
    """
    Typ 2.1, 7 Bit, [-64..63]

    see EN 60870-5-4:1994, Typ 2.1 (p. 13)
    """

    def __init__(self, name, default):
        BitField.__init__(self, name, default, 7)

    def m2i(self, pkt, x):

        if x & 64:
            x = x - 128

        return x

    def i2m(self, pkt, x):

        sign = 0
        if x < 0:
            sign = 64
            x = x + 64

        x = x | sign

        return x
