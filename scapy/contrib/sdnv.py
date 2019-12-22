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

"""
 Copyright 2012, The MITRE Corporation::

                              NOTICE
    This software/technical data was produced for the U.S. Government
    under Prime Contract No. NASA-03001 and JPL Contract No. 1295026
      and is subject to FAR 52.227-14 (6/87) Rights in Data General,
        and Article GP-51, Rights in Data  General, respectively.
       This software is publicly released under MITRE case #12-3054
"""

# scapy.contrib.description = Self-Delimiting Numeric Values (SDNV)
# scapy.contrib.status = library

from scapy.fields import Field, FieldLenField, LenField
from scapy.compat import raw

# SDNV definitions


class SDNVValueError(Exception):
    def __init__(self, maxValue):
        self.maxValue = maxValue


class SDNV:
    def __init__(self, maxValue=2**32 - 1):
        self.maxValue = maxValue
        return

    def setMax(self, maxValue):
        self.maxValue = maxValue

    def getMax(self):
        return self.maxValue

    def encode(self, number):
        if number > self.maxValue:
            raise SDNVValueError(self.maxValue)

        foo = bytearray()
        foo.append(number & 0x7F)
        number = number >> 7

        while (number > 0):
            thisByte = number & 0x7F
            thisByte |= 0x80
            number = number >> 7
            temp = bytearray()
            temp.append(thisByte)
            foo = temp + foo

        return(foo)

    def decode(self, ba, offset):
        number = 0
        numBytes = 1

        b = ba[offset]
        number = (b & 0x7F)
        while (b & 0x80 == 0x80):
            number = number << 7
            if (number > self.maxValue):
                raise SDNVValueError(self.maxValue)
            b = ba[offset + numBytes]
            number += (b & 0x7F)
            numBytes += 1
        if (number > self.maxValue):
            raise SDNVValueError(self.maxValue)
        return(number, numBytes)


SDNVUtil = SDNV()


class SDNV2(Field):
    """ SDNV2 field """

    def addfield(self, pkt, s, val):
        return s + raw(SDNVUtil.encode(val))

    def getfield(self, pkt, s):
        b = bytearray(s)
        val, len = SDNVUtil.decode(b, 0)
        return s[len:], val


class SDNV2FieldLenField(FieldLenField, SDNV2):
    def addfield(self, pkt, s, val):
        return s + raw(SDNVUtil.encode(FieldLenField.i2m(self, pkt, val)))


class SDNV2LenField(LenField, SDNV2):
    def addfield(self, pkt, s, val):
        return s + raw(SDNVUtil.encode(LenField.i2m(self, pkt, val)))
