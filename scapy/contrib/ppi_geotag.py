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

# scapy.contrib.description = CACE Per-Packet Information (PPI) Geolocation
# scapy.contrib.status = loads


"""
PPI-GEOLOCATION tags
"""

from __future__ import absolute_import
import functools
import struct

from scapy.base_classes import Packet_metaclass
from scapy.data import PPI_GPS, PPI_VECTOR, PPI_SENSOR, PPI_ANTENNA
from scapy.packet import bind_layers
from scapy.fields import ByteField, ConditionalField, Field, FlagsField, \
    LEIntField, LEShortEnumField, LEShortField, StrFixedLenField, \
    UTCTimeField, XLEIntField, SignedByteField, XLEShortField
from scapy.layers.ppi import PPI_Hdr, PPI_Element
from scapy.error import warning
import scapy.modules.six as six
from scapy.modules.six.moves import range

CURR_GEOTAG_VER = 2  # Major revision of specification


# The FixedX_Y Fields are used to store fixed point numbers in a variety of
# fields in the GEOLOCATION-TAGS specification


class _RMMLEIntField(LEIntField):
    __slots__ = ["min_i2h", "max_i2h", "lambda_i2h",
                 "min_h2i", "max_h2i", "lambda_h2i",
                 "rname", "ffmt"]

    def __init__(self, name, default, _min, _max, _min2, _max2, _lmb, _lmb2,
                 fmt, *args, **kargs):
        LEIntField.__init__(self, name, default, *args, **kargs)
        self.min_i2h = _min
        self.max_i2h = _max
        self.lambda_i2h = _lmb
        self.min_h2i = _min2
        self.max_h2i = _max2
        self.lambda_h2i = _lmb2
        self.rname = self.__class__.__name__
        self.ffmt = fmt

    def i2h(self, pkt, x):
        if x is not None:
            if (x < self.min_i2h):
                warning("%s: Internal value too negative: %d", self.rname, x)
                x = int(round(self.min_i2h))
            elif (x > self.max_i2h):
                warning("%s: Internal value too positive: %d", self.rname, x)
                x = self.max_i2h
            x = self.lambda_i2h(x)
        return x

    def h2i(self, pkt, x):
        if x is not None:
            if (x < self.min_h2i):
                warning("%s: Input value too negative: %.10f", self.rname, x)
                x = int(round(self.min_h2i))
            elif (x >= self.max_h2i):
                warning("%s: Input value too positive: %.10f", self.rname, x)
                x = int(round(self.max_h2i))
            x = self.lambda_h2i(x)
        return x

    def i2m(self, pkt, x):
        """Convert internal value to machine value"""
        if x is None:
            # Try to return zero if undefined
            x = self.h2i(pkt, 0)
        return x

    def i2repr(self, pkt, x):
        if x is None:
            y = 0
        else:
            y = self.i2h(pkt, x)
        return ("%" + self.ffmt) % (y)


class Fixed3_6Field(_RMMLEIntField):
    def __init__(self, name, default, *args, **kargs):
        _RMMLEIntField.__init__(self,
                                name, default,
                                0,
                                999999999,
                                -0.5e-6,
                                999.9999995,
                                lambda x: x * 1e-6,
                                lambda x: int(round(x * 1e6)),
                                "3.6f")


class Fixed3_7Field(_RMMLEIntField):
    def __init__(self, name, default, *args, **kargs):
        _RMMLEIntField.__init__(self,
                                name, default,
                                0,
                                3600000000,
                                -180.00000005,
                                180.00000005,
                                lambda x: (x - 1800000000) * 1e-7,
                                lambda x: int(round((x + 180.0) * 1e7)),
                                "3.7f")


class Fixed6_4Field(_RMMLEIntField):
    def __init__(self, name, default, *args, **kargs):
        _RMMLEIntField.__init__(self,
                                name, default,
                                0,
                                3600000000,
                                -180000.00005,
                                180000.00005,
                                lambda x: (x - 1800000000) * 1e-4,
                                lambda x: int(round((x + 180000.0) * 1e4)),
                                "6.4f")

# The GPS timestamps fractional time counter is stored in a 32-bit unsigned ns
# counter.
# The ept field is as well,


class NSCounter_Field(_RMMLEIntField):
    def __init__(self, name, default):
        _RMMLEIntField.__init__(self,
                                name, default,
                                0,
                                2**32,
                                0,
                                (2**32 - 1) / 1e9,
                                lambda x: (x / 1e9),
                                lambda x: int(round(x * 1e9)),
                                "1.9f")


class LETimeField(UTCTimeField, LEIntField):
    __slots__ = ["epoch", "delta", "strf"]

    def __init__(self, name, default, epoch=None,
                 strf="%a, %d %b %Y %H:%M:%S %z"):
        LEIntField.__init__(self, name, default)
        UTCTimeField.__init__(self, name, default, epoch=epoch, strf=strf)


class GPSTime_Field(LETimeField):
    def __init__(self, name, default):
        LETimeField.__init__(self, name, default,
                             strf="%a, %d %b %Y %H:%M:%S UTC")


class VectorFlags_Field(XLEIntField):
    """Represents the VectorFlags field. Handles the RelativeTo:sub-field"""
    _fwdstr = "DefinesForward"
    _resmask = 0xfffffff8
    _relmask = 0x6
    _relnames = [
        "RelativeToForward",
        "RelativeToEarth",
        "RelativeToCurrent",
        "RelativeToReserved",
    ]
    _relvals = [0x00, 0x02, 0x04, 0x06]

    def i2repr(self, pkt, x):
        if x is None:
            return str(x)
        r = []
        if (x & 0x1):
            r.append(self._fwdstr)
        i = (x & self._relmask) >> 1
        r.append(self._relnames[i])
        i = x & self._resmask
        if (i):
            r.append("ReservedBits:%08X" % i)
        sout = "+".join(r)
        return sout

    def any2i(self, pkt, x):
        if isinstance(x, str):
            r = x.split("+")
            y = 0
            for value in r:
                if (value == self._fwdstr):
                    y |= 0x1
                elif (value in self._relnames):
                    i = self._relnames.index(value)
                    y &= (~self._relmask)
                    y |= self._relvals[i]
                else:
                    # logging.warning("Unknown VectorFlags Arg: %s", value)
                    pass
        else:
            y = x
        # print "any2i: %s --> %s" % (str(x), str(y))
        return y


class HCSIFlagsField(FlagsField):
    """A FlagsField where each bit/flag turns a conditional field on or off.

    If the value is None when building a packet, i2m() will check the value of
    every field in self.names.  If the field's value is not None, the
    corresponding flag will be set.
    """

    def i2m(self, pkt, val):
        if val is None:
            val = 0
            if (pkt):
                for i, name in enumerate(self.names):
                    value = pkt.getfieldval(name)
                    if value is not None:
                        val |= 1 << i
        return val


class HCSINullField(Field):
    def __init__(self, name):
        Field.__init__(self, name, None, '!')


def _hcsi_null_range(*args, **kwargs):
    """Builds a list of _HCSINullField with numbered "Reserved" names.

    Takes the same arguments as the ``range`` built-in.

    :returns: list[HCSINullField]
    """
    return [
        HCSINullField('Reserved{:02d}'.format(x))
        for x in range(*args, **kwargs)
    ]


class HCSIDescField(StrFixedLenField):
    def __init__(self, name, default):
        StrFixedLenField.__init__(self, name, default, length=32)


class HCSIAppField(StrFixedLenField):
    def __init__(self, name, default):
        StrFixedLenField.__init__(self, name, default, length=60)


def _FlagsList(myfields):
    flags = ["Reserved%02d" % i for i in range(32)]
    for i, value in six.iteritems(myfields):
        flags[i] = value
    return flags


# Define all geolocation-tag flags lists
_hcsi_gps_flags = _FlagsList({
    0: "No Fix Available",
    1: "GPS",
    2: "Differential GPS",
    3: "Pulse Per Second",
    4: "Real Time Kinematic",
    5: "Float Real Time Kinematic",
    6: "Estimated (Dead Reckoning)",
    7: "Manual Input",
    8: "Simulation",
})

_hcsi_vector_char_flags = _FlagsList({
    0: "Antenna",
    1: "Direction of Travel",
    2: "Front of Vehicle",
    3: "Angle of Arrival",
    4: "Transmitter Position",
    8: "GPS Derived",
    9: "INS Derived",
    10: "Compass Derived",
    11: "Acclerometer Derived",
    12: "Human Derived",
})

_hcsi_antenna_flags = _FlagsList({
    1: "Horizontal Polarization",
    2: "Vertical Polarization",
    3: "Circular Polarization Left",
    4: "Circular Polarization Right",
    16: "Electronically Steerable",
    17: "Mechanically Steerable",
})

# HCSI PPI Fields are similar to RadioTap.  A mask field called "present"
# specifies if each field is present.  All other fields are conditional.  When
# dissecting a packet, each field is present if "present" has the corresponding
# bit set.
#
# When building a packet, if "present" is None, the mask is set to include
# every field that does not have a value of None.  Otherwise, if the mask field
# is not None, only the fields specified by "present" will be added to the
# packet.
#
# To build each Packet type, build a list of the fields normally, excluding
# the present bitmask field.  The code will then construct conditional
# versions of each field and add the present field.
#
# See GPS_Fields as an example.

_COMMON_GEOTAG_HEADERS = [
    ByteField('geotag_ver', CURR_GEOTAG_VER),
    ByteField('geotag_pad', 0),
    LEShortField('geotag_len', None),
]

_COMMON_GEOTAG_FOOTER = [
    HCSIDescField("DescString", None),
    XLEIntField("AppId", None),
    HCSIAppField("AppData", None),
    HCSINullField("Extended"),
]


# Conditional test for all HCSI Fields
def _HCSITest(fname, fbit, pkt):
    if pkt.present is None:
        return pkt.getfieldval(fname) is not None
    return pkt.present & fbit


class _Geotag_metaclass(Packet_metaclass):
    def __new__(cls, name, bases, dct):
        hcsi_fields = dct.get('hcsi_fields', [])

        if len(hcsi_fields) != 0:
            hcsi_fields += _COMMON_GEOTAG_FOOTER
            if len(hcsi_fields) not in (8, 16, 32):
                raise TypeError(
                    'hcsi_fields in {} was {} elements long, expected 8, 16 '
                    'or 32'.format(name, len(hcsi_fields)))

            names = [f.name for f in hcsi_fields]

            # Add the base fields
            fields_desc = _COMMON_GEOTAG_HEADERS + [
                HCSIFlagsField('present', None, -len(names), names),
            ]

            # Add conditional fields
            for i, field in enumerate(hcsi_fields):
                fields_desc.append(ConditionalField(
                    field, functools.partial(
                        _HCSITest, field.name, 1 << i)))

            dct['fields_desc'] = fields_desc

        x = super(_Geotag_metaclass, cls).__new__(cls, name, bases, dct)
        return x


class HCSIPacket(six.with_metaclass(_Geotag_metaclass, PPI_Element)):
    def post_build(self, p, pay):
        if self.geotag_len is None:
            sl_g = struct.pack('<H', len(p))
            p = p[:2] + sl_g + p[4:]
        p += pay
        return p


# GPS Fields
class PPI_Geotag_GPS(HCSIPacket):
    name = "PPI GPS"
    hcsi_fields = [
        FlagsField("GPSFlags", None, -32, _hcsi_gps_flags),
        Fixed3_7Field("Latitude", None),
        Fixed3_7Field("Longitude", None),
        Fixed6_4Field("Altitude", None),
        Fixed6_4Field("Altitude_g", None),
        GPSTime_Field("GPSTime", None),
        NSCounter_Field("FractionalTime", None),
        Fixed3_6Field("eph", None),
        Fixed3_6Field("epv", None),
        NSCounter_Field("ept", None),
    ] + _hcsi_null_range(10, 28)


# Vector fields
class PPI_Geotag_Vector(HCSIPacket):
    name = "PPI Vector"
    hcsi_fields = [
        VectorFlags_Field("VectorFlags", None),
        FlagsField("VectorChars", None, -32, _hcsi_vector_char_flags),
        Fixed3_6Field("Pitch", None),
        Fixed3_6Field("Roll", None),
        Fixed3_6Field("Heading", None),
        Fixed6_4Field("Off_X", None),
        Fixed6_4Field("Off_Y", None),
        Fixed6_4Field("Off_Z", None),
    ] + _hcsi_null_range(8, 16) + [
        Fixed3_6Field("Err_Rot", None),
        Fixed6_4Field("Err_Off", None),
    ] + _hcsi_null_range(18, 28)


# Sensor Fields
# http://www.iana.org/assignments/icmp-parameters
sensor_types = {
    1: "Velocity",
    2: "Acceleration",
    3: "Jerk",
    100: "Rotation",
    101: "Magnetic",
    1000: "Temperature",
    1001: "Barometer",
    1002: "Humidity",
    2000: "TDOA_Clock",
    2001: "Phase"
}


class PPI_Geotag_Sensor(HCSIPacket):
    name = "PPI Sensor"
    hcsi_fields = [
        LEShortEnumField('SensorType', None, sensor_types),
        SignedByteField('ScaleFactor', None),
        Fixed6_4Field('Val_X', None),
        Fixed6_4Field('Val_Y', None),
        Fixed6_4Field('Val_Z', None),
        Fixed6_4Field('Val_T', None),
        Fixed6_4Field('Val_E', None),
    ] + _hcsi_null_range(7, 28)


# HCSIAntenna Fields
class PPI_Geotag_Antenna(HCSIPacket):
    name = "PPI Antenna"
    hcsi_fields = [
        FlagsField("AntennaFlags", None, -32, _hcsi_antenna_flags),
        ByteField("Gain", None),
        Fixed3_6Field("HorizBw", None),
        Fixed3_6Field("VertBw", None),
        Fixed3_6Field("PrecisionGain", None),
        XLEShortField("BeamID", None),
    ] + _hcsi_null_range(6, 26) + [
        HCSIDescField("SerialNumber", None),
        HCSIDescField("ModelName", None),
    ]


bind_layers(PPI_Hdr, PPI_Geotag_GPS, pfh_type=PPI_GPS)
bind_layers(PPI_Hdr, PPI_Geotag_Vector, pfh_type=PPI_VECTOR)
bind_layers(PPI_Hdr, PPI_Geotag_Sensor, pfh_type=PPI_SENSOR)
bind_layers(PPI_Hdr, PPI_Geotag_Antenna, pfh_type=PPI_ANTENNA)
