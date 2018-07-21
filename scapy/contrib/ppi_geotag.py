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

# scapy.contrib.description = Parallel Peripheral Interface (PPI) Geolocation
# scapy.contrib.status = loads


"""
PPI-GEOLOCATION tags
"""

from __future__ import absolute_import
import struct

from scapy.packet import Packet
from scapy.fields import ByteField, ConditionalField, FlagsField, \
    LEIntField, LEShortEnumField, LEShortField, StrFixedLenField, \
    UTCTimeField, XLEIntField, SignedByteField, XLEShortField
from scapy.layers.ppi import addPPIType
from scapy.error import warning
import scapy.modules.six as six
from scapy.modules.six.moves import range

CURR_GEOTAG_VER = 2  # Major revision of specification

PPI_GPS = 30002
PPI_VECTOR = 30003
PPI_SENSOR = 30004
PPI_ANTENNA = 30005

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

# The GPS timestamps fractional time counter is stored in a 32-bit unsigned ns counter.  # noqa: E501
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

    def __init__(self, name, default, epoch=None, strf="%a, %d %b %Y %H:%M:%S +0000"):  # noqa: E501
        LEIntField.__init__(self, name, default)
        UTCTimeField.__init__(self, name, default, epoch=epoch, strf=strf)


class GPSTime_Field(LETimeField):
    def __init__(self, name, default):
        return LETimeField.__init__(self, name, default, strf="%a, %d %b %Y %H:%M:%S UTC")  # noqa: E501


class VectorFlags_Field(XLEIntField):
    """Represents the VectorFlags field. Handles the RelativeTo:sub-field"""
    _fwdstr = "DefinesForward"
    _resmask = 0xfffffff8
    _relmask = 0x6
    _relnames = ["RelativeToForward", "RelativeToEarth", "RelativeToCurrent", "RelativeToReserved"]  # noqa: E501
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
                    # logging.warning("Unknown VectorFlags Argument: %s",  value)  # noqa: E501
                    pass
        else:
            y = x
        # print "any2i: %s --> %s" % (str(x), str(y))
        return y


class HCSIFlagsField(FlagsField):
    """ A FlagsField where each bit/flag turns a conditional field on or off.
    If the value is None when building a packet, i2m() will check the value of
    every field in self.names.  If the field's value is not None, the corresponding  # noqa: E501
    flag will be set. """

    def i2m(self, pkt, val):
        if val is None:
            val = 0
            if (pkt):
                for i, name in enumerate(self.names):
                    value = pkt.getfieldval(name)
                    if value is not None:
                        val |= 1 << i
        return val


class HCSINullField(StrFixedLenField):
    def __init__(self, name, default):
        return StrFixedLenField.__init__(self, name, default, length=0)


class HCSIDescField(StrFixedLenField):
    def __init__(self, name, default):
        return StrFixedLenField.__init__(self, name, default, length=32)


class HCSIAppField(StrFixedLenField):
    def __init__(self, name, default):
        return StrFixedLenField.__init__(self, name, default, length=60)


def _FlagsList(myfields):
    flags = ["Reserved%02d" % i for i in range(32)]
    for i, value in six.iteritems(myfields):
        flags[i] = value
    return flags


# Define all geolocation-tag flags lists
_hcsi_gps_flags = _FlagsList({0: "No Fix Available", 1: "GPS", 2: "Differential GPS",  # noqa: E501
                              3: "Pulse Per Second", 4: "Real Time Kinematic",
                              5: "Float Real Time Kinematic", 6: "Estimated (Dead Reckoning)",  # noqa: E501
                              7: "Manual Input", 8: "Simulation"})

# _hcsi_vector_flags = _FlagsList({0:"ForwardFrame", 1:"RotationsAbsoluteXYZ", 5:"OffsetFromGPS_XYZ"})  # noqa: E501
# This has been replaced with the VectorFlags_Field class, in order to handle the RelativeTo:subfield  # noqa: E501

_hcsi_vector_char_flags = _FlagsList({0: "Antenna", 1: "Direction of Travel",
                                      2: "Front of Vehicle", 3: "Angle of Arrival", 4: "Transmitter Position",  # noqa: E501
                                      8: "GPS Derived", 9: "INS Derived", 10: "Compass Derived",  # noqa: E501
                                      11: "Acclerometer Derived", 12: "Human Derived"})  # noqa: E501

_hcsi_antenna_flags = _FlagsList({1: "Horizontal Polarization", 2: "Vertical Polarization",  # noqa: E501
                                  3: "Circular Polarization Left", 4: "Circular Polarization Right",  # noqa: E501
                                  16: "Electronically Steerable", 17: "Mechanically Steerable"})  # noqa: E501

""" HCSI PPI Fields are similar to RadioTap.  A mask field called "present" specifies if each field  # noqa: E501
is present.  All other fields are conditional.  When dissecting a packet, each field is present if  # noqa: E501
"present" has the corresponding bit set.  When building a packet, if "present" is None, the mask is  # noqa: E501
set to include every field that does not have a value of None.  Otherwise, if the mask field is  # noqa: E501
not None, only the fields specified by "present" will be added to the packet.

To build each Packet type, build a list of the fields normally, excluding the present bitmask field.  # noqa: E501
The code will then construct conditional versions of each field and add the present field.  # noqa: E501
See GPS_Fields as an example. """

# Conditional test for all HCSI Fields


def _HCSITest(pkt, ibit, name):
    if pkt.present is None:
        return (pkt.getfieldval(name) is not None)
    return pkt.present & ibit

# Wrap optional fields in ConditionalField, add HCSIFlagsField


def _HCSIBuildFields(fields):
    names = [f.name for f in fields]
    cond_fields = [HCSIFlagsField('present', None, -len(names), names)]
    for i, name in enumerate(names):
        ibit = 1 << i
        seval = "lambda pkt:_HCSITest(pkt,%s,'%s')" % (ibit, name)
        test = eval(seval)
        cond_fields.append(ConditionalField(fields[i], test))
    return cond_fields


class HCSIPacket(Packet):
    name = "PPI HCSI"
    fields_desc = [LEShortField('pfh_type', None),
                   LEShortField('pfh_length', None),
                   ByteField('geotag_ver', CURR_GEOTAG_VER),
                   ByteField('geotag_pad', 0),
                   LEShortField('geotag_len', None)]

    def post_build(self, p, pay):
        if self.pfh_length is None:
            tmp_len = len(p) - 4
            sl = struct.pack('<H', tmp_len)
            p = p[:2] + sl + p[4:]
        if self.geotag_len is None:
            l_g = len(p) - 4
            sl_g = struct.pack('<H', l_g)
            p = p[:6] + sl_g + p[8:]
        p += pay
        return p

    def extract_padding(self, p):
        return b"", p


# GPS Fields
GPS_Fields = [FlagsField("GPSFlags", None, -32, _hcsi_gps_flags),
              Fixed3_7Field("Latitude", None),
              Fixed3_7Field("Longitude", None), Fixed6_4Field("Altitude", None),  # noqa: E501
              Fixed6_4Field("Altitude_g", None), GPSTime_Field("GPSTime", None),  # noqa: E501
              NSCounter_Field("FractionalTime", None), Fixed3_6Field("eph", None),  # noqa: E501
              Fixed3_6Field("epv", None), NSCounter_Field("ept", None),
              HCSINullField("Reserved10", None), HCSINullField("Reserved11", None),  # noqa: E501
              HCSINullField("Reserved12", None), HCSINullField("Reserved13", None),  # noqa: E501
              HCSINullField("Reserved14", None), HCSINullField("Reserved15", None),  # noqa: E501
              HCSINullField("Reserved16", None), HCSINullField("Reserved17", None),  # noqa: E501
              HCSINullField("Reserved18", None), HCSINullField("Reserved19", None),  # noqa: E501
              HCSINullField("Reserved20", None), HCSINullField("Reserved21", None),  # noqa: E501
              HCSINullField("Reserved22", None), HCSINullField("Reserved23", None),  # noqa: E501
              HCSINullField("Reserved24", None), HCSINullField("Reserved25", None),  # noqa: E501
              HCSINullField("Reserved26", None), HCSINullField("Reserved27", None),  # noqa: E501
              HCSIDescField("DescString", None), XLEIntField("AppId", None),
              HCSIAppField("AppData", None), HCSINullField("Extended", None)]


class GPS(HCSIPacket):
    name = "PPI GPS"
    fields_desc = [LEShortField('pfh_type', PPI_GPS),  # pfh_type
                   LEShortField('pfh_length', None),  # pfh_len
                   ByteField('geotag_ver', CURR_GEOTAG_VER),  # base_geotag_header.ver  # noqa: E501
                   ByteField('geotag_pad', 0),  # base_geotag_header.pad
                   LEShortField('geotag_len', None)] + _HCSIBuildFields(GPS_Fields)  # noqa: E501


# Vector Fields
VEC_Fields = [VectorFlags_Field("VectorFlags", None),
              FlagsField("VectorChars", None, -32, _hcsi_vector_char_flags),
              Fixed3_6Field("Pitch", None), Fixed3_6Field("Roll", None),
              Fixed3_6Field("Heading", None), Fixed6_4Field("Off_X", None),
              Fixed6_4Field("Off_Y", None), Fixed6_4Field("Off_Z", None),
              HCSINullField("Reserved08", None), HCSINullField("Reserved09", None),  # noqa: E501
              HCSINullField("Reserved10", None), HCSINullField("Reserved11", None),  # noqa: E501
              HCSINullField("Reserved12", None), HCSINullField("Reserved13", None),  # noqa: E501
              HCSINullField("Reserved14", None), HCSINullField("Reserved15", None),  # noqa: E501
              Fixed3_6Field("Err_Rot", None), Fixed6_4Field("Err_Off", None),
              HCSINullField("Reserved18", None), HCSINullField("Reserved19", None),  # noqa: E501
              HCSINullField("Reserved20", None), HCSINullField("Reserved21", None),  # noqa: E501
              HCSINullField("Reserved22", None), HCSINullField("Reserved23", None),  # noqa: E501
              HCSINullField("Reserved24", None), HCSINullField("Reserved25", None),  # noqa: E501
              HCSINullField("Reserved26", None), HCSINullField("Reserved27", None),  # noqa: E501
              HCSIDescField("DescString", None), XLEIntField("AppId", None),
              HCSIAppField("AppData", None), HCSINullField("Extended", None)]


class Vector(HCSIPacket):
    name = "PPI Vector"
    fields_desc = [LEShortField('pfh_type', PPI_VECTOR),  # pfh_type
                   LEShortField('pfh_length', None),  # pfh_len
                   ByteField('geotag_ver', CURR_GEOTAG_VER),  # base_geotag_header.ver  # noqa: E501
                   ByteField('geotag_pad', 0),  # base_geotag_header.pad
                   LEShortField('geotag_len', None)] + _HCSIBuildFields(VEC_Fields)  # noqa: E501


# Sensor Fields
# http://www.iana.org/assignments/icmp-parameters
sensor_types = {1: "Velocity",
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
SENS_Fields = [LEShortEnumField('SensorType', None, sensor_types),
               SignedByteField('ScaleFactor', None),
               Fixed6_4Field('Val_X', None),
               Fixed6_4Field('Val_Y', None),
               Fixed6_4Field('Val_Z', None),
               Fixed6_4Field('Val_T', None),
               Fixed6_4Field('Val_E', None),
               HCSINullField("Reserved07", None), HCSINullField("Reserved08", None),  # noqa: E501
               HCSINullField("Reserved09", None), HCSINullField("Reserved10", None),  # noqa: E501
               HCSINullField("Reserved11", None), HCSINullField("Reserved12", None),  # noqa: E501
               HCSINullField("Reserved13", None), HCSINullField("Reserved14", None),  # noqa: E501
               HCSINullField("Reserved15", None), HCSINullField("Reserved16", None),  # noqa: E501
               HCSINullField("Reserved17", None), HCSINullField("Reserved18", None),  # noqa: E501
               HCSINullField("Reserved19", None), HCSINullField("Reserved20", None),  # noqa: E501
               HCSINullField("Reserved21", None), HCSINullField("Reserved22", None),  # noqa: E501
               HCSINullField("Reserved23", None), HCSINullField("Reserved24", None),  # noqa: E501
               HCSINullField("Reserved25", None), HCSINullField("Reserved26", None),  # noqa: E501
               HCSINullField("Reserved27", None),
               HCSIDescField("DescString", None), XLEIntField("AppId", None),
               HCSIAppField("AppData", None), HCSINullField("Extended", None)]


class Sensor(HCSIPacket):
    name = "PPI Sensor"
    fields_desc = [LEShortField('pfh_type', PPI_SENSOR),  # pfh_type
                   LEShortField('pfh_length', None),  # pfh_len
                   ByteField('geotag_ver', CURR_GEOTAG_VER),  # base_geotag_header.ver  # noqa: E501
                   ByteField('geotag_pad', 0),  # base_geotag_header.pad
                   LEShortField('geotag_len', None)] + _HCSIBuildFields(SENS_Fields)  # noqa: E501


# HCSIAntenna Fields
ANT_Fields = [FlagsField("AntennaFlags", None, -32, _hcsi_antenna_flags),
              ByteField("Gain", None),
              Fixed3_6Field("HorizBw", None), Fixed3_6Field("VertBw", None),
              Fixed3_6Field("PrecisionGain", None), XLEShortField("BeamID", None),  # noqa: E501
              HCSINullField("Reserved06", None), HCSINullField("Reserved07", None),  # noqa: E501
              HCSINullField("Reserved08", None), HCSINullField("Reserved09", None),  # noqa: E501
              HCSINullField("Reserved10", None), HCSINullField("Reserved11", None),  # noqa: E501
              HCSINullField("Reserved12", None), HCSINullField("Reserved13", None),  # noqa: E501
              HCSINullField("Reserved14", None), HCSINullField("Reserved15", None),  # noqa: E501
              HCSINullField("Reserved16", None), HCSINullField("Reserved17", None),  # noqa: E501
              HCSINullField("Reserved18", None), HCSINullField("Reserved19", None),  # noqa: E501
              HCSINullField("Reserved20", None), HCSINullField("Reserved21", None),  # noqa: E501
              HCSINullField("Reserved22", None), HCSINullField("Reserved23", None),  # noqa: E501
              HCSINullField("Reserved24", None), HCSINullField("Reserved25", None),  # noqa: E501
              HCSIDescField("SerialNumber", None), HCSIDescField("ModelName", None),  # noqa: E501
              HCSIDescField("DescString", None), XLEIntField("AppId", None),
              HCSIAppField("AppData", None), HCSINullField("Extended", None)]


class Antenna(HCSIPacket):
    name = "PPI Antenna"
    fields_desc = [LEShortField('pfh_type', PPI_ANTENNA),  # pfh_type
                   LEShortField('pfh_length', None),  # pfh_len
                   ByteField('geotag_ver', CURR_GEOTAG_VER),  # base_geotag_header.ver  # noqa: E501
                   ByteField('geotag_pad', 0),  # base_geotag_header.pad
                   LEShortField('geotag_len', None)] + _HCSIBuildFields(ANT_Fields)  # noqa: E501


addPPIType(PPI_GPS, GPS)
addPPIType(PPI_VECTOR, Vector)
addPPIType(PPI_SENSOR, Sensor)
addPPIType(PPI_ANTENNA, Antenna)
