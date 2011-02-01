## This file is (hopefully) part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## <jellch@harris.com>
## This program is published under a GPLv2 license
"""
PPI-GEOLOCATION tags
"""
import struct,time
from scapy.packet import *
from scapy.fields import *
from scapy.layers.ppi import PPIGenericFldHdr,addPPIType

PPI_GPS     = 30002
PPI_VECTOR  = 30003
PPI_ANTENNA = 30005

#The FixedX_Y Fields are used to store fixed point numbers in a variety of fields in the GEOLOCATION-TAGS specification
class Fixed3_6Field(LEIntField):
    def i2h(self, pkt, x):
        if x is not None:
            if (x < 0):
                warning("Fixed3_6: Internal value too negative: %d" % x)
                x = 0
            elif (x > 999999999):
                warning("Fixed3_6: Internal value too positive: %d" % x)
                x = 999999999
            x = x * 1e-6
        return x
    def h2i(self, pkt, x):
        if x is not None:
            if (x <= -0.5e-6):
                warning("Fixed3_6: Input value too negative: %.7f" % x)
                x = 0
            elif (x >= 999.9999995):
                warning("Fixed3_6: Input value too positive: %.7f" % x)
                x = 999.999999
            x = int(round(x * 1e6))
        return x
    def i2repr(self,pkt,x):
        if x is None:
            y=0
        else:
            y=self.i2h(pkt,x)
        return "%3.6f"%(y)
class Fixed3_7Field(LEIntField):
    def i2h(self, pkt, x):
        if x is not None:
            if (x < 0):
                warning("Fixed3_7: Internal value too negative: %d" % x)
                x = 0
            elif (x > 3600000000):
                warning("Fixed3_7: Internal value too positive: %d" % x)
                x = 3600000000
            x = (x - 1800000000) * 1e-7
        return x
    def h2i(self, pkt, x):
        if x is not None:
            if (x <= -180.00000005):
                warning("Fixed3_7: Input value too negative: %.8f" % x)
                x = -180.0
            elif (x >= 180.00000005):
                warning("Fixed3_7: Input value too positive: %.8f" % x)
                x = 180.0
            x = int(round((x + 180.0) * 1e7))
        return x
    def i2repr(self,pkt,x):
        if x is None:
            y=0
        else:
            y=self.i2h(pkt,x)
        return "%3.7f"%(y)

class Fixed6_4Field(LEIntField):
    def i2h(self, pkt, x):
        if x is not None:
            if (x < 0):
                warning("Fixed6_4: Internal value too negative: %d" % x)
                x = 0
            elif (x > 3600000000):
                warning("Fixed6_4: Internal value too positive: %d" % x)
                x = 3600000000
            x = (x - 1800000000) * 1e-4
        return x
    def h2i(self, pkt, x):
        if x is not None:
            if (x <= -180000.00005):
                warning("Fixed6_4: Input value too negative: %.5f" % x)
                x = -180000.0
            elif (x >= 180000.00005):
                warning("Fixed6_4: Input value too positive: %.5f" % x)
                x = 180000.0
            x = int(round((x + 180000.0) * 1e4))
        return x
    def i2repr(self,pkt,x):
        if x is None:
            y=0
        else:
            y=self.i2h(pkt,x)
        return "%6.4f"%(y)
#The GPS timestamps fractional time counter is stored in a 32-bit unsigned ns counter.
#The ept field is as well,
class NSCounter_Field(LEIntField):
    def i2h(self, pkt, x): #converts nano-seconds to seconds for output
        if x is not None:
            if (x < 0):
                warning("NSCounter_Field: Internal value too negative: %d" % x)
                x = 0
            elif (x >= 2**32):
                warning("NSCounter_Field: Internal value too positive: %d" % x)
                x = 2**32-1
            x = (x / 1e9)
        return x
    def h2i(self, pkt, x): #converts input in seconds into nano-seconds for storage
        if x is not None:
            if (x < 0):
                warning("NSCounter_Field: Input value too negative: %.10f" % x)
                x = 0
            elif (x >= (2**32) / 1e9):
                warning("NSCounter_Field: Input value too positive: %.10f" % x)
                x = (2**32-1) / 1e9
            x = int(round((x * 1e9)))
        return x
    def i2repr(self,pkt,x):
        if x is None:
            y=0
        else:
            y=self.i2h(pkt,x)
        return "%1.9f"%(y)
#This belongs in fields.py
class XLEIntField(LEIntField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))
class XLEShortField(LEShortField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

#This is based off dhcp6.py
class GPSTime_Field(LEIntField):
    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x) #this was stored in UTC
        t = time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime(x))
        return "%s (%d)" % (t, x)

class HCSIFlagsField(FlagsField):
    """ A FlagsField where each bit/flag turns a conditional field on or off.
    If the value is None when building a packet, i2m() will check the value of
    every field in self.names.  If the field's value is not None, the corresponding
    flag will be set. """
    def i2m(self, pkt, val):
        if val is None:
            val = 0
            if (pkt):
                for i in range(len(self.names)):
                    name = self.names[i][0]
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

def FlagsList(myfields):
    flags = []
    for i in range(32):
        flags.append("Reserved%02d" % i)
    for i in myfields.keys():
        flags[i] = myfields[i]
    return flags

# Define all geolocation-tag flags lists
_hcsi_gps_flags = FlagsList({0:"No Fix Available", 1:"GPS", 2:"Differential GPS",
                             3:"Pulse Per Second", 4:"Real Time Kinematic",
                             5:"Float Real Time Kinematic", 6:"Estimated (Dead Reckoning)",
                             7:"Manual Input", 8:"Simulation"})
class HCSIGpsFlagsField(FlagsField):
    def __init__(self, name, default):
        return FlagsField.__init__(self, name, default, -32, _hcsi_gps_flags)

_hcsi_vector_flags = FlagsList({0:"ForwardFrame", 1:"RotationsAbsoluteXYZ", 5:"OffsetFromGPS_XYZ"})
class HCSIVectorFlagsField(FlagsField):
    def __init__(self, name, default):
        return FlagsField.__init__(self, name, default, -32, _hcsi_vector_flags)
_hcsi_vector_char_flags = FlagsList({0:"Antenna", 1:"Direction of Travel",
                                     2:"Front of Vehicle", 8:"GPS Derived",
                                     9:"INS Derived", 10:"Compass Derived",
                                    11:"Accerometer Derived", 12:"Human Derived"})

class HCSIVectorCharacteristicsFlagsField(FlagsField):
    def __init__(self, name, default):
        return FlagsField.__init__(self, name, default, -32, _hcsi_vector_char_flags)
_hcsi_antenna_flags = FlagsList({ 1:"Horizontal Polarization",     2:"Vertical Polarization",
                                  3:"Circular Polarization Left",  4:"Circular Polarization Right",
                                 16:"Electronically Steerable",   17:"Mechanically Steerable"})

class HCSIAntennaFlagsField(FlagsField):
    def __init__(self, name, default):
        return FlagsField.__init__(self, name, default, -32, _hcsi_antenna_flags)

""" HCSI PPI Fields are similar to RadioTap.  A mask field called "present" specifies if each field
is present.  All other fields are conditional.  When dissecting a packet, each field is present if
"present" has the corresponding bit set.  When building a packet, if "present" is None, the mask is
set to include every field that does not have a value of None.  Otherwise, if the mask field is
not None, only the fields specified by "present" will be added to the packet.

To build each Packet type, build a list of the fields normally, excluding the present bitmask field.
The code will then construct conditional versions of each field and add the present field.
See GPS_Fields as an example. """

# Conditional test for all HCSI Fields
def _HCSITest(pkt, ibit, name):
    if pkt.present is None:
        return (pkt.getfieldval(name) is not None)
    return pkt.present & ibit

class HCSIPacket(Packet):
    name = "PPI HCSI"
    fields_desc = [ LEShortField('pfh_type', None),
                    LEShortField('pfh_length', None),
                    ByteField('geotag_ver', None),
                    ByteField('geotag_pad', None),
                    LEShortField('geotag_len', None)]
    def post_build(self, p, pay):
        if self.pfh_length is None:
            l = len(p) - 4
            sl = struct.pack('<H',l)
            p = p[:2] + sl + p[4:]
        if self.geotag_len is None:
            l_g = len(p) - 4
            sl_g = struct.pack('<H',l_g)
            p = p[:6] + sl_g + p[8:]
        p += pay
        return p
    def extract_padding(self, p):
        return "",p

# HCSIGPS Fields
GPS_Fields = [HCSIGpsFlagsField("GPSFlags", None), Fixed3_7Field("Latitude", None),
              Fixed3_7Field("Longitude", None),    Fixed6_4Field("Altitude", None),
              Fixed6_4Field("Altitude_g", None),   GPSTime_Field("GPSTime", None),
              NSCounter_Field("FractionalTime", None),  Fixed3_6Field("eph", None),
              Fixed3_6Field("epv", None),          NSCounter_Field("ept", None),
              HCSINullField("Reserved10", None),   HCSINullField("Reserved11", None),
              HCSINullField("Reserved12", None),   HCSINullField("Reserved13", None),
              HCSINullField("Reserved14", None),   HCSINullField("Reserved15", None),
              HCSINullField("Reserved16", None),   HCSINullField("Reserved17", None),
              HCSINullField("Reserved18", None),   HCSINullField("Reserved19", None),
              HCSINullField("Reserved20", None),   HCSINullField("Reserved21", None),
              HCSINullField("Reserved22", None),   HCSINullField("Reserved23", None),
              HCSINullField("Reserved24", None),   HCSINullField("Reserved25", None),
              HCSINullField("Reserved26", None),   HCSINullField("Reserved27", None),
              HCSIDescField("DescString", None),   XLEIntField("AppId", None),
              HCSIAppField("AppData", None),       HCSINullField("Extended", None)]

names = []
for fld in GPS_Fields:
    names.append(fld.name)

_hcsi_gps_fields = [ HCSIFlagsField('present',None,-len(names), names)]
for i in range(len(names)):
    ibit = 1 << i
    seval = "lambda pkt:_HCSITest(pkt,%s,'%s')" % (ibit, names[i])
    test = eval(seval)
    _hcsi_gps_fields.append(ConditionalField(GPS_Fields[i], test))

class GPS(HCSIPacket):
    name = "PPI GPS"
    fields_desc = [ LEShortField('pfh_type', PPI_GPS), #pfh_type
                    LEShortField('pfh_length', None), #pfh_len
                    ByteField('geotag_ver', 1), #base_geotag_header.ver
                    ByteField('geotag_pad', 2), #base_geotag_header.pad
                    LEShortField('geotag_len', None)] + _hcsi_gps_fields


# HCSIVector Fields
VEC_Fields = [HCSIVectorFlagsField("VectorFlags", None),
              HCSIVectorCharacteristicsFlagsField("VectorChars", None),
              Fixed3_6Field("Pitch", None),       Fixed3_6Field("Roll", None),
              Fixed3_6Field("Heading", None),     Fixed6_4Field("Off_R", None),
              Fixed6_4Field("Off_F", None),       Fixed6_4Field("Off_U", None),
              Fixed6_4Field("Vel_R", None),       Fixed6_4Field("Vel_F", None),
              Fixed6_4Field("Vel_U", None),       Fixed6_4Field("Vel_T", None),
              Fixed6_4Field("Acc_R", None),       Fixed6_4Field("Acc_F", None),
              Fixed6_4Field("Acc_U", None),       Fixed6_4Field("Acc_T", None),
              Fixed3_6Field("Err_Rot", None),     Fixed6_4Field("Err_Off", None),
              Fixed6_4Field("Err_Vel", None),     Fixed6_4Field("Err_Acc", None),
              HCSINullField("Reserved20", None),  HCSINullField("Reserved21", None),
              HCSINullField("Reserved22", None),  HCSINullField("Reserved23", None),
              HCSINullField("Reserved24", None),  HCSINullField("Reserved25", None),
              HCSINullField("Reserved26", None),  HCSINullField("Reserved27", None),
              HCSIDescField("DescString", None),  XLEIntField("AppId", None),
              HCSIAppField("AppData", None),      HCSINullField("Extended", None)]

names = []
for fld in VEC_Fields:
    names.append(fld.name)

_hcsi_vec_fields = [ HCSIFlagsField('present',None,-len(names), names)]
for i in range(len(names)):
    ibit = 1 << i
    seval = "lambda pkt:_HCSITest(pkt,%s,'%s')" % (ibit, names[i])
    test = eval(seval)
    _hcsi_vec_fields.append(ConditionalField(VEC_Fields[i], test))

class Vector(HCSIPacket):
    name = "PPI Vector"
    fields_desc = [ LEShortField('pfh_type', PPI_VECTOR), #pfh_type
                    LEShortField('pfh_length', None), #pfh_len
                    ByteField('geotag_ver', 1), #base_geotag_header.ver
                    ByteField('geotag_pad', 2), #base_geotag_header.pad
                    LEShortField('geotag_len', None)] + _hcsi_vec_fields

# HCSIAntenna Fields
ANT_Fields = [HCSIAntennaFlagsField("AntennaFlags", None), ByteField("Gain", None),
              Fixed3_6Field("HorizBw", None),              Fixed3_6Field("VertBw", None),
              Fixed3_6Field("PrecisionGain",None),         XLEShortField("BeamID", None),
              HCSINullField("Reserved06", None),           HCSINullField("Reserved07", None),
              HCSINullField("Reserved08", None),           HCSINullField("Reserved09", None),
              HCSINullField("Reserved10", None),           HCSINullField("Reserved11", None),
              HCSINullField("Reserved12", None),           HCSINullField("Reserved13", None),
              HCSINullField("Reserved14", None),           HCSINullField("Reserved15", None),
              HCSINullField("Reserved16", None),           HCSINullField("Reserved17", None),
              HCSINullField("Reserved18", None),           HCSINullField("Reserved19", None),
              HCSINullField("Reserved20", None),           HCSINullField("Reserved21", None),
              HCSINullField("Reserved22", None),           HCSINullField("Reserved23", None),
              HCSINullField("Reserved24", None),           HCSINullField("Reserved25", None),
              HCSIDescField("SerialNumber", None),         HCSIDescField("ModelName", None),
              HCSIDescField("DescString", None),           XLEIntField("AppId", None),
              HCSIAppField("AppData", None),               HCSINullField("Extended", None)]

names = []
for fld in ANT_Fields:
    names.append(fld.name)

_hcsi_ant_fields = [ HCSIFlagsField('present',None,-len(names), names)]
for i in range(len(names)):
    ibit = 1 << i
    seval = "lambda pkt:_HCSITest(pkt,%s,'%s')" % (ibit, names[i])
    test = eval(seval)
    _hcsi_ant_fields.append(ConditionalField(ANT_Fields[i], test))

class Antenna(HCSIPacket):
    name = "PPI Antenna"
    fields_desc = [ LEShortField('pfh_type', PPI_ANTENNA), #pfh_type
                    LEShortField('pfh_length', None), #pfh_len
                    ByteField('geotag_ver', 1), #base_geotag_header.ver
                    ByteField('geotag_pad', 2), #base_geotag_header.pad
                    LEShortField('geotag_len', None)] + _hcsi_ant_fields

addPPIType(PPI_GPS, GPS)
addPPIType(PPI_VECTOR, Vector)
addPPIType(PPI_ANTENNA,Antenna)
