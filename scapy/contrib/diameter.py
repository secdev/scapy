##########################################################################
#
#       Diameter protocol implementation for Scapy
#   Original Author: patrick battistello
#
#   This implements the base Diameter protocol RFC6733 and the additional standards:  # noqa: E501
#     RFC7155, RFC4004, RFC4006, RFC4072, RFC4740, RFC5778, RFC5447, RFC6942, RFC5777  # noqa: E501
#     ETS29229 V12.3.0 (2014-09), ETS29272 V13.1.0 (2015-03), ETS29329 V12.5.0 (2014-12),  # noqa: E501
#     ETS29212 V13.1.0 (2015-03), ETS32299 V13.0.0 (2015-03), ETS29210 V6.7.0 (2006-12),  # noqa: E501
#     ETS29214 V13.1.0 (2015-03), ETS29273 V12.7.0 (2015-03), ETS29173 V12.3.0 (2015-03),  # noqa: E501
#     ETS29172 V12.5.0 (2015-03), ETS29215 V13.1.0 (2015-03), ETS29209 V6.8.0 (2011-09),  # noqa: E501
#     ETS29061 V13.0.0 (2015-03), ETS29219 V13.0.0 (2014-12)
#
#       IMPORTANT note:
#
#           - Some Diameter fields (Unsigned64, Float32, ...) have not been tested yet due to lack  # noqa: E501
#               of network captures containing AVPs of that types contributions are welcomed.  # noqa: E501
#
##########################################################################

# scapy.contrib.description = Diameter
# scapy.contrib.status = loads

import socket
import struct
from time import ctime

from scapy.packet import Packet, bind_layers
from scapy.fields import ConditionalField, EnumField, Field, FieldLenField, \
    FlagsField, IEEEDoubleField, IEEEFloatField, IntEnumField, IntField, \
    LongField, PacketListField, SignedIntField, StrLenField, X3BytesField, \
    XByteField, XIntField
from scapy.layers.inet import TCP
from scapy.layers.sctp import SCTPChunkData
import scapy.modules.six as six
from scapy.modules.six.moves import range
from scapy.compat import chb, orb, raw, bytes_hex, plain_str
from scapy.error import warning
from scapy.utils import inet_ntoa, inet_aton
from scapy.pton_ntop import inet_pton, inet_ntop

#####################################################################
#####################################################################
#
#       Definition of additional fields
#
#####################################################################
#####################################################################


class I3BytesEnumField (X3BytesField, EnumField):
    """ 3 bytes enum field """

    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "!I")


class I3FieldLenField(X3BytesField, FieldLenField):
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(
            self,
            name,
            default,
            length_of=None,
            count_of=None,
            adjust=lambda pkt,
            x: x):
        X3BytesField.__init__(self, name, default)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust

    def i2m(self, pkt, x):
        return FieldLenField.i2m(self, pkt, x)

###########################################################
# Fields for Diameter commands
###########################################################


class DRFlags (FlagsField):
    def i2repr(self, pkt, x):
        if x is None:
            return "None"
        res = hex(int(x))
        r = ''
        cmdt = ' Request' if (x & 128) else ' Answer'
        if x & 15:  # Check if reserved bits are used
            nb = 8
            offset = 0
        else:       # Strip the first 4 bits
            nb = 4
            offset = 4
            x >>= 4
        for i in range(nb):
            r += (x & 1) and str(self.names[offset + i][0]) or '-'
            x >>= 1
        invert = r[::-1]
        return res + cmdt + ' (' + invert[:nb] + ')'


class DRCode (I3BytesEnumField):
    def __init__(self, name, default, enum):
        """enum is a dict of tuples, so conversion is required before calling the actual init method.  # noqa: E501
           Note: the conversion is done only once."""
        enumDict = {}
        for k, v in enum.items():
            enumDict[k] = v[0]
        I3BytesEnumField.__init__(self, name, default, enumDict)

    def i2repr(self, pkt, x):
        cmd = self.i2repr_one(pkt, x)
        sx = str(x)
        if cmd == sx:
            cmd = 'Unknown'
        return sx + " (" + cmd + ")"

###########################################################
# Fields for Diameter AVPs
###########################################################


class AVPFlags (FlagsField):
    def i2repr(self, pkt, x):
        if x is None:
            return "None"
        res = hex(int(x))
        r = ''
        if x & 31:  # Check if reserved bits are used
            nb = 8
            offset = 0
        else:       # Strip the first 5 bits
            nb = 3
            offset = 5
            x >>= 5
        for i in range(nb):
            r += (x & 1) and str(self.names[offset + i][0]) or '-'
            x >>= 1
        invert = r[::-1]
        return res + ' (' + invert[:nb] + ')'


class AVPVendor (IntField):
    def i2repr(self, pkt, x):
        vendor = vendorList.get(x, "Unkown_Vendor")
        return "%s (%s)" % (vendor, str(x))


# Note the dictionary below is minimal (taken from scapy/layers/dhcp6.py
# + added 3GPP and ETSI
vendorList = {
    9: "ciscoSystems",
    35: "Nortel Networks",
    43: "3Com",
    311: "Microsoft",
    323: "Tekelec",
    2636: "Juniper Networks, Inc.",
    4526: "Netgear",
    5771: "Cisco Systems, Inc.",
    5842: "Cisco Systems",
    8164: "Starent Networks",
    10415: "3GPP",
    13019: "ETSI",
    16885: "Nortel Networks"}

# The Application IDs for the Diameter command field
AppIDsEnum = {
    0: "Diameter_Common_Messages",
    1: "NASREQ_Application",
    2: "Mobile_IPv4_Application",
    3: "Diameter_Base_Accounting",
    4: "Diameter_Credit_Control_Application",
    5: "EAP_Application",
    6: "Diameter_Session_Initiation_Protocol_(SIP)_Application",
    7: "Diameter_Mobile_IPv6_IKE___(MIP6I)",
    8: "Diameter_Mobile_IPv6_Auth__(MIP6A)",
    111: "ALU_Sy",
    555: "Sun_Ping_Application",
    16777216: "3GPP_Cx",
    16777217: "3GPP_Sh",
    16777222: "3GPP_Gq",
    16777223: "3GPP_Gmb",
    16777224: "3GPP_Gx",
    16777227: "Ericsson_MSI",
    16777228: "Ericsson_Zx",
    16777229: "3GPP_RX",
    16777231: "Diameter_e2e4_Application",
    16777232: "Ericsson_Charging-CIP",
    16777236: "3GPP_Rx",
    16777238: "3GPP_Gx",
    16777250: "3GPP_STa",
    16777251: "3GPP_S6a/S6d",
    16777252: "3GPP_S13/S13'",
    16777255: "3GPP_SLg",
    16777264: "3GPP_SWm",
    16777265: "3GPP_SWx",
    16777266: "3GPP_Gxx",
    16777267: "3GPP_S9",
    16777269: "Ericsson_HSI",
    16777272: "3GPP_S6b",
    16777291: "3GPP_SLh",
    16777292: "3GPP_SGmb",
    16777302: "3GPP_Sy",
    16777304: "Ericsson_Sy",
    16777315: "Ericsson_Diameter_Signalling_Controller_Application_(DSC)",
    4294967295: "Relay",
}


###########################################################
# Definition of fields contained in section 4.2 of RFC6733
# for AVPs payloads
###########################################################

class OctetString (StrLenField):
    def i2repr(self, pkt, x):
        try:
            return plain_str(x)
        except BaseException:
            return bytes_hex(x)


class Integer32 (SignedIntField):
    pass


class Integer64 (Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "q")


class Unsigned32 (IntField):
    pass


class Unsigned64 (LongField):
    pass


class Float32 (IEEEFloatField):
    pass


class Float64 (IEEEDoubleField):
    pass


###########################################################
# Definition of additional fields contained in section 4.3
# of RFC6733 for AVPs payloads
###########################################################

class Address (StrLenField):
    def i2repr(self, pkt, x):
        if x.startswith(b'\x00\x01'):  # IPv4 address
            return inet_ntoa(x[2:])
        elif x.startswith(b'\x00\x02'):    # IPv6 address
            return inet_ntop(socket.AF_INET6, x[2:])
        else:   # Address format not yet decoded
            print('Warning: Address format not yet decoded.')
            return bytes_hex(x)

    def any2i(self, pkt, x):
        if x and isinstance(x, str):
            try:    # Try IPv4 conversion
                s = inet_aton(x)
                return b'\x00\x01' + s
            except BaseException:
                try:    # Try IPv6 conversion
                    s = inet_pton(socket.AF_INET6, x)
                    return b'\x00\x02' + s
                except BaseException:
                    print('Warning: Address format not supported yet.')
        return b''


class Time (IntField):
    def i2repr(self, pkt, x):
        return ctime(x)


class Enumerated (IntEnumField):
    def i2repr(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x] + " (%d)" % x
        else:
            return repr(x) + " (Unknown)"


class IPFilterRule (StrLenField):
    pass


class Grouped (StrLenField):
    """This class is just for declarative purpose because it is used in the AVP definitions dict."""  # noqa: E501
    pass


####################################################################
# Definition of additional fields contained in other standards
####################################################################

class QoSFilterRule (StrLenField):        # Defined in 4.1.1 of RFC7155
    pass


class ISDN (StrLenField):
    def i2repr(self, pkt, x):
        out = b''
        for char in x:
            c = orb(char)
            out += chb(48 + (c & 15))  # convert second digit first
            v = (c & 240) >> 4
            if v != 15:
                out += chb(48 + v)
        return out

    def any2i(self, pkt, x):
        out = b''
        if x:
            fd = True     # waiting for first digit
            for c in x:
                digit = orb(c) - 48
                if fd:
                    val = digit
                else:
                    val = val + 16 * digit
                    out += chb(val)
                fd = not fd
            if not fd:    # Fill with 'f' if odd number of characters
                out += chb(240 + val)
        return out


#####################################################################
#####################################################################
#
#       AVPs classes and definitions
#
#####################################################################
#####################################################################

AVP_Code_length = 4
AVP_Flag_length = 1
DIAMETER_BYTES_ALIGNMENT = 4
AVP_Flags_List = ["x", "x", "x", "x", "x", "P", "M", "V"]


def GuessAvpType(p, **kargs):
    if len(p) > AVP_Code_length + AVP_Flag_length:
        # Set AVP code and vendor
        avpCode = struct.unpack("!I", p[:AVP_Code_length])[0]
        vnd = bool(struct.unpack(
            "!B", p[AVP_Code_length:AVP_Code_length + AVP_Flag_length])[0] & 128)  # noqa: E501
        vndCode = struct.unpack("!I", p[8:12])[0] if vnd else 0
        # Check if vendor and code defined and fetch the corresponding AVP
        # definition
        if vndCode in AvpDefDict:
            AvpVndDict = AvpDefDict[vndCode]
            if avpCode in AvpVndDict:
                # Unpack only the first 4 tuple items at this point
                avpName, AVPClass, flags = AvpVndDict[avpCode][:3]
                result = AVPClass(p, **kargs)
                result.name = 'AVP ' + avpName
                return result
    # Packet too short or AVP vendor or AVP code not found ...
    return AVP_Unknown(p, **kargs)


class AVP_Generic (Packet):
    """ Parent class for the 5 following AVP intermediate classes below"""

    def extract_padding(self, s):
        nbBytes = self.avpLen % DIAMETER_BYTES_ALIGNMENT
        if nbBytes:
            nbBytes = DIAMETER_BYTES_ALIGNMENT - nbBytes
        return s[:nbBytes], s[nbBytes:]

    def post_build(self, p, pay):
        nbBytes = (-len(p)) % 4
        while nbBytes:
            p += struct.pack("B", 0)
            nbBytes -= 1
        return p + pay

    def show2(self):
        self.__class__(raw(self), name=self.name).show()


def AVP(avpId, **fields):
    """ Craft an AVP based on its id and optional parameter fields"""
    val = None
    classType = AVP_Unknown
    if isinstance(avpId, str):
        try:
            for vnd in AvpDefDict:
                for code in AvpDefDict[vnd]:
                    val = AvpDefDict[vnd][code]
                    if val[0][:len(
                            avpId)] == avpId:  # A prefix of the full name is considered valid  # noqa: E501
                        raise
            found = False
        except BaseException:
            found = True
    else:
        if isinstance(avpId, list):
            code = avpId[0]
            vnd = avpId[1]
        else:  # Assume this is an int
            code = avpId
            vnd = 0
        try:
            val = AvpDefDict[vnd][code]
            found = True
        except BaseException:
            found = False
    if not found:
        warning('The AVP identifier %s has not been found.' % str(avpId))
        if isinstance(avpId, str):  # The string input is not valid
            return None
    # At this point code, vnd are provisionned val may be set (if found is True)  # noqa: E501
    # Set/override AVP code
    fields['avpCode'] = code
    # Set vendor if not already defined and relevant
    if 'avpVnd' not in fields and vnd:
        fields['avpVnd'] = vnd
    # Set flags if not already defined and possible ...
    if 'avpFlags' not in fields:
        if val:
            fields['avpFlags'] = val[2]
        else:
            fields['avpFlags'] = 128 if vnd else 0
    # Finally, set the name and class if possible
    if val:
        classType = val[1]
    _ret = classType(**fields)
    if val:
        _ret.name = 'AVP ' + val[0]
    return _ret


# AVP intermediate classes:
############################

class AVP_FL_NV (AVP_Generic):
    """ Defines the AVP of Fixed Length with No Vendor field."""
    fields_desc = [
        IntField("avpCode", None),
        AVPFlags("avpFlags", None, 8, AVP_Flags_List),
        X3BytesField("avpLen", None)
    ]


class AVP_FL_V (AVP_Generic):
    """ Defines the AVP of Fixed Length with Vendor field."""
    fields_desc = [
        IntField("avpCode", None),
        AVPFlags("avpFlags", None, 8, AVP_Flags_List),
        X3BytesField("avpLen", None),
        AVPVendor("avpVnd", 0)
    ]


class AVP_VL_NV (AVP_Generic):
    """ Defines the AVP of Variable Length with No Vendor field."""
    fields_desc = [
        IntField("avpCode", None),
        AVPFlags("avpFlags", None, 8, AVP_Flags_List),
        I3FieldLenField("avpLen", None, length_of="val",
                        adjust=lambda pkt, x:x + 8)
    ]


class AVP_VL_V (AVP_Generic):
    """ Defines the AVP of Variable Length with Vendor field."""
    fields_desc = [
        IntField("avpCode", None),
        AVPFlags("avpFlags", None, 8, AVP_Flags_List),
        I3FieldLenField("avpLen", None, length_of="val",
                        adjust=lambda pkt, x:x + 12),
        AVPVendor("avpVnd", 0)
    ]


class AVP_Unknown (AVP_Generic):
    """ The default structure for AVPs which could not be decoded (optional vendor field, variable length). """  # noqa: E501
    name = 'AVP Unknown'
    fields_desc = [
        IntField("avpCode", None),
        AVPFlags("avpFlags", None, 8, AVP_Flags_List),
        I3FieldLenField("avpLen", None, length_of="val",
                        adjust=lambda pkt, x:x + 8 + ((pkt.avpFlags & 0x80) >> 5)),  # noqa: E501
        ConditionalField(AVPVendor("avpVnd", 0), lambda pkt:pkt.avpFlags & 0x80),  # noqa: E501
        StrLenField("val", None,
                    length_from=lambda pkt:pkt.avpLen - 8 - ((pkt.avpFlags & 0x80) >> 5))  # noqa: E501
    ]


# AVP 'low level' classes:
############################

class AVPV_StrLenField (AVP_VL_V):
    fields_desc = [
        AVP_VL_V,
        StrLenField("val", None, length_from=lambda pkt:pkt.avpLen - 12)
    ]


class AVPNV_StrLenField (AVP_VL_NV):
    fields_desc = [
        AVP_VL_NV,
        StrLenField("val", None, length_from=lambda pkt:pkt.avpLen - 8)
    ]


class AVPV_OctetString (AVP_VL_V):
    fields_desc = [
        AVP_VL_V,
        OctetString("val", None, length_from=lambda pkt:pkt.avpLen - 12)
    ]


class AVPNV_OctetString (AVP_VL_NV):
    fields_desc = [
        AVP_VL_NV,
        OctetString("val", None, length_from=lambda pkt:pkt.avpLen - 8)
    ]


class AVPV_Grouped (AVP_VL_V):
    fields_desc = [
        AVP_VL_V,
        PacketListField('val', [], GuessAvpType,
                        length_from=lambda pkt:pkt.avpLen - 12)
    ]


class AVPNV_Grouped (AVP_VL_NV):
    fields_desc = [
        AVP_VL_NV,
        PacketListField('val', [], GuessAvpType,
                        length_from=lambda pkt:pkt.avpLen - 8)]


class AVPV_Unsigned32 (AVP_FL_V):
    avpLen = 16
    fields_desc = [AVP_FL_V, Unsigned32('val', None)]


class AVPNV_Unsigned32 (AVP_FL_NV):
    avpLen = 12
    fields_desc = [AVP_FL_NV, Unsigned32('val', None)]


class AVPV_Integer32 (AVP_FL_V):
    avpLen = 16
    fields_desc = [AVP_FL_V, Integer32('val', None)]


class AVPNV_Integer32 (AVP_FL_NV):
    avpLen = 12
    fields_desc = [AVP_FL_NV, Integer32('val', None)]


class AVPV_Unsigned64 (AVP_FL_V):
    avpLen = 20
    fields_desc = [AVP_FL_V, Unsigned64('val', None)]


class AVPNV_Unsigned64 (AVP_FL_NV):
    avpLen = 16
    fields_desc = [AVP_FL_NV, Unsigned64('val', None)]


class AVPV_Integer64 (AVP_FL_V):
    avpLen = 20
    fields_desc = [AVP_FL_V, Integer64('val', None)]


class AVPNV_Integer64 (AVP_FL_NV):
    avpLen = 16
    fields_desc = [AVP_FL_NV, Integer64('val', None)]


class AVPV_Time (AVP_FL_V):
    avpLen = 16
    fields_desc = [AVP_FL_V, Time("val", None)]


class AVPNV_Time (AVP_FL_NV):
    avpLen = 12
    fields_desc = [AVP_FL_NV, Time("val", None)]


class AVPV_Address (AVP_VL_V):
    fields_desc = [
        AVP_VL_V,
        Address("val", None, length_from=lambda pkt:pkt.avpLen - 12)
    ]


class AVPNV_Address (AVP_VL_NV):
    fields_desc = [
        AVP_VL_NV,
        Address("val", None, length_from=lambda pkt:pkt.avpLen - 8)
    ]


class AVPV_IPFilterRule (AVP_VL_V):
    fields_desc = [
        AVP_VL_V,
        IPFilterRule("val", None, length_from=lambda pkt:pkt.avpLen - 12)
    ]


class AVPNV_IPFilterRule (AVP_VL_NV):
    fields_desc = [
        AVP_VL_NV,
        IPFilterRule("val", None, length_from=lambda pkt:pkt.avpLen - 8)
    ]


class AVPV_QoSFilterRule (AVP_VL_V):
    fields_desc = [
        AVP_VL_V,
        QoSFilterRule("val", None, length_from=lambda pkt:pkt.avpLen - 12)
    ]


class AVPNV_QoSFilterRule (AVP_VL_NV):
    fields_desc = [
        AVP_VL_NV,
        QoSFilterRule("val", None, length_from=lambda pkt:pkt.avpLen - 8)
    ]


###############################################
# Actual AVPs based on previous parent classes
###############################################

# AVP special classes (which required interpretation/adaptation from standard)
##############################################################################

class AVP_0_258 (AVP_FL_NV):
    name = 'AVP Auth-Application-Id'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, AppIDsEnum)]


class AVP_0_266 (AVP_FL_NV):
    name = 'AVP Vendor-Id'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, vendorList)]


class AVP_0_268 (AVP_FL_NV):
    name = 'AVP Result-Code'
    avpLen = 12
    fields_desc = [AVP_FL_NV,
                   Enumerated('val',
                              None,
                              {1001: "DIAMETER_MULTI_ROUND_AUTH",
                               2001: "DIAMETER_SUCCESS",
                               2002: "DIAMETER_LIMITED_SUCCESS",
                               2003: "DIAMETER_FIRST_REGISTRATION",
                               2004: "DIAMETER_SUBSEQUENT_REGISTRATION",
                               2005: "DIAMETER_UNREGISTERED_SERVICE",
                               2006: "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
                               2007: "DIAMETER_SERVER_SELECTION",
                               2008: "DIAMETER_SUCCESS_AUTH_SENT_SERVER_NOT_STORED",  # noqa: E501
                               2009: "DIAMETER_SUCCESS_RELOCATE_HA",
                               3001: "DIAMETER_COMMAND_UNSUPPORTED",
                               3002: "DIAMETER_UNABLE_TO_DELIVER",
                               3003: "DIAMETER_REALM_NOT_SERVED",
                               3004: "DIAMETER_TOO_BUSY",
                               3005: "DIAMETER_LOOP_DETECTED",
                               3006: "DIAMETER_REDIRECT_INDICATION",
                               3007: "DIAMETER_APPLICATION_UNSUPPORTED",
                               3008: "DIAMETER_INVALID_HDR_BITS",
                               3009: "DIAMETER_INVALID_AVP_BITS",
                               3010: "DIAMETER_UNKNOWN_PEER",
                               4001: "DIAMETER_AUTHENTICATION_REJECTED",
                               4002: "DIAMETER_OUT_OF_SPACE",
                               4003: "DIAMETER_ELECTION_LOST",
                               4005: "DIAMETER_ERROR_MIP_REPLY_FAILURE",
                               4006: "DIAMETER_ERROR_HA_NOT_AVAILABLE",
                               4007: "DIAMETER_ERROR_BAD_KEY",
                               4008: "DIAMETER_ERROR_MIP_FILTER_NOT_SUPPORTED",
                               4010: "DIAMETER_END_USER_SERVICE_DENIED",
                               4011: "DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE",
                               4012: "DIAMETER_CREDIT_LIMIT_REACHED",
                               4013: "DIAMETER_USER_NAME_REQUIRED",
                               4241: "DIAMETER_END_USER_SERVICE_DENIED",
                               5001: "DIAMETER_AVP_UNSUPPORTED",
                               5002: "DIAMETER_UNKNOWN_SESSION_ID",
                               5003: "DIAMETER_AUTHORIZATION_REJECTED",
                               5004: "DIAMETER_INVALID_AVP_VALUE",
                               5005: "DIAMETER_MISSING_AVP",
                               5006: "DIAMETER_RESOURCES_EXCEEDED",
                               5007: "DIAMETER_CONTRADICTING_AVPS",
                               5008: "DIAMETER_AVP_NOT_ALLOWED",
                               5009: "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES",
                               5010: "DIAMETER_NO_COMMON_APPLICATION",
                               5011: "DIAMETER_UNSUPPORTED_VERSION",
                               5012: "DIAMETER_UNABLE_TO_COMPLY",
                               5013: "DIAMETER_INVALID_BIT_IN_HEADER",
                               5014: "DIAMETER_INVALID_AVP_LENGTH",
                               5015: "DIAMETER_INVALID_MESSAGE_LENGTH",
                               5016: "DIAMETER_INVALID_AVP_BIT_COMBO",
                               5017: "DIAMETER_NO_COMMON_SECURITY",
                               5018: "DIAMETER_RADIUS_AVP_UNTRANSLATABLE",
                               5024: "DIAMETER_ERROR_NO_FOREIGN_HA_SERVICE",
                               5025: "DIAMETER_ERROR_END_TO_END_MIP_KEY_ENCRYPTION",  # noqa: E501
                               5030: "DIAMETER_USER_UNKNOWN",
                               5031: "DIAMETER_RATING_FAILED",
                               5032: "DIAMETER_ERROR_USER_UNKNOWN",
                               5033: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
                               5034: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
                               5035: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
                               5036: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",  # noqa: E501
                               5037: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",  # noqa: E501
                               5038: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
                               5039: "DIAMETER_ERROR_TOO_MUCH_DATA",
                               5040: "DIAMETER_ERROR_NOT SUPPORTED_USER_DATA",
                               5041: "DIAMETER_ERROR_MIP6_AUTH_MODE",
                               5241: "DIAMETER_END_USER_NOT_FOUND",
                               })]


class AVP_0_298 (AVP_FL_NV):
    name = 'AVP Experimental-Result-Code'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                2001: "DIAMETER_FIRST_REGISTRATION",
                2002: "DIAMETER_SUBSEQUENT_REGISTRATION",
                2003: "DIAMETER_UNREGISTERED_SERVICE",
                2004: "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
                2021: "DIAMETER_PDP_CONTEXT_DELETION_INDICATION",
                4100: "DIAMETER_USER_DATA_NOT_AVAILABLE",
                4101: "DIAMETER_PRIOR_UPDATE_IN_PROGRESS",
                4121: "DIAMETER_ERROR_OUT_OF_RESOURCES",
                4141: "DIAMETER_PCC_BEARER_EVENT",
                4181: "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE",
                4201: "DIAMETER_ERROR_ABSENT_USER",
                4221: "DIAMETER_ERROR_UNREACHABLE_USER",
                4222: "DIAMETER_ERROR_SUSPENDED_USER",
                4223: "DIAMETER_ERROR_DETACHED_USER",
                4224: "DIAMETER_ERROR_POSITIONING_DENIED",
                4225: "DIAMETER_ERROR_POSITIONING_FAILED",
                4226: "DIAMETER_ERROR_UNKNOWN_UNREACHABLE LCS_CLIENT",
                5001: "DIAMETER_ERROR_USER_UNKNOWN",
                5002: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
                5003: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
                5004: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
                5005: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",
                5006: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",
                5007: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
                5008: "DIAMETER_ERROR_TOO_MUCH_DATA",
                5009: "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA",
                5010: "DIAMETER_MISSING_USER_ID",
                5011: "DIAMETER_ERROR_FEATURE_UNSUPPORTED",
                5041: "DIAMETER_ERROR_USER_NO_WLAN_SUBSCRIPTION",
                5042: "DIAMETER_ERROR_W-APN_UNUSED_BY_USER",
                5043: "DIAMETER_ERROR_W-DIAMETER_ERROR_NO_ACCESS_INDEPENDENT_SUBSCRIPTION",  # noqa: E501
                5044: "DIAMETER_ERROR_USER_NO_W-APN_SUBSCRIPTION",
                5045: "DIAMETER_ERROR_UNSUITABLE_NETWORK",
                5061: "INVALID_SERVICE_INFORMATION",
                5062: "FILTER_RESTRICTIONS",
                5063: "REQUESTED_SERVICE_NOT_AUTHORIZED",
                5064: "DUPLICATED_AF_SESSION",
                5065: "IP-CAN_SESSION_NOT_AVAILABLE",
                5066: "UNAUTHORIZED_NON_EMERGENCY_SESSION",
                5100: "DIAMETER_ERROR_USER_DATA_NOT_RECOGNIZED",
                5101: "DIAMETER_ERROR_OPERATION_NOT_ALLOWED",
                5102: "DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ",
                5103: "DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED",
                5104: "DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED",
                5105: "DIAMETER_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC",
                5106: "DIAMETER_ERROR_SUBS_DATA_ABSENT",
                5107: "DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA",
                5108: "DIAMETER_ERROR_DSAI_NOT_AVAILABLE",
                5120: "DIAMETER_ERROR_START_INDICATION",
                5121: "DIAMETER_ERROR_STOP_INDICATION",
                5122: "DIAMETER_ERROR_UNKNOWN_MBMS_BEARER_SERVICE",
                5123: "DIAMETER_ERROR_SERVICE_AREA",
                5140: "DIAMETER_ERROR_INITIAL_PARAMETERS",
                5141: "DIAMETER_ERROR_TRIGGER_EVENT",
                5142: "DIAMETER_BEARER_EVENT",
                5143: "DIAMETER_ERROR_BEARER_NOT_AUTHORIZED",
                5144: "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED",
                5145: "DIAMETER_QOS_RULE_EVENT",
                5146: "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED",
                5147: "DIAMETER_ERROR_CONFLICTING_REQUEST",
                5401: "DIAMETER_ERROR_IMPI_UNKNOWN",
                5402: "DIAMETER_ERROR_NOT_AUTHORIZED",
                5403: "DIAMETER_ERROR_TRANSACTION_IDENTIFIER_INVALID",
                5420: "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
                5421: "DIAMETER_ERROR_RAT_NOT_ALLOWED",
                5422: "DIAMETER_ERROR_EQUIPMENT_UNKNOWN",
                5423: "DIAMETER_ERROR_UNKNOWN_SERVING_NODE",
                5450: "DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION",
                5451: "DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION",
                5452: "DIAMETER_ERROR_RAT_TYPE_NOT_ALLOWED",
                5470: "DIAMETER_ERROR_SUBSESSION",
                5490: "DIAMETER_ERROR_UNAUTHORIZED_REQUESTING_NETWORK",
                5510: "DIAMETER_ERROR_UNAUTHORIZED_REQUESTING_ENTITY",
                5511: "DIAMETER_ERROR_UNAUTHORIZED_SERVICE",
                5530: "DIAMETER_ERROR_INVALID_SME_ADDRESS",
                5531: "DIAMETER_ERROR_SC_CONGESTION",
                5532: "DIAMETER_ERROR_SM_PROTOCOL",
            })]


class AVP_10415_630 (AVP_FL_V):
    name = 'AVP Feature-List'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   FlagsField('val', None, 32,
                              ['SiFC',
                               'AliasInd',
                               'IMSRestorationInd',
                               'b3',
                               'b4',
                               'b5',
                               'b6',
                               'b7',
                               'b8',
                               'b9',
                               'b10',
                               'b11',
                               'b12',
                               'b13',
                               'b14',
                               'b15',
                               'b16',
                               'b17',
                               'b18',
                               'b19',
                               'b20',
                               'b21',
                               'b22',
                               'b23',
                               'b24',
                               'b25',
                               'b26',
                               'b27',
                               'b28',
                               'b29',
                               'b30',
                               'b31'])]


class AVP_10415_701 (AVP_VL_V):
    name = 'AVP MSISDN'
    fields_desc = [AVP_VL_V, ISDN('val', None,
                                  length_from=lambda pkt:pkt.avpLen - 12)]


class AVP_10415_1643 (AVP_VL_V):
    name = 'AVP A_MSISDN'
    fields_desc = [AVP_VL_V, ISDN('val', None,
                                  length_from=lambda pkt:pkt.avpLen - 12)]


# AVP enumerated classes (which could not be defined in AvpDefDict dict below)
##############################################################################

class AVP_0_6 (AVP_FL_NV):
    name = 'Service-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       0: "Unknown",
                       1: "Login",
                       2: "Framed",
                       3: "Callback-Login",
                       4: "Callback-Framed",
                       5: "Outbound",
                       6: "Administrative",
                       7: "NAS-Prompt",
                       8: "Authenticate-Only",
                       9: "Callback-NAS-Prompt",
                       10: "Call Check",
                       11: "Callback Administrative",
                       12: "Voice",
                       13: "Fax",
                       14: "Modem Relay",
                       15: "IAPP-Register",
                       16: "IAPP-AP-Check",
                       17: "Authorize Only",
                       18: "Framed-Management",
                   })]


class AVP_0_7 (AVP_FL_NV):
    name = 'Framed-Protocol'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       1: "PPP",
                       2: "SLIP",
                       3: "ARAP",
                       4: "Gandalf",
                       5: "Xylogics",
                       6: "X.75",
                       7: "GPRS PDP Context",
                       255: "Ascend-ARA",
                       256: "MPP",
                       257: "EURAW",
                       258: "EUUI",
                       259: "X25",
                       260: "COMB",
                       261: "FR",
                   })]


class AVP_0_10 (AVP_FL_NV):
    name = 'Framed-Routing'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       0: "None",
                       1: "Send routing packets",
                       2: "Listen for routing packets",
                       3: "Send and Listen    ",
                   })]


class AVP_0_13 (AVP_FL_NV):
    name = 'Framed-Compression'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {0: "None", 2: "IPX header compression", 3: "Stac-LZS compression", })  # noqa: E501
    ]


class AVP_0_15 (AVP_FL_NV):
    name = 'Login-Service'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       0: "Telnet",
                       1: "Rlogin",
                       2: "TCP-Clear",
                       3: "PortMaster",
                       4: "LAT",
                       5: "X25-PAD",
                       6: "X25-T3POS",
                       7: "Unassigned",
                   })]


class AVP_0_45 (AVP_FL_NV):
    name = 'Acct-Authentic'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {0: "None", 1: "RADIUS", 2: "Local", 3: "Remote", 4: "Diameter", })]  # noqa: E501


class AVP_0_61 (AVP_FL_NV):
    name = 'NAS-Port-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       0: "Async",
                       1: "Sync",
                       2: "ISDN-Sync",
                       3: "ISDN-Async-v120",
                       4: "ISDN-Async-v110",
                       5: "Virtual",
                       6: "PIAFS",
                       7: "HDLC-Clear-Channel",
                       8: "X25",
                       9: "X75",
                       10: "G.3 Fax",
                       11: "SDSL - Symmetric DSL",
                       14: "IDSL - ISDN Digital Subscriber Line",
                       15: "Ethernet",
                       16: "xDSL - Digital Subscriber Line of unknown type",
                       17: "Cable",
                       18: "Wireless - Other",
                       19: "Wireless - IEEE 802.11",
                       20: "Token-Ring",
                       21: "FDDI",
                       22: "Wireless - CDMA2000",
                       23: "Wireless - UMTS",
                       24: "Wireless - 1X-EV",
                       25: "IAPP",
                       26: "FTTP - Fiber to the Premises",
                       27: "Wireless - IEEE 802.16",
                       28: "Wireless - IEEE 802.20",
                       29: "Wireless - IEEE 802.22",
                       30: "PPPoA - PPP over ATM",
                       31: "PPPoEoA - PPP over Ethernet over ATM",
                       32: "PPPoEoE - PPP over Ethernet over Ethernet",
                       33: "PPPoEoVLAN - PPP over Ethernet over VLAN",
                       34: "PPPoEoQinQ - PPP over Ethernet over IEEE 802.1QinQ",  # noqa: E501
                       35: "xPON - Passive Optical Network",
                       36: "Wireless - XGP",
                   })]


class AVP_0_64 (AVP_FL_NV):
    name = 'Tunnel-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       1: "PPTP",
                       2: "L2F",
                       3: "L2TP",
                       4: "ATMP",
                       5: "VTP",
                       6: "AH",
                       7: "IP-IP-Encap",
                       8: "MIN-IP-IP",
                       9: "ESP",
                       10: "GRE",
                       11: "DVS",
                       12: "IP-in-IP Tunneling",
                       13: "VLAN",
                   })]


class AVP_0_65 (AVP_FL_NV):
    name = 'Tunnel-Medium-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       1: "IPv4",
                       2: "IPv6",
                       3: "NSAP",
                       4: "HDLC",
                       5: "BBN",
                       6: "IEEE-802",
                       7: "E-163",
                       8: "E-164",
                       9: "F-69",
                       10: "X-121",
                       11: "IPX",
                       12: "Appletalk-802",
                       13: "Decnet4",
                       14: "Vines",
                       15: "E-164-NSAP",
                   })]


class AVP_0_72 (AVP_FL_NV):
    name = 'ARAP-Zone-Access'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       1: "Only allow access to default zone",
                       2: "Use zone filter inclusively",
                       3: "Use zone filter exclusively",
                   })]


class AVP_0_76 (AVP_FL_NV):
    name = 'Prompt'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None, {0: "No Echo", 1: "Echo", })
    ]


class AVP_0_261 (AVP_FL_NV):
    name = 'Redirect-Host-Usage'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {
                       0: "Don't Care",
                       1: "All Session",
                       2: "All Realm",
                       3: "Realm and Application",
                       4: "All Application",
                       5: "All Host",
                       6: "ALL_USER",
                   })]


class AVP_0_271 (AVP_FL_NV):
    name = 'Session-Server-Failover'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated('val', None,
                   {0: "REFUSE_SERVICE", 1: "TRY_AGAIN", 2: "ALLOW_SERVICE", 3: "TRY_AGAIN_ALLOW_SERVICE", })]  # noqa: E501


class AVP_0_273 (AVP_FL_NV):
    name = 'Disconnect-Cause'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, {0: "REBOOTING", 1: "BUSY", 2: "DO_NOT_WANT_TO_TALK_TO_YOU", })]  # noqa: E501


class AVP_0_274 (AVP_FL_NV):
    name = 'Auth-Request-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            1: "AUTHENTICATE_ONLY", 2: "AUTHORIZE_ONLY", 3: "AUTHORIZE_AUTHENTICATE", })]  # noqa: E501


class AVP_0_277 (AVP_FL_NV):
    name = 'Auth-Session-State'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, {0: "STATE_MAINTAINED", 1: "NO_STATE_MAINTAINED", })]  # noqa: E501


class AVP_0_285 (AVP_FL_NV):
    name = 'Re-Auth-Request-Type'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, {0: "AUTHORIZE_ONLY", 1: "AUTHORIZE_AUTHENTICATE", })]  # noqa: E501


class AVP_0_295 (AVP_FL_NV):
    name = 'Termination-Cause'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                1: "DIAMETER_LOGOUT",
                2: "DIAMETER_SERVICE_NOT_PROVIDED",
                3: "DIAMETER_BAD_ANSWER",
                4: "DIAMETER_ADMINISTRATIVE",
                5: "DIAMETER_LINK_BROKEN",
                6: "DIAMETER_AUTH_EXPIRED",
                7: "DIAMETER_USER_MOVED",
                8: "DIAMETER_SESSION_TIMEOUT",
            })]


class AVP_0_345 (AVP_FL_NV):
    name = 'MIP-Algorithm-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {2: "HMAC-SHA-1", })]


class AVP_0_346 (AVP_FL_NV):
    name = 'MIP-Replay-Mode'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {1: "None", 2: "Timestamps", 3: "Nonces", })]  # noqa: E501


class AVP_0_375 (AVP_FL_NV):
    name = 'SIP-Server-Assignment-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "NO_ASSIGNMENT",
                1: "REGISTRATION",
                2: "RE_REGISTRATION",
                3: "UNREGISTERED_USER",
                4: "TIMEOUT_DEREGISTRATION",
                5: "USER_DEREGISTRATION",
                6: "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME",
                7: "USER_DEREGISTRATION_STORE_SERVER_NAME",
                8: "ADMINISTRATIVE_DEREGISTRATION",
                9: "AUTHENTICATION_FAILURE",
                10: "AUTHENTICATION_TIMEOUT",
                11: "DEREGISTRATION_TOO_MUCH_DATA",
            })]


class AVP_0_377 (AVP_FL_NV):
    name = 'SIP-Authentication-Scheme'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "DIGEST", })]


class AVP_0_384 (AVP_FL_NV):
    name = 'SIP-Reason-Code'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "PERMANENT_TERMINATION",
                1: "NEW_SIP_SERVER_ASSIGNED",
                2: "SIP_SERVER_CHANGE",
                3: "REMOVE_SIP_SERVER",
            })]


class AVP_0_387 (AVP_FL_NV):
    name = 'SIP-User-Authorization-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "REGISTRATION", 1: "DEREGISTRATION", 2: "REGISTRATION_AND_CAPABILITIES", })]  # noqa: E501


class AVP_0_392 (AVP_FL_NV):
    name = 'SIP-User-Data-Already-Available'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "USER_DATA_NOT_AVAILABLE", 1: "USER_DATA_ALREADY_AVAILABLE", })]


class AVP_0_403 (AVP_FL_NV):
    name = 'CHAP-Algorithm'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {5: "CHAP with MD5", })]


class AVP_0_406 (AVP_FL_NV):
    name = 'Accounting-Auth-Method'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            1: "PAP", 2: "CHAP", 3: "MS-CHAP-1", 4: "MS-CHAP-2", 5: "EAP", 6: "Undefined", 7: "None", })]  # noqa: E501


class AVP_0_416 (AVP_FL_NV):
    name = 'CC-Request-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            1: "INITIAL_REQUEST", 2: "UPDATE_REQUEST", 3: "TERMINATION_REQUEST", 4: "EVENT_REQUEST", })]  # noqa: E501


class AVP_0_418 (AVP_FL_NV):
    name = 'CC-Session-Failover'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, {0: "FAILOVER_NOT_SUPPORTED", 1: "FAILOVER_SUPPORTED", })]  # noqa: E501


class AVP_0_422 (AVP_FL_NV):
    name = 'Check-Balance-Result'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "ENOUGH_CREDIT", 1: "NO_CREDIT", })]  # noqa: E501


class AVP_0_426 (AVP_FL_NV):
    name = 'Credit-Control'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, {0: "CREDIT_AUTHORIZATION", 1: "RE_AUTHORIZATION", })]  # noqa: E501


class AVP_0_427 (AVP_FL_NV):
    name = 'Credit-Control-Failure-Handling'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "TERMINATE", 1: "CONTINUE", 2: "RETRY_AND_TERMINATE", })]


class AVP_0_428 (AVP_FL_NV):
    name = 'Direct-Debiting-Failure-Handling'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "TERMINATE_OR_BUFFER", 1: "CONTINUE", })]  # noqa: E501


class AVP_0_433 (AVP_FL_NV):
    name = 'Redirect-Address-Type'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, {0: "IPV4_ADDRESS", 1: "IPV6_ADDRESS", 2: "URL", 3: "SIP_URI", })]  # noqa: E501


class AVP_0_436 (AVP_FL_NV):
    name = 'Requested-Action'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "DIRECT_DEBITING", 1: "REFUND_ACCOUNT", 2: "CHECK_BALANCE", 3: "PRICE_ENQUIRY", })]  # noqa: E501


class AVP_0_449 (AVP_FL_NV):
    name = 'Final-Unit-Action'
    avpLen = 12
    fields_desc = [AVP_FL_NV, Enumerated('val', None, {0: "TERMINATE", 1: "REDIRECT", 2: "RESTRICT_ACCESS", })]  # noqa: E501


class AVP_0_450 (AVP_FL_NV):
    name = 'Subscription-Id-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "END_USER_E164",
                1: "END_USER_IMSI",
                2: "END_USER_SIP_URI",
                3: "END_USER_NAI",
                4: "END_USER_PRIVATE",
            })]


class AVP_0_452 (AVP_FL_NV):
    name = 'Tariff-Change-Usage'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "UNIT_BEFORE_TARIFF_CHANGE", 1: "UNIT_AFTER_TARIFF_CHANGE", 2: "UNIT_INDETERMINATE", })]  # noqa: E501


class AVP_0_454 (AVP_FL_NV):
    name = 'CC-Unit-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "TIME",
                1: "MONEY",
                2: "TOTAL-OCTETS",
                3: "INPUT-OCTETS",
                4: "OUTPUT-OCTETS",
                5: "SERVICE-SPECIFIC-UNITS",
            })]


class AVP_0_455 (AVP_FL_NV):
    name = 'Multiple-Services-Indicator'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "MULTIPLE_SERVICES_NOT_SUPPORTED", 1: "MULTIPLE_SERVICES_SUPPORTED", })]  # noqa: E501


class AVP_0_459 (AVP_FL_NV):
    name = 'User-Equipment-Info-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "IMEISV", 1: "MAC", 2: "EUI64", 3: "MODIFIED_EUI64", })]


class AVP_0_480 (AVP_FL_NV):
    name = 'Accounting-Record-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            1: "Event Record", 2: "Start Record", 3: "Interim Record", 4: "Stop Record", })]  # noqa: E501


class AVP_0_483 (AVP_FL_NV):
    name = 'Accounting-Realtime-Required'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            0: "Reserved", 1: "DELIVER_AND_GRANT", 2: "GRANT_AND_STORE", 3: "GRANT_AND_LOSE", })]  # noqa: E501


class AVP_0_494 (AVP_FL_NV):
    name = 'MIP6-Auth-Mode'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "Reserved", 1: "IP6_AUTH_MN_AAA", })]  # noqa: E501


class AVP_0_513 (AVP_FL_NV):
    name = 'Protocol'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {
            1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 17: "UDP", 132: "SCTP", })]  # noqa: E501


class AVP_0_514 (AVP_FL_NV):
    name = 'Direction'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "IN", 1: "OUT", 2: "BOTH", })]


class AVP_0_517 (AVP_FL_NV):
    name = 'Negated'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "False", 1: "True", })]


class AVP_0_534 (AVP_FL_NV):
    name = 'Use-Assigned-Address'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "False", 1: "True", })]


class AVP_0_535 (AVP_FL_NV):
    name = 'Diffserv-Code-Point'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "CS0",
                8: "CS1",
                10: "AF11",
                12: "AF12",
                14: "AF13",
                16: "CS2",
                18: "AF21",
                20: "AF22",
                22: "AF23",
                24: "CS3",
                26: "AF31",
                28: "AF32",
                30: "AF33",
                32: "CS4",
                34: "AF41",
                36: "AF42",
                38: "AF43",
                40: "CS5",
                46: "EF_PHB",
                48: "CS6",
                56: "CS7",
            })]


class AVP_0_536 (AVP_FL_NV):
    name = 'Fragmentation-Flag'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "Don't Fragment", 1: "More Fragments", })]  # noqa: E501


class AVP_0_538 (AVP_FL_NV):
    name = 'IP-Option-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "end_of_list",
                1: "nop",
                2: "security",
                3: "loose_source_route",
                4: "timestamp",
                5: "extended_security",
                6: "commercial_security",
                7: "record_route",
                8: "stream_id",
                9: "strict_source_route",
                10: "experimental_measurement",
                11: "mtu_probe",
                12: "mtu_reply",
                13: "flow_control",
                14: "access_control",
                15: "encode",
                16: "imi_traffic_descriptor",
                17: "extended_IP",
                18: "traceroute",
                19: "address_extension",
                20: "router_alert",
                21: "selective_directed_broadcast_mode",
                23: "dynamic_packet_state",
                24: "upstream_multicast_packet",
                25: "quick_start",
                30: "rfc4727_experiment",
            })]


class AVP_0_541 (AVP_FL_NV):
    name = 'TCP-Option-Type'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "EOL",
                1: "NOP",
                2: "MSS",
                3: "WScale",
                4: "SAckOK",
                5: "SAck",
                8: "Timestamp",
                14: "AltChkSum",
                15: "AltChkSumOpt",
                25: "Mood",
            })]


class AVP_0_546 (AVP_FL_NV):
    name = 'ICMP-Type-Number'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "echo-reply",
                3: "dest-unreach",
                4: "source-quench",
                5: "redirect",
                8: "echo-request",
                9: "router-advertisement",
                10: "router-solicitation",
                11: "time-exceeded",
                12: "parameter-problem",
                13: "timestamp-request",
                14: "timestamp-reply",
                15: "information-request",
                16: "information-response",
                17: "address-mask-request",
                18: "address-mask-reply",
            })]


class AVP_0_547 (AVP_FL_NV):
    name = 'ICMP-Code'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "TBD", })]


class AVP_0_570 (AVP_FL_NV):
    name = 'Timezone-Flag'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV, Enumerated('val', None, {0: "UTC", 1: "LOCAL", 2: "OFFSET", })]  # noqa: E501


class AVP_0_575 (AVP_FL_NV):
    name = 'QoS-Semantics'
    avpLen = 12
    fields_desc = [
        AVP_FL_NV,
        Enumerated(
            'val',
            None,
            {
                0: "QoS_Desired",
                1: "QoS_Available",
                2: "QoS_Delivered",
                3: "Minimum_QoS",
                4: "QoS_Authorized",
            })]


class AVP_10415_500 (AVP_FL_V):
    name = 'Abort-Cause'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "BEARER_RELEASED",
                               1: "INSUFFICIENT_SERVER_RESOURCES",
                               2: "INSUFFICIENT_BEARER_RESOURCES",
                               })]


class AVP_10415_511 (AVP_FL_V):
    name = 'Flow-Status'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "ENABLED-UPLINK", 1: "ENABLED-DOWNLINK", 2: "ENABLED", 3: "DISABLED", 4: "REMOVED", })]  # noqa: E501


class AVP_10415_512 (AVP_FL_V):
    name = 'Flow-Usage'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "NO_INFORMATION", 1: "RTCP", 2: "AF_SIGNALLING", })]  # noqa: E501


class AVP_10415_513 (AVP_FL_V):
    name = 'Specific-Action'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                1: "CHARGING_CORRELATION_EXCHANGE",
                2: "INDICATION_OF_LOSS_OF_BEARER",
                3: "INDICATION_OF_RECOVERY_OF_BEARER",
                4: "INDICATION_OF_RELEASE_OF_BEARER",
                6: "IP-CAN_CHANGE",
                7: "INDICATION_OF_OUT_OF_CREDIT",
                8: "INDICATION_OF_SUCCESSFUL_RESOURCES_ALLOCATION",
                9: "INDICATION_OF_FAILED_RESOURCES_ALLOCATION",
                10: "INDICATION_OF_LIMITED_PCC_DEPLOYMENT",
                11: "USAGE_REPORT",
                12: "ACCESS_NETWORK_INFO_REPORT",
            })]


class AVP_10415_520 (AVP_FL_V):
    name = 'Media-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "AUDIO",
                               1: "VIDEO",
                               2: "DATA",
                               3: "APPLICATION",
                               4: "CONTROL",
                               5: "TEXT",
                               6: "MESSAGE",
                               4294967295: "OTHER",
                               })]


class AVP_10415_523 (AVP_FL_V):
    name = 'SIP-Forking-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "SINGLE_DIALOGUE", 1: "SEVERAL_DIALOGUES", })]


class AVP_10415_527 (AVP_FL_V):
    name = 'Service-Info-Status'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "FINAL_SERVICE_INFORMATION", 1: "PRELIMINARY_SERVICE_INFORMATION", })]  # noqa: E501


class AVP_10415_529 (AVP_FL_V):
    name = 'AF-Signalling-Protocol'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NO_INFORMATION", 1: "SIP", })]


class AVP_10415_533 (AVP_FL_V):
    name = 'Rx-Request-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "INITIAL_REQUEST", 1: "UPDATE_REQUEST", })]  # noqa: E501


class AVP_10415_536 (AVP_FL_V):
    name = 'Required-Access-Info'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "USER_LOCATION", 1: "MS_TIME_ZONE", })]  # noqa: E501


class AVP_10415_614 (AVP_FL_V):
    name = 'Server-Assignment-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "NO_ASSIGNMENT",
                1: "REGISTRATION",
                2: "RE_REGISTRATION",
                3: "UNREGISTERED_USER",
                4: "TIMEOUT_DEREGISTRATION",
                5: "USER_DEREGISTRATION",
                6: "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME",
                7: "USER_DEREGISTRATION_STORE_SERVER_NAME",
                8: "ADMINISTRATIVE_DEREGISTRATION",
                9: "AUTHENTICATION_FAILURE",
                10: "AUTHENTICATION_TIMEOUT",
                11: "DEREGISTRATION_TOO_MUCH_DATA",
                12: "AAA_USER_DATA_REQUEST",
                13: "PGW_UPDATE",
            })]


class AVP_10415_616 (AVP_FL_V):
    name = 'Reason-Code'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "PERMANENT_TERMINATION",
                               1: "NEW_SERVER_ASSIGNED",
                               2: "SERVER_CHANGE",
                               3: "REMOVE_S-CSCF",
                               })]


class AVP_10415_623 (AVP_FL_V):
    name = 'User-Authorization-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "REGISTRATION", 1: "DE_REGISTRATION", 2: "REGISTRATION_AND_CAPABILITIES", })]  # noqa: E501


class AVP_10415_624 (AVP_FL_V):
    name = 'User-Data-Already-Available'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "USER_DATA_NOT_AVAILABLE", 1: "USER_DATA_ALREADY_AVAILABLE", })]


class AVP_10415_633 (AVP_FL_V):
    name = 'Originating-Request'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ORIGINATING", })]


class AVP_10415_638 (AVP_FL_V):
    name = 'Loose-Route-Indication'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "LOOSE_ROUTE_NOT_REQUIRED", 1: "LOOSE_ROUTE_REQUIRED", })]  # noqa: E501


class AVP_10415_648 (AVP_FL_V):
    name = 'Multiple-Registration-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "NOT_MULTIPLE_REGISTRATION", 1: "MULTIPLE_REGISTRATION", })]


class AVP_10415_650 (AVP_FL_V):
    name = 'Session-Priority'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "PRIORITY-0", 1: "PRIORITY-1", 2: "PRIORITY-2", 3: "PRIORITY-3", 4: "PRIORITY-4", })]  # noqa: E501


class AVP_10415_652 (AVP_FL_V):
    name = 'Priviledged-Sender-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "NOT_PRIVILEDGED_SENDER", 1: "PRIVILEDGED_SENDER", })]


class AVP_10415_703 (AVP_FL_V):
    name = 'Data-Reference'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "RepositoryData",
                1: "Undefined",
                2: "Undefined",
                3: "Undefined",
                4: "Undefined",
                5: "Undefined",
                6: "Undefined",
                7: "Undefined",
                8: "Undefined",
                9: "Undefined",
                10: "IMSPublicIdentity",
                11: "IMSUserState",
                12: "S-CSCFName",
                13: "InitialFilterCriteria",
                14: "LocationInformation",
                15: "UserState",
                16: "ChargingInformation",
                17: "MSISDN",
                18: "PSIActivation",
                19: "DSAI",
                20: "Reserved",
                21: "ServiceLevelTraceInfo",
                22: "IPAddressSecureBindingInformation",
                23: "ServicePriorityLevel",
                24: "SMSRegistrationInfo",
                25: "UEReachabilityForIP",
                26: "TADSinformation",
                27: "STN-SR",
                28: "UE-SRVCC-Capability",
                29: "ExtendedPriority",
                30: "CSRN",
                31: "ReferenceLocationInformation",
            })]


class AVP_10415_705 (AVP_FL_V):
    name = 'Subs-Req-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Subscribe", 1: "Unsubscribe", })]  # noqa: E501


class AVP_10415_706 (AVP_FL_V):
    name = 'Requested-Domain'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "CS-Domain", 1: "PS-Domain", })]


class AVP_10415_707 (AVP_FL_V):
    name = 'Current-Location'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "DoNotNeedInitiateActiveLocationRetrieval", 1: "InitiateActiveLocationRetrieval", })]  # noqa: E501


class AVP_10415_708 (AVP_FL_V):
    name = 'Identity-Set'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "ALL_IDENTITIES",
                1: "REGISTERED_IDENTITIES",
                2: "IMPLICIT_IDENTITIES",
                3: "ALIAS_IDENTITIES",
            })]


class AVP_10415_710 (AVP_FL_V):
    name = 'Send-Data-Indication'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "USER_DATA_NOT_REQUESTED", 1: "USER_DATA_REQUESTED", })]  # noqa: E501


class AVP_10415_712 (AVP_FL_V):
    name = 'One-Time-Notification'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ONE_TIME_NOTIFICATION_REQUESTED", })]  # noqa: E501


class AVP_10415_714 (AVP_FL_V):
    name = 'Serving-Node-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ONLY_SERVING_NODES_REQUIRED", })]  # noqa: E501


class AVP_10415_717 (AVP_FL_V):
    name = 'Pre-paging-Supported'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "PREPAGING_NOT_SUPPORTED", 1: "PREPAGING_SUPPORTED", })]  # noqa: E501


class AVP_10415_718 (AVP_FL_V):
    name = 'Local-Time-Zone-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "ONLY_LOCAL_TIME_ZONE_REQUESTED", 1: "LOCAL_TIME_ZONE_WITH_LOCATION_INFO_REQUESTED", })]  # noqa: E501


class AVP_10415_829 (AVP_FL_V):
    name = 'Role-Of-Node'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "HPLMN", 1: "VPLMN", 2: "FORWARDING_ROLE", })]  # noqa: E501


class AVP_10415_862 (AVP_FL_V):
    name = 'Node-Functionality'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "S-CSCF",
                1: "P-CSCF",
                2: "I-CSCF",
                5: "BGCF",
                6: "AS",
                7: "IBCF",
                8: "S-GW",
                9: "P-GW",
                10: "HSGW",
                11: "E-CSCF ",
                12: "MME ",
                13: "TRF",
                14: "TF",
                15: "ATCF",
                16: "Proxy Function",
                17: "ePDG",
            })]


class AVP_10415_864 (AVP_FL_V):
    name = 'Originator'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "Calling Party", 1: "Called Party", })]  # noqa: E501


class AVP_10415_867 (AVP_FL_V):
    name = 'PS-Append-Free-Format-Data'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "'Append' ", 1: "'Overwrite' ", })]  # noqa: E501


class AVP_10415_870 (AVP_FL_V):
    name = 'Trigger-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {1: "CHANGE_IN_SGSN_IP_ADDRESS ",
                               2: "CHANGE_IN_QOS",
                               3: "CHANGE_IN_LOCATION",
                               4: "CHANGE_IN_RAT",
                               5: "CHANGE_IN_UE_TIMEZONE",
                               10: "CHANGEINQOS_TRAFFIC_CLASS",
                               11: "CHANGEINQOS_RELIABILITY_CLASS",
                               12: "CHANGEINQOS_DELAY_CLASS",
                               13: "CHANGEINQOS_PEAK_THROUGHPUT",
                               14: "CHANGEINQOS_PRECEDENCE_CLASS",
                               15: "CHANGEINQOS_MEAN_THROUGHPUT",
                               16: "CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_UPLINK",
                               17: "CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_DOWNLINK",
                               18: "CHANGEINQOS_RESIDUAL_BER",
                               19: "CHANGEINQOS_SDU_ERROR_RATIO",
                               20: "CHANGEINQOS_TRANSFER_DELAY",
                               21: "CHANGEINQOS_TRAFFIC_HANDLING_PRIORITY",
                               22: "CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_UPLINK",  # noqa: E501
                               23: "CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_DOWNLINK",  # noqa: E501
                               24: "CHANGEINQOS_APN_AGGREGATE_MAXIMUM_BIT_RATE",  # noqa: E501
                               30: "CHANGEINLOCATION_MCC",
                               31: "CHANGEINLOCATION_MNC",
                               32: "CHANGEINLOCATION_RAC",
                               33: "CHANGEINLOCATION_LAC",
                               34: "CHANGEINLOCATION_CellId",
                               35: "CHANGEINLOCATION_TAC",
                               36: "CHANGEINLOCATION_ECGI",
                               40: "CHANGE_IN_MEDIA_COMPOSITION",
                               50: "CHANGE_IN_PARTICIPANTS_NMB",
                               51: "CHANGE_IN_ THRSHLD_OF_PARTICIPANTS_NMB",
                               52: "CHANGE_IN_USER_PARTICIPATING_TYPE",
                               60: "CHANGE_IN_SERVICE_CONDITION",
                               61: "CHANGE_IN_SERVING_NODE",
                               70: "CHANGE_IN_USER_CSG_INFORMATION",
                               71: "CHANGE_IN_HYBRID_SUBSCRIBED_USER_CSG_INFORMATION",  # noqa: E501
                               72: "CHANGE_IN_HYBRID_UNSUBSCRIBED_USER_CSG_INFORMATION",  # noqa: E501
                               73: "CHANGE_OF_UE_PRESENCE_IN_PRESENCE_REPORTING_AREA",  # noqa: E501
                               })]


class AVP_10415_872 (AVP_FL_V):
    name = 'Reporting-Reason'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "THRESHOLD",
                1: "QHT",
                2: "FINAL",
                3: "QUOTA_EXHAUSTED",
                4: "VALIDITY_TIME",
                5: "OTHER_QUOTA_TYPE",
                6: "RATING_CONDITION_CHANGE",
                7: "FORCED_REAUTHORISATION",
                8: "POOL_EXHAUSTED",
            })]


class AVP_10415_882 (AVP_FL_V):
    name = 'Media-Initiator-Flag'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "called party", 1: "calling party", 2: "unknown", })]  # noqa: E501


class AVP_10415_883 (AVP_FL_V):
    name = 'PoC-Server-Role'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "Participating PoC Server", 1: "Controlling PoC Server", })]  # noqa: E501


class AVP_10415_884 (AVP_FL_V):
    name = 'PoC-Session-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "1 to 1 PoC session",
                1: "Chat PoC group session",
                2: "Pre-arranged PoC group session",
                3: "Ad-hoc PoC group session",
            })]


class AVP_10415_899 (AVP_FL_V):
    name = 'Address-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "e-mail address",
                1: "MSISDN",
                2: "IPv4 Address",
                3: "IPv6 Address",
                4: "Numeric Shortcode",
                5: "Alphanumeric Shortcode",
                6: "Other",
                7: "IMSI",
            })]


class AVP_10415_902 (AVP_FL_V):
    name = 'MBMS-StartStop-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "START", 1: "STOP", 2: "UPDATE", })]  # noqa: E501


class AVP_10415_906 (AVP_FL_V):
    name = 'MBMS-Service-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "MULTICAST", 1: "BROADCAST", })]


class AVP_10415_907 (AVP_FL_V):
    name = 'MBMS-2G-3G-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "2G", 1: "3G", 2: "2G-AND-3G", })]  # noqa: E501


class AVP_10415_921 (AVP_FL_V):
    name = 'CN-IP-Multicast-Distribution'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NO-IP-MULTICAST", 1: "IP-MULTICAST", })]  # noqa: E501


class AVP_10415_922 (AVP_FL_V):
    name = 'MBMS-HC-Indicator'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "uncompressed-header", 1: "compressed-header", })]  # noqa: E501


class AVP_10415_1000 (AVP_FL_V):
    name = 'Bearer-Usage'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "GENERAL", 1: "IMS SIGNALLING", 2: "DEDICATED", })]  # noqa: E501


class AVP_10415_1006 (AVP_FL_V):
    name = 'Event-Trigger'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "SGSN_CHANGE",
                1: "QOS_CHANGE",
                2: "RAT_CHANGE",
                3: "TFT_CHANGE",
                4: "PLMN_CHANGE",
                5: "LOSS_OF_BEARER",
                6: "RECOVERY_OF_BEARER",
                7: "IP-CAN_CHANGE",
                8: "GW-PCEF-MALFUNCTION",
                9: "RESOURCES_LIMITATION",
                10: "MAX_NR_BEARERS_REACHED",
                11: "QOS_CHANGE_EXCEEDING_AUTHORIZATION",
                12: "RAI_CHANGE",
                13: "USER_LOCATION_CHANGE",
                14: "NO_EVENT_TRIGGERS",
                15: "OUT_OF_CREDIT",
                16: "REALLOCATION_OF_CREDIT",
                17: "REVALIDATION_TIMEOUT",
                18: "UE_IP_ADDRESS_ALLOCATE",
                19: "UE_IP_ADDRESS_RELEASE",
                20: "DEFAULT_EPS_BEARER_QOS_CHANGE",
                21: "AN_GW_CHANGE",
                22: "SUCCESSFUL_RESOURCE_ALLOCATION",
                23: "RESOURCE_MODIFICATION_REQUEST",
                24: "PGW_TRACE_CONTROL",
                25: "UE_TIME_ZONE_CHANGE",
                26: "TAI_CHANGE",
                27: "ECGI_CHANGE",
                28: "CHARGING_CORRELATION_EXCHANGE",
                29: "APN-AMBR_MODIFICATION_FAILURE",
                30: "USER_CSG_INFORMATION_CHANGE",
                33: "USAGE_REPORT",
                34: "DEFAULT-EPS-BEARER-QOS_MODIFICATION_FAILURE",
                35: "USER_CSG_HYBRID_SUBSCRIBED_INFORMATION_CHANGE",
                36: "USER_CSG_ HYBRID_UNSUBSCRIBED_INFORMATION_CHANGE",
                37: "ROUTING_RULE_CHANGE",
                38: "MAX_MBR_APN_AMBR_CHANGE",
                39: "APPLICATION_START",
                40: "APPLICATION_STOP",
                41: "ADC_REVALIDATION_TIMEOUT",
                42: "CS_TO_PS_HANDOVER",
                43: "UE_LOCAL_IP_ADDRESS_CHANGE",
                45: "ACCESS_NETWORK_INFO_REPORT",
                100: "TIME_CHANGE",
                1000: "TFT DELETED",
                1001: "LOSS OF BEARER",
                1002: "RECOVERY OF BEARER",
                1003: "POLICY ENFORCEMENT FAILED",
            })]


class AVP_10415_1007 (AVP_FL_V):
    name = 'Metering-Method'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "DURATION", 1: "VOLUME", 2: "DURATION_VOLUME", })]  # noqa: E501


class AVP_10415_1008 (AVP_FL_V):
    name = 'Offline'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "DISABLE_OFFLINE", 1: "ENABLE_OFFLINE", })]  # noqa: E501


class AVP_10415_1009 (AVP_FL_V):
    name = 'Online'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "DISABLE_ONLINE", 1: "ENABLE_ONLINE", })]  # noqa: E501


class AVP_10415_1011 (AVP_FL_V):
    name = 'Reporting-Level'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "SERVICE_IDENTIFIER_LEVEL", 1: "RATING_GROUP_LEVEL", 2: "SPONSORED_CONNECTIVITY_LEVEL", })]  # noqa: E501


class AVP_10415_1015 (AVP_FL_V):
    name = 'PDP-Session-Operation'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "PDP-SESSION-TERMINATION", })]


class AVP_10415_1019 (AVP_FL_V):
    name = 'PCC-Rule-Status'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "ACTIVE", 1: "INACTIVE", 2: "TEMPORARY_INACTIVE", })]  # noqa: E501


class AVP_10415_1021 (AVP_FL_V):
    name = 'Bearer-Operation'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "TERMINATION", 1: "ESTABLISHMENT", 2: "MODIFICATION", })]  # noqa: E501


class AVP_10415_1023 (AVP_FL_V):
    name = 'Bearer-Control-Mode'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "UE_ONLY", 1: "RESERVED", 2: "UE_NW", })]  # noqa: E501


class AVP_10415_1024 (AVP_FL_V):
    name = 'Network-Request-Support'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "NETWORK_REQUEST NOT SUPPORTED", 1: "NETWORK_REQUEST SUPPORTED", })]  # noqa: E501


class AVP_10415_1027 (AVP_FL_V):
    name = 'IP-CAN-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "3GPP-GPRS",
                               1: "DOCSIS",
                               2: "xDSL",
                               3: "WiMAX",
                               4: "3GPP2",
                               5: "3GPP-EPS",
                               6: "Non-3GPP-EPS",
                               })]


class AVP_10415_1028 (AVP_FL_V):
    name = 'QoS-Class-Identifier'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                1: "QCI_1",
                2: "QCI_2",
                3: "QCI_3",
                4: "QCI_4",
                5: "QCI_5",
                6: "QCI_6",
                7: "QCI_7",
                8: "QCI_8",
                9: "QCI_9",
            })]


class AVP_10415_1032 (AVP_FL_V):
    name = 'RAT-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "WLAN",
                               1: "VIRTUAL",
                               1000: "UTRAN",
                               1001: "GERAN",
                               1002: "GAN",
                               1003: "HSPA_EVOLUTION",
                               1004: "EUTRAN",
                               2000: "CDMA2000_1X",
                               2001: "HRPD",
                               2002: "UMB",
                               2003: "EHRPD",
                               })]


class AVP_10415_1045 (AVP_FL_V):
    name = 'Session-Release-Cause'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "UNSPECIFIED_REASON", 1: "UE_SUBSCRIPTION_REASON", 2: "INSUFFICIENT_SERVER_RESOURCES", })]  # noqa: E501


class AVP_10415_1047 (AVP_FL_V):
    name = 'Pre-emption-Capability'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "PRE-EMPTION_CAPABILITY_ENABLED", 1: "PRE-EMPTION_CAPABILITY_DISABLED", })]  # noqa: E501


class AVP_10415_1048 (AVP_FL_V):
    name = 'Pre-emption-Vulnerability'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "PRE-EMPTION_VULNERABILITY_ENABLED", 1: "PRE-EMPTION_VULNERABILITY_DISABLED", })]  # noqa: E501


class AVP_10415_1062 (AVP_FL_V):
    name = 'Packet-Filter-Operation'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "DELETION", 1: "ADDITION", 2: "MODIFICATION", })]


class AVP_10415_1063 (AVP_FL_V):
    name = 'Resource-Allocation-Notification'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ENABLE_NOTIFICATION", })]


class AVP_10415_1068 (AVP_FL_V):
    name = 'Usage-Monitoring-Level'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "SESSION_LEVEL", 1: "PCC_RULE_LEVEL", 2: "ADC_RULE_LEVEL", })]  # noqa: E501


class AVP_10415_1069 (AVP_FL_V):
    name = 'Usage-Monitoring-Report'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "USAGE_MONITORING_REPORT_REQUIRED", })]  # noqa: E501


class AVP_10415_1070 (AVP_FL_V):
    name = 'Usage-Monitoring-Support'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "USAGE_MONITORING_DISABLED", })]


class AVP_10415_1071 (AVP_FL_V):
    name = 'CSG-Information-Reporting'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "CHANGE_CSG_CELL",
                1: "CHANGE_CSG_SUBSCRIBED_HYBRID_CELL",
                2: "CHANGE_CSG_UNSUBSCRIBED_HYBRID_CELL",
            })]


class AVP_10415_1072 (AVP_FL_V):
    name = 'Packet-Filter-Usage'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {1: "SEND_TO_UE", })]


class AVP_10415_1073 (AVP_FL_V):
    name = 'Charging-Correlation-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "CHARGING_IDENTIFIER_REQUIRED", })]  # noqa: E501


class AVP_10415_1080 (AVP_FL_V):
    name = 'Flow-Direction'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "UNSPECIFIED", 1: "DOWNLINK", 2: "UPLINK", 3: "BIDIRECTIONAL", })]  # noqa: E501


class AVP_10415_1086 (AVP_FL_V):
    name = 'Redirect-Support'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "REDIRECTION_DISABLED", 1: "REDIRECTION_ENABLED", })]  # noqa: E501


class AVP_10415_1099 (AVP_FL_V):
    name = 'PS-to-CS-Session-Continuity'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "VIDEO_PS2CS_CONT_CANDIDATE", })]


class AVP_10415_1204 (AVP_FL_V):
    name = 'Type-Number'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "TBC", })]


class AVP_10415_1208 (AVP_FL_V):
    name = 'Addressee-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "TO ", 1: "CC ", 2: "BCC", })]


class AVP_10415_1209 (AVP_FL_V):
    name = 'Priority'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "Low", 1: "Normal", 2: "High", })]


class AVP_10415_1211 (AVP_FL_V):
    name = 'Message-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                1: "m-send-req",
                2: "m-send-conf",
                3: "m-notification-ind ",
                4: "m-notifyresp-ind ",
                5: "m-retrieve-conf ",
                6: "m-acknowledge-ind ",
                7: "m-delivery-ind ",
                8: "m-read-rec-ind ",
                9: "m-read-orig-ind",
                10: "m-forward-req ",
                11: "m-forward-conf ",
                12: "m-mbox-store-conf",
                13: "m-mbox-view-conf ",
                14: "m-mbox-upload-conf ",
                15: "m-mbox-delete-conf ",
            })]


class AVP_10415_1214 (AVP_FL_V):
    name = 'Class-Identifier'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "Personal", 1: "Advertisement", 2: "Informational", 3: "Auto", })]  # noqa: E501


class AVP_10415_1216 (AVP_FL_V):
    name = 'Delivery-Report-Requested'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "No", 1: "Yes", })]


class AVP_10415_1217 (AVP_FL_V):
    name = 'Adaptations'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Yes", 1: "No", })]


class AVP_10415_1220 (AVP_FL_V):
    name = 'Content-Class'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "text ",
                1: "image-basic ",
                2: "image-rich ",
                3: "video-basic",
                4: "video-rich ",
                5: "megapixel ",
                6: "content-basic ",
                7: "content-rich ",
            })]


class AVP_10415_1221 (AVP_FL_V):
    name = 'DRM-Content'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "No", 1: "Yes", })]


class AVP_10415_1222 (AVP_FL_V):
    name = 'Read-Reply-Report-Requested'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "No", 1: "Yes", })]


class AVP_10415_1224 (AVP_FL_V):
    name = 'File-Repair-Supported'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "Forwarding not pending", 1: "Forwarding pending", 2: "NOT_SUPPORTED", })]  # noqa: E501


class AVP_10415_1225 (AVP_FL_V):
    name = 'MBMS-User-Service-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {1: "DOWNLOAD", 2: "STREAMING", })]


class AVP_10415_1247 (AVP_FL_V):
    name = 'PDP-Context-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Primary", 1: "Secondary", })]


class AVP_10415_1248 (AVP_FL_V):
    name = 'MMBox-Storage-Requested'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "No", 1: "Yes", })]


class AVP_10415_1254 (AVP_FL_V):
    name = 'PoC-User-Role-info-Units'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            1: "Moderator", 2: "Dispatcher", 3: "Session-Owner", 4: "Session-Participant", })]  # noqa: E501


class AVP_10415_1259 (AVP_FL_V):
    name = 'Participant-Access-Priority'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                1: "Pre-emptive priority: ",
                2: "High priority: Lower than Pre-emptive priority",
                3: "Normal priority: Normal level. Lower than High priority",
                4: "Low priority: Lowest level priority",
            })]


class AVP_10415_1261 (AVP_FL_V):
    name = 'PoC-Change-Condition'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "ServiceChange",
                1: "VolumeLimit",
                2: "TimeLimit",
                3: "NumberofTalkBurstLimit",
                4: "NumberofActiveParticipants",
            })]


class AVP_10415_1268 (AVP_FL_V):
    name = 'Envelope-Reporting'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "DO_NOT_REPORT_ENVELOPES",
                1: "REPORT_ENVELOPES",
                2: "REPORT_ENVELOPES_WITH_VOLUME",
                3: "REPORT_ENVELOPES_WITH_EVENTS",
                4: "REPORT_ENVELOPES_WITH_VOLUME_AND_EVENTS",
            })]


class AVP_10415_1271 (AVP_FL_V):
    name = 'Time-Quota-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "DISCRETE_TIME_PERIOD", 1: "CONTINUOUS_TIME_PERIOD", })]  # noqa: E501


class AVP_10415_1277 (AVP_FL_V):
    name = 'PoC-Session-Initiation-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Pre-established", 1: "On-demand", })]  # noqa: E501


class AVP_10415_1279 (AVP_FL_V):
    name = 'User-Participating-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "Normal", 1: "NW PoC Box", 2: "UE PoC Box", })]


class AVP_10415_1417 (AVP_FL_V):
    name = 'Network-Access-Mode'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "PACKET_AND_CIRCUIT", 1: "Reserved", 2: "ONLY_PACKET", })]  # noqa: E501


class AVP_10415_1420 (AVP_FL_V):
    name = 'Cancellation-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "MME_UPDATE_PROCEDURE",
                1: "SGSN_UPDATE_PROCEDURE",
                2: "SUBSCRIPTION_WITHDRAWAL",
                3: "UPDATE_PROCEDURE_IWF",
                4: "INITIAL_ATTACH_PROCEDURE",
            })]


class AVP_10415_1424 (AVP_FL_V):
    name = 'Subscriber-Status'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "SERVICE_GRANTED", 1: "OPERATOR_DETERMINED_BARRING", })]  # noqa: E501


class AVP_10415_1428 (AVP_FL_V):
    name = 'All-APN-Configurations-Included-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ALL_APN_CONFIGURATIONS_INCLUDED", })]  # noqa: E501


class AVP_10415_1432 (AVP_FL_V):
    name = 'VPLMN-Dynamic-Address-Allowed'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NOTALLOWED", 1: "ALLOWED", })]


class AVP_10415_1434 (AVP_FL_V):
    name = 'Alert-Reason'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "UE_PRESENT", 1: "UE_MEMORY_AVAILABLE", })]  # noqa: E501


class AVP_10415_1438 (AVP_FL_V):
    name = 'PDN-GW-Allocation-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "STATIC", 1: "DYNAMIC", })]


class AVP_10415_1445 (AVP_FL_V):
    name = 'Equipment-Status'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "WHITELISTED", 1: "BLACKLISTED", 2: "GREYLISTED", })]  # noqa: E501


class AVP_10415_1456 (AVP_FL_V):
    name = 'PDN-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "IPv4", 1: "IPv6", 2: "IPv4v6", 3: "IPv4_OR_IPv6", })]  # noqa: E501


class AVP_10415_1457 (AVP_FL_V):
    name = 'Roaming-Restricted-Due-To-Unsupported-Feature'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Roaming-Restricted-Due-To-Unsupported-Feature", })]  # noqa: E501


class AVP_10415_1462 (AVP_FL_V):
    name = 'Trace-Depth'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "Minimum",
                               1: "Medium",
                               2: "Maximum",
                               3: "MinimumWithoutVendorSpecificExtension",
                               4: "MediumWithoutVendorSpecificExtension",
                               5: "MaximumWithoutVendorSpecificExtension",
                               })]


class AVP_10415_1468 (AVP_FL_V):
    name = 'Complete-Data-List-Included-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ALL_PDP_CONTEXTS_INCLUDED", })]


class AVP_10415_1478 (AVP_FL_V):
    name = 'Notification-To-UE-User'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "NOTIFY_LOCATION_ALLOWED",
                1: "NOTIFYANDVERIFY_LOCATION_ALLOWED_IF_NO_RESPONSE",
                2: "NOTIFYANDVERIFY_LOCATION_NOT_ALLOWED_IF_NO_RESPONSE",
                3: "LOCATION_NOT_ALLOWED",
            })]


class AVP_10415_1481 (AVP_FL_V):
    name = 'GMLC-Restriction'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "GMLC_LIST", 1: "HOME_COUNTRY", })]  # noqa: E501


class AVP_10415_1482 (AVP_FL_V):
    name = 'PLMN-Client'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "BROADCAST_SERVICE",
                               1: "O_AND_M_HPLMN",
                               2: "O_AND_M_VPLMN",
                               3: "ANONYMOUS_LOCATION",
                               4: "TARGET_UE_SUBSCRIBED_SERVICE",
                               })]


class AVP_10415_1491 (AVP_FL_V):
    name = 'ICS-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "FALSE", 1: "TRUE", })]


class AVP_10415_1492 (AVP_FL_V):
    name = 'IMS-Voice-Over-PS-Sessions-Supported'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NOT_SUPPORTED", 1: "SUPPORTED", })]  # noqa: E501


class AVP_10415_1493 (AVP_FL_V):
    name = 'Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NOT_SUPPORTED", 1: "SUPPORTED", })]  # noqa: E501


class AVP_10415_1499 (AVP_FL_V):
    name = 'User-State'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "DETACHED",
                               1: "ATTACHED_NOT_REACHABLE_FOR_PAGING",
                               2: "ATTACHED_REACHABLE_FOR_PAGING",
                               3: "CONNECTED_NOT_REACHABLE_FOR_PAGING",
                               4: "CONNECTED_REACHABLE_FOR_PAGING",
                               5: "NETWORK_DETERMINED_NOT_REACHABLE",
                               })]


class AVP_10415_1501 (AVP_FL_V):
    name = 'Non-3GPP-IP-Access'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "NON_3GPP_SUBSCRIPTION_ALLOWED", 1: "NON_3GPP_SUBSCRIPTION_BARRED", })]  # noqa: E501


class AVP_10415_1502 (AVP_FL_V):
    name = 'Non-3GPP-IP-Access-APN'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "NON_3GPP_APNS_ENABLE", 1: "NON_3GPP_APNS_DISABLE", })]  # noqa: E501


class AVP_10415_1503 (AVP_FL_V):
    name = 'AN-Trusted'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "TRUSTED", 1: "UNTRUSTED", })]


class AVP_10415_1515 (AVP_FL_V):
    name = 'Trust-Relationship-Update'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "TBC", })]


class AVP_10415_1519 (AVP_FL_V):
    name = 'Transport-Access-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "BBF", })]


class AVP_10415_1610 (AVP_FL_V):
    name = 'Current-Location-Retrieved'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ACTIVE-LOCATION-RETRIEVAL", })]


class AVP_10415_1613 (AVP_FL_V):
    name = 'SIPTO-Permission'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "SIPTO_ALLOWED", 1: "SIPTO_NOTALLOWED", })]  # noqa: E501


class AVP_10415_1614 (AVP_FL_V):
    name = 'Error-Diagnostic'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "GPRS_DATA_SUBSCRIBED",
                1: "NO_GPRS_DATA_SUBSCRIBED",
                2: "ODB-ALL-APN",
                3: "ODB-HPLMN-APN",
                4: "ODB-VPLMN-APN",
            })]


class AVP_10415_1615 (AVP_FL_V):
    name = 'UE-SRVCC-Capability'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "UE-SRVCC-NOT-SUPPORTED", 1: "UE-SRVCC-SUPPORTED", })]  # noqa: E501


class AVP_10415_1617 (AVP_FL_V):
    name = 'VPLMN-LIPA-Allowed'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "LIPA-NOTALLOWED", 1: "LIPA-ALLOWED", })]  # noqa: E501


class AVP_10415_1618 (AVP_FL_V):
    name = 'LIPA-Permission'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "LIPA-PROHIBITED", 1: "LIPA-ONLY", 2: "LIPA-CONDITIONAL", })]  # noqa: E501


class AVP_10415_1623 (AVP_FL_V):
    name = 'Job-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V,
                   Enumerated('val',
                              None,
                              {0: "Immediate-MDT-only",
                               1: "Logged-MDT-only",
                               2: "Trace-only",
                               3: "Immediate-MDT-and-Trace",
                               4: "RLF-reports-only",
                               })]


class AVP_10415_1627 (AVP_FL_V):
    name = 'Report-Interval'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "UMTS_250_ms",
                1: "UMTS_500_ms",
                2: "UMTS_1000_ms",
                3: "UMTS_2000_ms",
                4: "UMTS_3000_ms",
                5: "UMTS_4000_ms",
                6: "UMTS_6000_ms",
                7: "UMTS_8000_ms",
                8: "UMTS_12000_ms",
                9: "UMTS_16000_ms",
                10: "UMTS_20000_ms",
                11: "UMTS_24000_ms",
                12: "UMTS_28000_ms",
                13: "UMTS_32000_ms",
                14: "UMTS_64000_ms",
                15: "LTE_120_ms",
                16: "LTE_240_ms",
                17: "LTE_480_ms",
                18: "LTE_640_ms",
                19: "LTE_1024_ms",
                20: "LTE_2048_ms",
                21: "LTE_5120_ms",
                22: "LTE_10240_ms",
                23: "LTE_60000_ms",
                24: "LTE_360000_ms",
                25: "LTE_720000_ms",
                26: "LTE_1800000_ms",
                27: "LTE_3600000_ms",
            })]


class AVP_10415_1628 (AVP_FL_V):
    name = 'Report-Amount'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "1", 1: "2", 2: "4", 3: "8", 4: "16", 5: "32", 6: "64", 7: "infinity", })]  # noqa: E501


class AVP_10415_1631 (AVP_FL_V):
    name = 'Logging-Interval'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "1.28",
                1: "2.56",
                2: "5.12",
                3: "10.24",
                4: "20.48",
                5: "30.72",
                6: "40.96",
                7: "61.44",
            })]


class AVP_10415_1632 (AVP_FL_V):
    name = 'Logging-Duration'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "600_sec", 1: "1200_sec", 2: "2400_sec", 3: "3600_sec", 4: "5400_sec", 5: "7200_sec", })]  # noqa: E501


class AVP_10415_1633 (AVP_FL_V):
    name = 'Relay-Node-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NOT_RELAY_NODE", 1: "RELAY_NODE", })]  # noqa: E501


class AVP_10415_1634 (AVP_FL_V):
    name = 'MDT-User-Consent'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "CONSENT_NOT_GIVEN", 1: "CONSENT_GIVEN", })]  # noqa: E501


class AVP_10415_1636 (AVP_FL_V):
    name = 'Subscribed-VSRVCC'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "VSRVCC_SUBSCRIBED", })]


class AVP_10415_1648 (AVP_FL_V):
    name = 'SMS-Register-Request'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "SMS_REGISTRATION_REQUIRED", 1: "SMS_REGISTRATION_NOT_PREFERRED", 2: "NO_PREFERENCE", })]  # noqa: E501


class AVP_10415_1650 (AVP_FL_V):
    name = 'Daylight-Saving-Time'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "NO_ADJUSTMENT", 1: "PLUS_ONE_HOUR_ADJUSTMENT", 2: "PLUS_TWO_HOURS_ADJUSTMENT", })]  # noqa: E501


class AVP_10415_2006 (AVP_FL_V):
    name = 'Interface-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "Unknown",
                1: "MOBILE_ORIGINATING",
                2: "MOBILE_TERMINATING",
                3: "APPLICATION_ORIGINATING",
                4: "APPLICATION_TERMINATION",
            })]


class AVP_10415_2007 (AVP_FL_V):
    name = 'SM-Message-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "SUBMISSION", })]


class AVP_10415_2011 (AVP_FL_V):
    name = 'Reply-Path-Requested'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "No Reply Path Set", 1: "Reply path Set", })]  # noqa: E501


class AVP_10415_2016 (AVP_FL_V):
    name = 'SMS-Node'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "SMS Router", 1: "IP-SM-GW", 2: "SMS Router and IP-SM-GW", 3: "SMS-SC", })]  # noqa: E501


class AVP_10415_2025 (AVP_FL_V):
    name = 'PoC-Event-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "Normal;",
                1: "Instant Ppersonal Aalert event;",
                2: "PoC Group Advertisement event;",
                3: "Early Ssession Setting-up event;",
                4: "PoC Talk Burst",
            })]


class AVP_10415_2029 (AVP_FL_V):
    name = 'SM-Service-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "VAS4SMS Short Message content processing",
                1: "VAS4SMS Short Message forwarding",
                2: "VAS4SMS Short Message Forwarding multiple subscriptions ",
                3: "VAS4SMS Short Message filtering ",
                4: "VAS4SMS Short Message receipt",
                5: "VAS4SMS Short Message Network Storage ",
                6: "VAS4SMS Short Message to multiple destinations",
                7: "VAS4SMS Short Message Virtual Private Network (VPN)",
                8: "VAS4SMS Short Message Auto Reply",
                9: "VAS4SMS Short Message Personal Signature",
                10: "VAS4SMS Short Message Deferred Delivery ",
            })]


class AVP_10415_2033 (AVP_FL_V):
    name = 'Subscriber-Role'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Originating", 1: "Terminating", })]  # noqa: E501


class AVP_10415_2036 (AVP_FL_V):
    name = 'SDP-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "SDP Offer", 1: "SDP Answer", })]


class AVP_10415_2047 (AVP_FL_V):
    name = 'Serving-Node-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "SGSN", 1: "PMIPSGW", 2: "GTPSGW", 3: "ePDG", 4: "hSGW", 5: "MME", 6: "TWAN", })]  # noqa: E501


class AVP_10415_2049 (AVP_FL_V):
    name = 'Participant-Action-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "CREATE_CONF", 1: "JOIN_CONF", 2: "INVITE_INTO_CONF", 3: "QUIT_CONF", })]  # noqa: E501


class AVP_10415_2051 (AVP_FL_V):
    name = 'Dynamic-Address-Flag'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Static", 1: "Dynamic", })]


class AVP_10415_2065 (AVP_FL_V):
    name = 'SGW-Change'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ACR_Start_NOT_due_to_SGW_Change", })]  # noqa: E501


class AVP_10415_2066 (AVP_FL_V):
    name = 'Charging-Characteristics-Selection-Mode'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "Serving-Node-Supplied",
                1: "Subscription-specific",
                2: "APN-specific",
                3: "Home-Default",
                4: "Roaming-Default",
                5: "Visiting-Default",
            })]


class AVP_10415_2068 (AVP_FL_V):
    name = 'Dynamic-Address-Flag-Extension'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Static", 1: "Dynamic", })]


class AVP_10415_2118 (AVP_FL_V):
    name = 'Charge-Reason-Code'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "UNKNOWN",
                1: "USAGE",
                2: "COMMUNICATION-ATTEMPT-CHARGE",
                3: "SETUP-CHARGE",
                4: "ADD-ON-CHARGE",
            })]


class AVP_10415_2203 (AVP_FL_V):
    name = 'Subsession-Operation'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "TERMINATION", 1: "ESTABLISHMENT", 2: "MODIFICATION", })]  # noqa: E501


class AVP_10415_2204 (AVP_FL_V):
    name = 'Multiple-BBERF-Action'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ESTABLISHMENT", 1: "TERMINATION", })]  # noqa: E501


class AVP_10415_2206 (AVP_FL_V):
    name = 'DRA-Deployment'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "DRA_Deployed", })]


class AVP_10415_2208 (AVP_FL_V):
    name = 'DRA-Binding'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "DRA_BINDING_DELETION", })]


class AVP_10415_2303 (AVP_FL_V):
    name = 'Online-Charging-Flag'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "ECF address not provided", 1: "ECF address provided", })]  # noqa: E501


class AVP_10415_2308 (AVP_FL_V):
    name = 'IMSI-Unauthenticated-Flag'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Authenticated", 1: "Unauthenticated", })]  # noqa: E501


class AVP_10415_2310 (AVP_FL_V):
    name = 'AoC-Format'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "MONETARY", 1: "NON_MONETARY", 2: "CAI", })]  # noqa: E501


class AVP_10415_2312 (AVP_FL_V):
    name = 'AoC-Service-Obligatory-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NON_BINDING", 1: "BINDING", })]


class AVP_10415_2313 (AVP_FL_V):
    name = 'AoC-Service-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "NONE", 1: "AOC-S", 2: "AOC-D", 3: "AOC-E", })]  # noqa: E501


class AVP_10415_2317 (AVP_FL_V):
    name = 'CSG-Access-Mode'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Closed mode", 1: "Hybrid Mode", })]  # noqa: E501


class AVP_10415_2318 (AVP_FL_V):
    name = 'CSG-Membership-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Not CSG member", 1: "CSG Member  ", })]  # noqa: E501


class AVP_10415_2322 (AVP_FL_V):
    name = 'IMS-Emergency-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Non Emergency", 1: "Emergency", })]  # noqa: E501


class AVP_10415_2323 (AVP_FL_V):
    name = 'MBMS-Charged-Party'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Content Provider", 1: "Subscriber", })]  # noqa: E501


class AVP_10415_2500 (AVP_FL_V):
    name = 'SLg-Location-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "CURRENT_LOCATION",
                1: "CURRENT_OR_LAST_KNOWN_LOCATION",
                2: "INITIAL_LOCATION",
                3: "ACTIVATE_DEFERRED_LOCATION",
                4: "CANCEL_DEFERRED_LOCATION",
                5: "NOTIFICATION_VERIFICATION_ONLY",
            })]


class AVP_10415_2507 (AVP_FL_V):
    name = 'Vertical-Requested'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "VERTICAL_COORDINATE_IS_NOT REQUESTED", 1: "VERTICAL_COORDINATE_IS_REQUESTED", })]  # noqa: E501


class AVP_10415_2508 (AVP_FL_V):
    name = 'Velocity-Requested'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "VELOCITY_IS_NOT_REQUESTED", 1: "BEST VELOCITY_IS_REQUESTED", })]  # noqa: E501


class AVP_10415_2509 (AVP_FL_V):
    name = 'Response-Time'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "LOW_DELAY", 1: "DELAY_TOLERANT", })]  # noqa: E501


class AVP_10415_2512 (AVP_FL_V):
    name = 'LCS-Privacy-Check'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "ALLOWED_WITHOUT_NOTIFICATION",
                1: "ALLOWED_WITH_NOTIFICATION",
                2: "ALLOWED_IF_NO_RESPONSE",
                3: "RESTRICTED_IF_NO_RESPONSE",
                4: "NOT_ALLOWED",
            })]


class AVP_10415_2513 (AVP_FL_V):
    name = 'Accuracy-Fulfilment-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "REQUESTED_ACCURACY_FULFILLED", 1: "REQUESTED_ACCURACY_NOT_FULFILLED", })]  # noqa: E501


class AVP_10415_2518 (AVP_FL_V):
    name = 'Location-Event'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "EMERGENCY_CALL_ORIGINATION",
                1: "EMERGENCY_CALL_RELEASE",
                2: "MO_LR",
                3: "EMERGENCY_CALL_HANDOVER",
            })]


class AVP_10415_2519 (AVP_FL_V):
    name = 'Pseudonym-Indicator'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "PSEUDONYM_NOT_REQUESTED", 1: "PSEUDONYM_REQUESTED", })]  # noqa: E501


class AVP_10415_2523 (AVP_FL_V):
    name = 'LCS-QoS-Class'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "ASSURED", 1: "BEST EFFORT", })]


class AVP_10415_2538 (AVP_FL_V):
    name = 'Occurrence-Info'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "ONE_TIME_EVENT", 1: "MULTIPLE_TIME_EVENT", })]  # noqa: E501


class AVP_10415_2550 (AVP_FL_V):
    name = 'Periodic-Location-Support-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NOT_SUPPORTED", 1: "SUPPORTED", })]  # noqa: E501


class AVP_10415_2551 (AVP_FL_V):
    name = 'Prioritized-List-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NOT_PRIORITIZED", 1: "PRIORITIZED", })]  # noqa: E501


class AVP_10415_2602 (AVP_FL_V):
    name = 'Low-Priority-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "NO", })]


class AVP_10415_2604 (AVP_FL_V):
    name = 'Local-GW-Inserted-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "Local GW Not Inserted", 1: "Local GW Inserted", })]


class AVP_10415_2605 (AVP_FL_V):
    name = 'Transcoder-Inserted-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "Transcoder Not Inserted", 1: "Transcoder Inserted", })]


class AVP_10415_2702 (AVP_FL_V):
    name = 'AS-Code'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "4xx;", 1: "5xx;", 2: "Timeout", })]


class AVP_10415_2704 (AVP_FL_V):
    name = 'NNI-Type'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "non-roaming", 1: "roaming without loopback", 2: "roaming with loopback", })]  # noqa: E501


class AVP_10415_2706 (AVP_FL_V):
    name = 'Relationship-Mode'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "trusted", 1: "non-trusted", })]


class AVP_10415_2707 (AVP_FL_V):
    name = 'Session-Direction'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "inbound", })]


class AVP_10415_2710 (AVP_FL_V):
    name = 'Access-Transfer-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "PS to CS Transfer", 1: "CS to PS Transfer", })]  # noqa: E501


class AVP_10415_2717 (AVP_FL_V):
    name = 'TAD-Identifier'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "CS", 1: "PS", })]


class AVP_10415_2809 (AVP_FL_V):
    name = 'Mute-Notification'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "MUTE_REQUIRED", })]


class AVP_10415_2811 (AVP_FL_V):
    name = 'AN-GW-Status'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "AN_GW_FAILED", })]


class AVP_10415_2904 (AVP_FL_V):
    name = 'SL-Request-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "INITIAL_REQUEST", 1: "INTERMEDIATE_REQUEST", })]  # noqa: E501


class AVP_10415_3407 (AVP_FL_V):
    name = 'SM-Device-Trigger-Indicator'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Not DeviceTrigger ", 1: "Device Trigger", })]  # noqa: E501


class AVP_10415_3415 (AVP_FL_V):
    name = 'Forwarding-Pending'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "Forwarding not pending", 1: "Forwarding pending", })]  # noqa: E501


class AVP_10415_3421 (AVP_FL_V):
    name = 'CN-Operator-Selection-Entity'
    avpLen = 16
    fields_desc = [
        AVP_FL_V,
        Enumerated(
            'val',
            None,
            {
                0: "The Serving Network has been selected by the UE",
                1: "The Serving Network has been selected by the network",
            })]


class AVP_10415_3428 (AVP_FL_V):
    name = 'Coverage-Status'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Out of coverage", 1: "In coverage", })]  # noqa: E501


class AVP_10415_3438 (AVP_FL_V):
    name = 'Role-Of-ProSe-Function'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "HPLMN", 1: "VPLMN", })]


class AVP_10415_3442 (AVP_FL_V):
    name = 'ProSe-Direct-Discovery-Model'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Model A", 1: "Model B", })]


class AVP_10415_3443 (AVP_FL_V):
    name = 'ProSe-Event-Type'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "Announcing", 1: "Monitoring", 2: "Match Report", })]  # noqa: E501


class AVP_10415_3445 (AVP_FL_V):
    name = 'ProSe-Functionality'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "Direct discovery", 1: "EPC-level discovery", })]  # noqa: E501


class AVP_10415_3448 (AVP_FL_V):
    name = 'ProSe-Range-Class'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "Reserved", 1: "50 m", 2: "100 m", 3: "200 m", 4: "500 m", 5: "1000 m", })]  # noqa: E501


class AVP_10415_3449 (AVP_FL_V):
    name = 'ProSe-Reason-For-Cancellation'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {
            0: "Proximity Alert sent", 1: "Time expired with no renewal", })]


class AVP_10415_3451 (AVP_FL_V):
    name = 'ProSe-Role-Of-UE'
    avpLen = 16
    fields_desc = [AVP_FL_V, Enumerated('val', None, {0: "Announcing UE", 1: "Monitoring UE", 2: "Requestor UE", })]  # noqa: E501


class AVP_10415_3454 (AVP_FL_V):
    name = 'Proximity-Alert-Indication'
    avpLen = 16
    fields_desc = [
        AVP_FL_V, Enumerated('val', None, {0: "Alert", 1: "No Alert", })]


# Remaining AVPs (which do not need to be declared as classes)
##############################################################

# In AvpDefDict dictionary, the first level key is the 'AVP vendor' and the second level key is the 'AVP code'  # noqa: E501
# Each tuple then defines the AVP name, the Scapy class and the default flags
AvpDefDict = {
    0: {
        1: ('User-Name', AVPNV_StrLenField, 64),
        2: ('User-Password', AVPNV_OctetString, 64),
        5: ('NAS-Port', AVPNV_Unsigned32, 64),
        6: ('Service-Type', AVP_0_6, 64),
        7: ('Framed-Protocol', AVP_0_7, 64),
        9: ('Framed-IP-Netmask', AVPNV_OctetString, 64),
        10: ('Framed-Routing', AVP_0_10, 64),
        11: ('Filter-Id', AVPNV_StrLenField, 64),
        12: ('Framed-MTU', AVPNV_Unsigned32, 64),
        13: ('Framed-Compression', AVP_0_13, 64),
        15: ('Login-Service', AVP_0_15, 64),
        16: ('Login-TCP-Port', AVPNV_Unsigned32, 64),
        18: ('Reply-Message', AVPNV_StrLenField, 64),
        19: ('Callback-Number', AVPNV_StrLenField, 64),
        20: ('Callback-Id', AVPNV_StrLenField, 64),
        22: ('Framed-Route', AVPNV_StrLenField, 64),
        23: ('Framed-IPX-Network', AVPNV_Unsigned32, 64),
        25: ('Class', AVPNV_OctetString, 64),
        27: ('Session-Timeout', AVPNV_Unsigned32, 64),
        28: ('Idle-Timeout', AVPNV_Unsigned32, 64),
        30: ('Called-Station-Id', AVPNV_StrLenField, 64),
        31: ('Calling-Station-Id', AVPNV_StrLenField, 64),
        33: ('Proxy-State', AVPNV_OctetString, 64),
        34: ('Login-LAT-Service', AVPNV_OctetString, 64),
        35: ('Login-LAT-Node', AVPNV_OctetString, 64),
        36: ('Login-LAT-Group', AVPNV_OctetString, 64),
        37: ('Framed-Appletalk-Link', AVPNV_Unsigned32, 64),
        38: ('Framed-Appletalk-Network', AVPNV_Unsigned32, 64),
        39: ('Framed-Appletalk-Zone', AVPNV_OctetString, 64),
        41: ('Acct-Delay-Time', AVPNV_Unsigned32, 64),
        44: ('Acct-Session-Id', AVPNV_OctetString, 64),
        45: ('Acct-Authentic', AVP_0_45, 64),
        46: ('Acct-Session-Time', AVPNV_Unsigned32, 64),
        50: ('Acct-Multi-Session-Id', AVPNV_StrLenField, 64),
        51: ('Acct-Link-Count', AVPNV_Unsigned32, 64),
        55: ('Event-Timestamp', AVPNV_Time, 64),
        60: ('CHAP-Challenge', AVPNV_OctetString, 64),
        61: ('NAS-Port-Type', AVP_0_61, 64),
        62: ('Port-Limit', AVPNV_Unsigned32, 64),
        63: ('Login-LAT-Port', AVPNV_OctetString, 64),
        64: ('Tunnel-Type', AVP_0_64, 64),
        65: ('Tunnel-Medium-Type', AVP_0_65, 64),
        66: ('Tunnel-Client-Endpoint', AVPNV_StrLenField, 64),
        67: ('Tunnel-Server-Endpoint', AVPNV_StrLenField, 64),
        68: ('Acct-Tunnel-Connection', AVPNV_OctetString, 64),
        69: ('Tunnel-Password', AVPNV_OctetString, 64),
        70: ('ARAP-Password', AVPNV_OctetString, 64),
        71: ('ARAP-Features', AVPNV_OctetString, 64),
        72: ('ARAP-Zone-Access', AVP_0_72, 64),
        73: ('ARAP-Security', AVPNV_Unsigned32, 64),
        74: ('ARAP-Security-Data', AVPNV_OctetString, 64),
        75: ('Password-Retry', AVPNV_Unsigned32, 64),
        76: ('Prompt', AVP_0_76, 64),
        77: ('Connect-Info', AVPNV_StrLenField, 64),
        78: ('Configuration-Token', AVPNV_OctetString, 64),
        81: ('Tunnel-Private-Group-Id', AVPNV_OctetString, 64),
        82: ('Tunnel-Assignment-Id', AVPNV_OctetString, 64),
        83: ('Tunnel-Preference', AVPNV_Unsigned32, 64),
        84: ('ARAP-Challenge-Response', AVPNV_OctetString, 64),
        85: ('Acct-Interim-Interval', AVPNV_Unsigned32, 64),
        86: ('Acct-Tunnel-Packets-Lost', AVPNV_Unsigned32, 64),
        87: ('NAS-Port-Id', AVPNV_StrLenField, 64),
        88: ('Framed-Pool', AVPNV_OctetString, 64),
        89: ('Chargeable-User-Identity', AVPNV_OctetString, 64),
        90: ('Tunnel-Client-Auth-Id', AVPNV_StrLenField, 64),
        91: ('Tunnel-Server-Auth-Id', AVPNV_StrLenField, 64),
        94: ('Originating-Line-Info', AVPNV_OctetString, 64),
        96: ('Framed-Interface-Id', AVPNV_Unsigned64, 64),
        97: ('Framed-IPv6-Prefix', AVPNV_OctetString, 64),
        99: ('Framed-IPv6-Route', AVPNV_StrLenField, 64),
        100: ('Framed-IPv6-Pool', AVPNV_OctetString, 64),
        102: ('EAP-Key-Name', AVPNV_OctetString, 64),
        104: ('Digest-Realm', AVPNV_StrLenField, 64),
        110: ('Digest-Qop', AVPNV_StrLenField, 64),
        111: ('Digest-Algorithm', AVPNV_StrLenField, 64),
        121: ('Digest-HA1', AVPNV_OctetString, 64),
        124: ('MIP6-Feature-Vector', AVPNV_Unsigned64, 64),
        125: ('MIP6-Home-Link-Prefix', AVPNV_OctetString, 64),
        257: ('Host-IP-Address', AVPNV_Address, 64),
        258: ('Auth-Application-Id', AVP_0_258, 64),
        259: ('Acct-Application-Id', AVPNV_Unsigned32, 64),
        260: ('Vendor-Specific-Application-Id', AVPNV_Grouped, 64),
        261: ('Redirect-Host-Usage', AVP_0_261, 64),
        262: ('Redirect-Max-Cache-Time', AVPNV_Unsigned32, 64),
        263: ('Session-Id', AVPNV_StrLenField, 64),
        264: ('Origin-Host', AVPNV_StrLenField, 64),
        265: ('Supported-Vendor-Id', AVPNV_Unsigned32, 64),
        266: ('Vendor-Id', AVP_0_266, 64),
        267: ('Firmware-Revision', AVPNV_Unsigned32, 0),
        268: ('Result-Code', AVP_0_268, 64),
        269: ('Product-Name', AVPNV_StrLenField, 0),
        270: ('Session-Binding', AVPNV_Unsigned32, 64),
        271: ('Session-Server-Failover', AVP_0_271, 64),
        272: ('Multi-Round-Time-Out', AVPNV_Unsigned32, 64),
        273: ('Disconnect-Cause', AVP_0_273, 64),
        274: ('Auth-Request-Type', AVP_0_274, 64),
        276: ('Auth-Grace-Period', AVPNV_Unsigned32, 64),
        277: ('Auth-Session-State', AVP_0_277, 64),
        278: ('Origin-State-Id', AVPNV_Unsigned32, 64),
        279: ('Failed-AVP', AVPNV_Grouped, 64),
        280: ('Proxy-Host', AVPNV_StrLenField, 64),
        281: ('Error-Message', AVPNV_StrLenField, 0),
        282: ('Route-Record', AVPNV_StrLenField, 64),
        283: ('Destination-Realm', AVPNV_StrLenField, 64),
        284: ('Proxy-Info', AVPNV_Grouped, 64),
        285: ('Re-Auth-Request-Type', AVP_0_285, 64),
        287: ('Accounting-Sub-Session-Id', AVPNV_Unsigned64, 64),
        291: ('Authorization-Lifetime', AVPNV_Unsigned32, 64),
        292: ('Redirect-Host', AVPNV_StrLenField, 64),
        293: ('Destination-Host', AVPNV_StrLenField, 64),
        294: ('Error-Reporting-Host', AVPNV_StrLenField, 0),
        295: ('Termination-Cause', AVP_0_295, 64),
        296: ('Origin-Realm', AVPNV_StrLenField, 64),
        297: ('Experimental-Result', AVPNV_Grouped, 64),
        298: ('Experimental-Result-Code', AVP_0_298, 64),
        299: ('Inband-Security-Id', AVPNV_Unsigned32, 64),
        318: ('MIP-FA-to-HA-SPI', AVPNV_Unsigned32, 64),
        319: ('MIP-FA-to-MN-SPI', AVPNV_Unsigned32, 64),
        320: ('MIP-Reg-Request', AVPNV_OctetString, 64),
        321: ('MIP-Reg-Reply', AVPNV_OctetString, 64),
        322: ('MIP-MN-AAA-Auth', AVPNV_Grouped, 64),
        323: ('MIP-HA-to-FA-SPI', AVPNV_Unsigned32, 64),
        325: ('MIP-MN-to-FA-MSA', AVPNV_Grouped, 64),
        326: ('MIP-FA-to-MN-MSA', AVPNV_Grouped, 64),
        328: ('MIP-FA-to-HA-MSA', AVPNV_Grouped, 64),
        329: ('MIP-HA-to-FA-MSA', AVPNV_Grouped, 64),
        331: ('MIP-MN-to-HA-MSA', AVPNV_Grouped, 64),
        332: ('MIP-HA-to-MN-MSA', AVPNV_Grouped, 64),
        333: ('MIP-Mobile-Node-Address', AVPNV_Address, 64),
        334: ('MIP-Home-Agent-Address', AVPNV_Address, 64),
        335: ('MIP-Nonce', AVPNV_OctetString, 64),
        336: ('MIP-Candidate-Home-Agent-Host', AVPNV_StrLenField, 64),
        337: ('MIP-Feature-Vector', AVPNV_Unsigned32, 64),
        338: ('MIP-Auth-Input-Data-Length', AVPNV_Unsigned32, 64),
        339: ('MIP-Authenticator-Length', AVPNV_Unsigned32, 64),
        340: ('MIP-Authenticator-Offset', AVPNV_Unsigned32, 64),
        341: ('MIP-MN-AAA-SPI', AVPNV_Unsigned32, 64),
        342: ('MIP-Filter-Rule', AVPNV_IPFilterRule, 64),
        343: ('MIP-Session-Key', AVPNV_OctetString, 64),
        344: ('MIP-FA-Challenge', AVPNV_OctetString, 64),
        345: ('MIP-Algorithm-Type', AVP_0_345, 64),
        346: ('MIP-Replay-Mode', AVP_0_346, 64),
        347: ('MIP-Originating-Foreign-AAA', AVPNV_Grouped, 64),
        348: ('MIP-Home-Agent-Host', AVPNV_StrLenField, 64),
        363: ('Accounting-Input-Octets', AVPNV_Unsigned64, 64),
        364: ('Accounting-Output-Octets', AVPNV_Unsigned64, 64),
        365: ('Accounting-Input-Packets', AVPNV_Unsigned64, 64),
        366: ('Accounting-Output-Packets', AVPNV_Unsigned64, 64),
        367: ('MIP-MSA-Lifetime', AVPNV_Unsigned32, 64),
        368: ('SIP-Accounting-Information', AVPNV_Grouped, 64),
        369: ('SIP-Accounting-Server-URI', AVPNV_StrLenField, 64),
        370: ('SIP-Credit-Control-Server-URI', AVPNV_StrLenField, 64),
        371: ('SIP-Server-URI', AVPNV_StrLenField, 64),
        372: ('SIP-Server-Capabilities', AVPNV_Grouped, 64),
        373: ('SIP-Mandatory-Capability', AVPNV_Unsigned32, 64),
        374: ('SIP-Optional-Capability', AVPNV_Unsigned32, 64),
        375: ('SIP-Server-Assignment-Type', AVP_0_375, 64),
        376: ('SIP-Auth-Data-Item', AVPNV_Grouped, 64),
        377: ('SIP-Authentication-Scheme', AVP_0_377, 64),
        378: ('SIP-Item-Number', AVPNV_Unsigned32, 64),
        379: ('SIP-Authenticate', AVPNV_Grouped, 64),
        380: ('SIP-Authorization', AVPNV_Grouped, 64),
        381: ('SIP-Authentication-Info', AVPNV_Grouped, 64),
        382: ('SIP-Number-Auth-Items', AVPNV_Unsigned32, 64),
        383: ('SIP-Deregistration-Reason', AVPNV_Grouped, 64),
        384: ('SIP-Reason-Code', AVP_0_384, 64),
        385: ('SIP-Reason-Info', AVPNV_StrLenField, 64),
        386: ('SIP-Visited-Network-Id', AVPNV_StrLenField, 64),
        387: ('SIP-User-Authorization-Type', AVP_0_387, 64),
        388: ('SIP-Supported-User-Data-Type', AVPNV_StrLenField, 64),
        389: ('SIP-User-Data', AVPNV_Grouped, 64),
        390: ('SIP-User-Data-Type', AVPNV_StrLenField, 64),
        391: ('SIP-User-Data-Contents', AVPNV_OctetString, 64),
        392: ('SIP-User-Data-Already-Available', AVP_0_392, 64),
        393: ('SIP-Method', AVPNV_StrLenField, 64),
        400: ('NAS-Filter-Rule', AVPNV_IPFilterRule, 64),
        401: ('Tunneling', AVPNV_Grouped, 64),
        402: ('CHAP-Auth', AVPNV_Grouped, 64),
        403: ('CHAP-Algorithm', AVP_0_403, 64),
        404: ('CHAP-Ident', AVPNV_OctetString, 64),
        405: ('CHAP-Response', AVPNV_OctetString, 64),
        406: ('Accounting-Auth-Method', AVP_0_406, 64),
        407: ('QoS-Filter-Rule', AVPNV_QoSFilterRule, 64),
        411: ('CC-Correlation-Id', AVPNV_OctetString, 0),
        412: ('CC-Input-Octets', AVPNV_Unsigned64, 64),
        413: ('CC-Money', AVPNV_Grouped, 64),
        414: ('CC-Output-Octets', AVPNV_Unsigned64, 64),
        415: ('CC-Request-Number', AVPNV_Unsigned32, 64),
        416: ('CC-Request-Type', AVP_0_416, 64),
        417: ('CC-Service-Specific-Units', AVPNV_Unsigned64, 64),
        418: ('CC-Session-Failover', AVP_0_418, 64),
        419: ('CC-Sub-Session-Id', AVPNV_Unsigned64, 64),
        420: ('CC-Time', AVPNV_Unsigned32, 64),
        421: ('CC-Total-Octets', AVPNV_Unsigned64, 64),
        422: ('Check-Balance-Result', AVP_0_422, 64),
        423: ('Cost-Information', AVPNV_Grouped, 64),
        424: ('Cost-Unit', AVPNV_StrLenField, 64),
        425: ('Currency-Code', AVPNV_Unsigned32, 64),
        426: ('Credit-Control', AVP_0_426, 64),
        427: ('Credit-Control-Failure-Handling', AVP_0_427, 64),
        428: ('Direct-Debiting-Failure-Handling', AVP_0_428, 64),
        429: ('Exponent', AVPNV_Integer32, 64),
        430: ('Final-Unit-Indication', AVPNV_Grouped, 64),
        431: ('Granted-Service-Unit', AVPNV_Grouped, 64),
        432: ('Rating-Group', AVPNV_Unsigned32, 64),
        433: ('Redirect-Address-Type', AVP_0_433, 64),
        434: ('Redirect-Server', AVPNV_Grouped, 64),
        435: ('Redirect-Server-Address', AVPNV_StrLenField, 64),
        436: ('Requested-Action', AVP_0_436, 64),
        437: ('Requested-Service-Unit', AVPNV_Grouped, 64),
        438: ('Restriction-Filter-Rule', AVPNV_IPFilterRule, 64),
        439: ('Service-Identifier', AVPNV_Unsigned32, 64),
        440: ('Service-Parameter-Info', AVPNV_Grouped, 0),
        441: ('Service-Parameter-Type', AVPNV_Unsigned32, 0),
        442: ('Service-Parameter-Value', AVPNV_OctetString, 0),
        443: ('Subscription-Id', AVPNV_Grouped, 64),
        444: ('Subscription-Id-Data', AVPNV_StrLenField, 64),
        445: ('Unit-Value', AVPNV_Grouped, 64),
        446: ('Used-Service-Unit', AVPNV_Grouped, 64),
        447: ('Value-Digits', AVPNV_Integer64, 64),
        448: ('Validity-Time', AVPNV_Unsigned32, 64),
        449: ('Final-Unit-Action', AVP_0_449, 64),
        450: ('Subscription-Id-Type', AVP_0_450, 64),
        451: ('Tariff-Time-Change', AVPNV_Time, 64),
        452: ('Tariff-Change-Usage', AVP_0_452, 64),
        453: ('G-S-U-Pool-Identifier', AVPNV_Unsigned32, 64),
        454: ('CC-Unit-Type', AVP_0_454, 64),
        455: ('Multiple-Services-Indicator', AVP_0_455, 64),
        456: ('Multiple-Services-Credit-Control', AVPNV_Grouped, 64),
        457: ('G-S-U-Pool-Reference', AVPNV_Grouped, 64),
        458: ('User-Equipment-Info', AVPNV_Grouped, 0),
        459: ('User-Equipment-Info-Type', AVP_0_459, 0),
        460: ('User-Equipment-Info-Value', AVPNV_OctetString, 0),
        461: ('Service-Context-Id', AVPNV_StrLenField, 64),
        462: ('EAP-Payload', AVPNV_OctetString, 64),
        463: ('EAP-Reissued-Payload', AVPNV_OctetString, 64),
        464: ('EAP-Master-Session-Key', AVPNV_OctetString, 64),
        465: ('Accounting-EAP-Auth-Method', AVPNV_Unsigned64, 64),
        480: ('Accounting-Record-Type', AVP_0_480, 64),
        483: ('Accounting-Realtime-Required', AVP_0_483, 64),
        485: ('Accounting-Record-Number', AVPNV_Unsigned32, 64),
        486: ('MIP6-Agent-Info', AVPNV_Grouped, 64),
        487: ('MIP-Careof-Address', AVPNV_Address, 64),
        488: ('MIP-Authenticator', AVPNV_OctetString, 64),
        489: ('MIP-MAC-Mobility-Data', AVPNV_OctetString, 64),
        490: ('MIP-Timestamp', AVPNV_OctetString, 64),
        491: ('MIP-MN-HA-SPI', AVPNV_Unsigned32, 64),
        492: ('MIP-MN-HA-MSA', AVPNV_Grouped, 64),
        493: ('Service-Selection', AVPNV_StrLenField, 64),
        494: ('MIP6-Auth-Mode', AVP_0_494, 64),
        506: ('Mobile-Node-Identifier', AVPNV_StrLenField, 64),
        508: ('QoS-Resources', AVPNV_Grouped, 64),
        509: ('Filter-Rule', AVPNV_Grouped, 64),
        510: ('Filter-Rule-Precedence', AVPNV_Unsigned32, 64),
        511: ('Classifier', AVPNV_Grouped, 64),
        512: ('Classifier-ID', AVPNV_OctetString, 64),
        513: ('Protocol', AVP_0_513, 64),
        514: ('Direction', AVP_0_514, 64),
        515: ('From-Spec', AVPNV_Grouped, 64),
        516: ('To-Spec', AVPNV_Grouped, 64),
        517: ('Negated', AVP_0_517, 64),
        518: ('IP-Address', AVPNV_Address, 64),
        519: ('IP-Address-Range', AVPNV_Grouped, 64),
        520: ('IP-Address-Start', AVPNV_Address, 64),
        521: ('IP-Address-End', AVPNV_Address, 64),
        522: ('IP-Address-Mask', AVPNV_Grouped, 64),
        523: ('IP-Mask-Bit-Mask-Width', AVPNV_Unsigned32, 64),
        524: ('MAC-Address', AVPNV_OctetString, 64),
        525: ('MAC-Address-Mask', AVPNV_Grouped, 64),
        526: ('MAC-Address-Mask-Pattern', AVPNV_OctetString, 64),
        527: ('EUI64-Address', AVPNV_OctetString, 64),
        528: ('EUI64-Address-Mask', AVPNV_Grouped, 64),
        529: ('EUI64-Address-Mask-Pattern', AVPNV_OctetString, 64),
        530: ('Port', AVPNV_Integer32, 64),
        531: ('Port-Range', AVPNV_Grouped, 64),
        532: ('Port-Start', AVPNV_Integer32, 64),
        533: ('Port-End', AVPNV_Integer32, 64),
        534: ('Use-Assigned-Address', AVP_0_534, 64),
        535: ('Diffserv-Code-Point', AVP_0_535, 64),
        536: ('Fragmentation-Flag', AVP_0_536, 64),
        537: ('IP-Option', AVPNV_Grouped, 64),
        538: ('IP-Option-Type', AVP_0_538, 64),
        539: ('IP-Option-Value', AVPNV_OctetString, 64),
        540: ('TCP-Option', AVPNV_Grouped, 64),
        541: ('TCP-Option-Type', AVP_0_541, 64),
        542: ('TCP-Option-Value', AVPNV_OctetString, 64),
        543: ('TCP-Flags', AVPNV_Grouped, 64),
        544: ('TCP-Flag-Type', AVPNV_Unsigned32, 64),
        545: ('ICMP-Type', AVPNV_Grouped, 64),
        546: ('ICMP-Type-Number', AVP_0_546, 64),
        547: ('ICMP-Code', AVP_0_547, 64),
        548: ('ETH-Option', AVPNV_Grouped, 64),
        549: ('ETH-Proto-Type', AVPNV_Grouped, 64),
        550: ('ETH-Ether-Type', AVPNV_OctetString, 64),
        551: ('ETH-SAP', AVPNV_OctetString, 64),
        552: ('VLAN-ID-Range', AVPNV_Grouped, 64),
        553: ('S-VID-Start', AVPNV_Unsigned32, 64),
        554: ('S-VID-End', AVPNV_Unsigned32, 64),
        555: ('C-VID-Start', AVPNV_Unsigned32, 64),
        556: ('C-VID-End', AVPNV_Unsigned32, 64),
        557: ('User-Priority-Range', AVPNV_Grouped, 64),
        558: ('Low-User-Priority', AVPNV_Unsigned32, 64),
        559: ('High-User-Priority', AVPNV_Unsigned32, 64),
        560: ('Time-Of-Day-Condition', AVPNV_Grouped, 64),
        561: ('Time-Of-Day-Start', AVPNV_Unsigned32, 64),
        562: ('Time-Of-Day-End', AVPNV_Unsigned32, 64),
        563: ('Day-Of-Week-Mask', AVPNV_Unsigned32, 64),
        564: ('Day-Of-Month-Mask', AVPNV_Unsigned32, 64),
        565: ('Month-Of-Year-Mask', AVPNV_Unsigned32, 64),
        566: ('Absolute-Start-Time', AVPNV_Time, 64),
        567: ('Absolute-Start-Fractional-Seconds', AVPNV_Unsigned32, 64),
        568: ('Absolute-End-Time', AVPNV_Time, 64),
        569: ('Absolute-End-Fractional-Seconds', AVPNV_Unsigned32, 64),
        570: ('Timezone-Flag', AVP_0_570, 64),
        571: ('Timezone-Offset', AVPNV_Integer32, 64),
        572: ('Treatment-Action', AVPNV_Grouped, 64),
        573: ('QoS-Profile-Id', AVPNV_Unsigned32, 64),
        574: ('QoS-Profile-Template', AVPNV_Grouped, 64),
        575: ('QoS-Semantics', AVP_0_575, 64),
        576: ('QoS-Parameters', AVPNV_Grouped, 64),
        577: ('Excess-Treatment', AVPNV_Grouped, 64),
        578: ('QoS-Capability', AVPNV_Grouped, 64),
        618: ('ERP-RK-Request', AVPNV_Grouped, 64),
        619: ('ERP-Realm', AVPNV_StrLenField, 64),
    },
    10415: {
        13: ('3GPP-Charging-Characteristics', AVPV_StrLenField, 192),
        318: ('3GPP-AAA-Server-Name', AVPV_StrLenField, 192),
        500: ('Abort-Cause', AVP_10415_500, 192),
        501: ('Access-Network-Charging-Address', AVPV_Address, 192),
        502: ('Access-Network-Charging-Identifier', AVPV_Grouped, 192),
        503: ('Access-Network-Charging-Identifier-Value', AVPV_OctetString, 192),  # noqa: E501
        504: ('AF-Application-Identifier', AVPV_OctetString, 192),
        505: ('AF-Charging-Identifier', AVPV_OctetString, 192),
        506: ('Authorization-Token', AVPV_OctetString, 192),
        507: ('Flow-Description', AVPV_IPFilterRule, 192),
        508: ('Flow-Grouping', AVPV_Grouped, 192),
        509: ('Flow-Number', AVPV_Unsigned32, 192),
        510: ('Flows', AVPV_Grouped, 192),
        511: ('Flow-Status', AVP_10415_511, 192),
        512: ('Flow-Usage', AVP_10415_512, 192),
        513: ('Specific-Action', AVP_10415_513, 192),
        515: ('Max-Requested-Bandwidth-DL', AVPV_Unsigned32, 192),
        516: ('Max-Requested-Bandwidth-UL', AVPV_Unsigned32, 192),
        517: ('Media-Component-Description', AVPV_Grouped, 192),
        518: ('Media-Component-Number', AVPV_Unsigned32, 192),
        519: ('Media-Sub-Component', AVPV_Grouped, 192),
        520: ('Media-Type', AVP_10415_520, 192),
        521: ('RR-Bandwidth', AVPV_Unsigned32, 192),
        522: ('RS-Bandwidth', AVPV_Unsigned32, 192),
        523: ('SIP-Forking-Indication', AVP_10415_523, 192),
        525: ('Service-URN', AVPV_OctetString, 192),
        526: ('Acceptable-Service-Info', AVPV_Grouped, 192),
        527: ('Service-Info-Status', AVP_10415_527, 192),
        528: ('MPS-Identifier', AVPV_OctetString, 128),
        529: ('AF-Signalling-Protocol', AVP_10415_529, 128),
        531: ('Sponsor-Identity', AVPV_StrLenField, 128),
        532: ('Application-Service-Provider-Identity', AVPV_StrLenField, 128),
        533: ('Rx-Request-Type', AVP_10415_533, 128),
        534: ('Min-Requested-Bandwidth-DL', AVPV_Unsigned32, 128),
        535: ('Min-Requested-Bandwidth-UL', AVPV_Unsigned32, 128),
        536: ('Required-Access-Info', AVP_10415_536, 128),
        537: ('IP-Domain-Id', AVPV_OctetString, 128),
        538: ('GCS-Identifier', AVPV_OctetString, 128),
        539: ('Sharing-Key-DL', AVPV_Unsigned32, 128),
        540: ('Sharing-Key-UL', AVPV_Unsigned32, 128),
        541: ('Retry-Interval', AVPV_Unsigned32, 128),
        600: ('Visited-Network-Identifier', AVPV_OctetString, 192),
        601: ('Public-Identity', AVPV_StrLenField, 192),
        602: ('Server-Name', AVPV_StrLenField, 192),
        603: ('Server-Capabilities', AVPV_Grouped, 192),
        604: ('Mandatory-Capability', AVPV_Unsigned32, 192),
        605: ('Optional-Capability', AVPV_Unsigned32, 192),
        606: ('User-Data', AVPV_OctetString, 192),
        607: ('SIP-Number-Auth-Items', AVPV_Unsigned32, 192),
        608: ('SIP-Authentication-Scheme', AVPV_StrLenField, 192),
        609: ('SIP-Authenticate', AVPV_OctetString, 192),
        610: ('SIP-Authorization', AVPV_OctetString, 192),
        611: ('SIP-Authentication-Context', AVPV_OctetString, 192),
        612: ('SIP-Auth-Data-Item', AVPV_Grouped, 192),
        613: ('SIP-Item-Number', AVPV_Unsigned32, 192),
        614: ('Server-Assignment-Type', AVP_10415_614, 192),
        615: ('Deregistration-Reason', AVPV_Grouped, 192),
        616: ('Reason-Code', AVP_10415_616, 192),
        617: ('Reason-Info', AVPV_StrLenField, 192),
        618: ('Charging-Information', AVPV_Grouped, 192),
        619: ('Primary-Event-Charging-Function-Name', AVPV_StrLenField, 192),
        620: ('Secondary-Event-Charging-Function-Name', AVPV_StrLenField, 192),
        621: ('Primary-Charging-Collection-Function-Name', AVPV_StrLenField, 192),  # noqa: E501
        622: ('Secondary-Charging-Collection-Function-Name', AVPV_StrLenField, 192),  # noqa: E501
        623: ('User-Authorization-Type', AVP_10415_623, 192),
        624: ('User-Data-Already-Available', AVP_10415_624, 192),
        625: ('Confidentiality-Key', AVPV_OctetString, 192),
        626: ('Integrity-Key', AVPV_OctetString, 192),
        628: ('Supported-Features', AVPV_Grouped, 128),
        629: ('Feature-List-ID', AVPV_Unsigned32, 128),
        630: ('Feature-List', AVP_10415_630, 128),
        631: ('Supported-Applications', AVPV_Grouped, 128),
        632: ('Associated-Identities', AVPV_Grouped, 128),
        633: ('Originating-Request', AVP_10415_633, 192),
        634: ('Wildcarded-Public-Identity', AVPV_StrLenField, 128),
        635: ('SIP-Digest-Authenticate', AVPV_Grouped, 128),
        636: ('Wildcarded-IMPU', AVPV_StrLenField, 128),
        637: ('UAR-Flags', AVPV_Unsigned32, 128),
        638: ('Loose-Route-Indication', AVP_10415_638, 128),
        639: ('SCSCF-Restoration-Info', AVPV_Grouped, 128),
        640: ('Path', AVPV_OctetString, 128),
        641: ('Contact', AVPV_OctetString, 128),
        642: ('Subscription-Info', AVPV_Grouped, 128),
        643: ('Call-ID-SIP-Header', AVPV_OctetString, 128),
        644: ('From-SIP-Header', AVPV_OctetString, 128),
        645: ('To-SIP-Header', AVPV_OctetString, 128),
        646: ('Record-Route', AVPV_OctetString, 128),
        647: ('Associated-Registered-Identities', AVPV_Grouped, 128),
        648: ('Multiple-Registration-Indication', AVP_10415_648, 128),
        649: ('Restoration-Info', AVPV_Grouped, 128),
        650: ('Session-Priority', AVP_10415_650, 128),
        651: ('Identity-with-Emergency-Registration', AVPV_Grouped, 128),
        652: ('Priviledged-Sender-Indication', AVP_10415_652, 128),
        653: ('LIA-Flags', AVPV_Unsigned32, 128),
        654: ('Initial-CSeq-Sequence-Number', AVPV_Unsigned32, 128),
        655: ('SAR-Flags', AVPV_Unsigned32, 128),
        700: ('User-Identity', AVPV_Grouped, 192),
        701: ('MSISDN', AVP_10415_701, 192),
        702: ('User-Data', AVPV_OctetString, 192),
        703: ('Data-Reference', AVP_10415_703, 192),
        704: ('Service-Indication', AVPV_OctetString, 192),
        705: ('Subs-Req-Type', AVP_10415_705, 192),
        706: ('Requested-Domain', AVP_10415_706, 192),
        707: ('Current-Location', AVP_10415_707, 192),
        708: ('Identity-Set', AVP_10415_708, 128),
        709: ('Expiry-Time', AVPV_Time, 128),
        710: ('Send-Data-Indication', AVP_10415_710, 128),
        711: ('DSAI-Tag', AVPV_OctetString, 192),
        712: ('One-Time-Notification', AVP_10415_712, 128),
        713: ('Requested-Nodes', AVPV_Unsigned32, 128),
        714: ('Serving-Node-Indication', AVP_10415_714, 128),
        715: ('Repository-Data-ID', AVPV_Grouped, 128),
        716: ('Sequence-Number', AVPV_Unsigned32, 128),
        717: ('Pre-paging-Supported', AVP_10415_717, 128),
        718: ('Local-Time-Zone-Indication', AVP_10415_718, 128),
        719: ('UDR-Flags', AVPV_Unsigned32, 128),
        720: ('Call-Reference-Info', AVPV_Grouped, 128),
        721: ('Call-Reference-Number', AVPV_OctetString, 128),
        722: ('AS-Number', AVPV_OctetString, 128),
        823: ('Event-Type', AVPV_Grouped, 192),
        824: ('SIP-Method', AVPV_StrLenField, 192),
        825: ('Event', AVPV_StrLenField, 192),
        826: ('Content-Type', AVPV_StrLenField, 192),
        827: ('Content-Length', AVPV_Unsigned32, 192),
        828: ('Content-Disposition', AVPV_StrLenField, 192),
        829: ('Role-Of-Node', AVP_10415_829, 192),
        830: ('Session-Id', AVPV_StrLenField, 192),
        831: ('Calling-Party-Address', AVPV_StrLenField, 192),
        832: ('Called-Party-Address', AVPV_StrLenField, 192),
        833: ('Time-Stamps', AVPV_Grouped, 192),
        834: ('SIP-Request-Timestamp', AVPV_Time, 192),
        835: ('SIP-Response-Timestamp', AVPV_Time, 192),
        836: ('Application-Server', AVPV_StrLenField, 192),
        837: ('Application-provided-called-party-address', AVPV_StrLenField, 192),  # noqa: E501
        838: ('Inter-Operator-Identifier', AVPV_Grouped, 192),
        839: ('Originating-IOI', AVPV_StrLenField, 192),
        840: ('Terminating-IOI', AVPV_StrLenField, 192),
        841: ('IMS-Charging-Identifier', AVPV_StrLenField, 192),
        842: ('SDP-Session-Description', AVPV_StrLenField, 192),
        843: ('SDP-Media-Component', AVPV_Grouped, 192),
        844: ('SDP-Media-Name', AVPV_StrLenField, 192),
        845: ('SDP-Media-Description', AVPV_StrLenField, 192),
        846: ('CG-Address', AVPV_Address, 192),
        847: ('GGSN-Address', AVPV_Address, 192),
        848: ('Served-Party-IP-Address', AVPV_Address, 192),
        849: ('Authorised-QoS', AVPV_StrLenField, 192),
        850: ('Application-Server-Information', AVPV_Grouped, 192),
        851: ('Trunk-Group-Id', AVPV_Grouped, 192),
        852: ('Incoming-Trunk-Group-Id', AVPV_StrLenField, 192),
        853: ('Outgoing-Trunk-Group-Id', AVPV_StrLenField, 192),
        854: ('Bearer-Service', AVPV_OctetString, 192),
        855: ('Service-Id', AVPV_StrLenField, 192),
        856: ('Associated-URI', AVPV_StrLenField, 192),
        857: ('Charged-Party', AVPV_StrLenField, 192),
        858: ('PoC-Controlling-Address', AVPV_StrLenField, 192),
        859: ('PoC-Group-Name', AVPV_StrLenField, 192),
        861: ('Cause-Code', AVPV_Integer32, 192),
        862: ('Node-Functionality', AVP_10415_862, 192),
        864: ('Originator', AVP_10415_864, 192),
        865: ('PS-Furnish-Charging-Information', AVPV_Grouped, 192),
        866: ('PS-Free-Format-Data', AVPV_OctetString, 192),
        867: ('PS-Append-Free-Format-Data', AVP_10415_867, 192),
        868: ('Time-Quota-Threshold', AVPV_Unsigned32, 192),
        869: ('Volume-Quota-Threshold', AVPV_Unsigned32, 192),
        870: ('Trigger-Type', AVP_10415_870, 192),
        871: ('Quota-Holding-Time', AVPV_Unsigned32, 192),
        872: ('Reporting-Reason', AVP_10415_872, 192),
        873: ('Service-Information', AVPV_Grouped, 192),
        874: ('PS-Information', AVPV_Grouped, 192),
        876: ('IMS-Information', AVPV_Grouped, 192),
        877: ('MMS-Information', AVPV_Grouped, 192),
        878: ('LCS-Information', AVPV_Grouped, 192),
        879: ('PoC-Information', AVPV_Grouped, 192),
        880: ('MBMS-Information', AVPV_Grouped, 192),
        881: ('Quota-Consumption-Time', AVPV_Unsigned32, 192),
        882: ('Media-Initiator-Flag', AVP_10415_882, 192),
        883: ('PoC-Server-Role', AVP_10415_883, 192),
        884: ('PoC-Session-Type', AVP_10415_884, 192),
        885: ('Number-Of-Participants', AVPV_Unsigned32, 192),
        887: ('Participants-Involved', AVPV_StrLenField, 192),
        888: ('Expires', AVPV_Unsigned32, 192),
        889: ('Message-Body', AVPV_Grouped, 192),
        897: ('Address-Data', AVPV_StrLenField, 192),
        898: ('Address-Domain', AVPV_Grouped, 192),
        899: ('Address-Type', AVP_10415_899, 192),
        900: ('TMGI', AVPV_OctetString, 192),
        901: ('Required-MBMS-Bearer-Capabilities', AVPV_StrLenField, 192),
        902: ('MBMS-StartStop-Indication', AVP_10415_902, 192),
        903: ('MBMS-Service-Area', AVPV_OctetString, 192),
        904: ('MBMS-Session-Duration', AVPV_OctetString, 192),
        905: ('Alternative-APN', AVPV_StrLenField, 192),
        906: ('MBMS-Service-Type', AVP_10415_906, 192),
        907: ('MBMS-2G-3G-Indicator', AVP_10415_907, 192),
        909: ('RAI', AVPV_StrLenField, 192),
        910: ('Additional-MBMS-Trace-Info', AVPV_OctetString, 192),
        911: ('MBMS-Time-To-Data-Transfer', AVPV_OctetString, 192),
        920: ('MBMS-Flow-Identifier', AVPV_OctetString, 192),
        921: ('CN-IP-Multicast-Distribution', AVP_10415_921, 192),
        922: ('MBMS-HC-Indicator', AVP_10415_922, 192),
        1000: ('Bearer-Usage', AVP_10415_1000, 192),
        1001: ('Charging-Rule-Install', AVPV_Grouped, 192),
        1002: ('Charging-Rule-Remove', AVPV_Grouped, 192),
        1003: ('Charging-Rule-Definition', AVPV_Grouped, 192),
        1004: ('Charging-Rule-Base-Name', AVPV_StrLenField, 192),
        1005: ('Charging-Rule-Name', AVPV_OctetString, 192),
        1006: ('Event-Trigger', AVP_10415_1006, 192),
        1007: ('Metering-Method', AVP_10415_1007, 192),
        1008: ('Offline', AVP_10415_1008, 192),
        1009: ('Online', AVP_10415_1009, 192),
        1010: ('Precedence', AVPV_Unsigned32, 192),
        1011: ('Reporting-Level', AVP_10415_1011, 192),
        1012: ('TFT-Filter', AVPV_IPFilterRule, 192),
        1013: ('TFT-Packet-Filter-Information', AVPV_Grouped, 192),
        1014: ('ToS-Traffic-Class', AVPV_OctetString, 192),
        1015: ('PDP-Session-Operation', AVP_10415_1015, 192),
        1018: ('Charging-Rule-Report', AVPV_Grouped, 192),
        1019: ('PCC-Rule-Status', AVP_10415_1019, 192),
        1020: ('Bearer-Identifier', AVPV_OctetString, 192),
        1021: ('Bearer-Operation', AVP_10415_1021, 192),
        1022: ('Access-Network-Charging-Identifier-Gx', AVPV_Grouped, 192),
        1023: ('Bearer-Control-Mode', AVP_10415_1023, 192),
        1024: ('Network-Request-Support', AVP_10415_1024, 192),
        1025: ('Guaranteed-Bitrate-DL', AVPV_Unsigned32, 192),
        1026: ('Guaranteed-Bitrate-UL', AVPV_Unsigned32, 192),
        1027: ('IP-CAN-Type', AVP_10415_1027, 192),
        1028: ('QoS-Class-Identifier', AVP_10415_1028, 192),
        1032: ('RAT-Type', AVP_10415_1032, 128),
        1033: ('Event-Report-Indication', AVPV_Grouped, 128),
        1034: ('Allocation-Retention-Priority', AVPV_Grouped, 128),
        1035: ('CoA-IP-Address', AVPV_Address, 128),
        1036: ('Tunnel-Header-Filter', AVPV_IPFilterRule, 128),
        1037: ('Tunnel-Header-Length', AVPV_Unsigned32, 128),
        1038: ('Tunnel-Information', AVPV_Grouped, 128),
        1039: ('CoA-Information', AVPV_Grouped, 128),
        1040: ('APN-Aggregate-Max-Bitrate-DL', AVPV_Unsigned32, 128),
        1041: ('APN-Aggregate-Max-Bitrate-UL', AVPV_Unsigned32, 128),
        1042: ('Revalidation-Time', AVPV_Time, 192),
        1043: ('Rule-Activation-Time', AVPV_Time, 192),
        1044: ('Rule-Deactivation-Time', AVPV_Time, 192),
        1045: ('Session-Release-Cause', AVP_10415_1045, 192),
        1046: ('Priority-Level', AVPV_Unsigned32, 128),
        1047: ('Pre-emption-Capability', AVP_10415_1047, 128),
        1048: ('Pre-emption-Vulnerability', AVP_10415_1048, 128),
        1049: ('Default-EPS-Bearer-QoS', AVPV_Grouped, 128),
        1050: ('AN-GW-Address', AVPV_Address, 128),
        1056: ('Security-Parameter-Index', AVPV_OctetString, 128),
        1057: ('Flow-Label', AVPV_OctetString, 128),
        1058: ('Flow-Information', AVPV_Grouped, 128),
        1059: ('Packet-Filter-Content', AVPV_IPFilterRule, 128),
        1060: ('Packet-Filter-Identifier', AVPV_OctetString, 128),
        1061: ('Packet-Filter-Information', AVPV_Grouped, 128),
        1062: ('Packet-Filter-Operation', AVP_10415_1062, 128),
        1063: ('Resource-Allocation-Notification', AVP_10415_1063, 128),
        1065: ('PDN-Connection-ID', AVPV_OctetString, 128),
        1066: ('Monitoring-Key', AVPV_OctetString, 128),
        1067: ('Usage-Monitoring-Information', AVPV_Grouped, 128),
        1068: ('Usage-Monitoring-Level', AVP_10415_1068, 128),
        1069: ('Usage-Monitoring-Report', AVP_10415_1069, 128),
        1070: ('Usage-Monitoring-Support', AVP_10415_1070, 128),
        1071: ('CSG-Information-Reporting', AVP_10415_1071, 128),
        1072: ('Packet-Filter-Usage', AVP_10415_1072, 128),
        1073: ('Charging-Correlation-Indicator', AVP_10415_1073, 128),
        1075: ('Routing-Rule-Remove', AVPV_Grouped, 128),
        1076: ('Routing-Rule-Definition', AVPV_Grouped, 128),
        1077: ('Routing-Rule-Identifier', AVPV_OctetString, 128),
        1078: ('Routing-Filter', AVPV_Grouped, 128),
        1079: ('Routing-IP-Address', AVPV_Address, 128),
        1080: ('Flow-Direction', AVP_10415_1080, 128),
        1082: ('Credit-Management-Status', AVPV_Unsigned32, 128),
        1085: ('Redirect-Information', AVPV_Grouped, 128),
        1086: ('Redirect-Support', AVP_10415_1086, 128),
        1087: ('TDF-Information', AVPV_Grouped, 128),
        1088: ('TDF-Application-Identifier', AVPV_OctetString, 128),
        1089: ('TDF-Destination-Host', AVPV_StrLenField, 128),
        1090: ('TDF-Destination-Realm', AVPV_StrLenField, 128),
        1091: ('TDF-IP-Address', AVPV_Address, 128),
        1098: ('Application-Detection-Information', AVPV_Grouped, 128),
        1099: ('PS-to-CS-Session-Continuity', AVP_10415_1099, 128),
        1200: ('Domain-Name', AVPV_StrLenField, 192),
        1203: ('MM-Content-Type', AVPV_Grouped, 192),
        1204: ('Type-Number', AVP_10415_1204, 192),
        1205: ('Additional-Type-Information', AVPV_StrLenField, 192),
        1206: ('Content-Size', AVPV_Unsigned32, 192),
        1207: ('Additional-Content-Information', AVPV_Grouped, 192),
        1208: ('Addressee-Type', AVP_10415_1208, 192),
        1209: ('Priority', AVP_10415_1209, 192),
        1211: ('Message-Type', AVP_10415_1211, 192),
        1212: ('Message-Size', AVPV_Unsigned32, 192),
        1213: ('Message-Class', AVPV_Grouped, 192),
        1214: ('Class-Identifier', AVP_10415_1214, 192),
        1215: ('Token-Text', AVPV_StrLenField, 192),
        1216: ('Delivery-Report-Requested', AVP_10415_1216, 192),
        1217: ('Adaptations', AVP_10415_1217, 192),
        1218: ('Applic-ID', AVPV_StrLenField, 192),
        1219: ('Aux-Applic-Info', AVPV_StrLenField, 192),
        1220: ('Content-Class', AVP_10415_1220, 192),
        1221: ('DRM-Content', AVP_10415_1221, 192),
        1222: ('Read-Reply-Report-Requested', AVP_10415_1222, 192),
        1223: ('Reply-Applic-ID', AVPV_StrLenField, 192),
        1224: ('File-Repair-Supported', AVP_10415_1224, 192),
        1225: ('MBMS-User-Service-Type', AVP_10415_1225, 192),
        1226: ('Unit-Quota-Threshold', AVPV_Unsigned32, 192),
        1227: ('PDP-Address', AVPV_Address, 192),
        1228: ('SGSN-Address', AVPV_Address, 192),
        1229: ('PoC-Session-Id', AVPV_StrLenField, 192),
        1230: ('Deferred-Location-Event-Type', AVPV_StrLenField, 192),
        1231: ('LCS-APN', AVPV_StrLenField, 192),
        1245: ('Positioning-Data', AVPV_StrLenField, 192),
        1247: ('PDP-Context-Type', AVP_10415_1247, 192),
        1248: ('MMBox-Storage-Requested', AVP_10415_1248, 192),
        1250: ('Called-Asserted-Identity', AVPV_StrLenField, 192),
        1251: ('Requested-Party-Address', AVPV_StrLenField, 192),
        1252: ('PoC-User-Role', AVPV_Grouped, 192),
        1253: ('PoC-User-Role-IDs', AVPV_StrLenField, 192),
        1254: ('PoC-User-Role-info-Units', AVP_10415_1254, 192),
        1255: ('Talk-Burst-Exchange', AVPV_Grouped, 192),
        1258: ('Event-Charging-TimeStamp', AVPV_Time, 192),
        1259: ('Participant-Access-Priority', AVP_10415_1259, 192),
        1260: ('Participant-Group', AVPV_Grouped, 192),
        1261: ('PoC-Change-Condition', AVP_10415_1261, 192),
        1262: ('PoC-Change-Time', AVPV_Time, 192),
        1263: ('Access-Network-Information', AVPV_OctetString, 192),
        1264: ('Trigger', AVPV_Grouped, 192),
        1265: ('Base-Time-Interval', AVPV_Unsigned32, 192),
        1266: ('Envelope', AVPV_Grouped, 192),
        1267: ('Envelope-End-Time', AVPV_Time, 192),
        1268: ('Envelope-Reporting', AVP_10415_1268, 192),
        1269: ('Envelope-Start-Time', AVPV_Time, 192),
        1270: ('Time-Quota-Mechanism', AVPV_Grouped, 192),
        1271: ('Time-Quota-Type', AVP_10415_1271, 192),
        1272: ('Early-Media-Description', AVPV_Grouped, 192),
        1273: ('SDP-TimeStamps', AVPV_Grouped, 192),
        1274: ('SDP-Offer-Timestamp', AVPV_Time, 192),
        1275: ('SDP-Answer-Timestamp', AVPV_Time, 192),
        1276: ('AF-Correlation-Information', AVPV_Grouped, 192),
        1277: ('PoC-Session-Initiation-Type', AVP_10415_1277, 192),
        1278: ('Offline-Charging', AVPV_Grouped, 192),
        1279: ('User-Participating-Type', AVP_10415_1279, 192),
        1281: ('IMS-Communication-Service-Identifier', AVPV_StrLenField, 192),
        1282: ('Number-Of-Received-Talk-Bursts', AVPV_Unsigned32, 192),
        1283: ('Number-Of-Talk-Bursts', AVPV_Unsigned32, 192),
        1284: ('Received-Talk-Burst-Time', AVPV_Unsigned32, 192),
        1285: ('Received-Talk-Burst-Volume', AVPV_Unsigned32, 192),
        1286: ('Talk-Burst-Time', AVPV_Unsigned32, 192),
        1287: ('Talk-Burst-Volume', AVPV_Unsigned32, 192),
        1288: ('Media-Initiator-Party', AVPV_StrLenField, 192),
        1400: ('Subscription-Data', AVPV_Grouped, 192),
        1401: ('Terminal-Information', AVPV_Grouped, 192),
        1402: ('IMEI', AVPV_StrLenField, 192),
        1403: ('Software-Version', AVPV_StrLenField, 192),
        1404: ('QoS-Subscribed', AVPV_OctetString, 192),
        1405: ('ULR-Flags', AVPV_Unsigned32, 192),
        1406: ('ULA-Flags', AVPV_Unsigned32, 192),
        1407: ('Visited-PLMN-Id', AVPV_OctetString, 192),
        1408: ('Requested-EUTRAN-Authentication-Info', AVPV_Grouped, 192),
        1409: ('GERAN-Authentication-Info', AVPV_Grouped, 192),
        1410: ('Number-Of-Requested-Vectors', AVPV_Unsigned32, 192),
        1411: ('Re-Synchronization-Info', AVPV_OctetString, 192),
        1412: ('Immediate-Response-Preferred', AVPV_Unsigned32, 192),
        1413: ('Authentication-Info', AVPV_Grouped, 192),
        1414: ('E-UTRAN-Vector', AVPV_Grouped, 192),
        1415: ('UTRAN-Vector', AVPV_Grouped, 192),
        1416: ('GERAN-Vector', AVPV_Grouped, 192),
        1417: ('Network-Access-Mode', AVP_10415_1417, 192),
        1418: ('HPLMN-ODB', AVPV_Unsigned32, 192),
        1419: ('Item-Number', AVPV_Unsigned32, 192),
        1420: ('Cancellation-Type', AVP_10415_1420, 192),
        1421: ('DSR-Flags', AVPV_Unsigned32, 192),
        1422: ('DSA-Flags', AVPV_Unsigned32, 192),
        1423: ('Context-Identifier', AVPV_Unsigned32, 192),
        1424: ('Subscriber-Status', AVP_10415_1424, 192),
        1425: ('Operator-Determined-Barring', AVPV_Unsigned32, 192),
        1426: ('Access-Restriction-Data', AVPV_Unsigned32, 192),
        1427: ('APN-OI-Replacement', AVPV_StrLenField, 192),
        1428: ('All-APN-Configurations-Included-Indicator', AVP_10415_1428, 192),  # noqa: E501
        1429: ('APN-Configuration-Profile', AVPV_Grouped, 192),
        1430: ('APN-Configuration', AVPV_Grouped, 192),
        1431: ('EPS-Subscribed-QoS-Profile', AVPV_Grouped, 192),
        1432: ('VPLMN-Dynamic-Address-Allowed', AVP_10415_1432, 192),
        1433: ('STN-SR', AVPV_OctetString, 192),
        1434: ('Alert-Reason', AVP_10415_1434, 192),
        1435: ('AMBR', AVPV_Grouped, 192),
        1437: ('CSG-Id', AVPV_Unsigned32, 192),
        1438: ('PDN-GW-Allocation-Type', AVP_10415_1438, 192),
        1439: ('Expiration-Date', AVPV_Time, 192),
        1440: ('RAT-Frequency-Selection-Priority-ID', AVPV_Unsigned32, 192),
        1441: ('IDA-Flags', AVPV_Unsigned32, 192),
        1442: ('PUA-Flags', AVPV_Unsigned32, 192),
        1443: ('NOR-Flags', AVPV_Unsigned32, 192),
        1444: ('User-Id', AVPV_StrLenField, 128),
        1445: ('Equipment-Status', AVP_10415_1445, 192),
        1446: ('Regional-Subscription-Zone-Code', AVPV_OctetString, 192),
        1447: ('RAND', AVPV_OctetString, 192),
        1448: ('XRES', AVPV_OctetString, 192),
        1449: ('AUTN', AVPV_OctetString, 192),
        1450: ('KASME', AVPV_OctetString, 192),
        1452: ('Trace-Collection-Entity', AVPV_Address, 192),
        1453: ('Kc', AVPV_OctetString, 192),
        1454: ('SRES', AVPV_OctetString, 192),
        1456: ('PDN-Type', AVP_10415_1456, 192),
        1457: ('Roaming-Restricted-Due-To-Unsupported-Feature', AVP_10415_1457, 192),  # noqa: E501
        1458: ('Trace-Data', AVPV_Grouped, 192),
        1459: ('Trace-Reference', AVPV_OctetString, 192),
        1462: ('Trace-Depth', AVP_10415_1462, 192),
        1463: ('Trace-NE-Type-List', AVPV_OctetString, 192),
        1464: ('Trace-Interface-List', AVPV_OctetString, 192),
        1465: ('Trace-Event-List', AVPV_OctetString, 192),
        1466: ('OMC-Id', AVPV_OctetString, 192),
        1467: ('GPRS-Subscription-Data', AVPV_Grouped, 192),
        1468: ('Complete-Data-List-Included-Indicator', AVP_10415_1468, 192),
        1469: ('PDP-Context', AVPV_Grouped, 192),
        1470: ('PDP-Type', AVPV_OctetString, 192),
        1471: ('3GPP2-MEID', AVPV_OctetString, 192),
        1472: ('Specific-APN-Info', AVPV_Grouped, 192),
        1473: ('LCS-Info', AVPV_Grouped, 192),
        1474: ('GMLC-Number', AVPV_OctetString, 192),
        1475: ('LCS-PrivacyException', AVPV_Grouped, 192),
        1476: ('SS-Code', AVPV_OctetString, 192),
        1477: ('SS-Status', AVPV_OctetString, 192),
        1478: ('Notification-To-UE-User', AVP_10415_1478, 192),
        1479: ('External-Client', AVPV_Grouped, 192),
        1480: ('Client-Identity', AVPV_OctetString, 192),
        1481: ('GMLC-Restriction', AVP_10415_1481, 192),
        1482: ('PLMN-Client', AVP_10415_1482, 192),
        1483: ('Service-Type', AVPV_Grouped, 192),
        1484: ('ServiceTypeIdentity', AVPV_Unsigned32, 192),
        1485: ('MO-LR', AVPV_Grouped, 192),
        1486: ('Teleservice-List', AVPV_Grouped, 192),
        1487: ('TS-Code', AVPV_OctetString, 192),
        1488: ('Call-Barring-Info', AVPV_Grouped, 192),
        1489: ('SGSN-Number', AVPV_OctetString, 192),
        1490: ('IDR-Flags', AVPV_Unsigned32, 192),
        1491: ('ICS-Indicator', AVP_10415_1491, 128),
        1492: ('IMS-Voice-Over-PS-Sessions-Supported', AVP_10415_1492, 128),
        1493: ('Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions', AVP_10415_1493, 128),  # noqa: E501
        1494: ('Last-UE-Activity-Time', AVPV_Time, 128),
        1495: ('EPS-User-State', AVPV_Grouped, 128),
        1496: ('EPS-Location-Information', AVPV_Grouped, 128),
        1497: ('MME-User-State', AVPV_Grouped, 128),
        1498: ('SGSN-User-State', AVPV_Grouped, 128),
        1499: ('User-State', AVP_10415_1499, 128),
        1500: ('Non-3GPP-User-Data', AVPV_Grouped, 192),
        1501: ('Non-3GPP-IP-Access', AVP_10415_1501, 192),
        1502: ('Non-3GPP-IP-Access-APN', AVP_10415_1502, 192),
        1503: ('AN-Trusted', AVP_10415_1503, 192),
        1504: ('ANID', AVPV_StrLenField, 192),
        1505: ('Trace-Info', AVPV_Grouped, 128),
        1506: ('MIP-FA-RK', AVPV_OctetString, 192),
        1507: ('MIP-FA-RK-SPI', AVPV_Unsigned32, 192),
        1508: ('PPR-Flags', AVPV_Unsigned32, 128),
        1509: ('WLAN-Identifier', AVPV_Grouped, 128),
        1510: ('TWAN-Access-Info', AVPV_Grouped, 128),
        1511: ('Access-Authorization-Flags', AVPV_Unsigned32, 128),
        1512: ('TWAN-Default-APN-Context-Id', AVPV_Unsigned32, 128),
        1515: ('Trust-Relationship-Update', AVP_10415_1515, 128),
        1516: ('Full-Network-Name', AVPV_OctetString, 128),
        1517: ('Short-Network-Name', AVPV_OctetString, 128),
        1518: ('AAA-Failure-Indication', AVPV_Unsigned32, 128),
        1519: ('Transport-Access-Type', AVP_10415_1519, 128),
        1520: ('DER-Flags', AVPV_Unsigned32, 128),
        1521: ('DEA-Flags', AVPV_Unsigned32, 128),
        1522: ('RAR-Flags', AVPV_Unsigned32, 128),
        1523: ('DER-S6b-Flags', AVPV_Unsigned32, 128),
        1524: ('SSID', AVPV_StrLenField, 128),
        1525: ('HESSID', AVPV_StrLenField, 128),
        1526: ('Access-Network-Info', AVPV_Grouped, 128),
        1527: ('TWAN-Connection-Mode', AVPV_Unsigned32, 128),
        1528: ('TWAN-Connectivity-Parameters', AVPV_Grouped, 128),
        1529: ('Connectivity-Flags', AVPV_Unsigned32, 128),
        1530: ('TWAN-PCO', AVPV_OctetString, 128),
        1531: ('TWAG-CP-Address', AVPV_Address, 128),
        1532: ('TWAG-UP-Address', AVPV_StrLenField, 128),
        1533: ('TWAN-S2a-Failure-Cause', AVPV_Unsigned32, 128),
        1534: ('SM-Back-Off-Timer', AVPV_Unsigned32, 128),
        1535: ('WLCP-Key', AVPV_OctetString, 128),
        1600: ('Information', AVPV_Grouped, 128),
        1601: ('SGSN-Location-Information', AVPV_Grouped, 128),
        1602: ('E-UTRAN-Cell-Global-Identity', AVPV_OctetString, 128),
        1603: ('Tracking-Area-Identity', AVPV_OctetString, 128),
        1604: ('Cell-Global-Identity', AVPV_OctetString, 128),
        1605: ('Routing-Area-Identity', AVPV_OctetString, 128),
        1606: ('Location-Area-Identity', AVPV_OctetString, 128),
        1607: ('Service-Area-Identity', AVPV_OctetString, 128),
        1608: ('Geographical-Information', AVPV_OctetString, 128),
        1609: ('Geodetic-Information', AVPV_OctetString, 128),
        1610: ('Current-Location-Retrieved', AVP_10415_1610, 128),
        1611: ('Age-Of-Location-Information', AVPV_Unsigned32, 128),
        1612: ('Active-APN', AVPV_Grouped, 128),
        1613: ('SIPTO-Permission', AVP_10415_1613, 128),
        1614: ('Error-Diagnostic', AVP_10415_1614, 128),
        1615: ('UE-SRVCC-Capability', AVP_10415_1615, 128),
        1616: ('MPS-Priority', AVPV_Unsigned32, 128),
        1617: ('VPLMN-LIPA-Allowed', AVP_10415_1617, 128),
        1618: ('LIPA-Permission', AVP_10415_1618, 128),
        1619: ('Subscribed-Periodic-RAU-TAU-Timer', AVPV_Unsigned32, 128),
        1621: ('Ext-PDP-Address', AVPV_Address, 128),
        1622: ('MDT-Configuration', AVPV_Grouped, 128),
        1623: ('Job-Type', AVP_10415_1623, 128),
        1624: ('Area-Scope', AVPV_Grouped, 128),
        1625: ('List-Of-Measurements', AVPV_Unsigned32, 128),
        1626: ('Reporting-Trigger', AVPV_Unsigned32, 128),
        1627: ('Report-Interval', AVP_10415_1627, 128),
        1628: ('Report-Amount', AVP_10415_1628, 128),
        1629: ('Event-Threshold-RSRP', AVPV_Unsigned32, 128),
        1631: ('Logging-Interval', AVP_10415_1631, 128),
        1632: ('Logging-Duration', AVP_10415_1632, 128),
        1633: ('Relay-Node-Indicator', AVP_10415_1633, 128),
        1634: ('MDT-User-Consent', AVP_10415_1634, 128),
        1635: ('PUR-Flags', AVPV_Unsigned32, 128),
        1636: ('Subscribed-VSRVCC', AVP_10415_1636, 128),
        1638: ('CLR-Flags', AVPV_Unsigned32, 128),
        1639: ('UVR-Flags', AVPV_Unsigned32, 192),
        1640: ('UVA-Flags', AVPV_Unsigned32, 192),
        1641: ('VPLMN-CSG-Subscription-Data', AVPV_Grouped, 192),
        1642: ('Time-Zone', AVPV_StrLenField, 128),
        1643: ('A-MSISDN', AVP_10415_1643, 128),
        1645: ('MME-Number-for-MT-SMS', AVPV_OctetString, 128),
        1648: ('SMS-Register-Request', AVP_10415_1648, 128),
        1649: ('Local-Time-Zone', AVPV_Grouped, 128),
        1650: ('Daylight-Saving-Time', AVP_10415_1650, 128),
        1654: ('Subscription-Data-Flags', AVPV_Unsigned32, 128),
        1659: ('Positioning-Method', AVPV_OctetString, 128),
        1660: ('Measurement-Quantity', AVPV_OctetString, 128),
        1661: ('Event-Threshold-Event-1F', AVPV_Integer32, 128),
        1662: ('Event-Threshold-Event-1I', AVPV_Integer32, 128),
        1663: ('Restoration-Priority', AVPV_Unsigned32, 128),
        1664: ('SGs-MME-Identity', AVPV_StrLenField, 128),
        1665: ('SIPTO-Local-Network-Permission', AVPV_Unsigned32, 128),
        1666: ('Coupled-Node-Diameter-ID', AVPV_StrLenField, 128),
        1667: ('WLAN-offloadability', AVPV_Grouped, 128),
        1668: ('WLAN-offloadability-EUTRAN', AVPV_Unsigned32, 128),
        1669: ('WLAN-offloadability-UTRAN', AVPV_Unsigned32, 128),
        1670: ('Reset-ID', AVPV_OctetString, 128),
        1671: ('MDT-Allowed-PLMN-Id', AVPV_OctetString, 128),
        2000: ('SMS-Information', AVPV_Grouped, 192),
        2001: ('Data-Coding-Scheme', AVPV_Integer32, 192),
        2002: ('Destination-Interface', AVPV_Grouped, 192),
        2003: ('Interface-Id', AVPV_StrLenField, 192),
        2004: ('Interface-Port', AVPV_StrLenField, 192),
        2005: ('Interface-Text', AVPV_StrLenField, 192),
        2006: ('Interface-Type', AVP_10415_2006, 192),
        2007: ('SM-Message-Type', AVP_10415_2007, 192),
        2008: ('Originator-SCCP-Address', AVPV_Address, 192),
        2009: ('Originator-Interface', AVPV_Grouped, 192),
        2010: ('Recipient-SCCP-Address', AVPV_Address, 192),
        2011: ('Reply-Path-Requested', AVP_10415_2011, 192),
        2012: ('SM-Discharge-Time', AVPV_Time, 192),
        2013: ('SM-Protocol-ID', AVPV_OctetString, 192),
        2015: ('SM-User-Data-Header', AVPV_OctetString, 192),
        2016: ('SMS-Node', AVP_10415_2016, 192),
        2018: ('Client-Address', AVPV_Address, 192),
        2019: ('Number-Of-Messages-Sent', AVPV_Unsigned32, 192),
        2021: ('Remaining-Balance', AVPV_Grouped, 192),
        2022: ('Refund-Information', AVPV_OctetString, 192),
        2023: ('Carrier-Select-Routing-Information', AVPV_StrLenField, 192),
        2024: ('Number-Portability-Routing-Information', AVPV_StrLenField, 192),  # noqa: E501
        2025: ('PoC-Event-Type', AVP_10415_2025, 192),
        2026: ('Recipient-Info', AVPV_Grouped, 192),
        2027: ('Originator-Received-Address', AVPV_Grouped, 192),
        2028: ('Recipient-Received-Address', AVPV_Grouped, 192),
        2029: ('SM-Service-Type', AVP_10415_2029, 192),
        2030: ('MMTel-Information', AVPV_Grouped, 192),
        2031: ('MMTel-SService-Type', AVPV_Unsigned32, 192),
        2032: ('Service-Mode', AVPV_Unsigned32, 192),
        2033: ('Subscriber-Role', AVP_10415_2033, 192),
        2034: ('Number-Of-Diversions', AVPV_Unsigned32, 192),
        2035: ('Associated-Party-Address', AVPV_StrLenField, 192),
        2036: ('SDP-Type', AVP_10415_2036, 192),
        2037: ('Change-Condition', AVPV_Integer32, 192),
        2038: ('Change-Time', AVPV_Time, 192),
        2039: ('Diagnostics', AVPV_Integer32, 192),
        2040: ('Service-Data-Container', AVPV_Grouped, 192),
        2041: ('Start-Time', AVPV_Time, 192),
        2042: ('Stop-Time', AVPV_Time, 192),
        2043: ('Time-First-Usage', AVPV_Time, 192),
        2044: ('Time-Last-Usage', AVPV_Time, 192),
        2045: ('Time-Usage', AVPV_Unsigned32, 192),
        2046: ('Traffic-Data-Volumes', AVPV_Grouped, 192),
        2047: ('Serving-Node-Type', AVP_10415_2047, 192),
        2048: ('Supplementary-Service', AVPV_Grouped, 192),
        2049: ('Participant-Action-Type', AVP_10415_2049, 192),
        2050: ('PDN-Connection-Charging-ID', AVPV_Unsigned32, 192),
        2051: ('Dynamic-Address-Flag', AVP_10415_2051, 192),
        2052: ('Accumulated-Cost', AVPV_Grouped, 192),
        2053: ('AoC-Cost-Information', AVPV_Grouped, 192),
        2056: ('Current-Tariff', AVPV_Grouped, 192),
        2058: ('Rate-Element', AVPV_Grouped, 192),
        2059: ('Scale-Factor', AVPV_Grouped, 192),
        2060: ('Tariff-Information', AVPV_Grouped, 192),
        2061: ('Unit-Cost', AVPV_Grouped, 192),
        2062: ('Incremental-Cost', AVPV_Grouped, 192),
        2063: ('Local-Sequence-Number', AVPV_Unsigned32, 192),
        2064: ('Node-Id', AVPV_StrLenField, 192),
        2065: ('SGW-Change', AVP_10415_2065, 192),
        2066: ('Charging-Characteristics-Selection-Mode', AVP_10415_2066, 192),
        2067: ('SGW-Address', AVPV_Address, 192),
        2068: ('Dynamic-Address-Flag-Extension', AVP_10415_2068, 192),
        2118: ('Charge-Reason-Code', AVP_10415_2118, 192),
        2200: ('Subsession-Decision-Info', AVPV_Grouped, 192),
        2201: ('Subsession-Enforcement-Info', AVPV_Grouped, 192),
        2202: ('Subsession-Id', AVPV_Unsigned32, 192),
        2203: ('Subsession-Operation', AVP_10415_2203, 192),
        2204: ('Multiple-BBERF-Action', AVP_10415_2204, 192),
        2206: ('DRA-Deployment', AVP_10415_2206, 128),
        2208: ('DRA-Binding', AVP_10415_2208, 128),
        2301: ('SIP-Request-Timestamp-Fraction', AVPV_Unsigned32, 192),
        2302: ('SIP-Response-Timestamp-Fraction', AVPV_Unsigned32, 192),
        2303: ('Online-Charging-Flag', AVP_10415_2303, 192),
        2304: ('CUG-Information', AVPV_OctetString, 192),
        2305: ('Real-Time-Tariff-Information', AVPV_Grouped, 192),
        2306: ('Tariff-XML', AVPV_StrLenField, 192),
        2307: ('MBMS-GW-Address', AVPV_Address, 192),
        2308: ('IMSI-Unauthenticated-Flag', AVP_10415_2308, 192),
        2309: ('Account-Expiration', AVPV_Time, 192),
        2310: ('AoC-Format', AVP_10415_2310, 192),
        2311: ('AoC-Service', AVPV_Grouped, 192),
        2312: ('AoC-Service-Obligatory-Type', AVP_10415_2312, 192),
        2313: ('AoC-Service-Type', AVP_10415_2313, 192),
        2314: ('AoC-Subscription-Information', AVPV_Grouped, 192),
        2315: ('Preferred-AoC-Currency', AVPV_Unsigned32, 192),
        2317: ('CSG-Access-Mode', AVP_10415_2317, 192),
        2318: ('CSG-Membership-Indication', AVP_10415_2318, 192),
        2319: ('User-CSG-Information', AVPV_Grouped, 192),
        2320: ('Outgoing-Session-Id', AVPV_StrLenField, 192),
        2321: ('Initial-IMS-Charging-Identifier', AVPV_StrLenField, 192),
        2322: ('IMS-Emergency-Indicator', AVP_10415_2322, 192),
        2323: ('MBMS-Charged-Party', AVP_10415_2323, 192),
        2400: ('LMSI', AVPV_OctetString, 192),
        2401: ('Serving-Node', AVPV_Grouped, 192),
        2402: ('MME-Name', AVPV_StrLenField, 192),
        2403: ('MSC-Number', AVPV_OctetString, 192),
        2404: ('LCS-Capabilities-Sets', AVPV_Unsigned32, 192),
        2405: ('GMLC-Address', AVPV_Address, 192),
        2406: ('Additional-Serving-Node', AVPV_Grouped, 192),
        2407: ('PPR-Address', AVPV_Address, 192),
        2408: ('MME-Realm', AVPV_StrLenField, 128),
        2409: ('SGSN-Name', AVPV_StrLenField, 128),
        2410: ('SGSN-Realm', AVPV_StrLenField, 128),
        2411: ('RIA-Flags', AVPV_Unsigned32, 128),
        2500: ('SLg-Location-Type', AVP_10415_2500, 192),
        2501: ('LCS-EPS-Client-Name', AVPV_Grouped, 192),
        2502: ('LCS-Requestor-Name', AVPV_Grouped, 192),
        2503: ('LCS-Priority', AVPV_Unsigned32, 192),
        2504: ('LCS-QoS', AVPV_Grouped, 192),
        2505: ('Horizontal-Accuracy', AVPV_Unsigned32, 192),
        2506: ('Vertical-Accuracy', AVPV_Unsigned32, 192),
        2507: ('Vertical-Requested', AVP_10415_2507, 192),
        2508: ('Velocity-Requested', AVP_10415_2508, 192),
        2509: ('Response-Time', AVP_10415_2509, 192),
        2510: ('Supported-GAD-Shapes', AVPV_Unsigned32, 192),
        2511: ('LCS-Codeword', AVPV_StrLenField, 192),
        2512: ('LCS-Privacy-Check', AVP_10415_2512, 192),
        2513: ('Accuracy-Fulfilment-Indicator', AVP_10415_2513, 192),
        2514: ('Age-Of-Location-Estimate', AVPV_Unsigned32, 192),
        2515: ('Velocity-Estimate', AVPV_OctetString, 192),
        2516: ('EUTRAN-Positioning-Data', AVPV_OctetString, 192),
        2517: ('ECGI', AVPV_OctetString, 192),
        2518: ('Location-Event', AVP_10415_2518, 192),
        2519: ('Pseudonym-Indicator', AVP_10415_2519, 192),
        2520: ('LCS-Service-Type-ID', AVPV_Unsigned32, 192),
        2523: ('LCS-QoS-Class', AVP_10415_2523, 192),
        2524: ('GERAN-Positioning-Info', AVPV_Grouped, 128),
        2525: ('GERAN-Positioning-Data', AVPV_OctetString, 128),
        2526: ('GERAN-GANSS-Positioning-Data', AVPV_OctetString, 128),
        2527: ('UTRAN-Positioning-Info', AVPV_Grouped, 128),
        2528: ('UTRAN-Positioning-Data', AVPV_OctetString, 128),
        2529: ('UTRAN-GANSS-Positioning-Data', AVPV_OctetString, 128),
        2530: ('LRR-Flags', AVPV_Unsigned32, 128),
        2531: ('LCS-Reference-Number', AVPV_OctetString, 128),
        2532: ('Deferred-Location-Type', AVPV_Unsigned32, 128),
        2533: ('Area-Event-Info', AVPV_Grouped, 128),
        2534: ('Area-Definition', AVPV_Grouped, 128),
        2535: ('Area', AVPV_Grouped, 128),
        2536: ('Area-Type', AVPV_Unsigned32, 128),
        2537: ('Area-Identification', AVPV_Grouped, 128),
        2538: ('Occurrence-Info', AVP_10415_2538, 128),
        2539: ('Interval-Time', AVPV_Unsigned32, 128),
        2540: ('Periodic-LDR-Information', AVPV_Grouped, 128),
        2541: ('Reporting-Amount', AVPV_Unsigned32, 128),
        2542: ('Reporting-Interval', AVPV_Unsigned32, 128),
        2543: ('Reporting-PLMN-List', AVPV_Grouped, 128),
        2544: ('PLMN-ID-List', AVPV_Grouped, 128),
        2545: ('PLR-Flags', AVPV_Unsigned32, 128),
        2546: ('PLA-Flags', AVPV_Unsigned32, 128),
        2547: ('Deferred-MT-LR-Data', AVPV_Grouped, 128),
        2548: ('Termination-Cause', AVPV_Unsigned32, 128),
        2549: ('LRA-Flags', AVPV_Unsigned32, 128),
        2550: ('Periodic-Location-Support-Indicator', AVP_10415_2550, 128),
        2551: ('Prioritized-List-Indicator', AVP_10415_2551, 128),
        2552: ('ESMLC-Cell-Info', AVPV_Grouped, 128),
        2553: ('Cell-Portion-ID', AVPV_Unsigned32, 128),
        2554: ('1xRTT-RCID', AVPV_OctetString, 128),
        2601: ('IMS-Application-Reference-Identifier', AVPV_StrLenField, 192),
        2602: ('Low-Priority-Indicator', AVP_10415_2602, 192),
        2604: ('Local-GW-Inserted-Indication', AVP_10415_2604, 192),
        2605: ('Transcoder-Inserted-Indication', AVP_10415_2605, 192),
        2606: ('PDP-Address-Prefix-Length', AVPV_Unsigned32, 192),
        2701: ('Transit-IOI-List', AVPV_StrLenField, 192),
        2702: ('AS-Code', AVP_10415_2702, 192),
        2704: ('NNI-Type', AVP_10415_2704, 192),
        2705: ('Neighbour-Node-Address', AVPV_Address, 192),
        2706: ('Relationship-Mode', AVP_10415_2706, 192),
        2707: ('Session-Direction', AVP_10415_2707, 192),
        2708: ('From-Address', AVPV_StrLenField, 192),
        2709: ('Access-Transfer-Information', AVPV_Grouped, 192),
        2710: ('Access-Transfer-Type', AVP_10415_2710, 192),
        2711: ('Related-IMS-Charging-Identifier', AVPV_StrLenField, 192),
        2712: ('Related-IMS-Charging-Identifier-Node', AVPV_Address, 192),
        2713: ('IMS-Visited-Network-Identifier', AVPV_StrLenField, 192),
        2714: ('TWAN-User-Location-Info', AVPV_Grouped, 192),
        2716: ('BSSID', AVPV_StrLenField, 192),
        2717: ('TAD-Identifier', AVP_10415_2717, 192),
        2802: ('TDF-Application-Instance-Identifier', AVPV_OctetString, 128),
        2804: ('HeNB-Local-IP-Address', AVPV_Address, 128),
        2805: ('UE-Local-IP-Address', AVPV_Address, 128),
        2806: ('UDP-Source-Port', AVPV_Unsigned32, 128),
        2809: ('Mute-Notification', AVP_10415_2809, 128),
        2810: ('Monitoring-Time', AVPV_Time, 128),
        2811: ('AN-GW-Status', AVP_10415_2811, 128),
        2812: ('User-Location-Info-Time', AVPV_Time, 128),
        2816: ('Default-QoS-Information', AVPV_Grouped, 128),
        2817: ('Default-QoS-Name', AVPV_StrLenField, 128),
        2818: ('Conditional-APN-Aggregate-Max-Bitrate', AVPV_Grouped, 128),
        2819: ('RAN-NAS-Release-Cause', AVPV_OctetString, 128),
        2820: ('Presence-Reporting-Area-Elements-List', AVPV_OctetString, 128),
        2821: ('Presence-Reporting-Area-Identifier', AVPV_OctetString, 128),
        2822: ('Presence-Reporting-Area-Information', AVPV_Grouped, 128),
        2823: ('Presence-Reporting-Area-Status', AVPV_Unsigned32, 128),
        2824: ('NetLoc-Access-Support', AVPV_Unsigned32, 128),
        2825: ('Fixed-User-Location-Info', AVPV_Grouped, 128),
        2826: ('PCSCF-Restoration-Indication', AVPV_Unsigned32, 128),
        2827: ('IP-CAN-Session-Charging-Scope', AVPV_Unsigned32, 128),
        2828: ('Monitoring-Flags', AVPV_Unsigned32, 128),
        2901: ('Policy-Counter-Identifier', AVPV_StrLenField, 192),
        2902: ('Policy-Counter-Status', AVPV_StrLenField, 192),
        2903: ('Policy-Counter-Status-Report', AVPV_Grouped, 192),
        2904: ('SL-Request-Type', AVP_10415_2904, 192),
        2905: ('Pending-Policy-Counter-Information', AVPV_Grouped, 192),
        2906: ('Pending-Policy-Counter-Change-Time', AVPV_Time, 192),
        3401: ('Reason-Header', AVPV_StrLenField, 192),
        3402: ('Instance-Id', AVPV_StrLenField, 192),
        3403: ('Route-Header-Received', AVPV_StrLenField, 192),
        3404: ('Route-Header-Transmitted', AVPV_StrLenField, 192),
        3405: ('SM-Device-Trigger-Information', AVPV_Grouped, 192),
        3406: ('MTC-IWF-Address', AVPV_Address, 192),
        3407: ('SM-Device-Trigger-Indicator', AVP_10415_3407, 192),
        3408: ('SM-Sequence-Number', AVPV_Unsigned32, 192),
        3409: ('SMS-Result', AVPV_Unsigned32, 192),
        3410: ('VCS-Information', AVPV_Grouped, 192),
        3411: ('Basic-Service-Code', AVPV_Grouped, 192),
        3412: ('Bearer-Capability', AVPV_OctetString, 192),
        3413: ('Teleservice', AVPV_OctetString, 192),
        3414: ('ISUP-Location-Number', AVPV_OctetString, 192),
        3415: ('Forwarding-Pending', AVP_10415_3415, 192),
        3416: ('ISUP-Cause', AVPV_Grouped, 192),
        3417: ('MSC-Address', AVPV_OctetString, 192),
        3418: ('Network-Call-Reference-Number', AVPV_OctetString, 192),
        3419: ('Start-of-Charging', AVPV_Time, 192),
        3420: ('VLR-Number', AVPV_OctetString, 192),
        3421: ('CN-Operator-Selection-Entity', AVP_10415_3421, 192),
        3422: ('ISUP-Cause-Diagnostics', AVPV_OctetString, 192),
        3423: ('ISUP-Cause-Location', AVPV_Unsigned32, 192),
        3424: ('ISUP-Cause-Value', AVPV_Unsigned32, 192),
        3425: ('ePDG-Address', AVPV_Address, 192),
        3428: ('Coverage-Status', AVP_10415_3428, 192),
        3429: ('Layer-2-Group-ID', AVPV_StrLenField, 192),
        3430: ('Monitored-PLMN-Identifier', AVPV_StrLenField, 192),
        3431: ('Monitoring-UE-HPLMN-Identifier', AVPV_StrLenField, 192),
        3432: ('Monitoring-UE-Identifier', AVPV_StrLenField, 192),
        3433: ('Monitoring-UE-VPLMN-Identifier', AVPV_StrLenField, 192),
        3434: ('PC3-Control-Protocol-Cause', AVPV_Integer32, 192),
        3435: ('PC3-EPC-Control-Protocol-Cause', AVPV_Integer32, 192),
        3436: ('Requested-PLMN-Identifier', AVPV_StrLenField, 192),
        3437: ('Requestor-PLMN-Identifier', AVPV_StrLenField, 192),
        3438: ('Role-Of-ProSe-Function', AVP_10415_3438, 192),
        3439: ('Usage-Information-Report-Sequence-Number', AVPV_Integer32, 192),  # noqa: E501
        3440: ('ProSe-3rd-Party-Application-ID', AVPV_StrLenField, 192),
        3441: ('ProSe-Direct-Communication-Data-Container', AVPV_Grouped, 192),
        3442: ('ProSe-Direct-Discovery-Model', AVP_10415_3442, 192),
        3443: ('ProSe-Event-Type', AVP_10415_3443, 192),
        3444: ('ProSe-Function-IP-Address', AVPV_Address, 192),
        3445: ('ProSe-Functionality', AVP_10415_3445, 192),
        3446: ('ProSe-Group-IP-Multicast-Address', AVPV_Address, 192),
        3447: ('ProSe-Information', AVPV_Grouped, 192),
        3448: ('ProSe-Range-Class', AVP_10415_3448, 192),
        3449: ('ProSe-Reason-For-Cancellation', AVP_10415_3449, 192),
        3450: ('ProSe-Request-Timestamp', AVPV_Time, 192),
        3451: ('ProSe-Role-Of-UE', AVP_10415_3451, 192),
        3452: ('ProSe-Source-IP-Address', AVPV_Address, 192),
        3453: ('ProSe-UE-ID', AVPV_StrLenField, 192),
        3454: ('Proximity-Alert-Indication', AVP_10415_3454, 192),
        3455: ('Proximity-Alert-Timestamp', AVPV_Time, 192),
        3456: ('Proximity-Cancellation-Timestamp', AVPV_Time, 192),
        3457: ('ProSe-Function-PLMN-Identifier', AVPV_StrLenField, 192),
    },
}


#####################################################################
#####################################################################
#
#       Diameter commands classes and definitions
#
#####################################################################
#####################################################################

# Version + message length + flags + code + Application-ID + Hop-by-Hop ID
# + End-to-End ID
DR_Header_Length = 20
DR_Flags_List = ["x", "x", "x", "x", "T", "E", "P", "R"]

# The Diameter commands definition fields meaning:
# 2nd: the 2 letters prefix for both requests and answers
# 3rd: dictionary of Request/Answer command flags for each supported application ID. Each dictionary key is one of the  # noqa: E501
# supported application ID and each value is a tuple defining the request
# flag and then the answer flag
DR_cmd_def = {
    257: ('Capabilities-Exchange', 'CE', {0: (128, 0)}),
    258: ('Re-Auth', 'RA', {0: (192, 64), 1: (192, 64), 16777250: (192, 64), 16777272: (192, 64), 16777264: (192, 64)}),  # noqa: E501
    260: ('AA-Mobile-Node', 'AM', {2: (192, 64)}),
    262: ('Home-Agent-MIP', 'HA', {2: (192, 64)}),
    265: ('AA', 'AA', {16777272: (192, 64), 1: (192, 64), 16777250: (192, 64), 16777264: (192, 64)}),  # noqa: E501
    268: ('Diameter-EAP', 'DE', {16777272: (192, 64), 16777264: (192, 64), 16777250: (192, 64), 5: (192, 64), 7: (192, 64)}),  # noqa: E501
    271: ('Accounting', 'AC', {0: (192, 64), 1: (192, 64)}),
    272: ('Credit-Control', 'CC', {4: (192, 64)}),
    274: ('Abort-Session', 'AS', {0: (192, 64), 1: (192, 64), 16777250: (192, 64), 16777272: (192, 64), 16777264: (192, 64)}),  # noqa: E501
    275: ('Session-Termination', 'ST', {0: (192, 64), 1: (192, 64), 16777250: (192, 64), 16777264: (192, 64), 16777272: (192, 64)}),  # noqa: E501
    280: ('Device-Watchdog', 'DW', {0: (128, 0)}),
    282: ('Disconnect-Peer', 'DP', {0: (128, 0)}),
    283: ('User-Authorization', 'UA', {6: (192, 64)}),
    284: ('Server-Assignment', 'SA', {6: (192, 64)}),
    285: ('Location-Info', 'LI', {6: (192, 64)}),
    286: ('Multimedia-Auth', 'MA', {6: (192, 64)}),
    287: ('Registration-Termination', 'RT', {6: (192, 64)}),
    288: ('Push-Profile', 'PP', {6: (192, 64)}),
    300: ('User-Authorization', 'UA', {16777216: (192, 64)}),
    301: ('Server-Assignment', 'SA', {16777216: (192, 64), 16777265: (192, 64)}),  # noqa: E501
    302: ('Location-Info', 'LI', {16777216: (192, 64)}),
    303: ('Multimedia-Auth', 'MA', {16777216: (192, 64), 16777265: (192, 64)}),
    304: ('Registration-Termination', 'RT', {16777216: (192, 64), 16777265: (192, 64)}),  # noqa: E501
    305: ('Push-Profile', 'PP', {16777216: (192, 64), 16777265: (128, 64)}),
    306: ('User-Data', 'UD', {16777217: (192, 64)}),
    307: ('Profile-Update', 'PU', {16777217: (192, 64)}),
    308: ('Subscribe-Notifications', 'SN', {16777217: (192, 64)}),
    309: ('Push-Notification', 'PN', {16777217: (192, 64)}),
    316: ('Update-Location', 'UL', {16777251: (192, 64)}),
    317: ('Cancel-Location', 'CL', {16777251: (192, 64)}),
    318: ('Authentication-Information', 'AI', {16777251: (192, 64)}),
    319: ('Insert-Subscriber-Data', 'ID', {16777251: (192, 64)}),
    320: ('Delete-Subscriber-Data', 'DS', {16777251: (192, 64)}),
    321: ('Purge-UE', 'PU', {16777251: (192, 64)}),
    322: ('Reset', 'RS', {16777251: (192, 64)}),
    323: ('Notify', 'NO', {16777251: (192, 64)}),
    324: ('ME-Identity-Check', 'EC', {16777252: (192, 64)}),
    325: ('MIP6', 'MI', {8: (192, 64)}),
    8388620: ('Provide-Location', 'PL', {16777255: (192, 64)}),
    8388621: ('Location-Report', 'LR', {16777255: (192, 64)}),
    8388622: ('LCS-Routing-Info', 'RI', {16777291: (192, 64)}),
    8388635: ('Spending-Limit', 'SL', {16777255: (192, 64)}),
    8388636: ('Spending-Status-Notification', 'SN', {16777255: (192, 64)}),
    8388638: ('Update-VCSG-Location', 'UV', {16777308: (192, 64)}),
    8388642: ('Cancel-VCSG-Location', 'CV', {16777308: (192, 64)}),
}

# Generic class + commands builder
#######################################


class DiamG (Packet):
    """   Generic class defining all the Diameter fields"""
    name = "Diameter"
    fields_desc = [
        # Protocol version field, 1 byte, default value = 1
        XByteField("version", 1),
        I3FieldLenField(
            "drLen",
            None,
            length_of="avpList",
            adjust=lambda p,
            x:x +
            DR_Header_Length),
        DRFlags("drFlags", None, 8, DR_Flags_List),
        # Command Code, 3 bytes, no default
        DRCode("drCode", None, DR_cmd_def),
        # Application ID, 4 bytes, no default
        IntEnumField("drAppId", None, AppIDsEnum),
        # Hop-by-Hop Identifier, 4 bytes
        XIntField("drHbHId", 0),
        # End-to-end Identifier, 4 bytes
        XIntField("drEtEId", 0),
        PacketListField(
            "avpList",
            [],
            GuessAvpType,
            length_from=lambda pkt:pkt.drLen -
            DR_Header_Length),
    ]


def getCmdParams(cmd, request, **fields):
    """Update or fill the fields parameters depending on command code. Both cmd and drAppId can be provided  # noqa: E501
       in string or int format."""
    drCode = None
    params = None
    drAppId = None
    # Fetch the parameters if cmd is found in dict
    if isinstance(cmd, int):
        drCode = cmd    # Enable to craft commands with non standard code
        if cmd in DR_cmd_def:
            params = DR_cmd_def[drCode]
        else:
            params = ('Unknown', 'UK', {0: (128, 0)})
            warning(
                'No Diameter command with code %d found in DR_cmd_def dictionary' %  # noqa: E501
                cmd)
    else:  # Assume command is a string
        if len(cmd) > 3:     # Assume full command name given
            fpos = 0
        else:         # Assume abbreviated name is given and take only the first two letters  # noqa: E501
            cmd = cmd[:2]
            fpos = 1
        for k, f in DR_cmd_def.items():
            if f[fpos][:len(
                    cmd)] == cmd:   # Accept only a prefix of the full name
                drCode = k
                params = f
                break
        if not drCode:
            warning(
                'Diameter command with name %s not found in DR_cmd_def dictionary.' %  # noqa: E501
                cmd)
            return (fields, 'Unknown')
    # The drCode is set/overridden in any case
    fields['drCode'] = drCode
    # Processing of drAppId
    if 'drAppId' in fields:
        val = fields['drAppId']
        if isinstance(val, str):   # Translate into application Id code
            found = False
            for k, v in six.iteritems(AppIDsEnum):
                if v.find(val) != -1:
                    drAppId = k
                    fields['drAppId'] = drAppId
                    found = True
                    break
            if not found:
                del(fields['drAppId'])
                warning(
                    'Application ID with name %s not found in AppIDsEnum dictionary.' %  # noqa: E501
                    val)
                return (fields, 'Unknown')
        else:   # Assume type is int
            drAppId = val
    else:  # Application Id shall be taken from the params found based on cmd
        drAppId = next(iter(params[2]))   # The first record is taken
        fields['drAppId'] = drAppId
    # Set the command name
    name = params[0] + '-Request' if request else params[0] + '-Answer'
    # Processing of flags (only if not provided manually)
    if 'drFlags' not in fields:
        if drAppId in params[2]:
            flags = params[2][drAppId]
            fields['drFlags'] = flags[0] if request else flags[1]
    return (fields, name)


def DiamReq(cmd, **fields):
    """Craft Diameter request commands"""
    upfields, name = getCmdParams(cmd, True, **fields)
    p = DiamG(**upfields)
    p.name = name
    return p


def DiamAns(cmd, **fields):
    """Craft Diameter answer commands"""
    upfields, name = getCmdParams(cmd, False, **fields)
    p = DiamG(**upfields)
    p.name = name
    return p

# Binding
#######################################


bind_layers(TCP, DiamG, dport=3868)
bind_layers(TCP, DiamG, sport=3868)
bind_layers(SCTPChunkData, DiamG, dport=3868)
bind_layers(SCTPChunkData, DiamG, sport=3868)
bind_layers(SCTPChunkData, DiamG, proto_id=46)
bind_layers(SCTPChunkData, DiamG, proto_id=47)
