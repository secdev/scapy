# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
NTP (Network Time Protocol).
References : RFC 5905, RC 1305, ntpd source code
"""

from __future__ import absolute_import
import struct
import time
import datetime

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, BitEnumField, ByteField, ByteEnumField, \
    XByteField, SignedByteField, FlagsField, ShortField, LEShortField, \
    IntField, LEIntField, FixedPointField, IPField, StrField, \
    StrFixedLenField, StrFixedLenEnumField, XStrFixedLenField, PacketField, \
    PacketLenField, PacketListField, FieldListField, ConditionalField, \
    PadField
from scapy.layers.inet6 import IP6Field
from scapy.layers.inet import UDP
from scapy.utils import lhex
from scapy.compat import orb
from scapy.config import conf
import scapy.libs.six as six


#############################################################################
# Constants
#############################################################################

_NTP_AUTH_MD5_MIN_SIZE = 68
_NTP_EXT_MIN_SIZE = 16
_NTP_HDR_WITH_EXT_MIN_SIZE = _NTP_AUTH_MD5_MIN_SIZE + _NTP_EXT_MIN_SIZE
_NTP_AUTH_MD5_TAIL_SIZE = 20
_NTP_AUTH_MD5_DGST_SIZE = 16
_NTP_PRIVATE_PACKET_MIN_SIZE = 8

# ntpd "Private" messages are the shortest
_NTP_PACKET_MIN_SIZE = _NTP_PRIVATE_PACKET_MIN_SIZE

_NTP_PRIVATE_REQ_PKT_TAIL_LEN = 28

# seconds between 01-01-1900 and 01-01-1970
_NTP_BASETIME = 2208988800

# include/ntp.h
_NTP_SHIFT = 8
_NTP_HASH_SIZE = 128


#############################################################################
#     Fields and utilities
#############################################################################

class XLEShortField(LEShortField):
    """
    XShortField which value is encoded in little endian.
    """

    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class TimeStampField(FixedPointField):
    """
    This field handles the timestamp fields in the NTP header.
    """

    def __init__(self, name, default):
        FixedPointField.__init__(self, name, default, 64, 32)

    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        val = self.i2h(pkt, val)
        if val < _NTP_BASETIME:
            return val
        return time.strftime(
            "%a, %d %b %Y %H:%M:%S +0000",
            time.gmtime(int(val - _NTP_BASETIME))
        )

    def any2i(self, pkt, val):
        if isinstance(val, six.string_types):
            val = int(time.mktime(time.strptime(val))) + _NTP_BASETIME
        elif isinstance(val, datetime.datetime):
            val = int(val.strftime("%s")) + _NTP_BASETIME
        return FixedPointField.any2i(self, pkt, val)

    def i2m(self, pkt, val):
        if val is None:
            val = FixedPointField.any2i(self, pkt, time.time() + _NTP_BASETIME)
        return FixedPointField.i2m(self, pkt, val)


#############################################################################
#     NTP
#############################################################################

# RFC 5905 / Section 7.3
_leap_indicator = {
    0: "no warning",
    1: "last minute of the day has 61 seconds",
    2: "last minute of the day has 59 seconds",
    3: "unknown (clock unsynchronized)"
}


# RFC 5905 / Section 7.3
_ntp_modes = {
    0: "reserved",
    1: "symmetric active",
    2: "symmetric passive",
    3: "client",
    4: "server",
    5: "broadcast",
    6: "NTP control message",
    7: "reserved for private use"
}


# RFC 5905 / Section 7.3
_reference_identifiers = {
    "GOES": "Geosynchronous Orbit Environment Satellite",
    "GPS ": "Global Position System",
    "GAL ": "Galileo Positioning System",
    "PPS ": "Generic pulse-per-second",
    "IRIG": "Inter-Range Instrumentation Group",
    "WWVB": "LF Radio WWVB Ft. Collins, CO 60 kHz",
    "DCF ": "LF Radio DCF77 Mainflingen, DE 77.5 kHz",
    "HBG ": "LF Radio HBG Prangins, HB 75 kHz",
    "MSF ": "LF Radio MSF Anthorn, UK 60 kHz",
    "JJY ": "LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz",
    "LORC": "MF Radio LORAN C station, 100 kHz",
    "TDF ": "MF Radio Allouis, FR 162 kHz",
    "CHU ": "HF Radio CHU Ottawa, Ontario",
    "WWV ": "HF Radio WWV Ft. Collins, CO",
    "WWVH": "HF Radio WWVH Kauai, HI",
    "NIST": "NIST telephone modem",
    "ACTS": "NIST telephone modem",
    "USNO": "USNO telephone modem",
    "PTB ": "European telephone modem",
}


# RFC 5905 / Section 7.4
_kiss_codes = {
    "ACST": "The association belongs to a unicast server.",
    "AUTH": "Server authentication failed.",
    "AUTO": "Autokey sequence failed.",
    "BCST": "The association belongs to a broadcast server.",
    "CRYP": "Cryptographic authentication or identification failed.",
    "DENY": "Access denied by remote server.",
    "DROP": "Lost peer in symmetric mode.",
    "RSTR": "Access denied due to local policy.",
    "INIT": "The association has not yet synchronized for the first time.",
    "MCST": "The association belongs to a dynamically discovered server.",
    "NKEY": "No key found.",
    "RATE": "Rate exceeded.",
    "RMOT": "Alteration of association from a remote host running ntpdc."
}


# Used by _ntp_dispatcher to instantiate the appropriate class
def _ntp_dispatcher(payload):
    """
    Returns the right class for a given NTP packet.
    """
    # By default, calling NTP() will build a NTP packet as defined in RFC 5905
    # (see the code of NTPHeader). Use NTPHeader for extension fields and MAC.
    if payload is None:
        return NTPHeader
    else:
        length = len(payload)
        if length >= _NTP_PACKET_MIN_SIZE:
            first_byte = orb(payload[0])
            # Extract NTP mode
            mode = first_byte & 7
            return {6: NTPControl, 7: NTPPrivate}.get(mode, NTPHeader)
    return conf.raw_layer


class NTP(Packet):
    """
    Base class that allows easier instantiation of a NTP packet from binary
    data.
    """

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """

        return _ntp_dispatcher(_pkt)

    def pre_dissect(self, s):
        """
        Check that the payload is long enough to build a NTP packet.
        """
        length = len(s)
        if length < _NTP_PACKET_MIN_SIZE:
            err = " ({}".format(length) + " is < _NTP_PACKET_MIN_SIZE "
            err += "({})).".format(_NTP_PACKET_MIN_SIZE)
            raise _NTPInvalidDataException(err)
        return s

    def mysummary(self):
        return self.sprintf("NTP v%ir,NTP.version%, %NTP.mode%")


class _NTPAuthenticatorPaddingField(StrField):
    """
    StrField handling the padding that may be found before the
    "authenticator" field.
    """

    def getfield(self, pkt, s):
        ret = None
        remain = s
        length = len(s)

        if length > _NTP_AUTH_MD5_TAIL_SIZE:
            start = length - _NTP_AUTH_MD5_TAIL_SIZE
            ret = s[:start]
            remain = s[start:]
        return remain, ret


class NTPAuthenticator(Packet):
    """
    Packet handling the "authenticator" part of a NTP packet, as
    defined in RFC 5905.
    """

    name = "Authenticator"
    fields_desc = [
        _NTPAuthenticatorPaddingField("padding", ""),
        IntField("key_id", 0),
        XStrFixedLenField("dgst", "", length_from=lambda x: 16)
    ]

    def extract_padding(self, s):
        return b"", s


class NTPExtension(Packet):
    """
    Packet handling a NTPv4 extension.
    """

    #########################################################################
    #
    # RFC 7822
    #########################################################################
    #
    # 7.5.  NTP Extension Field Format
    #
    #    In NTPv3, one or more extension fields can be inserted after the
    #    header and before the MAC, if a MAC is present.
    #
    #    Other than defining the field format, this document makes no use
    #    of the field contents.  An extension field contains a request or
    #    response message in the format shown in Figure 14.
    #
    #     0                   1                   2                   3
    #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |          Field Type           |            Length             |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    .                                                               .
    #    .                            Value                              .
    #    .                                                               .
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |                       Padding (as needed)                     |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    #                    Figure 14: Extension Field Format
    #
    #
    #    All extension fields are zero-padded to a word (four octets)
    #    boundary.
    #########################################################################
    #

    name = "extension"
    fields_desc = [
        ShortField("type", 0),
        ShortField("len", 0),
        PadField(PacketField("value", "", Packet), align=4, padwith=b"\x00")
    ]


class NTPExtPacketListField(PacketListField):

    """
    PacketListField handling NTPv4 extensions (NTPExtension list).
    """

    def m2i(self, pkt, m):
        ret = None
        if len(m) >= 16:
            ret = NTPExtension(m)
        else:
            ret = conf.raw_layer(m)
        return ret

    def getfield(self, pkt, s):
        lst = []
        remain = s
        length = len(s)
        if length > _NTP_AUTH_MD5_TAIL_SIZE:
            end = length - _NTP_AUTH_MD5_TAIL_SIZE
            extensions = s[:end]
            remain = s[end:]

            extensions_len = len(extensions)
            while extensions_len >= 16:
                ext_len = struct.unpack("!H", extensions[2:4])[0]
                ext_len = min(ext_len, extensions_len)
                if ext_len < 1:
                    ext_len = extensions_len
                current = extensions[:ext_len]
                extensions = extensions[ext_len:]
                current_packet = self.m2i(pkt, current)
                lst.append(current_packet)
                extensions_len = len(extensions)

            if extensions_len > 0:
                lst.append(self.m2i(pkt, extensions))

        return remain, lst


class NTPExtensions(Packet):
    """
    Packet handling the NTPv4 extensions and the "MAC part" of the packet.
    """

    #########################################################################
    #
    # RFC 5905 / RFC 7822
    #########################################################################
    #
    # 7.5. NTP Extension Field Format
    #
    # In NTPv4, one or more extension fields can be inserted after the
    # header and before the MAC, if a MAC is present.
    #########################################################################
    #

    name = "NTPv4 extensions"
    fields_desc = [
        NTPExtPacketListField("extensions", [], Packet),
        PacketField("mac", NTPAuthenticator(), NTPAuthenticator)
    ]


class NTPHeader(NTP):

    """
    Packet handling the RFC 5905 NTP packet.
    """

    #########################################################################
    #
    # RFC 5905
    #########################################################################
    #
    #   0                   1                   2                   3
    #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Root Delay                            |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Root Dispersion                       |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                          Reference ID                         |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                                                               |
    #  +                     Reference Timestamp (64)                  +
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                                                               |
    #  +                      Origin Timestamp (64)                    +
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                                                               |
    #  +                      Receive Timestamp (64)                   +
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                                                               |
    #  +                      Transmit Timestamp (64)                  +
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                                                               |
    #  .                                                               .
    #  .                    Extension Field 1 (variable)               .
    #  .                                                               .
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                                                               |
    #  .                                                               .
    #  .                    Extension Field 2 (variable)               .
    #  .                                                               .
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                          Key Identifier                       |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                                                               |
    #  |                            dgst (128)                         |
    #  |                                                               |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    #                  Figure 8: Packet Header Format
    #########################################################################
    #

    name = "NTPHeader"
    match_subclass = True
    fields_desc = [
        BitEnumField("leap", 0, 2, _leap_indicator),
        BitField("version", 4, 3),
        BitEnumField("mode", 3, 3, _ntp_modes),
        BitField("stratum", 2, 8),
        BitField("poll", 0xa, 8),
        BitField("precision", 0, 8),
        FixedPointField("delay", 0, size=32, frac_bits=16),
        FixedPointField("dispersion", 0, size=32, frac_bits=16),
        ConditionalField(IPField("id", "127.0.0.1"), lambda p: p.stratum > 1),
        ConditionalField(
            StrFixedLenEnumField(
                "ref_id",
                "",
                length=4,
                enum=_reference_identifiers
            ),
            lambda p: p.stratum < 2
        ),
        TimeStampField("ref", 0),
        TimeStampField("orig", None),
        TimeStampField("recv", 0),
        TimeStampField("sent", None),
    ]

    def guess_payload_class(self, payload):
        """
        Handles NTPv4 extensions and MAC part (when authentication is used.)
        """
        plen = len(payload)

        if plen - 4 in [16, 20, 32, 64]:  # length of MD5, SHA1, SHA256, SHA512
            return NTPAuthenticator
        elif plen > _NTP_AUTH_MD5_TAIL_SIZE:
            return NTPExtensions

        return Packet.guess_payload_class(self, payload)


class _NTPInvalidDataException(Exception):
    """
    Raised when it is not possible to instantiate a NTP packet with the
    given data.
    """

    def __init__(self, details):
        Exception.__init__(
            self,
            "Data does not seem to be a valid NTP message" + details
        )


##############################################################################
#     Private (mode 7)
##############################################################################

# Operation codes
_op_codes = {
    0: "CTL_OP_UNSPEC",
    1: "CTL_OP_READSTAT",
    2: "CTL_OP_READVAR",
    3: "CTL_OP_WRITEVAR",
    4: "CTL_OP_READCLOCK",
    5: "CTL_OP_WRITECLOCK",
    6: "CTL_OP_SETTRAP",
    7: "CTL_OP_ASYNCMSG",
    8: "CTL_OP_CONFIGURE",
    9: "CTL_OP_SAVECONFIG",
    10: "CTL_OP_READ_MRU",
    11: "CTL_OP_READ_ORDLIST_A",
    12: "CTL_OP_REQ_NONCE",
    31: "CTL_OP_UNSETTRAP"
}


# System status words
_system_statuses = {
    0: "no warning",
    1: "last minute was 61 seconds",
    2: "last minute was 59 seconds",
    3: "alarm condition (clock not synchronized)"
}


_clock_sources = {
    0: "unspecified or unknown",
    1: " Calibrated atomic clock",
    2: "VLF (band 4) or LF (band 5) radio",
    3: "HF (band 7) radio",
    4: "UHF (band 9) satellite",
    5: "local net",
    6: "UDP/NTP",
    7: "UDP/TIME",
    8: "eyeball-and-wristwatch",
    9: "telephone modem"
}


_system_event_codes = {
    0: "unspecified",
    1: "system restart",
    2: "system or hardware fault",
    3: "system new status word (leap bits or synchronization change)",
    4: "system new synchronization source or stratum (sys.peer or sys.stratum change)",  # noqa: E501
    5: "system clock reset (offset correction exceeds CLOCK.MAX)",
    6: "system invalid time or date",
    7: "system clock exception",
}


# Peer status words
_peer_statuses = {
    0: "configured",
    1: "authentication enabled",
    2: "authentication okay",
    3: "reachability okay",
    4: "reserved"
}


_peer_selection = {
    0: "rejected",
    1: "passed sanity checks",
    2: "passed correctness checks",
    3: "passed candidate checks",
    4: "passed outlyer checks",
    5: "current synchronization source; max distance exceeded",
    6: "current synchronization source; max distance okay",
    7: "reserved"
}


_peer_event_codes = {
    0: "unspecified",
    1: "peer IP error",
    2: "peer authentication failure",
    3: "peer unreachable",
    4: "peer reachable",
    5: "peer clock exception",
}


# Clock status words
_clock_statuses = {
    0: "clock operating within nominals",
    1: "reply timeout",
    2: "bad reply format",
    3: "hardware or software fault",
    4: "propagation failure",
    5: "bad date format or value",
    6: "bad time format or value"
}


# Error status words
_error_statuses = {
    0: "unspecified",
    1: "authentication failure",
    2: "invalid message length or format",
    3: "invalid opcode",
    4: "unknown association identifier",
    5: "unknown variable name",
    6: "invalid variable value",
    7: "administratively prohibited"
}


class NTPStatusPacket(Packet):
    """
    Packet handling a non specific status word.
    """

    name = "status"
    fields_desc = [ShortField("status", 0)]

    def extract_padding(self, s):
        return b"", s


class NTPSystemStatusPacket(Packet):

    """
    Packet handling the system status fields.
    """

    name = "system status"
    fields_desc = [
        BitEnumField("leap_indicator", 0, 2, _system_statuses),
        BitEnumField("clock_source", 0, 6, _clock_sources),
        BitField("system_event_counter", 0, 4),
        BitEnumField("system_event_code", 0, 4, _system_event_codes),
    ]

    def extract_padding(self, s):
        return b"", s


class NTPPeerStatusPacket(Packet):
    """
    Packet handling the peer status fields.
    """

    name = "peer status"
    fields_desc = [
        BitField("configured", 0, 1),
        BitField("auth_enabled", 0, 1),
        BitField("authentic", 0, 1),
        BitField("reachability", 0, 1),
        BitField("reserved", 0, 1),
        BitEnumField("peer_sel", 0, 3, _peer_selection),
        BitField("peer_event_counter", 0, 4),
        BitEnumField("peer_event_code", 0, 4, _peer_event_codes),
    ]

    def extract_padding(self, s):
        return b"", s


class NTPClockStatusPacket(Packet):
    """
    Packet handling the clock status fields.
    """

    name = "clock status"
    fields_desc = [
        BitEnumField("clock_status", 0, 8, _clock_statuses),
        BitField("code", 0, 8)
    ]

    def extract_padding(self, s):
        return b"", s


class NTPErrorStatusPacket(Packet):
    """
    Packet handling the error status fields.
    """

    name = "error status"
    fields_desc = [
        BitEnumField("error_code", 0, 8, _error_statuses),
        BitField("reserved", 0, 8)
    ]

    def extract_padding(self, s):
        return b"", s


class NTPControlStatusField(PacketField):
    """
    This field provides better readability for the "status" field.
    """

    #########################################################################
    #
    # RFC 1305
    #########################################################################
    #
    # Appendix B.3. Commands // ntpd source code: ntp_control.h
    #########################################################################
    #

    def m2i(self, pkt, m):
        ret = None
        association_id = struct.unpack("!H", m[2:4])[0]

        if pkt.err == 1:
            ret = NTPErrorStatusPacket(m)

        # op_code == CTL_OP_READSTAT
        elif pkt.op_code == 1:
            if association_id != 0:
                ret = NTPPeerStatusPacket(m)
            else:
                ret = NTPSystemStatusPacket(m)

        # op_code == CTL_OP_READVAR
        elif pkt.op_code == 2:
            if association_id != 0:
                ret = NTPPeerStatusPacket(m)
            else:
                ret = NTPSystemStatusPacket(m)

        # op_code == CTL_OP_WRITEVAR
        elif pkt.op_code == 3:
            ret = NTPStatusPacket(m)

        # op_code == CTL_OP_READCLOCK or op_code == CTL_OP_WRITECLOCK
        elif pkt.op_code == 4 or pkt.op_code == 5:
            ret = NTPClockStatusPacket(m)

        else:
            ret = NTPStatusPacket(m)

        return ret


class NTPPeerStatusDataPacket(Packet):
    """
    Packet handling the data field when op_code is CTL_OP_READSTAT
    and the association_id field is null.
    """

    name = "data / peer status"
    fields_desc = [
        ShortField("association_id", 0),
        PacketField("peer_status", NTPPeerStatusPacket(), NTPPeerStatusPacket),
    ]


class NTPControlDataPacketLenField(PacketLenField):

    """
    PacketField handling the "data" field of NTP control messages.
    """

    def m2i(self, pkt, m):
        ret = None

        # op_code == CTL_OP_READSTAT
        if pkt.op_code == 1:
            if pkt.association_id == 0:
                # Data contains association ID and peer status
                ret = NTPPeerStatusDataPacket(m)
            else:
                ret = conf.raw_layer(m)
        else:
            ret = conf.raw_layer(m)

        return ret

    def getfield(self, pkt, s):
        length = self.length_from(pkt)
        i = None
        if length > 0:
            # RFC 1305
            # The maximum number of data octets is 468.
            #
            # include/ntp_control.h
            # u_char data[480 + MAX_MAC_LEN]; /* data + auth */
            #
            # Set the minimum length to 480 - 468
            length = max(12, length)
            if length % 4:
                length += (4 - length % 4)
        try:
            i = self.m2i(pkt, s[:length])
        except Exception:
            if conf.debug_dissector:
                raise
            i = conf.raw_layer(load=s[:length])
        return s[length:], i


class NTPControl(NTP):
    """
    Packet handling NTP mode 6 / "Control" messages.
    """

    #########################################################################
    #
    # RFC 1305
    #########################################################################
    #
    # Appendix B.3. Commands // ntpd source code: ntp_control.h
    #########################################################################
    #

    name = "Control message"
    match_subclass = True
    fields_desc = [
        BitField("zeros", 0, 2),
        BitField("version", 2, 3),
        BitField("mode", 6, 3),
        BitField("response", 0, 1),
        BitField("err", 0, 1),
        BitField("more", 0, 1),
        BitEnumField("op_code", 0, 5, _op_codes),
        ShortField("sequence", 0),
        ConditionalField(NTPControlStatusField(
            "status_word", "", Packet), lambda p: p.response == 1),
        ConditionalField(ShortField("status", 0), lambda p: p.response == 0),
        ShortField("association_id", 0),
        ShortField("offset", 0),
        ShortField("count", None),
        NTPControlDataPacketLenField(
            "data", "", Packet, length_from=lambda p: p.count),
        PacketField("authenticator", "", NTPAuthenticator),
    ]

    def post_build(self, p, pay):
        if self.count is None:
            length = 0
            if self.data:
                length = len(self.data)
            p = p[:11] + struct.pack("!H", length) + p[13:]
        return p + pay


##############################################################################
#     Private (mode 7)
##############################################################################

_information_error_codes = {
    0: "INFO_OKAY",
    1: "INFO_ERR_IMPL",
    2: "INFO_ERR_REQ",
    3: "INFO_ERR_FMT",
    4: "INFO_ERR_NODATA",
    7: "INFO_ERR_AUTH"
}


_implementations = {
    0: "IMPL_UNIV",
    2: "IMPL_XNTPD_OLD",
    3: "XNTPD"
}


_request_codes = {
    0: "REQ_PEER_LIST",
    1: "REQ_PEER_LIST_SUM",
    2: "REQ_PEER_INFO",
    3: "REQ_PEER_STATS",
    4: "REQ_SYS_INFO",
    5: "REQ_SYS_STATS",
    6: "REQ_IO_STATS",
    7: "REQ_MEM_STATS",
    8: "REQ_LOOP_INFO",
    9: "REQ_TIMER_STATS",
    10: "REQ_CONFIG",
    11: "REQ_UNCONFIG",
    12: "REQ_SET_SYS_FLAG",
    13: "REQ_CLR_SYS_FLAG",
    14: "REQ_MONITOR",
    15: "REQ_NOMONITOR",
    16: "REQ_GET_RESTRICT",
    17: "REQ_RESADDFLAGS",
    18: "REQ_RESSUBFLAGS",
    19: "REQ_UNRESTRICT",
    20: "REQ_MON_GETLIST",
    21: "REQ_RESET_STATS",
    22: "REQ_RESET_PEER",
    23: "REQ_REREAD_KEYS",
    24: "REQ_DO_DIRTY_HACK",
    25: "REQ_DONT_DIRTY_HACK",
    26: "REQ_TRUSTKEY",
    27: "REQ_UNTRUSTKEY",
    28: "REQ_AUTHINFO",
    29: "REQ_TRAPS",
    30: "REQ_ADD_TRAP",
    31: "REQ_CLR_TRAP",
    32: "REQ_REQUEST_KEY",
    33: "REQ_CONTROL_KEY",
    34: "REQ_GET_CTLSTATS",
    35: "REQ_GET_LEAPINFO",
    36: "REQ_GET_CLOCKINFO",
    37: "REQ_SET_CLKFUDGE",
    38: "REQ_GET_KERNEL",
    39: "REQ_GET_CLKBUGINFO",
    41: "REQ_SET_PRECISION",
    42: "REQ_MON_GETLIST_1",
    43: "REQ_HOSTNAME_ASSOCID",
    44: "REQ_IF_STATS",
    45: "REQ_IF_RELOAD"
}


# Flags in the peer information returns
_peer_flags = [
    "INFO_FLAG_CONFIG",
    "INFO_FLAG_SYSPEER",
    "INFO_FLAG_BURST",
    "INFO_FLAG_REFCLOCK",
    "INFO_FLAG_PREFER",
    "INFO_FLAG_AUTHENABLE",
    "INFO_FLAG_SEL_CANDIDATE",
    "INFO_FLAG_SHORTLIST",
    "INFO_FLAG_IBURST"
]


# Flags in the system information returns
_sys_info_flags = [
    "INFO_FLAG_BCLIENT",
    "INFO_FLAG_AUTHENTICATE",
    "INFO_FLAG_NTP",
    "INFO_FLAG_KERNEL",
    "INFO_FLAG_CAL",
    "INFO_FLAG_PPS_SYNC",
    "INFO_FLAG_MONITOR",
    "INFO_FLAG_FILEGEN",
]


class NTPInfoPeerList(Packet):

    """
    Used to return raw lists of peers.
    """
    name = "info_peer_list"
    fields_desc = [
        IPField("addr", "0.0.0.0"),
        ShortField("port", 0),
        ByteEnumField("hmode", 0, _ntp_modes),
        FlagsField("flags", 0, 8, _peer_flags),
        IntField("v6_flag", 0),
        IntField("unused1", 0),
        IP6Field("addr6", "::")
    ]


class NTPInfoPeerSummary(Packet):
    """
    Sort of the info that ntpdc returns by default.
    """
    name = "info_peer_summary"
    fields_desc = [
        IPField("dstaddr", "0.0.0.0"),
        IPField("srcaddr", "0.0.0.0"),
        ShortField("srcport", 0),
        ByteField("stratum", 0),
        ByteField("hpoll", 0),
        ByteField("ppoll", 0),
        ByteField("reach", 0),
        FlagsField("flags", 0, 8, _peer_flags),
        ByteField("hmode", _ntp_modes),
        FixedPointField("delay", 0, size=32, frac_bits=16),
        TimeStampField("offset", 0),
        FixedPointField("dispersion", 0, size=32, frac_bits=16),
        IntField("v6_flag", 0),
        IntField("unused1", 0),
        IP6Field("dstaddr6", "::"),
        IP6Field("srcaddr6", "::")
    ]


class NTPInfoPeer(Packet):
    """
    Peer information structure.
    """

    name = "info_peer"
    fields_desc = [
        IPField("dstaddr", "0.0.0.0"),
        IPField("srcaddr", "0.0.0.0"),
        ShortField("srcport", 0),
        FlagsField("flags", 0, 8, _peer_flags),
        ByteField("leap", 0),
        ByteEnumField("hmode", 0, _ntp_modes),
        ByteField("pmode", 0),
        ByteField("stratum", 0),
        ByteField("ppoll", 0),
        ByteField("hpoll", 0),
        SignedByteField("precision", 0),
        ByteField("version", 0),
        ByteField("unused8", 0),
        ByteField("reach", 0),
        ByteField("unreach", 0),
        XByteField("flash", 0),
        ByteField("ttl", 0),
        XLEShortField("flash2", 0),
        ShortField("associd", 0),
        LEIntField("keyid", 0),
        IntField("pkeyid", 0),
        IPField("refid", 0),
        IntField("timer", 0),
        FixedPointField("rootdelay", 0, size=32, frac_bits=16),
        FixedPointField("rootdispersion", 0, size=32, frac_bits=16),
        TimeStampField("reftime", 0),
        TimeStampField("org", 0),
        TimeStampField("rec", 0),
        TimeStampField("xmt", 0),
        FieldListField(
            "filtdelay",
            [0.0 for i in range(0, _NTP_SHIFT)],
            FixedPointField("", 0, size=32, frac_bits=16),
            count_from=lambda p: _NTP_SHIFT
        ),
        FieldListField(
            "filtoffset",
            [0.0 for i in range(0, _NTP_SHIFT)],
            TimeStampField("", 0),
            count_from=lambda p: _NTP_SHIFT
        ),
        FieldListField(
            "order",
            [0 for i in range(0, _NTP_SHIFT)],
            ByteField("", 0),
            count_from=lambda p: _NTP_SHIFT
        ),
        FixedPointField("delay", 0, size=32, frac_bits=16),
        FixedPointField("dispersion", 0, size=32, frac_bits=16),
        TimeStampField("offset", 0),
        FixedPointField("selectdisp", 0, size=32, frac_bits=16),
        IntField("unused1", 0),
        IntField("unused2", 0),
        IntField("unused3", 0),
        IntField("unused4", 0),
        IntField("unused5", 0),
        IntField("unused6", 0),
        IntField("unused7", 0),
        FixedPointField("estbdelay", 0, size=32, frac_bits=16),
        IntField("v6_flag", 0),
        IntField("unused9", 0),
        IP6Field("dstaddr6", "::"),
        IP6Field("srcaddr6", "::"),
    ]


class NTPInfoPeerStats(Packet):
    """
    Peer statistics structure.
    """

    name = "info_peer_stats"
    fields_desc = [
        IPField("dstaddr", "0.0.0.0"),
        IPField("srcaddr", "0.0.0.0"),
        ShortField("srcport", 0),
        FlagsField("flags", 0, 16, _peer_flags),
        IntField("timereset", 0),
        IntField("timereceived", 0),
        IntField("timetosend", 0),
        IntField("timereachable", 0),
        IntField("sent", 0),
        IntField("unused1", 0),
        IntField("processed", 0),
        IntField("unused2", 0),
        IntField("badauth", 0),
        IntField("bogusorg", 0),
        IntField("oldpkt", 0),
        IntField("unused3", 0),
        IntField("unused4", 0),
        IntField("seldisp", 0),
        IntField("selbroken", 0),
        IntField("unused5", 0),
        ByteField("candidate", 0),
        ByteField("unused6", 0),
        ByteField("unused7", 0),
        ByteField("unused8", 0),
        IntField("v6_flag", 0),
        IntField("unused9", 0),
        IP6Field("dstaddr6", "::"),
        IP6Field("srcaddr6", "::"),
    ]


class NTPInfoLoop(Packet):
    """
    Loop filter variables.
    """

    name = "info_loop"
    fields_desc = [
        TimeStampField("last_offset", 0),
        TimeStampField("drift_comp", 0),
        IntField("compliance", 0),
        IntField("watchdog_timer", 0)
    ]


class NTPInfoSys(Packet):
    """
    System info. Mostly the sys.* variables, plus a few unique to
    the implementation.
    """

    name = "info_sys"
    fields_desc = [
        IPField("peer", "0.0.0.0"),
        ByteField("peer_mode", 0),
        ByteField("leap", 0),
        ByteField("stratum", 0),
        ByteField("precision", 0),
        FixedPointField("rootdelay", 0, size=32, frac_bits=16),
        FixedPointField("rootdispersion", 0, size=32, frac_bits=16),
        IPField("refid", 0),
        TimeStampField("reftime", 0),
        IntField("poll", 0),
        FlagsField("flags", 0, 8, _sys_info_flags),
        ByteField("unused1", 0),
        ByteField("unused2", 0),
        ByteField("unused3", 0),
        FixedPointField("bdelay", 0, size=32, frac_bits=16),
        FixedPointField("frequency", 0, size=32, frac_bits=16),
        TimeStampField("authdelay", 0),
        FixedPointField("stability", 0, size=32, frac_bits=16),
        IntField("v6_flag", 0),
        IntField("unused4", 0),
        IP6Field("peer6", "::")
    ]


class NTPInfoSysStats(Packet):
    """
    System stats. These are collected in the protocol module.
    """

    name = "info_sys_stats"
    fields_desc = [
        IntField("timeup", 0),
        IntField("timereset", 0),
        IntField("denied", 0),
        IntField("oldversionpkt", 0),
        IntField("newversionpkt", 0),
        IntField("unknownversion", 0),
        IntField("badlength", 0),
        IntField("processed", 0),
        IntField("badauth", 0),
        IntField("received", 0),
        IntField("limitrejected", 0)
    ]


class NTPInfoMemStats(Packet):
    """
    Peer memory statistics.
    """

    name = "info_mem_stats"
    fields_desc = [
        IntField("timereset", 0),
        ShortField("totalpeermem", 0),
        ShortField("freepeermem", 0),
        IntField("findpeer_calls", 0),
        IntField("allocations", 0),
        IntField("demobilizations", 0),
        FieldListField(
            "hashcount",
            [0.0 for i in range(0, _NTP_HASH_SIZE)],
            ByteField("", 0),
            count_from=lambda p: _NTP_HASH_SIZE
        )
    ]


class NTPInfoIOStats(Packet):
    """
    I/O statistics.
    """

    name = "info_io_stats"
    fields_desc = [
        IntField("timereset", 0),
        ShortField("totalrecvbufs", 0),
        ShortField("freerecvbufs", 0),
        ShortField("fullrecvbufs", 0),
        ShortField("lowwater", 0),
        IntField("dropped", 0),
        IntField("ignored", 0),
        IntField("received", 0),
        IntField("sent", 0),
        IntField("notsent", 0),
        IntField("interrupts", 0),
        IntField("int_received", 0)
    ]


class NTPInfoTimerStats(Packet):
    """
    Timer stats.
    """

    name = "info_timer_stats"
    fields_desc = [
        IntField("timereset", 0),
        IntField("alarms", 0),
        IntField("overflows", 0),
        IntField("xmtcalls", 0),
    ]


_conf_peer_flags = [
    "CONF_FLAG_AUTHENABLE",
    "CONF_FLAG_PREFER",
    "CONF_FLAG_BURST",
    "CONF_FLAG_IBURST",
    "CONF_FLAG_NOSELECT",
    "CONF_FLAG_SKEY"
]


class NTPConfPeer(Packet):
    """
    Structure for passing peer configuration information.
    """

    name = "conf_peer"
    fields_desc = [
        IPField("peeraddr", "0.0.0.0"),
        ByteField("hmode", 0),
        ByteField("version", 0),
        ByteField("minpoll", 0),
        ByteField("maxpoll", 0),
        FlagsField("flags", 0, 8, _conf_peer_flags),
        ByteField("ttl", 0),
        ShortField("unused1", 0),
        IntField("keyid", 0),
        StrFixedLenField("keystr", "", length=128),
        IntField("v6_flag", 0),
        IntField("unused2", 0),
        IP6Field("peeraddr6", "::")
    ]


class NTPConfUnpeer(Packet):
    """
    Structure for passing peer deletion information.
    """

    name = "conf_unpeer"
    fields_desc = [
        IPField("peeraddr", "0.0.0.0"),
        IntField("v6_flag", 0),
        IP6Field("peeraddr6", "::")
    ]


_restrict_flags = [
    "RES_IGNORE",
    "RES_DONTSERVE",
    "RES_DONTTRUST",
    "RES_VERSION",
    "RES_NOPEER",
    "RES_LIMITED",
    "RES_NOQUERY",
    "RES_NOMODIFY",
    "RES_NOTRAP",
    "RES_LPTRAP",
    "RES_KOD",
    "RES_MSSNTP",
    "RES_FLAKE",
    "RES_NOMRULIST",
]


class NTPConfRestrict(Packet):
    """
    Structure used for specifying restrict entries.
    """

    name = "conf_restrict"
    fields_desc = [
        IPField("addr", "0.0.0.0"),
        IPField("mask", "0.0.0.0"),
        FlagsField("flags", 0, 16, _restrict_flags),
        ShortField("m_flags", 0),
        IntField("v6_flag", 0),
        IP6Field("addr6", "::"),
        IP6Field("mask6", "::")
    ]


class NTPInfoKernel(Packet):
    """
    Structure used for returning kernel pll/PPS information
    """

    name = "info_kernel"
    fields_desc = [
        IntField("offset", 0),
        IntField("freq", 0),
        IntField("maxerror", 0),
        IntField("esterror", 0),
        ShortField("status", 0),
        ShortField("shift", 0),
        IntField("constant", 0),
        IntField("precision", 0),
        IntField("tolerance", 0),
        IntField("ppsfreq", 0),
        IntField("jitter", 0),
        IntField("stabil", 0),
        IntField("jitcnt", 0),
        IntField("calcnt", 0),
        IntField("errcnt", 0),
        IntField("stbcnt", 0),
    ]


class NTPInfoIfStatsIPv4(Packet):
    """
    Interface statistics.
    """

    name = "info_if_stats"
    fields_desc = [
        PadField(IPField("unaddr", "0.0.0.0"), 16, padwith=b"\x00"),
        PadField(IPField("unbcast", "0.0.0.0"), 16, padwith=b"\x00"),
        PadField(IPField("unmask", "0.0.0.0"), 16, padwith=b"\x00"),
        IntField("v6_flag", 0),
        StrFixedLenField("ifname", "", length=32),
        IntField("flags", 0),
        IntField("last_ttl", 0),
        IntField("num_mcast", 0),
        IntField("received", 0),
        IntField("sent", 0),
        IntField("notsent", 0),
        IntField("uptime", 0),
        IntField("scopeid", 0),
        IntField("ifindex", 0),
        IntField("ifnum", 0),
        IntField("peercnt", 0),
        ShortField("family", 0),
        ByteField("ignore_packets", 0),
        ByteField("action", 0),
        IntField("_filler0", 0)
    ]


class NTPInfoIfStatsIPv6(Packet):
    """
    Interface statistics.
    """

    name = "info_if_stats"
    fields_desc = [
        IP6Field("unaddr", "::"),
        IP6Field("unbcast", "::"),
        IP6Field("unmask", "::"),
        IntField("v6_flag", 0),
        StrFixedLenField("ifname", "", length=32),
        IntField("flags", 0),
        IntField("last_ttl", 0),
        IntField("num_mcast", 0),
        IntField("received", 0),
        IntField("sent", 0),
        IntField("notsent", 0),
        IntField("uptime", 0),
        IntField("scopeid", 0),
        IntField("ifindex", 0),
        IntField("ifnum", 0),
        IntField("peercnt", 0),
        ShortField("family", 0),
        ByteField("ignore_packets", 0),
        ByteField("action", 0),
        IntField("_filler0", 0)
    ]


class NTPInfoMonitor1(Packet):
    """
    Structure used for returning monitor data.
    """

    name = "InfoMonitor1"
    fields_desc = [
        IntField("lasttime", 0),
        IntField("firsttime", 0),
        IntField("lastdrop", 0),
        IntField("count", 0),
        IPField("addr", "0.0.0.0"),
        IPField("daddr", "0.0.0.0"),
        IntField("flags", 0),
        ShortField("port", 0),
        ByteField("mode", 0),
        ByteField("version", 0),
        IntField("v6_flag", 0),
        IntField("unused1", 0),
        IP6Field("addr6", "::"),
        IP6Field("daddr6", "::")
    ]


class NTPInfoAuth(Packet):
    """
    Structure used to return information concerning the authentication module.
    """

    name = "info_auth"
    fields_desc = [
        IntField("timereset", 0),
        IntField("numkeys", 0),
        IntField("numfreekeys", 0),
        IntField("keylookups", 0),
        IntField("keynotfound", 0),
        IntField("encryptions", 0),
        IntField("decryptions", 0),
        IntField("expired", 0),
        IntField("keyuncached", 0),
    ]


class NTPConfTrap(Packet):
    """
    Structure used to pass add/clear trap information to the client
    """

    name = "conf_trap"
    fields_desc = [
        IPField("local_address", "0.0.0.0"),
        IPField("trap_address", "0.0.0.0"),
        ShortField("trap_port", 0),
        ShortField("unused", 0),
        IntField("v6_flag", 0),
        IP6Field("local_address6", "::"),
        IP6Field("trap_address6", "::"),
    ]


class NTPInfoControl(Packet):
    """
    Structure used to return statistics from the control module.
    """

    name = "info_control"
    fields_desc = [
        IntField("ctltimereset", 0),
        IntField("numctlreq", 0),
        IntField("numctlbadpkts", 0),
        IntField("numctlresponses", 0),
        IntField("numctlfrags", 0),
        IntField("numctlerrors", 0),
        IntField("numctltooshort", 0),
        IntField("numctlinputresp", 0),
        IntField("numctlinputfrag", 0),
        IntField("numctlinputerr", 0),
        IntField("numctlbadoffset", 0),
        IntField("numctlbadversion", 0),
        IntField("numctldatatooshort", 0),
        IntField("numctlbadop", 0),
        IntField("numasyncmsgs", 0),
    ]


# ntp_request.h
_ntpd_private_errors = {
    0: "no error",
    1: "incompatible implementation number",
    2: "unimplemented request code",
    3: "format error (wrong data items, data size, packet size etc.)",
    4: "no data available (e.g. request for details on unknown peer)",
    5: "I don\"t know",
    6: "I don\"t know",
    7: "authentication failure (i.e. permission denied)",
}


# dict mapping request codes to the right response data class
_private_data_objects = {
    0: NTPInfoPeerList,  # "REQ_PEER_LIST",
    1: NTPInfoPeerSummary,  # "REQ_PEER_LIST_SUM",
    2: NTPInfoPeer,  # "REQ_PEER_INFO",
    3: NTPInfoPeerStats,  # "REQ_PEER_STATS",
    4: NTPInfoSys,  # "REQ_SYS_INFO",
    5: NTPInfoSysStats,  # "REQ_SYS_STATS",
    6: NTPInfoIOStats,  # "REQ_IO_STATS",
    7: NTPInfoMemStats,  # "REQ_MEM_STATS",
    8: NTPInfoLoop,  # "REQ_LOOP_INFO",
    9: NTPInfoTimerStats,  # "REQ_TIMER_STATS",
    10: NTPConfPeer,  # "REQ_CONFIG",
    11: NTPConfUnpeer,  # "REQ_UNCONFIG",
    28: NTPInfoAuth,  # "REQ_AUTHINFO",
    30: NTPConfTrap,  # "REQ_ADD_TRAP",
    34: NTPInfoControl,  # "REQ_GET_CTLSTATS",
    38: NTPInfoKernel,  # "REQ_GET_KERNEL",
    42: NTPInfoMonitor1,  # "REQ_MON_GETLIST_1",
}


class NTPPrivateRespPacketListField(PacketListField):
    """
    PacketListField handling the response data.
    """

    def m2i(self, pkt, s):
        ret = None

        # info_if_stats
        if pkt.request_code == 44 or pkt.request_code == 45:
            is_v6 = struct.unpack("!I", s[48:52])[0]
            ret = NTPInfoIfStatsIPv6(s) if is_v6 else NTPInfoIfStatsIPv4(s)
        else:
            ret = _private_data_objects.get(pkt.request_code, conf.raw_layer)(s)  # noqa: E501

        return ret

    def getfield(self, pkt, s):
        lst = []
        remain = s
        length = pkt.data_item_size
        if length > 0:
            item_counter = 0
            # Response payloads can be placed in several packets
            while len(remain) >= pkt.data_item_size and item_counter < pkt.nb_items:  # noqa: E501
                current = remain[:length]
                remain = remain[length:]
                current_packet = self.m2i(pkt, current)
                lst.append(current_packet)
                item_counter += 1

        return remain, lst


class NTPPrivateReqPacket(Packet):
    """
    Packet handling request data.
    """

    name = "request data"
    fields_desc = [StrField("req_data", "")]


_request_codes = {
    0: "REQ_PEER_LIST",
    1: "REQ_PEER_LIST_SUM",
    2: "REQ_PEER_INFO",
    3: "REQ_PEER_STATS",
    4: "REQ_SYS_INFO",
    5: "REQ_SYS_STATS",
    6: "REQ_IO_STATS",
    7: "REQ_MEM_STATS",
    8: "REQ_LOOP_INFO",
    9: "REQ_TIMER_STATS",
    10: "REQ_CONFIG",
    11: "REQ_UNCONFIG",
    12: "REQ_SET_SYS_FLAG",
    13: "REQ_CLR_SYS_FLAG",
    14: "REQ_MONITOR",
    15: "REQ_NOMONITOR",
    16: "REQ_GET_RESTRICT",
    17: "REQ_RESADDFLAGS",
    18: "REQ_RESSUBFLAGS",
    19: "REQ_UNRESTRICT",
    20: "REQ_MON_GETLIST",
    21: "REQ_RESET_STATS",
    22: "REQ_RESET_PEER",
    23: "REQ_REREAD_KEYS",
    24: "REQ_DO_DIRTY_HACK",
    25: "REQ_DONT_DIRTY_HACK",
    26: "REQ_TRUSTKEY",
    27: "REQ_UNTRUSTKEY",
    28: "REQ_AUTHINFO",
    29: "REQ_TRAPS",
    30: "REQ_ADD_TRAP",
    31: "REQ_CLR_TRAP",
    32: "REQ_REQUEST_KEY",
    33: "REQ_CONTROL_KEY",
    34: "REQ_GET_CTLSTATS",
    35: "REQ_GET_LEAPINFO",
    36: "REQ_GET_CLOCKINFO",
    37: "REQ_SET_CLKFUDGE",
    38: "REQ_GET_KERNEL",
    39: "REQ_GET_CLKBUGINFO",
    41: "REQ_SET_PRECISION",
    42: "REQ_MON_GETLIST_1",
    43: "REQ_HOSTNAME_ASSOCID",
    44: "REQ_IF_STATS",
    45: "REQ_IF_RELOAD"
}


class NTPPrivateReqPacketListField(PacketListField):
    """
    Handles specific request packets.
    """

    # See ntpdc/ntpdc.c and ntpdc/ntpdc_ops.c

    def m2i(self, pkt, s):
        ret = None

        if pkt.request_code == 2 or pkt.request_code == 3:
            # REQ_PEER_INFO (see ntpdc/ntpdc_ops.c: showpeer())
            # REQ_PEER_STATS (for request only)
            ret = NTPInfoPeerList(s)

        elif pkt.request_code == 10:
            # REQ_CONFIG
            ret = NTPConfPeer(s)

        elif pkt.request_code == 11:
            # REQ_CONFIG
            ret = NTPConfUnpeer(s)

        elif pkt.request_code == 17:
            # REQ_RESADDFLAGS
            ret = NTPConfRestrict(s)

        elif pkt.request_code == 18:
            # REQ_RESSUBFLAGS
            ret = NTPConfRestrict(s)

        elif pkt.request_code == 22:
            # REQ_RESET_PEER
            ret = NTPConfUnpeer(s)

        elif pkt.request_code == 30 or pkt.request_code == 31:
            # REQ_ADD_TRAP
            ret = NTPConfTrap(s)

        else:
            ret = NTPPrivateReqPacket(s)

        return ret

    def getfield(self, pkt, s):
        lst = []
        remain = s
        length = pkt.data_item_size
        if length > 0:
            item_counter = 0
            while len(remain) >= pkt.data_item_size * pkt.nb_items and item_counter < pkt.nb_items:  # noqa: E501
                current = remain[:length]
                remain = remain[length:]
                current_packet = self.m2i(pkt, current)
                lst.append(current_packet)
                item_counter += 1

        # If "auth" bit is set, don't forget the padding bytes
        if pkt.auth:
            padding_end = len(remain) - _NTP_PRIVATE_REQ_PKT_TAIL_LEN
            current_packet = conf.raw_layer(remain[:padding_end])
            lst.append(current_packet)
            remain = remain[padding_end:]

        return remain, lst


class NTPPrivatePktTail(Packet):
    """
    include/ntp_request.h
    The req_pkt_tail structure is used by ntpd to adjust for different
    packet sizes that may arrive.
    """

    name = "req_pkt_tail"
    fields_desc = [
        TimeStampField("tstamp", 0),
        IntField("key_id", 0),
        XStrFixedLenField(
            "dgst", "", length_from=lambda x: _NTP_AUTH_MD5_DGST_SIZE)
    ]


class NTPPrivate(NTP):
    """
    Packet handling the private (mode 7) messages.
    """

    #########################################################################
    # ntpd source code: ntp_request.h
    #########################################################################
    #
    # A mode 7 packet is used exchanging data between an NTP server
    # and a client for purposes other than time synchronization, e.g.
    # monitoring, statistics gathering and configuration.  A mode 7
    # packet has the following format:
    #
    #    0                        1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |R|M| VN  | Mode|A|  Sequence   | Implementation|   Req Code    |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |  Err  | Number of data items  |  MBZ  |   Size of data item   |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   |            Data (Minimum 0 octets, maximum 500 octets)        |
    #   |                                                               |
    #                            [...]                                  |
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |               Encryption Keyid (when A bit set)               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   |          Message Authentication Code (when A bit set)         |
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # where the fields are (note that the client sends requests, the server
    # responses):
    #
    # Response Bit:  This packet is a response (if clear, packet is a request).
    #
    # More Bit: Set for all packets but the last in a response which
    #           requires more than one packet.
    #
    # Version Number: 2 for current version
    #
    # Mode:     Always 7
    #
    # Authenticated bit: If set, this packet is authenticated.
    #
    # Sequence number: For a multipacket response, contains the sequence
    #           number of this packet.  0 is the first in the sequence,
    #           127 (or less) is the last.  The More Bit must be set in
    #           all packets but the last.
    #
    # Implementation number: The number of the implementation this request code
    #           is defined by.  An implementation number of zero is used
    #           for request codes/data formats which all implementations
    #           agree on.  Implementation number 255 is reserved (for
    #           extensions, in case we run out).
    #
    # Request code: An implementation-specific code which specifies the
    #           operation to be (which has been) performed and/or the
    #           format and semantics of the data included in the packet.
    #
    # Err:      Must be 0 for a request.  For a response, holds an error
    #           code relating to the request.  If nonzero, the operation
    #           requested wasn't performed.
    #
    #           0 - no error
    #           1 - incompatible implementation number
    #           2 - unimplemented request code
    #           3 - format error (wrong data items, data size, packet size etc.)  # noqa: E501
    #           4 - no data available (e.g. request for details on unknown peer)  # noqa: E501
    #           5-6 I don"t know
    #           7 - authentication failure (i.e. permission denied)
    #
    # Number of data items: number of data items in packet.  0 to 500
    #
    # MBZ:      A reserved data field, must be zero in requests and responses.
    #
    # Size of data item: size of each data item in packet.  0 to 500
    #
    # Data:     Variable sized area containing request/response data.  For
    #           requests and responses the size in octets must be greater
    #           than or equal to the product of the number of data items
    #           and the size of a data item.  For requests the data area
    #           must be exactly 40 octets in length.  For responses the
    #           data area may be any length between 0 and 500 octets
    #           inclusive.
    #
    # Message Authentication Code: Same as NTP spec, in definition and function.  # noqa: E501
    #           May optionally be included in requests which require
    #           authentication, is never included in responses.
    #
    # The version number, mode and keyid have the same function and are
    # in the same location as a standard NTP packet.  The request packet
    # is the same size as a standard NTP packet to ease receive buffer
    # management, and to allow the same encryption procedure to be used
    # both on mode 7 and standard NTP packets.  The mac is included when
    # it is required that a request be authenticated, the keyid should be
    # zero in requests in which the mac is not included.
    #
    # The data format depends on the implementation number/request code pair
    # and whether the packet is a request or a response.  The only requirement
    # is that data items start in the octet immediately following the size
    # word and that data items be concatenated without padding between (i.e.
    # if the data area is larger than data_items*size, all padding is at
    # the end).  Padding is ignored, other than for encryption purposes.
    # Implementations using encryption might want to include a time stamp
    # or other data in the request packet padding.  The key used for requests
    # is implementation defined, but key 15 is suggested as a default.
    #########################################################################
    #

    name = "Private (mode 7)"
    match_subclass = True
    fields_desc = [
        BitField("response", 0, 1),
        BitField("more", 0, 1),
        BitField("version", 2, 3),
        BitField("mode", 0, 3),
        BitField("auth", 0, 1),
        BitField("seq", 0, 7),
        ByteEnumField("implementation", 0, _implementations),
        ByteEnumField("request_code", 0, _request_codes),
        BitEnumField("err", 0, 4, _ntpd_private_errors),
        BitField("nb_items", 0, 12),
        BitField("mbz", 0, 4),
        BitField("data_item_size", 0, 12),
        ConditionalField(
            NTPPrivateReqPacketListField(
                "req_data",
                [],
                Packet,
                length_from=lambda p: p.data_item_size,
                count_from=lambda p: p.nb_items
            ),
            lambda p: p.response == 0
        ),
        # Responses
        ConditionalField(
            NTPPrivateRespPacketListField(
                "data",
                [],
                Packet,
                length_from=lambda p: p.data_item_size,
                count_from=lambda p: p.nb_items
            ),
            lambda p: p.response == 1
        ),
        # Responses are not supposed to be authenticated
        ConditionalField(PacketField("authenticator", "", NTPPrivatePktTail),
                         lambda p: p.response == 0 and p.auth == 1),
    ]


##############################################################################
#     Layer bindings
##############################################################################

bind_layers(UDP, NTP, {"sport": 123})
bind_layers(UDP, NTP, {"dport": 123})
bind_layers(UDP, NTP, {"sport": 123, "dport": 123})
