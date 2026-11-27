# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
# Copyright (C) Roger Meyer <roger.meyer@csus.edu>: 2012-03-10 Added frames
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>: 2018
# Copyright (C) Dimitrios-Georgios Akestoridis <akestoridis@cmu.edu>
# Copyright (C) Noë Flatreaud <nflatrea@mailo.com>

# Notes on IEEE 802.15.4-2024+
# Lacking irl samples to test it out, I'll build specific uts 
# part for testing but we need to try it on aquired frames.

"""
Wireless MAC according to IEEE 802.15.4.
"""

import struct

from scapy.compat import chb
from scapy.error import warning
from scapy.config import conf

from scapy.data import DLT_IEEE802_15_4_WITHFCS, DLT_IEEE802_15_4_NOFCS
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitEnumField,
    BitField,
    BitFieldLenField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Emph,
    FCSField,
    Field,
    FieldListField,
    LELongField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    StrFixedLenField,
    StrLenField,
    XByteField,
    XLEIntField,
    XLEShortField,
)

# Fields #


class dot15d4AddressField(Field):
    __slots__ = ["adjust", "length_of"]

    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        if adjust is not None:
            self.adjust = adjust
        else:
            self.adjust = lambda pkt, x: self.lengthFromAddrMode(pkt, x)

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt, x))) < 7:  # short address
            return hex(self.i2m(pkt, x))
        else:  # long address
            x = "%016x" % self.i2m(pkt, x)
            return ":".join(["%s%s" % (x[i], x[i + 1]) for i in range(0, len(x), 2)])  # noqa: E501

    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0] + "H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + struct.pack(self.fmt[0] + "Q", val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0] + "H", s[:2])[0])  # noqa: E501
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0] + "Q", s[:8])[0])  # noqa: E501
        else:
            raise Exception('impossible case')

    def lengthFromAddrMode(self, pkt, x):
        addrmode = 0
        pkttop = pkt.underlayer
        if pkttop is None:
            warning("No underlayer to guess address mode")
            return 0
        while True:
            try:
                addrmode = pkttop.getfieldval(x)
                break
            except Exception:
                if pkttop.underlayer is None:
                    break
                pkttop = pkttop.underlayer
        # print("Underlayer field value of", x, "is", addrmode)
        if addrmode == 2:
            return 2
        elif addrmode == 3:
            return 8
        return 0

# Helpers #

# Frame control (IEEE 802.15.4-2024)

# Frame Version field (7.2.2.10, Table 7-4).
# 0b10 enables sequence number suppression, IE Present, optional addressing
# fields and PAN ID Compression rules (Table 7-2).

DOT15D4_FRAME_VERSION_2015 = 0b10

# Header/Payload IE termination identifiers (7.4.1, Table 7-7 and Table 7-8)

DOT15D4_HEADER_IE_HT1 = 0x7e
DOT15D4_HEADER_IE_HT2 = 0x7f
DOT15D4_PAYLOAD_IE_TERMINATION_GID = 0xf


def dot15d4_fcf(pkt):
    """Return the Frame Control carrying layer (Dot15d4/Dot15d4FCS) of pkt."""
    # Standalone dissection/build of a MAC payload class: assume defaults
    return pkt.underlayer if pkt.underlayer is not None else Dot15d4()


def util_dstaddr_present(pkt):
    return dot15d4_fcf(pkt).getfieldval("fcf_destaddrmode") in (2, 3)


def util_srcaddr_present(pkt):
    return dot15d4_fcf(pkt).getfieldval("fcf_srcaddrmode") in (2, 3)


def util_panid_presence(fcf):
    """Return (dst_panid_present, src_panid_present) for a Frame Control layer.

    Frame version 0b00/0b01 (7.2.2.6):
    include destination PAN ID if destination address is present.
    include source PAN ID if source address is present and PAN ID compression == 0.

    Frame version 0b10: Table 7-2.
    """
    dam = fcf.getfieldval("fcf_destaddrmode")
    sam = fcf.getfieldval("fcf_srcaddrmode")
    comp = bool(fcf.getfieldval("fcf_panidcompress"))
    has_dst = dam in (2, 3)
    has_src = sam in (2, 3)
    if fcf.getfieldval("fcf_framever") != DOT15D4_FRAME_VERSION_2015:
        return has_dst, has_src and not comp
    if not has_dst and not has_src:
        return comp, False
    if has_dst and not has_src:
        return not comp, False
    if not has_dst and has_src:
        return False, not comp
    if dam == 3 and sam == 3:  # both extended
        return not comp, False
    # at least one short address, both present
    return True, not comp


def util_dstpanid_present(pkt):
    return util_panid_presence(dot15d4_fcf(pkt))[0]


def util_srcpanid_present(pkt):
    """A source PAN ID is included depending on addressing modes, the PAN ID
    Compression field and the frame version (see util_panid_presence)."""
    return util_panid_presence(dot15d4_fcf(pkt))[1]


def util_seqnum_present(pkt):
    return not pkt.getfieldval("fcf_seqnumsuppress")


def util_security_enabled(pkt):
    return bool(dot15d4_fcf(pkt).getfieldval("fcf_security"))


def util_ie_present(pkt):
    return bool(dot15d4_fcf(pkt).getfieldval("fcf_ie_present"))


def util_enhanced(pkt):
    return dot15d4_fcf(pkt).getfieldval("fcf_framever") == DOT15D4_FRAME_VERSION_2015


def util_legacy_beacon(pkt):
    return not util_enhanced(pkt)


def util_encrypted(pkt):
    """True if the MAC payload is encrypted (Security Level >= 4)."""
    ash = pkt.getfieldval("aux_sec_header")
    return ash is not None and ash.sec_sc_seclevel >= 4


def util_payload_ies_present(pkt):
    """Payload IEs are only present after a Header Termination 1 IE (7.4.1),
    and cannot be dissected when the payload is encrypted."""
    if not util_ie_present(pkt) or util_encrypted(pkt):
        return False
    hies = pkt.getfieldval("header_ies")
    return bool(hies) and hies[-1].element_id == DOT15D4_HEADER_IE_HT1


def _header_ie_next(pkt, lst, cur, remain):
    if len(remain) < 2:
        return None
    if cur is not None and cur.element_id in (DOT15D4_HEADER_IE_HT1, DOT15D4_HEADER_IE_HT2):
        return None
    return Dot15d4HeaderIE


def _payload_ie_next(pkt, lst, cur, remain):
    if len(remain) < 2:
        return None
    if cur is not None and cur.group_id == DOT15D4_PAYLOAD_IE_TERMINATION_GID:
        return None
    return Dot15d4PayloadIE


def dot15d4_mhr_fields(dest_addr_default=0xFFFF):
    """Addressing fields + Auxiliary Security Header + Header IEs, in MHR
    order (7.2.1). Shared by Data, Command, Ack (Enh-Ack) and Beacon."""
    return [
        ConditionalField(XLEShortField("dest_panid", 0xFFFF),
                         lambda pkt: util_dstpanid_present(pkt)),
        ConditionalField(dot15d4AddressField("dest_addr", dest_addr_default, length_of="fcf_destaddrmode"),  # noqa: E501
                         lambda pkt: util_dstaddr_present(pkt)),
        ConditionalField(XLEShortField("src_panid", 0x0),
                         lambda pkt: util_srcpanid_present(pkt)),
        ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),  # noqa: E501
                         lambda pkt: util_srcaddr_present(pkt)),
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt: util_security_enabled(pkt)),
        # Header IEs present if fcf_ie_present == True (frame version 2 only)
        ConditionalField(PacketListField("header_ies", [], Dot15d4HeaderIE, next_cls_cb=_header_ie_next),  # noqa: E501
                         lambda pkt: util_ie_present(pkt)),
    ]


def dot15d4_payload_ie_field():
    return ConditionalField(
        PacketListField("payload_ies", [], Dot15d4PayloadIE, next_cls_cb=_payload_ie_next),  # noqa: E501
        lambda pkt: util_payload_ies_present(pkt))


# Layers #

class Dot15d4(Packet):
    name = "802.15.4"
    fields_desc = [
        BitField("fcf_reserved_1", 0, 1),  # fcf p1 b1
        BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
        BitEnumField("fcf_ackreq", 0, 1, [False, True]),
        BitEnumField("fcf_pending", 0, 1, [False, True]),
        BitEnumField("fcf_security", 0, 1, [False, True]),  # fcf p1 b2
        Emph(BitEnumField("fcf_frametype", 0, 3, {0: "Beacon", 1: "Data", 2: "Ack", 3: "Command", 5: "Multipurpose", 6: "Fragment", 7: "Extended"})),  # noqa: E501
        BitEnumField("fcf_srcaddrmode", 0, 2, {0: "None", 1: "Reserved", 2: "Short", 3: "Long"}),  # fcf p2 b1  # noqa: E501
        BitEnumField("fcf_framever", 0, 2, {0: "2003", 1: "2006", 2: "2015+", 3: "Reserved"}),  # 0b10 = 802.15.4-2015/2020/2024  # noqa: E501
        BitEnumField("fcf_destaddrmode", 2, 2, {0: "None", 1: "Reserved", 2: "Short", 3: "Long"}),  # fcf p2 b2  # noqa: E501
        # these were reserved bits in 2003/2006
        BitEnumField("fcf_ie_present", 0, 1, [False, True]),  # fcf p2 bit 1
        BitEnumField("fcf_seqnumsuppress", 0, 1, [False, True]),  # fcf p2 bit 0
        # sequence number, absent if Sequence Number Suppression == 1
        ConditionalField(Emph(ByteField("seqnum", 1)),
                         lambda pkt: util_seqnum_present(pkt)),
    ]

    def mysummary(self):
        seq = "-" if self.fcf_seqnumsuppress else self.seqnum
        return self.sprintf("802.15.4 %Dot15d4.fcf_frametype% ackreq(%Dot15d4.fcf_ackreq%) ( %Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% ) Seq#") + str(seq)  # noqa: E501

    def guess_payload_class(self, payload):
        if self.fcf_frametype == 0x00:
            return Dot15d4Beacon
        elif self.fcf_frametype == 0x01:
            return Dot15d4Data
        elif self.fcf_frametype == 0x02:
            return Dot15d4Ack
        elif self.fcf_frametype == 0x03:
            return Dot15d4Cmd
        else:
            return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2:  # ack
                if self.seqnum != other.seqnum:  # check for seqnum matching
                    return 0
                elif other.fcf_ackreq == 1:  # check that an ack was indeed requested  # noqa: E501
                    return 1
        return 0

    def post_build(self, p, pay):
        # This just forces destaddrmode to None for Imm-Ack frames
        # (frame version 0b00/0b01). Enh-Ack (0b10) may carry addressing.
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0 \
                and self.fcf_framever != DOT15D4_FRAME_VERSION_2015:
            self.fcf_destaddrmode = 0
            return p[:1] + \
                chb((self.fcf_srcaddrmode << 6) + (self.fcf_framever << 4)) \
                + p[2:] + pay
        else:
            return p + pay


class Dot15d4FCS(Dot15d4):
    '''
    This class is a drop-in replacement for the Dot15d4 class above, except
    it expects a FCS/checksum in the input, and produces one in the output.
    This provides the user flexibility, as many 802.15.4 interfaces will have an AUTO_CRC setting  # noqa: E501
    that will validate the FCS/CRC in firmware, and add it automatically when transmitting.  # noqa: E501
    '''
    name = "802.15.4 - FCS"
    match_subclass = True
    fields_desc = Dot15d4.fields_desc + [FCSField("fcs", None, fmt="<H")]

    def compute_fcs(self, data):
        # Do a CRC-CCITT Kermit 16bit on the data given
        # Returns a CRC that is the FCS for the frame
        #  Implemented using pseudocode from: June 1986, Kermit Protocol Manual
        #  See also:
        #   http://regregex.bbcmicro.net/crc-catalogue.htm#crc.cat.kermit
        crc = 0
        for i in range(0, len(data)):
            c = data[i]
            q = (crc ^ c) & 15  # Do low-order 4 bits
            crc = (crc // 16) ^ (q * 4225)
            q = (crc ^ (c // 16)) & 15  # And high 4 bits
            crc = (crc // 16) ^ (q * 4225)
        return struct.pack('<H', crc)  # return as bytes in little endian order

    def post_build(self, p, pay):
        # construct the packet with the FCS at the end
        p = Dot15d4.post_build(self, p, pay)
        if self.fcs is None:
            p = p[:-2]
            p = p + self.compute_fcs(p)
        return p


class Dot15d4AuxSecurityHeader(Packet):
    name = "802.15.4 Auxiliary Security Header"
    fields_desc = [
        BitField("sec_sc_reserved", 0, 1),  # bit 7
        BitField("sec_sc_asn_in_nonce", 0, 1),  # bit 6 (802.15.4-2015+)
        BitField("sec_sc_fcsuppress", 0, 1),  # bit 5 Frame Counter Suppression  # noqa: E501
        # Key Identifier Mode
        # 0: Key is determined implicitly from the originator and recipient(s) of the frame  # noqa: E501
        # 1: Key is determined explicitly from the the 1-octet Key Index subfield of the Key Identifier field  # noqa: E501
        # 2: Key is determined explicitly from the 4-octet Key Source and the 1-octet Key Index  # noqa: E501
        # 3: Key is determined explicitly from the 8-octet Key Source and the 1-octet Key Index  # noqa: E501
        BitEnumField("sec_sc_keyidmode", 0, 2, {
            0: "Implicit", 1: "1oKeyIndex", 2: "4o-KeySource-1oKeyIndex", 3: "8o-KeySource-1oKeyIndex"}  # noqa: E501
        ),
        BitEnumField("sec_sc_seclevel", 0, 3, {0: "None", 1: "MIC-32", 2: "MIC-64", 3: "MIC-128", 4: "ENC", 5: "ENC-MIC-32", 6: "ENC-MIC-64", 7: "ENC-MIC-128"}),  # noqa: E501
        # 4 octets, absent if Frame Counter Suppression == 1 (9.4.2.4)
        ConditionalField(XLEIntField("sec_framecounter", 0x00000000),
                         lambda pkt: not pkt.getfieldval("sec_sc_fcsuppress")),
        # Key Identifier (variable length): identifies the key that is used for cryptographic protection  # noqa: E501
        # Key Source : length of sec_keyid_keysource varies btwn 0, 4, and 8 bytes depending on sec_sc_keyidmode  # noqa: E501
        MultipleTypeField([
            # 4 octets when sec_sc_keyidmode == 2
            (XLEIntField("sec_keyid_keysource", 0x00000000),
                lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 2),
            # 8 octets when sec_sc_keyidmode == 3
            (LELongField("sec_keyid_keysource", 0x0000000000000000),
                lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 3),
        ], StrFixedLenField("sec_keyid_keysource", "", length=0)),
        # Key Index (1 octet): allows unique identification of different keys with the same originator  # noqa: E501
        ConditionalField(XByteField("sec_keyid_keyindex", 0xFF),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") != 0),
    ]

    def extract_padding(self, s):
        return b"", s


class _Dot15d4IE(Packet):
    """Common helper for IE descriptors: they are little-endian 16-bit words,
    so the bit-fields are declared on the byte-swapped word."""

    def do_dissect(self, s):
        return Packet.do_dissect(self, s[1::-1] + s[2:])

    def post_build(self, p, pay):
        return p[1::-1] + p[2:] + pay

    def extract_padding(self, s):
        return b"", s


class Dot15d4HeaderIE(_Dot15d4IE):
    name = "802.15.4 Header IE"  # 7.4.2.1
    fields_desc = [
        BitField("type", 0, 1),  # bit 15, 0 for Header IEs
        BitEnumField("element_id", 0, 8, {
            0x00: "VendorSpecific", 0x1a: "CSL", 0x1b: "RIT",
            0x1c: "DSMEPANDescriptor", 0x1d: "RendezvousTime",
            0x1e: "TimeCorrection", 0x21: "ExtDSMEPANDescriptor",
            0x22: "FSCD", 0x23: "SimplifiedSuperframeSpec",
            0x24: "SimplifiedGTSSpec", 0x25: "LECIMCapabilities",
            0x26: "TRLEDescriptor", 0x27: "RCCCapabilities",
            0x28: "RCCNDescriptor", 0x29: "GlobalTime",
            0x2a: "ExternalOrganization",  # e.g. Wi-SUN
            0x2b: "DA", 0x2c: "RSSD",
            0x7e: "HeaderTermination1", 0x7f: "HeaderTermination2"}),
        BitFieldLenField("length", None, 7, length_of="content"),
        StrLenField("content", b"", length_from=lambda pkt: pkt.length),
    ]


class Dot15d4PayloadIE(_Dot15d4IE):
    name = "802.15.4 Payload IE"  # 7.4.3.1
    fields_desc = [
        BitField("type", 1, 1),  # bit 15, 1 for Payload IEs
        BitEnumField("group_id", 0, 4, {
            0x0: "ESDU", 0x1: "MLME", 0x2: "VendorSpecificNested",
            0xf: "PayloadTermination"}),
        BitFieldLenField("length", None, 11, length_of="content"),
        StrLenField("content", b"", length_from=lambda pkt: pkt.length),
    ]


class Dot15d4Ack(Packet):
    """Imm-Ack (frame version 0b00/0b01): empty. Enh-Ack (0b10, 7.3.3):
    optional addressing, Auxiliary Security Header and IEs."""
    name = "802.15.4 Ack"
    fields_desc = [
        ConditionalField(f, lambda pkt: util_enhanced(pkt))
        for f in dot15d4_mhr_fields()
    ] + [dot15d4_payload_ie_field()]

    def guess_payload_class(self, payload):
        if util_encrypted(self):
            return conf.raw_layer
        return Packet.guess_payload_class(self, payload)


class Dot15d4Data(Packet):
    name = "802.15.4 Data"
    fields_desc = dot15d4_mhr_fields(0xFFFF) + [dot15d4_payload_ie_field()]

    def guess_payload_class(self, payload):
        # Encrypted payloads (sec_sc_seclevel >= 4) cannot be dissected further
        if util_encrypted(self):
            return conf.raw_layer
        # TODO: See how it's done in wireshark:
        # https://github.com/wireshark/wireshark/blob/93c60b3b7c801dddd11d8c7f2a0ea4b7d02d700a/epan/dissectors/packet-ieee802154.c#L2061  # noqa: E501
        # it's too magic to me
        from scapy.layers.sixlowpan import SixLoWPAN
        from scapy.layers.zigbee import ZigbeeNWK
        if conf.dot15d4_protocol == "sixlowpan":
            return SixLoWPAN
        elif conf.dot15d4_protocol == "zigbee":
            return ZigbeeNWK
        else:
            if conf.dot15d4_protocol is None:
                _msg = "Please set conf.dot15d4_protocol to select a " + \
                       "802.15.4 protocol. Values must be in the list: "
            else:
                _msg = "Unknown conf.dot15d4_protocol value: must be in "
            warning(_msg +
                    "['sixlowpan', 'zigbee']" +
                    " Defaulting to SixLoWPAN")
            return SixLoWPAN

    def mysummary(self):
        # absent (suppressed) PAN IDs/addresses are omitted from the summary
        src = ":".join(self.sprintf("%Dot15d4Data." + f + "%") for f, present in (("src_panid", util_srcpanid_present(self)), ("src_addr", util_srcaddr_present(self))) if present) or "-"  # noqa: E501
        dst = ":".join(self.sprintf("%Dot15d4Data." + f + "%") for f, present in (("dest_panid", util_dstpanid_present(self)), ("dest_addr", util_dstaddr_present(self))) if present) or "-"  # noqa: E501
        return "802.15.4 Data ( %s -> %s )" % (src, dst)


class Dot15d4Beacon(Packet):
    """Beacon (frame version 0b00/0b01) or Enhanced Beacon (0b10, 7.3.1).
    An Enhanced Beacon has no Superframe Specification, GTS or Pending
    Address fields, only addressing, security, IEs and beacon payload."""
    name = "802.15.4 Beacon"
    fields_desc = [
        # Enhanced Beacon: generic addressing rules (Table 7-2)
        ConditionalField(XLEShortField("dest_panid", 0xFFFF),
                         lambda pkt: util_enhanced(pkt) and util_dstpanid_present(pkt)),  # noqa: E501
        ConditionalField(dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),  # noqa: E501
                         lambda pkt: util_enhanced(pkt) and util_dstaddr_present(pkt)),  # noqa: E501
        # Legacy beacon: Source PAN ID always present (PAN ID Compression
        # is ignored on reception, 7.3.1.2)
        ConditionalField(XLEShortField("src_panid", 0x0),
                         lambda pkt: (not util_enhanced(pkt)) or util_srcpanid_present(pkt)),  # noqa: E501
        ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),  # noqa: E501
                         lambda pkt: util_srcaddr_present(pkt)),
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt: util_security_enabled(pkt)),
        ConditionalField(PacketListField("header_ies", [], Dot15d4HeaderIE, next_cls_cb=_header_ie_next),  # noqa: E501
                         lambda pkt: util_ie_present(pkt)),
        dot15d4_payload_ie_field(),

        # Superframe spec field:
        ConditionalField(BitField("sf_sforder", 15, 4), util_legacy_beacon),  # not used by ZigBee
        ConditionalField(BitField("sf_beaconorder", 15, 4), util_legacy_beacon),  # not used by ZigBee
        ConditionalField(BitEnumField("sf_assocpermit", 0, 1, [False, True]), util_legacy_beacon),
        ConditionalField(BitEnumField("sf_pancoord", 0, 1, [False, True]), util_legacy_beacon),
        ConditionalField(BitField("sf_reserved", 0, 1), util_legacy_beacon),  # not used by ZigBee
        ConditionalField(BitEnumField("sf_battlifeextend", 0, 1, [False, True]), util_legacy_beacon),  # not used by ZigBee  # noqa: E501
        ConditionalField(BitField("sf_finalcapslot", 15, 4), util_legacy_beacon),  # not used by ZigBee

        # GTS Fields
        #  GTS Specification (1 byte)
        ConditionalField(BitEnumField("gts_spec_permit", 1, 1, [False, True]), util_legacy_beacon),  # GTS spec bit 7, true=1 iff PAN cord is accepting GTS requests  # noqa: E501
        ConditionalField(BitField("gts_spec_reserved", 0, 4), util_legacy_beacon),  # GTS spec bits 3-6
        ConditionalField(BitField("gts_spec_desccount", 0, 3), util_legacy_beacon),  # GTS spec bits 0-2
        #  GTS Directions (0 or 1 byte)
        ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt: util_legacy_beacon(pkt) and pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt: util_legacy_beacon(pkt) and pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        #  GTS List (variable size)
        # TODO add a Packet/FieldListField tied to 3bytes per count in gts_spec_desccount  # noqa: E501

        # Pending Address Fields:
        #  Pending Address Specification (1 byte)
        ConditionalField(BitField("pa_reserved_1", 0, 1), util_legacy_beacon),
        ConditionalField(BitField("pa_num_long", 0, 3), util_legacy_beacon),  # number of long addresses pending
        ConditionalField(BitField("pa_reserved_2", 0, 1), util_legacy_beacon),
        ConditionalField(BitField("pa_num_short", 0, 3), util_legacy_beacon),  # number of short addresses pending
        #  Address List (var length)
        ConditionalField(FieldListField("pa_short_addresses", [],
                                        XLEShortField("", 0x0000),
                                        count_from=lambda pkt: pkt.pa_num_short),  # noqa: E501
                         util_legacy_beacon),
        ConditionalField(FieldListField("pa_long_addresses", [],
                                        dot15d4AddressField("", 0, adjust=lambda pkt, x: 8),  # noqa: E501
                                        count_from=lambda pkt: pkt.pa_num_long),  # noqa: E501
                         util_legacy_beacon),
        # TODO beacon payload
    ]

    def guess_payload_class(self, payload):
        # Encrypted payloads (sec_sc_seclevel >= 4) cannot be dissected further
        if util_encrypted(self):
            return conf.raw_layer
        return Packet.guess_payload_class(self, payload)

    def mysummary(self):
        return self.sprintf("802.15.4 Beacon ( %Dot15d4Beacon.src_panid%:%Dot15d4Beacon.src_addr% ) assocPermit(%Dot15d4Beacon.sf_assocpermit%) panCoord(%Dot15d4Beacon.sf_pancoord%)")  # noqa: E501


class Dot15d4Cmd(Packet):
    name = "802.15.4 Command"
    fields_desc = dot15d4_mhr_fields(0x0) + [
        # Payload IEs precede the Command ID (Figure 7-17)
        dot15d4_payload_ie_field(),
        ByteEnumField("cmd_id", 0, {
            1: "AssocReq",  # Association request
            2: "AssocResp",  # Association response
            3: "DisassocNotify",  # Disassociation notification
            4: "DataReq",  # Data request
            5: "PANIDConflictNotify",  # PAN ID conflict notification
            6: "OrphanNotify",  # Orphan notification
            7: "BeaconReq",  # Beacon request
            8: "CoordRealign",  # coordinator realignment
            9: "GTSReq",  # GTS request
            0x0a: "TRLEMgmtReq", 0x0b: "TRLEMgmtResp",
            0x13: "DSMEAssocReq", 0x14: "DSMEAssocResp",
            0x15: "DSMEGTSReq", 0x16: "DSMEGTSResp", 0x17: "DSMEGTSNotify",
            0x18: "DSMEInfoReq", 0x19: "DSMEInfoResp",
            0x1a: "DSMEBeaconAllocNotify", 0x1b: "DSMEBeaconCollisionNotify",
            0x1c: "DSMELinkReport",
            0x20: "RITDataReq", 0x21: "DBSReq", 0x22: "DBSResp",
            0x23: "RITDataResp", 0x24: "VendorSpecific",
            0x25: "SRMReq", 0x26: "SRMResp", 0x27: "SRMReport",
            0x28: "SRMInfo", 0x29: "RangingVerifier", 0x2a: "RangingProver",
            # other values reserved
        }),
        # TODO command payload
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Command %Dot15d4Cmd.cmd_id% ( %Dot15d4Cmd.src_panid%:%Dot15d4Cmd.src_addr% -> %Dot15d4Cmd.dest_panid%:%Dot15d4Cmd.dest_addr% )")  # noqa: E501

    # command frame payloads are complete: DataReq, PANIDConflictNotify, OrphanNotify, BeaconReq don't have any payload  # noqa: E501
    # Although BeaconReq can have an optional ZigBee Beacon payload (implemented in ZigBeeBeacon)  # noqa: E501
    def guess_payload_class(self, payload):
        # Encrypted payloads (sec_sc_seclevel >= 4) cannot be dissected further
        if util_encrypted(self):
            return conf.raw_layer
        if self.cmd_id == 1:
            return Dot15d4CmdAssocReq
        elif self.cmd_id == 2:
            return Dot15d4CmdAssocResp
        elif self.cmd_id == 3:
            return Dot15d4CmdDisassociation
        elif self.cmd_id == 8:
            return Dot15d4CmdCoordRealign
        elif self.cmd_id == 9:
            return Dot15d4CmdGTSReq
        else:
            return Packet.guess_payload_class(self, payload)


class Dot15d4CmdCoordRealign(Packet):
    name = "802.15.4 Coordinator Realign Command"
    fields_desc = [
        # PAN Identifier (2 octets)
        XLEShortField("panid", 0xFFFF),
        # Coordinator Short Address (2 octets)
        XLEShortField("coord_address", 0x0000),
        # Logical Channel (1 octet): the logical channel that the coordinator intends to use for all future communications  # noqa: E501
        ByteField("channel", 0),
        # Short Address (2 octets)
        XLEShortField("dev_address", 0xFFFF),
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Coordinator Realign Payload ( PAN ID: %Dot15d4CmdCoordRealign.panid% : channel %Dot15d4CmdCoordRealign.channel% )")  # noqa: E501

    def guess_payload_class(self, payload):
        if len(payload) == 1:
            return Dot15d4CmdCoordRealignPage
        else:
            return Packet.guess_payload_class(self, payload)


class Dot15d4CmdCoordRealignPage(Packet):
    name = "802.15.4 Coordinator Realign Page"
    fields_desc = [
        ByteField("channel_page", 0),
    ]


class Dot15d4CmdAssocReq(Packet):
    name = "802.15.4 Association Request Payload"
    fields_desc = [
        BitField("allocate_address", 0, 1),  # Allocate Address
        BitField("security_capability", 0, 1),  # Security Capability
        BitField("reserved2", 0, 1),  # bit 5 is reserved
        BitField("reserved1", 0, 1),  # bit 4 is reserved
        BitField("receiver_on_when_idle", 0, 1),  # Receiver On When Idle
        BitField("power_source", 0, 1),  # Power Source
        BitField("device_type", 0, 1),  # Device Type
        BitField("alternate_pan_coordinator", 0, 1),  # Alternate PAN Coordinator  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Association Request Payload ( Alt PAN Coord: %Dot15d4CmdAssocReq.alternate_pan_coordinator% Device Type: %Dot15d4CmdAssocReq.device_type% )")  # noqa: E501


class Dot15d4CmdAssocResp(Packet):
    name = "802.15.4 Association Response Payload"
    fields_desc = [
        XLEShortField("short_address", 0xFFFF),  # Address assigned to device from coordinator (0xFFFF == none)  # noqa: E501
        # Association Status
        # 0x00 == successful
        # 0x01 == PAN at capacity
        # 0x02 == PAN access denied
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("association_status", 0x00, {0: 'successful', 1: 'PAN_at_capacity', 2: 'PAN_access_denied'}),  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Association Response Payload ( Association Status: %Dot15d4CmdAssocResp.association_status% Assigned Address: %Dot15d4CmdAssocResp.short_address% )")  # noqa: E501


class Dot15d4CmdDisassociation(Packet):
    name = "802.15.4 Disassociation Notification Payload"
    fields_desc = [
        # Disassociation Reason
        # 0x00 == Reserved
        # 0x01 == The coordinator wishes the device to leave the PAN
        # 0x02 == The device wishes to leave the PAN
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("disassociation_reason", 0x02, {1: 'coord_wishes_device_to_leave', 2: 'device_wishes_to_leave'}),  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Disassociation Notification Payload ( Disassociation Reason %Dot15d4CmdDisassociation.disassociation_reason% )")  # noqa: E501


class Dot15d4CmdGTSReq(Packet):
    name = "802.15.4 GTS request command"
    fields_desc = [
        # GTS Characteristics field (1 octet)
        # Reserved (bits 6-7)
        BitField("reserved", 0, 2),
        # Characteristics Type (bit 5)
        BitField("charact_type", 0, 1),
        # GTS Direction (bit 4)
        BitField("gts_dir", 0, 1),
        # GTS Length (bits 0-3)
        BitField("gts_len", 0, 4),
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 GTS Request Command ( %Dot15d4CmdGTSReq.gts_len% : %Dot15d4CmdGTSReq.gts_dir% )")  # noqa: E501

# PAN ID conflict notification command frame is not necessary, only Dot15d4Cmd with cmd_id = 5 ("PANIDConflictNotify")  # noqa: E501
# Orphan notification command not necessary, only Dot15d4Cmd with cmd_id = 6 ("OrphanNotify")  # noqa: E501

# Bindings #
bind_layers(Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers(Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers(Dot15d4, Dot15d4Ack, fcf_frametype=2)
bind_layers(Dot15d4, Dot15d4Cmd, fcf_frametype=3)

# DLT Types #
conf.l2types.register(DLT_IEEE802_15_4_WITHFCS, Dot15d4FCS)
conf.l2types.register(DLT_IEEE802_15_4_NOFCS, Dot15d4)
