# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Operation, administration and maintenance (OAM)
# scapy.contrib.status = loads

"""
    Operation, administration and maintenance (OAM)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Sergey Matsievskiy, matsievskiysv@gmail.com

    :description:

        This module provides Scapy layers for the OAM protocol.

        normative references:
          - ITU-T Rec. G.8013/Y.1731 (08/2019) - Operation, administration and
            maintenance (OAM) functions and mechanisms for Ethernet-based
            networks (https://www.itu.int/rec/T-REC-G.8013)
          - ITU-T Rec. G.8031/Y.1342 (01/2015) - Ethernet linear protection
            switching (https://www.itu.int/rec/T-REC-G.8031)
          - ITU-T Rec. G.8032/Y.1344 (02/2022) - Ethernet ring protection
            switching (https://www.itu.int/rec/T-REC-G.8032)
"""

from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    ConditionalField,
    EnumField,
    FCSField,
    FlagsField,
    IntField,
    LenField,
    LongField,
    MACField,
    MultipleTypeField,
    NBytesField,
    OUIField,
    PacketField,
    PadField,
    PacketListField,
    ShortField,
    FieldListField,
)
from scapy.layers.l2 import Dot1Q
from scapy.packet import Packet, bind_layers
from binascii import crc32
import struct


class MepIdField(ShortField):
    """
    Short field with insignificant three leading bytes
    """

    def __init__(self, name, default):
        super(MepIdField, self).__init__(
            name, default & 0x1FFF if default is not None else default
        )


class MegId(Packet):
    """
    MEG ID
    """

    name = "MEG ID"

    fields_desc = [
        ByteField("resv", 1),
        ByteField("format", 0),
        MultipleTypeField(
            [
                (
                    LenField("length", 13, fmt="B"),
                    lambda p: p.format == 32,
                ),
                (
                    LenField("length", 15, fmt="B"),
                    lambda p: p.format == 33,
                )
            ],
            LenField("length", 45, fmt="B"),
        ),
        PadField(
            MultipleTypeField(
                [
                    (
                        FieldListField("values", [0] * 13,
                                       ByteField("value", 0),
                                       count_from=lambda pkt: pkt.length),
                        lambda x: x.format == 32,
                    ),
                    (
                        FieldListField("values", [0] * 15,
                                       ByteField("value", 0),
                                       count_from=lambda pkt: pkt.length),
                        lambda x: x.format == 33,
                    )
                ],
                NBytesField("values", 0, sz=45),
            ),
            45),
    ]

    def extract_padding(self, s):
        return b"", s


class OAM_TLV(Packet):
    """
    OAM TLV
    """

    name = "OAM TLV"
    fields_desc = [ByteField("type", 1), LenField("length", None)]

    def extract_padding(self, s):
        return s[:self.length], s[self.length:]


class OAM_DATA_TLV(Packet):
    """
    OAM Data TLV
    """

    name = "OAM Data TLV"
    fields_desc = [ByteField("type", 3), LenField("length", None)]

    def extract_padding(self, s):
        return s[:self.length], s[self.length:]


class OAM_TEST_TLV(Packet):
    """
    OAM test TLV data
    """

    name = "OAM test TLV"

    fields_desc = [
        ByteField("type", 32),
        MultipleTypeField(
            [
                (
                    LenField("length", None, adjust=lambda l: l + 5),
                    lambda p: p.pat_type == 1 or p.pat_type == 3,
                )
            ],
            LenField("length", None, adjust=lambda l: l + 1),
        ),
        EnumField(
            "pat_type",
            0,
            {
                0: "Null signal without CRC-32",
                1: "Null signal with CRC-32",
                2: "PRBS 2^-31 - 1 without CRC-32",
                3: "PRBS 2^-31 - 1 with CRC-32",
            },
            fmt="B",
        ),
        ConditionalField(
            FCSField("crc", None, fmt="!I"),
            lambda p: p.pat_type == 1 or p.pat_type == 3,
        ),
    ]

    def do_dissect(self, s):
        if ord(s[3:4]) == 1 or ord(s[3:4]) == 3:
            # move crc to the end of packet
            length = struct.unpack("!H", s[1:3])[0]
            crc_end = 3 + length
            crc_start = crc_end - 4
            s1 = s[:crc_start]
            s2 = s[crc_start:crc_end]
            s3 = s[crc_end:]
            s = s1 + s3 + s2
        s = super(OAM_TEST_TLV, self).do_dissect(s)
        return s

    def post_build(self, p, pay):
        if ord(p[3:4]) == 1 or ord(p[3:4]) == 3:
            p1 = p
            p2 = pay[:-4]
            p3 = struct.pack("!I", crc32(p1 + p2) % (1 << 32))
            return p1 + p2 + p3
        else:
            return p + pay

    def extract_padding(self, s):
        if self.pat_type == 1 or self.pat_type == 3:
            # we already consumed crc
            return s[:self.length - 5], s[self.length - 5:]
        else:
            return s[:self.length - 1], s[self.length - 1:]


class OAM_LTM_TLV(Packet):
    """
    OAM LTM TLV data
    """

    name = "OAM LTM Egress ID TLV"

    fields_desc = [
        ByteField("type", 7),
        LenField("length", 8),
        LongField("egress_id", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class OAM_LTR_TLV(Packet):
    """
    OAM LTR TLV data
    """

    name = "OAM LTR Egress ID TLV"

    fields_desc = [
        ByteField("type", 8),
        LenField("length", 16),
        # NOTE: wireshark interprets this field as short+MAC
        LongField("last_egress_id", 0),
        # NOTE: wireshark interprets this field as short+MAC
        LongField("next_egress_id", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class OAM_LTR_IG_TLV(Packet):
    """
    OAM LTR TLV data
    """

    name = "OAM LTR Ingress TLV"

    fields_desc = [
        ByteField("type", 5),
        LenField("length", 7),
        ByteField("ingress_act", 0),
        MACField("ingress_mac", None),
    ]

    def extract_padding(self, s):
        return b"", s


class OAM_LTR_EG_TLV(Packet):
    """
    OAM LTR TLV data
    """

    name = "OAM LTR Egress TLV"

    fields_desc = [
        ByteField("type", 6),
        LenField("length", 7),
        ByteField("egress_act", 0),
        MACField("egress_mac", None),
    ]

    def extract_padding(self, s):
        return b"", s


class OAM_TEST_ID_TLV(Packet):
    """
    OAM Test ID TLV data
    """

    name = "OAM Test ID TLV"

    fields_desc = [
        ByteField("type", 36),
        LenField("length", 32),
        IntField("test_id", 0),
    ]

    def extract_padding(self, s):
        return b"", s


def guess_tlv_type(pkt, lst, cur, remain):
    if remain[0:1] == b'\x00':
        return None
    elif remain[0:1] == b'\x03':
        return OAM_DATA_TLV
    elif remain[0:1] == b'\x05':
        return OAM_LTR_IG_TLV
    elif remain[0:1] == b'\x06':
        return OAM_LTR_EG_TLV
    elif remain[0:1] == b'\x07':
        return OAM_LTM_TLV
    elif remain[0:1] == b'\x08':
        return OAM_LTR_TLV
    elif remain[0:1] == b'\x20':
        return OAM_TEST_TLV
    elif remain[0:1] == b'\x24':
        return OAM_TEST_ID_TLV
    else:
        return OAM_TLV


class PTP_TIMESTAMP(Packet):
    """
    PTP timestamp
    """

    # TODO: should be a part of PTP module
    name = "PTP timestamp"
    fields_desc = [IntField("seconds", 0), IntField("nanoseconds", 0)]

    def extract_padding(self, s):
        return b"", s


class APS(Packet):
    """
    Linear protective switching APS data packet
    """

    name = "APS"

    fields_desc = [
        BitEnumField(
            "req_st",
            0,
            4,
            {
                0b0000: "No request (NR)",
                0b0001: "Do not request (DNR)",
                0b0010: "Reverse request (RR)",
                0b0100: "Exercise (EXER)",
                0b0101: "Wait-to-restore (WTR)",
                0b0110: "Deprecated",
                0b0111: "Manual switch (MS)",
                0b1001: "Signal degrade (SD)",
                0b1011: "Signal fail for working (SF)",
                0b1101: "Forced switch (FS)",
                0b1110: "Signal fail on protection (SF-P)",
                0b1111: "Lockout of protection (LO)",
            },
        ),
        FlagsField(
            "prot_type",
            0,
            4,
            {
                (1 << 3): "A",
                (1 << 2): "B",
                (1 << 1): "D",
                (1 << 0): "R",
            },
        ),
        EnumField(
            "req_sig", 0, {0: "Null signal", 1: "Normal traffic"}, fmt="B"
        ),
        EnumField(
            "br_sig", 0, {0: "Null signal", 1: "Normal traffic"}, fmt="B"
        ),
        FlagsField("br_type", 0, 8, {(1 << 7): "T"}),
    ]

    def extract_padding(self, s):
        return b"", s


class RAPS(Packet):
    """
    Ring protective switching R-APS data packet
    """

    name = "R-APS"

    fields_desc = [
        BitEnumField(
            "req_st",
            0,
            4,
            {
                0b0000: "No request (NR)",
                0b0111: "Manual switch (MS)",
                0b1011: "Signal fail(SF)",
                0b1101: "Forced switch (FS)",
                0b1110: "Event",
            },
        ),
        MultipleTypeField(
            [
                (
                    BitEnumField("sub_code", 0, 4, {0b0000: "Flush"}),
                    lambda p: p.req_st == 0b1110,
                )
            ],
            BitField("sub_code", 0, 4),
        ),
        FlagsField(
            "status",
            0,
            8,
            {
                (1 << 7): "RB",
                (1 << 6): "DNF",
                (1 << 5): "BPR",
            },
        ),
        MACField("node_id", None),
        NBytesField("resv", 0, 24),
    ]

    def extract_padding(self, s):
        return b"", s


class OAM(Packet):
    """
    OAM data unit
    """

    name = "OAM"

    OPCODES = {
        1: "Continuity Check Message (CCM)",
        3: "Loopback Message (LBM)",
        2: "Loopback Reply (LBR)",
        5: "Linktrace Message (LTM)",
        4: "Linktrace Reply (LTR)",
        32: "Generic Notification Message (GNM)",
        33: "Alarm Indication Signal (AIS)",
        35: "Lock Signal (LCK)",
        37: "Test Signal (TST)",
        39: "Automatic Protection Switching (APS)",
        40: "Ring-Automatic Protection Switching (R-APS)",
        41: "Maintenance Communication Channel (MCC)",
        43: "Loss Measurement Message (LMM)",
        42: "Loss Measurement Reply (LMR)",
        45: "One Way Delay Measurement (1DM)",
        47: "Delay Measurement Message (DMM)",
        46: "Delay Measurement Reply (DMR)",
        49: "Experimental OAM Message (EXM)",
        48: "Experimental OAM Reply (EXR)",
        51: "Vendor Specific Message (VSM)",
        50: "Vendor Specific Reply (VSR)",
        52: "Client Signal Fail (CSF)",
        53: "One Way Synthetic Loss Measurement (1SL)",
        55: "Synthetic Loss Message (SLM)",
        54: "Synthetic Loss Reply (SLR)",
    }

    TIME_FLAGS = {
        0b000: "Invalid value",
        0b001: "Trans Int 3.33ms",
        0b010: "Trans Int 10ms",
        0b011: "Trans Int 100ms",
        0b100: "Trans Int 1s",
        0b101: "Trans Int 10s",
        0b110: "Trans Int 1min",
        0b111: "Trans Int 10min",
    }

    PERIOD_FLAGS = {
        0b100: "1 frame per second",
        0b110: "1 frame per minute",
    }

    BNM_PERIOD_FLAGS = {
        0b100: "1 frame per second",
        0b101: "1 frame per 10 seconds",
        0b110: "1 frame per minute",
    }

    fields_desc = [
        # Common fields
        BitField("mel", 0, 3),
        MultipleTypeField(
            [(BitField("version", 1, 5), lambda x: x.opcode in [43, 45, 47])],
            BitField("version", 0, 5),
        ),
        EnumField("opcode", None, OPCODES, fmt="B"),
        MultipleTypeField(
            [
                (
                    FlagsField("flags", 0, 5, {(1 << 4): "RDI"}),
                    lambda x: x.opcode == 1,
                ),
                (
                    FlagsField("flags", 0, 8, {(1 << 7): "HWonly"}),
                    lambda x: x.opcode == 5,
                ),
                (
                    FlagsField(
                        "flags",
                        0,
                        8,
                        {
                            (1 << 7): "HWonly",
                            (1 << 6): "FwdYes",
                            (1 << 5): "TerminalMEP",
                        },
                    ),
                    lambda x: x.opcode == 4,
                ),
                (BitField("flags", 0, 5), lambda x: x.opcode in [33, 35, 32]),
                (
                    FlagsField("flags", 0, 8, {1: "Proactive"}),
                    lambda x: x.opcode in [43, 45, 47],
                ),
                (
                    BitEnumField(
                        "flags",
                        0,
                        5,
                        {
                            0b000: "LOS",
                            0b001: "FDI",
                            0b010: "RDI",
                            0b011: "DCI",
                        },
                    ),
                    lambda x: x.opcode == 52,
                ),
            ],
            ByteField("flags", 0),
        ),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        BitEnumField("period", 1, 3, TIME_FLAGS),
                        lambda x: x.opcode == 1,
                    ),
                    (
                        BitEnumField("period", 0b110, 3, BNM_PERIOD_FLAGS),
                        lambda x: x.opcode in [13, 32],
                    ),
                ],
                BitEnumField("period", 0b110, 3, PERIOD_FLAGS),
            ),
            lambda x: x.opcode in [1, 33, 35, 52, 32],
        ),
        MultipleTypeField(
            [
                (ByteField("tlv_offset", 70), lambda x: x.opcode == 1),
                (
                    ByteField("tlv_offset", 4),
                    lambda x: x.opcode in [3, 2, 37, 39],
                ),
                (ByteField("tlv_offset", 17), lambda x: x.opcode == 5),
                (ByteField("tlv_offset", 6), lambda x: x.opcode == 4),
                (ByteField("tlv_offset", 32), lambda x: x.opcode in [40, 47]),
                (ByteField("tlv_offset", 12), lambda x: x.opcode == 43),
                (
                    ByteField("tlv_offset", 16),
                    lambda x: x.opcode in [45, 54, 53, 55],
                ),
                (ByteField("tlv_offset", 13), lambda x: x.opcode == 32),
                (
                    ByteField("tlv_offset", 10),
                    lambda x: x.opcode == 41
                ),
            ],
            ByteField("tlv_offset", 0),
        ),
        # End common fields
        ConditionalField(
            IntField("seq_num", 0), lambda x: x.opcode in [1, 3, 2, 37]
        ),
        ConditionalField(IntField("trans_id", 0),
                         lambda x: x.opcode in [5, 4]),
        ConditionalField(
            OUIField("oui", None), lambda x: x.opcode in [41, 49, 48, 51, 50]
        ),
        ConditionalField(
            MultipleTypeField(
                [(ByteField("subopcode", 1), lambda x: x.opcode == 32)],
                ByteField("subopcode", 0),
            ),
            lambda x: x.opcode in [41, 49, 48, 51, 50, 32],
        ),
        ConditionalField(
            MepIdField("mep_id", 0),
            lambda x: x.opcode == 1 \
            or (x.opcode == 41 and x.subopcode == 1 and x.oui == 6567),
        ),
        ConditionalField(
            PacketField("meg_id", MegId(), MegId), lambda x: x.opcode == 0x01
        ),
        ConditionalField(
            ShortField("src_mep_id", 0), lambda x: x.opcode in [55, 54, 53]
        ),
        ConditionalField(
            ShortField("rcv_mep_id", 0), lambda x: x.opcode in [55, 54, 53]
        ),
        ConditionalField(
            IntField("test_id", 0), lambda x: x.opcode in [55, 54, 53]
        ),
        ConditionalField(
            IntField("txfcf", 0), lambda x: x.opcode in [1, 43, 42, 55, 54, 53]
        ),
        ConditionalField(IntField("rxfcb", 0), lambda x: x.opcode == 1),
        ConditionalField(IntField("rxfcf", 0), lambda x: x.opcode in [43, 42]),
        ConditionalField(
            IntField("txfcb", 0), lambda x: x.opcode in [1, 43, 42, 55, 54]
        ),
        ConditionalField(IntField("resv", 0), lambda x: x.opcode in [1, 53]),
        ConditionalField(ByteField("ttl", 0), lambda x: x.opcode in [5, 4]),
        ConditionalField(MACField("orig_mac", None), lambda x: x.opcode == 5),
        ConditionalField(MACField("targ_mac", None), lambda x: x.opcode == 5),
        ConditionalField(ByteField("relay_act", None),
                         lambda x: x.opcode == 4),
        ConditionalField(
            PacketField("txtsf", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [45, 47, 46],
        ),
        ConditionalField(
            PacketField("rxtsf", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [45, 47, 46],
        ),
        ConditionalField(
            PacketField("txtsb", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [47, 46],
        ),
        ConditionalField(
            PacketField("rxtsb", PTP_TIMESTAMP(), PTP_TIMESTAMP),
            lambda x: x.opcode in [47, 46],
        ),
        ConditionalField(
            IntField("expct_dur", None),
            lambda x: x.opcode == 41 and x.subopcode == 1 and x.oui == 6567,
        ),
        ConditionalField(IntField("nom_bdw", None), lambda x: x.opcode == 32),
        ConditionalField(IntField("curr_bdw", None), lambda x: x.opcode == 32),
        ConditionalField(IntField("port_id", None), lambda x: x.opcode == 32),
        ConditionalField(
            PacketField("aps", APS(), APS), lambda x: x.opcode == 39
        ),
        ConditionalField(
            PacketField("raps", RAPS(), RAPS), lambda x: x.opcode == 40
        ),
        ConditionalField(
            PacketListField("tlvs", [], next_cls_cb=guess_tlv_type),
            lambda x: x.opcode in [3, 2, 5, 4, 37, 45, 47, 46, 55, 54, 53],
        ),
        ConditionalField(
            IntField("opt_data", None),
            lambda x: x.opcode in [49, 48, 51, 50] and False,
        ),  # FIXME: field documented elsewhere
        # TODO: add EXM, EXR, VSM and VSR data
        ByteField("end_tlv", 0),
    ]


bind_layers(Dot1Q, OAM, type=0x8902)
