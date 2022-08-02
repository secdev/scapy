# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2019 Luis Rosa <lmrosa@dei.uc.pt>

# scapy.contrib.description = PCOM Protocol
# scapy.contrib.status = loads

"""
PCOM

PCOM is a protocol to communicate with Unitronics PLCs either by serial
or TCP. Two modes are available, ASCII and Binary.

https://unitronicsplc.com/Download/SoftwareUtilities/Unitronics%20PCOM%20Protocol.pdf
"""

import struct

from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
from scapy.fields import XShortField, ByteEnumField, XByteField, \
    StrFixedLenField, StrLenField, LEShortField, \
    LEFieldLenField, LEX3BytesField, XLEShortField
from scapy.volatile import RandShort
from scapy.compat import bytes_encode, orb

_protocol_modes = {0x65: "ascii", 0x66: "binary"}

_ascii_command_codes = {
    "ID": "Send Identification Command",
    "CCR": "Send Start Command",
    "CCS": "Send Stop Command",
    "CCE": "Send Reset Command",
    "CCI": "Send Init Command",
    "CC": "Reply of Admin Commands (CC*)",
    "UG": "Get UnitID",
    "US": "Set UnitID",
    "RC": "Get RTC",
    "SC": "Set RTC",
    "RE": "Read Inputs",
    "RA": "Read Outputs",
    "GS": "Read System Bits",
    "GF": "Read System Integers",
    "RNH": "Read System Longs",
    "RNJ": "Read System Double Words",
    "RB": "Read Memory Bits",
    "RW": "Read Memory Integers",
    "RNL": "Read Memory Longs",
    "RND": "Read Memory Double Words",
    "RN": "Read Longs / Double Words",
    "SA": "Write Outputs",
    "SS": "Write System Bits",
    "SF": "Write System Integers",
    "SNH": "Write System Longs",
    "SNJ": "Write System Double Words",
    "SB": "Write Memory Bits",
    "SW": "Write Memory Integers",
    "SNL": "Write Memory Longs",
    "SND": "Write Memory Double Words",
    "SN": "Write Longs / Double Words"
}

_binary_command_codes = {
    0x0c: "Get PLC Name Request",
    0x8c: "Get PLC Name Reply",
    0x4d: "Read Operands Request",
    0xcd: "Read Operands Reply",
    0x04: "Read Data Table Request",
    0x84: "Read Data Table Reply",
    0x44: "Write Data Table Request",
    0xc4: "Write Data Table Reply"
}


class PCOM(Packet):
    fields_desc = [
        XShortField("transId", RandShort()),
        ByteEnumField("mode", 0x65, _protocol_modes),
        XByteField("reserved", 0x00),
        LEShortField("len", None)
    ]

    def post_build(self, pkt, pay):
        if self.len is None and pay:
            pkt = pkt[:4] + struct.pack("H", len(pay))
        return pkt + pay


class PCOMRequest(PCOM):
    name = "PCOM/TCP Request"


class PCOMResponse(PCOM):
    name = "PCOM/TCP Response"


class PCOMAscii(Packet):
    @staticmethod
    def pcom_ascii_checksum(command):
        n = 0
        command = bytes_encode(command)
        for _, c in enumerate(command):
            n += orb(c)
        return list(map(ord, hex(n % 256)[2:].zfill(2).upper()))


class PCOMAsciiCommandField(StrLenField):
    def i2repr(self, pkt, x):
        s = super(PCOMAsciiCommandField, self).i2repr(pkt, x)
        code = s[1:4]  # check for 3 chars known codes
        if code in _ascii_command_codes:
            return _ascii_command_codes[code] + " " + s
        code = s[1:3]  # check for 2 chars known codes
        if code in _ascii_command_codes:
            return _ascii_command_codes[code] + " " + s
        return s


class PCOMAsciiRequest(PCOMAscii):
    name = "PCOM/ASCII Request"
    fields_desc = [
        StrFixedLenField("stx", "/", 1),
        StrFixedLenField("unitId", "00", 2),
        PCOMAsciiCommandField(
            "command", '', length_from=lambda pkt: pkt.underlayer.len - 6),
        XShortField("chksum", None),
        XByteField("etx", 0x0d)
    ]

    def post_build(self, pkt, pay):
        if self.chksum is None:
            chksum = PCOMAscii.pcom_ascii_checksum(pkt[1:-3])
            pkt = pkt[:-3] + struct.pack("2B", chksum[0], chksum[1]) + pkt[-1:]
        return pkt + pay


class PCOMAsciiResponse(PCOMAscii):
    name = "PCOM/ASCII Response"
    fields_desc = [
        StrFixedLenField("stx", "/A", 2),
        StrFixedLenField("unitId", "00", 2),
        PCOMAsciiCommandField(
            "command", '', length_from=lambda pkt: pkt.underlayer.len - 7),
        XShortField("chksum", None),
        XByteField("etx", 0x0d)
    ]

    def post_build(self, pkt, pay):
        if self.chksum is None:
            chksum = PCOMAscii.pcom_ascii_checksum(pkt[2:-3])
            pkt = pkt[:-3] + struct.pack("2B", chksum[0], chksum[1]) + pkt[-1:]
        return pkt + pay


class PCOMBinary(Packet):
    @staticmethod
    def pcom_binary_checksum(command):
        n = 0
        command = bytes_encode(command)
        for _, c in enumerate(command):
            c = c if isinstance(c, int) else ord(c)  # python 2 fallback
            n += c
        if n == 0:
            return [0x00, 0x00]
        else:
            two_complement = hex(0x10000 - (n % 0x10000))[2:].zfill(4)
            return [int(two_complement[:2], 16), int(two_complement[2:], 16)]

    def post_build(self, pkt, pay):
        if self.headerChksum is None:
            chksum = PCOMBinaryRequest.pcom_binary_checksum(pkt[:21])
            pkt = pkt[:22] + struct.pack("2B", chksum[1], chksum[0]) + pkt[24:]
        if self.footerChksum is None:
            chksum = PCOMBinaryRequest.pcom_binary_checksum(pkt[24:-3])
            pkt = pkt[:-3] + struct.pack("2B", chksum[1], chksum[0]) + pkt[-1:]
        return pkt + pay


class PCOMBinaryCommandField(XByteField):
    def i2repr(self, pkt, x):
        s = super(PCOMBinaryCommandField, self).i2repr(pkt, x)
        if x in _binary_command_codes:
            return _binary_command_codes[x] + " - " + s
        else:
            return s


class PCOMBinaryRequest(PCOMBinary):
    name = "PCOM/Binary Request"
    fields_desc = [
        StrFixedLenField("stx", "/_OPLC", 6),
        XByteField("id", 0x0),
        XByteField("reserved1", 0xfe),
        XByteField("reserved2", 0x1),
        LEX3BytesField("reserved3", 0x0),
        PCOMBinaryCommandField("command", None),
        XByteField("reserved4", 0x0),
        StrFixedLenField("commandSpecific", '', 6),
        LEFieldLenField("len", 0, length_of="data"),
        XLEShortField("headerChksum", None),
        StrLenField("data", '', length_from=lambda pkt: pkt.len),
        XLEShortField("footerChksum", None),
        XByteField("etx", 0x5c)
    ]


class PCOMBinaryResponse(PCOMBinary):
    name = "PCOM/Binary Response"
    fields_desc = [
        StrFixedLenField("stx", "/_OPLC", 6),
        XByteField("reserved1", 0xfe),
        XByteField("id", 0x0),
        XByteField("reserved2", 0x1),
        LEX3BytesField("reserved3", 0x0),
        PCOMBinaryCommandField("command", None),
        XByteField("reserved4", 0x0),
        StrFixedLenField("commandSpecific", '', 6),
        LEFieldLenField("len", 0, length_of="data"),
        XLEShortField("headerChksum", None),
        StrLenField("data", '', length_from=lambda pkt: pkt.len),
        XLEShortField("footerChksum", None),
        XByteField("etx", 0x5c)
    ]


bind_layers(TCP, PCOMRequest, dport=20256)
bind_layers(TCP, PCOMResponse, sport=20256)
bind_layers(PCOMRequest, PCOMAsciiRequest, mode=0x65)
bind_layers(PCOMRequest, PCOMBinaryRequest, mode=0x66)
bind_layers(PCOMResponse, PCOMAsciiResponse, mode=0x65)
bind_layers(PCOMResponse, PCOMBinaryResponse, mode=0x66)
