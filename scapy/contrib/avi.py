"""
Implement AVI

https://github.com/thomzieg/avimaster/blob/main/AVIParser.cpp
https://github.com/mathiasbynens/small/blob/master/AudioVideoInterleave.avi
https://komh.github.io/os2books/os2tk45/mmref3/2239_L3_TheMainAVIHeaderLIST.html
https://github.com/raspberrypi/userland/blob/master/containers/avi/avi_reader.c
https://xoax.net/sub_web/ref_dev/fileformat_avi/
"""
import struct
from scapy.fields import (
    LEShortField,
    LEIntField,
    StrField,
    LEFieldLenField,
    PacketListField,
)
from scapy.packet import Packet
from scapy.utils import hexdump


class AVIHeader(Packet):
    """AVI Header"""

    name = "AVI Header"
    fields_desc = [
        StrField("riff_marker", "RIFF"),
        LEIntField("file_size", None),  # 4 bytes
        StrField("wave_marker", "AVI "),
        # Here we need to pick one or more of the list
    ]

    def post_build(self, pkt, pay):
        """Adjust the values"""
        if self.file_size is None and pay:
            size_wav = len(pay)
            pkt = (
                pkt[:4] + struct.pack("I", size_wav) + pkt[8:]
            )  # Size of the BMP file (bytes header + bytes data)

        return pkt + pay


class Chunkhdrl(Packet):
    """AVI Chunk hdrl"""

    name = "Chunk hdrl"
    fields_desc = [
        StrField("id", "hdrl"),
        StrField("sub_id", "avih"),
        LEIntField("fmt_size", 56),  # 14 * 4 => 56 (4 bytes)
        LEIntField("micro_sec_per_frame", 0),  # 4 bytes
        LEIntField("max_bytes_per_sec", 0),  # 4 bytes
        LEIntField("reserved1", 0),  # 4 bytes
        LEIntField("flags", 0),  # 4 bytes
        LEIntField("total_frames", 0),  # 4 bytes
        LEIntField("initial_frames", 0),  # 4 bytes
        LEIntField("streams", 0),  # 4 bytes
        LEIntField("suggested_buffer_size", 0),  # 4 bytes
        LEIntField("width", 0),  # 4 bytes
        LEIntField("height", 0),  # 4 bytes
        LEIntField("reserved", 0),  # 4 bytes
    ]


class ChunkLIST(Packet):
    """AVI Chunk LIST"""

    name = "Chunk LIST"
    fields_desc = [
        StrField("id", "LIST"),
        LEIntField("fmt_size", 16),  # 4 bytes
    ]


class Chunkstrl(Packet):
    """AVI Chunk strl"""

    name = "Chunk strl"
    fields_desc = [
        StrField("id", "strl"),
        StrField("id", "strh"),
        LEIntField("fmt_size", 16),  # 4 bytes
    ]


class Chunkvids(Packet):
    """AVI Chunk vids"""

    name = "Chunk vids"
    fields_desc = [
        StrField("id", "vids"),
        StrField("id", "FMP4"),
        LEIntField("fmt_size", 16),  # 4 bytes
        LEIntField("flags", 0), # 4 bytes
        LEIntField("reserved1", 0), # 4 bytes
        LEIntField("initial_frames", 0), # 4 bytes
        LEIntField("scale", 0), # 4 bytes
        LEIntField("rate", 0), # 4 bytes
        LEIntField("start", 0), # 4 bytes
        LEIntField("length", 0), # 4 bytes;
        LEIntField("suggested_buffer_size", 0), # 4 bytes
        LEIntField("quality", 0), # 4 bytes
        LEIntField("sample_size", 0), # 4 bytes
        LEIntField("Reserved", 0), # 4 bytes
    ]


class Chunkstrf(Packet):
    """AVI Chunk strf
    A stream format 'strf' chunk must follow a stream header 'strh' chunk."""

    name = "Chunk strf"
    fields_desc = [
        StrField("id", "strf"),
        LEIntField("fmt_size", 16),  # 4 bytes
        LEIntField("size", 0), # 4 bytes
        LEShortField("width", 0), # 2 bytes
        LEShortField("height", 0), # 2 bytes
        LEShortField("planes", 0), # 4 bytes
        LEShortField("bit_count", 0), # 4 bytes
        LEIntField("compression", 0), # 4 bytes
        LEIntField("size_image", 0), # 4 bytes;
        LEIntField("xpels_per_meter", 0), # 4 bytes;
        LEIntField("ypels_per_meter", 0), # 4 bytes
        LEIntField("clr_used", 0), # 4 bytes
        LEIntField("clr_important", 0), # 4 bytes
    ]
