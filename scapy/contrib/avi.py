"""
Implement AVI

https://github.com/thomzieg/avimaster/blob/main/AVIParser.cpp
https://github.com/mathiasbynens/small/blob/master/AudioVideoInterleave.avi
https://komh.github.io/os2books/os2tk45/mmref3/2239_L3_TheMainAVIHeaderLIST.html
https://github.com/raspberrypi/userland/blob/master/containers/avi/avi_reader.c
https://xoax.net/sub_web/ref_dev/fileformat_avi/
http://www.jmcgowan.com/odmlff2.pdf
"""
import struct
from scapy.fields import (
    LEShortField,
    LEIntField,
    StrField,
    LEFieldLenField,
    LELongField,
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
        LEIntField("size", 56),  # 14 * 4 => 56 (4 bytes)
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
        LEIntField("size", 16),  # 4 bytes
    ]


class ChunkINFO(Packet):
    """AVI Chunk INFO"""

    name = "Chunk INFO"
    fields_desc = [
        StrField("id", "INFO"),
    ]


class Chunkstrl(Packet):
    """AVI Chunk strl"""

    name = "Chunk strl"
    fields_desc = [
        StrField("id", "strl"),
        StrField("sub_sid", "strh"),
        LEIntField("size", 16),  # 4 bytes
    ]


class Chunkvids(Packet):
    """AVI Chunk vids"""

    name = "Chunk vids"
    fields_desc = [
        StrField("type", "vids"),
        StrField("handle", "FMP4"),
        LEIntField("size", 16),  # 4 bytes
        LEIntField("flags", 0),  # 4 bytes
        LEIntField("reserved1", 0),  # 4 bytes
        LEIntField("initial_frames", 0),  # 4 bytes
        LEIntField("scale", 0),  # 4 bytes
        LEIntField("rate", 0),  # 4 bytes
        LEIntField("start", 0),  # 4 bytes
        LEIntField("length", 0),  # 4 bytes
        LEIntField("suggested_buffer_size", 0),  # 4 bytes
        LEIntField("quality", 0),  # 4 bytes
        LEIntField("sample_size", 0),  # 4 bytes
        LEIntField("Reserved", 0),  # 4 bytes
    ]


class Chunkstrf(Packet):
    """AVI Chunk strf
    A stream format 'strf' chunk must follow a stream header 'strh' chunk."""

    name = "Chunk strf"
    fields_desc = [
        StrField("id", "strf"),
        LEIntField("size", 16),  # 4 bytes
    ]


class ChunkBITMAPINFOHEADER(Packet):
    """AVI BITMAPINFOHEADER"""

    name = "AVI BITMAPINFOHEADER"
    fields_desc = [
        LEIntField("size", 0),  # 4 bytes
        LEIntField("width", 0),  # 4 bytes
        LEIntField("height", 0),  # 4 bytes
        LEShortField("planes", 0),  # 2 bytes
        LEShortField("bit_count", 0),  # 2 bytes
        LEIntField("compression", 0),  # 4 bytes
        LEIntField("size_image", 0),  # 4 bytes
        LEIntField("xpels_per_meter", 0),  # 4 bytes
        LEIntField("ypels_per_meter", 0),  # 4 bytes
        LEIntField("clr_used", 0),  # 4 bytes
        LEIntField("clr_important", 0),  # 4 bytes
    ]


class Chunkauds(Packet):
    """AVI Chunk auds"""

    name = "Chunk auds"
    fields_desc = [
        StrField("type", "auds"),
        StrField("handler", "FMP4"),
        LEIntField("flags", 16),  # 4 bytes
        LEIntField("priority", 0),  # 4 bytes
        LEIntField("initial_frames", 0),  # 4 bytes
        LEIntField("scale", 0),  # 4 bytes
        LEIntField("rate", 0),  # 4 bytes
        LEIntField("start", 0),  # 4 bytes
        LEIntField("length", 0),  # 4 bytes
        LEIntField("buffer_size", 0),  # 4 bytes
        LEIntField("quality", 0),  # 4 bytes
        LEIntField("sample_size", 0),  # 4 bytes
        LELongField("frame", 0),  # 8 bytes
    ]


class ChunkWAVEFORMATEX(Packet):
    """AVI WAVEFORMATEX"""

    name = "AVI WAVEFORMATEX"
    fields_desc = [
        LEIntField("size", 0),  # 4 bytes
        LEShortField("channels", 0),  # 2 bytes
        LEIntField("samples_per_second", 0),  # 4 bytes
        LEIntField("average_bytes_per_second", 0),  # 4 bytes
        LEShortField("block_align", 0),  # 2 bytes
        LEShortField("bits_per_sample", 0),  # 2 bytes
        LEShortField("size_extra", 0),  # 2 bytes
        LEIntField("xpels_per_meter", 0),  # 4 bytes
        LEIntField("ypels_per_meter", 0),  # 4 bytes
        LEIntField("clr_used", 0),  # 4 bytes
        LEIntField("clr_important", 0),  # 4 bytes
    ]


class ChunkJUNK(Packet):
    """AVI Chunk JUNK"""

    name = "Chunk JUNK"
    fields_desc = [
        StrField("id", "JUNK"),
        LEFieldLenField("size", 16, length_of="data"),  # 4 bytes
        StrField("data", ""),
    ]


class Chunkmovi(Packet):
    """AVI movi"""

    name = "AVI movi"
    fields_desc = [
        StrField("type", "movi"),
    ]


class Chunk00db(Packet):
    """AVI 00db"""

    name = "AVI 00db"
    fields_desc = [
        StrField("type", "00db"),  # 4 bytes
        LEIntField("size", 0),  # 4 bytes
        StrField("pixel_data", ""),
        StrField("more_images", ""),
    ]


class Chunk01wb(Packet):
    """AVI 01wb"""

    name = "AVI 01wb"
    fields_desc = [
        StrField("type", "01wb"),  # 4 bytes
        LEIntField("size", 0),  # 4 bytes
        StrField("sound_data", ""),
    ]


class Chunkidx1(Packet):
    """AVI idx1"""

    name = "AVI idx1"
    fields_desc = [
        StrField("type", "idx1"),  # 4 bytes
        LEIntField("size", 0),  # 4 bytes
    ]


class Chunkodml(Packet):
    """AVI odml"""

    name = "AVI odml"
    fields_desc = [
        StrField("type", "odml"),  # 4 bytes
        LEIntField("size", 0),  # 4 bytes
    ]


class Chunkdmlh(Packet):
    """AVI dmlh"""

    name = "AVI dmlh"
    fields_desc = [
        StrField("type", "dmlh"),  # 4 bytes
        LEIntField("total_frames", 0),  # 4 bytes
    ]


class ChunkISFT(Packet):
    """AVI ISFT"""

    name = "AVI ISFT"
    fields_desc = [
        StrField("type", "ISFT"),  # 4 bytes
        LEFieldLenField("size", 16, length_of="data"),  # 4 bytes
        StrField("data", ""),
    ]


def test():
    avi_test = AVIHeader()

    avi_test /= ChunkLIST()

    avi_test /= Chunkhdrl()

    avi_test /= ChunkLIST()

    avi_test /= Chunkstrl() / Chunkstrl()

    avi_test /= Chunkvids()

    avi_test /= Chunkstrf()

    first_junk = ChunkJUNK()
    first_junk.data = bytes.fromhex(
        """04 00 00 00
    00 00 00 00 30 30 64 63 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"""
        + (0x000010F0 - 0x000000F0) * " 00"
        + """00 00 00 00"""
    )

    avi_test /= first_junk

    second_junk = ChunkJUNK()
    second_junk.data = bytes.fromhex(
        """6f 64 6d 6c
    64 6d 6c 68 f8 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"""
        + (0x00001200 - 0x00001110) * " 00"
    )

    avi_test /= second_junk

    avi_test /= Chunkodml()

    avi_test /= Chunkdmlh()

    avi_test /= ChunkLIST()

    avi_test /= ChunkINFO()

    isft = ChunkISFT()
    isft.data = b"Lavf57.41.100\0"
    avi_test /= isft

    avi_test /= ChunkJUNK()

    avi_test /= ChunkLIST()

    avi_test /= Chunkmovi()

    avi_test /= Chunkidx1()

    generated = hexdump(avi_test, dump=True)

    hex_encoded = (
        """
    52 49 46 46 2e 16 00 00 41 56 49 20 4c 49 53 54
    ec 11 00 00 68 64 72 6c 61 76 69 68 38 00 00 00
    10 27 00 00 a8 61 00 00 00 00 00 00 10 09 00 00
    00 00 00 00 00 00 00 00 01 00 00 00 00 00 10 00
    01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 4c 49 53 54 94 10 00 00
    73 74 72 6c 73 74 72 68 38 00 00 00 76 69 64 73
    46 4d 50 34 00 00 00 00 00 00 00 00 00 00 00 00
    01 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 ff ff ff ff 00 00 00 00 00 00 00 00
    01 00 01 00 73 74 72 66 28 00 00 00 28 00 00 00
    01 00 00 00 01 00 00 00 01 00 18 00 46 4d 50 34
    03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 4a 55 4e 4b 18 10 00 00 04 00 00 00
    00 00 00 00 30 30 64 63 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"""
        + (0x000010F0 - 0x000000F0) * " 00"
        + """00 00 00 00 4a 55 4e 4b 04 01 00 00 6f 64 6d 6c
    64 6d 6c 68 f8 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"""
        + (0x00001200 - 0x00001110) * " 00"
        + """4c 49 53 54 1a 00 00 00 49 4e 46 4f 49 53 46 54
    0e 00 00 00 4c 61 76 66 35 37 2e 34 31 2e 31 30
    30 00 4a 55 4e 4b f8 03 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"""
        + (0x00001620 - 0x00001230) * " 00"
        + """00 00 4c 49 53 54 04 00 00 00 6d 6f 76 69 69 64
    78 31 00 00 00 00"""
    )

    hex_decoded = hexdump(bytes.fromhex(hex_encoded), dump=True)

    if generated != hex_decoded:
        raise ValueError("Generator error")


test()
