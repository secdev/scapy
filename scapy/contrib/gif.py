"""
Implement GIF

https://en.wikipedia.org/wiki/GIF#Example_GIF_file
https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art011
https://coolbutuseless.github.io/2019/04/23/gif-image-writing-in-pure-r/
http://sintesis.ugto.mx/WintemplaWeb/02Wintempla/10Images/08GIF/index.htm
https://root.cern/doc/master/x11_2src_2gifdecode_8c_source.html
http://wiki.gis.com/wiki/index.php/Graphics_Interchange_Format
"""

from scapy.fields import (
    LEShortField,
    StrField,
    ByteField,
    PacketField,
    LEFieldLenField,
)
from scapy.packet import Packet
from scapy.utils import hexdump

class GIFRGB(Packet):
    """RGB Header"""

    name = "GIF RGB"
    fields_desc = [
        ByteField("r", default=0),
        ByteField("g", default=0),
        ByteField("b", default=0),
    ]


class GIF89aFileHeader(Packet):
    """GIF89a file header"""

    name = "GIF89a File Header"
    fields_desc = [
        StrField("header", default="GIF89a"),
        LEShortField("width", default=1),
        LEShortField("height", default=1),
        # 0x80 mask is GCT enabled, ((0x80 >> 4) & 7) + 1 -> how many colors
        ByteField("gct", default=0x80),
        ByteField("background_color", default=0x01),
        ByteField("aspect_ratio", default=0),
    ]

    for num in range(0, 2):
        field_name = "global_color_table_{:#04x}".format(num)
        global_color_table = PacketField(field_name, GIFRGB(), GIFRGB)
        global_color_table.default.default_fields["r"] = 0
        global_color_table.default.default_fields["g"] = 0
        global_color_table.default.default_fields["b"] = 0
        fields_desc.append(global_color_table)


class GIF89aImageBlock(Packet):
    """GIF89a image block"""

    name = "GIF89a Image Block"
    fields_desc = [
        ByteField("header", default=0x2C),
        LEShortField("image_left_position", default=0),
        LEShortField("image_top_position", default=0),
        LEShortField("image_width", default=0),
        LEShortField("image_height", default=0),
        ByteField("fields", default=0),
    ]


class GIF89aLZW(Packet):
    """GIF89a LZW block"""

    name = "GIF89a LZW Block"
    fields_desc = [
        LEFieldLenField("code_size", default=None, fmt="B", length_of="code"),
        StrField("code", default=0),
    ]


class GIF89aTrailer(Packet):
    """GIF89a trailer"""

    name = "GIF89a Trailer"
    fields_desc = [
        ByteField("header", default=0x3B),
    ]


def test():
    gif89a_header = GIF89aFileHeader()
    gif89a_header.global_color_table_0x00.r = 255
    gif89a_header.global_color_table_0x00.g = 255
    gif89a_header.global_color_table_0x00.b = 255
    gif89a_test = gif89a_header

    gif89a_image_block = GIF89aImageBlock()
    gif89a_image_block.image_left_position = 0
    gif89a_image_block.image_top_position = 0
    gif89a_image_block.image_width = 1
    gif89a_image_block.image_height = 1
    gif89a_image_block.flags = 2
    gif89a_test /= gif89a_image_block

    gif89a_lzw = GIF89aLZW()
    gif89a_lzw.code = bytes.fromhex("02 44")
    gif89a_test /= gif89a_lzw

    gif89a_lzw = GIF89aLZW()
    gif89a_lzw.code = bytes.fromhex("00")
    gif89a_test /= gif89a_lzw

    gif89a_test /= GIF89aTrailer()

    generated = hexdump(gif89a_test, dump=True)

    if (
        generated
        != """0000  47 49 46 38 39 61 01 00 01 00 80 01 00 FF FF FF  GIF89a..........
0010  00 00 00 2C 00 00 00 00 01 00 01 00 00 02 02 44  ...,...........D
0020  01 00 3B                                         ..;"""
    ):
        raise ValueError("Generator failed")
