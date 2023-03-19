"""
Implement BMP

https://en.wikipedia.org/wiki/BMP_file_format

"""
import struct
from scapy.fields import LEShortField, LESignedIntField, LEIntField, StrFieldWithFuzzingString
from scapy.packet import Packet, bind_layers
from scapy.utils import hexdump


class BitmapFileHeader(Packet):
    """Bitmap file header"""

    name = "Bitmap File Header"
    fields_desc = [  # 14 bytes
        LEShortField("identity", default=0x4D42),  # 2 bytes (424d => BM)
        LEIntField(
            "size_bmp", default=None
        ),  # 4 bytes - we cannot use PacketLenField as the header below us changes
        LEShortField("reserved1", default=0),  # 2 bytes
        LEShortField("reserved2", default=0),  # 2 bytes
        LEIntField("offset_bmp", default=None),  # 4 bytes
    ]

    def post_build(self, pkt, pay):
        """Adjust the values"""
        if self.size_bmp is None and pay:
            size_bmp = len(pkt) + len(pay)
            pkt = (
                pkt[:2] + struct.pack("I", size_bmp) + pkt[6:]
            )  # Size of the BMP file (bytes header + bytes data)

        if self.offset_bmp is not None and pay:
            pkt = pkt[:-2] + struct.pack("I", self.offset_bmp)

        return pkt + pay


class Bitmap_BITMAPCOREHEADER_Header(Packet):
    """BITMAPCOREHEADER"""

    name = "OS/2 1.x BITMAPCOREHEADER"
    fields_desc = [
        LEIntField("size", default=None),  # 4 bytes
        LEShortField("width", default=0),  # 2 bytes
        LEShortField("height", default=0),  # 2 bytes
        LEShortField("color_panels", default=1),  # 2 bytes
        LEShortField("number_of_bpp", default=0),  # 2 bytes
    ]

    def post_build(self, pkt, pay):
        """Calculate the size"""
        if self.size is None:
            size = len(pkt)
            pkt = struct.pack("I", size) + pkt[4:]  # Size of the header

        return pkt + pay


class Bitmap_BITMAPINFOHEADER_Header(Packet):
    """BITMAPINFOHEADER"""

    name = "Windows BITMAPINFOHEADER"
    fields_desc = [
        LEIntField("size", default=None),  # 4 bytes
        LESignedIntField("width", default=2),  # 4 bytes
        LESignedIntField("height", default=2),  # 4 bytes
        LEShortField("color_panels", default=1),  # 2 bytes
        LEShortField("number_of_bpp", default=24),  # 2 bytes
        LEIntField("compression_method", default=0),  # 4 bytes
        LEIntField("image_size", default=16),  # 4 bytes
        LEIntField("horizontal_resolution", default=2835),  # 4 bytes
        LEIntField("vertical_resolution", default=2835),  # 4 bytes
        LEIntField("number_of_colors", default=0),  # 4 bytes
        LEIntField("number_of_important_colors", default=0),  # 4 bytes
    ]

    def post_build(self, pkt, pay):
        """Calculate the size"""
        if self.size is None:
            size = len(pkt)
            pkt = struct.pack("I", size) + pkt[4:]  # Size of the header

        return pkt + pay


class Bitmap_BITMAPV4HEADER_Header(Packet):
    """BITMAPV4HEADER"""

    name = "Windows BITMAPV4HEADER"
    fields_desc = [
        LEIntField("size", default=None),  # 4 bytes
        LESignedIntField("width", default=4),  # 4 bytes
        LESignedIntField("height", default=2),  # 4 bytes
        LEShortField("color_panels", default=1),  # 2 bytes
        LEShortField("number_of_bpp", default=32),  # 2 bytes
        LEIntField("compression_method", default=3),  # 4 bytes
        LEIntField("image_size", default=32),  # 4 bytes
        LEIntField("horizontal_resolution", default=2835),  # 4 bytes
        LEIntField("vertical_resolution", default=2835),  # 4 bytes
        LEIntField("number_of_colors", default=0),  # 4 bytes
        LEIntField("number_of_important_colors", default=0),  # 4 bytes
        LEIntField("red_channel_mask", default=0x00FF0000),  # 4 bytes
        LEIntField("green_channel_mask", default=0x0000FF00),  # 4 bytes
        LEIntField("blue_channel_mask", default=0x000000FF),  # 4 bytes
        LEIntField("alpha_channel_mask", default=0xFF000000),  # 4 bytes
        LEIntField("lcs_windows_color_space", default=0x57696E20),  # 4 bytes " Win"
        StrFieldWithFuzzingString(name="CIEXYZTRIPLE", default=("\x00" * 0x24)),
        LEIntField("red_gamma", default=0),  # 4 bytes
        LEIntField("green_gamma", default=0),  # 4 bytes
        LEIntField("blue_gamma", default=0),  # 4 bytes
    ]

    def post_build(self, pkt, pay):
        """Calculate the size"""
        if self.size is None:
            size = len(pkt)
            pkt = struct.pack("I", size) + pkt[4:]  # Size of the header

        return pkt + pay


l = len(BitmapFileHeader()) + len(Bitmap_BITMAPCOREHEADER_Header())
bind_layers(BitmapFileHeader, Bitmap_BITMAPCOREHEADER_Header, offset_bmp=l)
l = len(BitmapFileHeader()) + len(Bitmap_BITMAPINFOHEADER_Header())
bind_layers(BitmapFileHeader, Bitmap_BITMAPINFOHEADER_Header, offset_bmp=l)
l = len(BitmapFileHeader()) + len(Bitmap_BITMAPV4HEADER_Header())
bind_layers(BitmapFileHeader, Bitmap_BITMAPV4HEADER_Header, offset_bmp=l)


def test():
    payload = bytes.fromhex("00 00 FF" "FF FF FF" "00 00" "FF 00 00" "00 FF 00" "00 00")
    bmp_test = BitmapFileHeader() / Bitmap_BITMAPV4HEADER_Header() / payload

    generated = hexdump(bmp_test, dump=True)

    if (
        generated
        != """0000  42 4D 8A 00 00 00 00 00 00 00 7A 00 7A 00 00 00  BM........z.z...
0010  6C 00 00 00 04 00 00 00 02 00 00 00 01 00 20 00  l............. .
0020  03 00 00 00 20 00 00 00 13 0B 00 00 13 0B 00 00  .... ...........
0030  00 00 00 00 00 00 00 00 00 00 FF 00 00 FF 00 00  ................
0040  FF 00 00 00 00 00 00 FF 20 6E 69 57 00 00 00 00  ........ niW....
0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF  ................
0080  FF FF 00 00 FF 00 00 00 FF 00 00 00              ............"""
    ):
        raise ValueError("Generator failed")
