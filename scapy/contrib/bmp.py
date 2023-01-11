"""
Implement BMP

https://en.wikipedia.org/wiki/BMP_file_format

"""
import struct
from scapy.fields import LEShortField, LESignedIntField, LEIntField
from scapy.packet import Packet, bind_layers


class BitmapFileHeader(Packet):
    """Bitmap file header"""

    name = "Bitmap File Header"
    fields_desc = [  # 14 bytes
        LEShortField("identity", default=0x424D),  # 2 bytes (424d => BM)
        LEIntField("size_bmp", default=None),  # 4 bytes
        LEShortField("reserved1", default=0),  # 2 bytes
        LEShortField("reserved2", default=0),  # 2 bytes
        LEIntField("offset_bmp", default=None),  # 4 bytes
    ]

    def post_build(self, pkt, pay):
        if self.size_bmp is None and pay:
            size_bmp = len(pkt) + len(pay)
            pkt = (
                pkt[:2] + struct.pack("I", size_bmp) + pkt[6:]
            )  # Size of the BMP file (bytes header + bytes data)

        if self.offset_bmp is not None and pay:
            pkt = pkt[: (2 + 4 + 2 + 2)] + struct.pack("I", self.offset_bmp)

        return pkt + pay


class BitmapBITMAPCOREHEADERHeader(Packet):
    """BITMAPCOREHEADER"""

    name = "OS/2 1.x BITMAPCOREHEADER"
    fields_desc = [  # 12 bytes
        LEIntField("size", default=None),  # 4 bytes
        LEShortField("width", default=0),  # 2 bytes
        LEShortField("height", default=0),  # 2 bytes
        LEShortField("color_panels", default=1),  # 2 bytes
        LEShortField("number_of_bpp", default=0),  # 2 bytes
    ]

    def post_build(self, pkt, pay):
        if self.size is None:
            size = len(pkt)
            pkt = struct.pack("I", size) + pkt[4:]  # Size of the header

        return pkt + pay


class BitmapBITMAPINFOHEADERHeader(Packet):
    """BITMAPINFOHEADER"""

    name = "Windows BITMAPINFOHEADER"
    fields_desc = [  # 12 bytes
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
        if self.size is None:
            size = len(pkt)
            pkt = struct.pack("I", size) + pkt[4:]  # Size of the header

        return pkt + pay


l = len(BitmapFileHeader()) + len(BitmapBITMAPCOREHEADERHeader())
bind_layers(BitmapFileHeader, BitmapBITMAPCOREHEADERHeader, offset_bmp=l)
l = len(BitmapFileHeader()) + len(BitmapBITMAPINFOHEADERHeader())
bind_layers(BitmapFileHeader, BitmapBITMAPINFOHEADERHeader, offset_bmp=l)
