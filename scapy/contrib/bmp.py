"""
Implement BMP

https://en.wikipedia.org/wiki/BMP_file_format

"""
import struct
from scapy.fields import StrField, LenField, ShortField, IntField
from scapy.packet import Packet, bind_layers


class BitmapFileHeader(Packet):
    """Bitmap file header"""

    name = "Bitmap File Header"
    fields_desc = [  # 14 bytes
        ShortField("identity", default=0x424D),  # 2 bytes (424d => BM)
        LenField("size_bmp", default=None, fmt="!I"),  # 4 bytes
        ShortField("reserved1", default=0),  # 2 bytes
        ShortField("reserved2", default=0),  # 2 bytes
        IntField("offset_bmp", default=None),  # 4 bytes
    ]

    def post_build(self, pkt, pay):
        if self.size_bmp is None and pay:
            size_bmp = len(pkt) + len(pay)
            pkt = (
                pkt[:2] + struct.pack("!I", size_bmp) + pkt[6:]
            )  # Size of the BMP file (bytes header + bytes data)

        return pkt + pay

    def build(self, internal=0):
        if not internal:
            current_layer = self
            if current_layer.offset_bmp is None:
                current_layer.offset_bmp = 14  # Size of the header
                if current_layer.haslayer(BitmapBITMAPCOREHEADERHeader):
                    layer_BitmapBITMAPCOREHEADERHeader = current_layer.getlayer(
                        BitmapBITMAPCOREHEADERHeader
                    )
                    current_layer.offset_bmp += len(
                        layer_BitmapBITMAPCOREHEADERHeader  # We want just the BitmapBITMAPCOREHEADERHeader layer
                    ) - len(layer_BitmapBITMAPCOREHEADERHeader.payload)

        pkt = self.do_build()
        pay = self.do_build_payload()

        packet = self.post_build(pkt, pay)
        return packet


class BitmapBITMAPCOREHEADERHeader(Packet):
    name = "OS/2 1.x BITMAPCOREHEADER"
    fields_desc = [  # 12 bytes
        LenField("size", default=None, fmt="I"),  # 4 bytes
        ShortField("width", default=0),  # 2 bytes
        ShortField("height", default=0),  # 2 bytes
        ShortField("color_panels", default=1),  # 2 bytes
        ShortField("number_of_bpp", default=0),  # 2 bytes
    ]

    def post_build(self, pkt, pay):
        if self.size is None:
            size = len(pkt)
            pkt = struct.pack("!I", size) + pkt[4:]  # Size of the BMP header

        return pkt + pay


bind_layers(BitmapFileHeader, BitmapBITMAPCOREHEADERHeader)
