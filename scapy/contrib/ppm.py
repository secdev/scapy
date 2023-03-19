"""
Implement PPM

https://en.wikipedia.org/wiki/Netpbm#File_formats
"""
from scapy.fields import StrField, FuzzingString
from scapy.packet import Packet
import scapy.layers.l2
import scapy.compat

TRIPLET_COUNT = 0

class StrDelimiterField(StrField):
    """ String field with a Delimiter (generic) """
    __slots__ = ["suffix"]
    ALIGNMENT = 1

    def __init__(self, name, default, suffix, fmt="H", remain=0):
        scapy.fields.StrField.__init__(self, name, default, fmt, remain)
        if not isinstance(suffix, bytes):
            suffix = scapy.compat.bytes_encode(suffix)

        self.suffix = suffix

    def randval(self):
        return FuzzingString(default=self.default, suffix=self.suffix)

    # def addfield(self, pkt, s, val):
    #     # type: (Packet, bytes, Optional[bytes]) -> bytes
    #     ret = s
    #     ret += self.i2m(pkt, val)
    #     ret += self.suffix
    #     return ret

    def getfield(self,
                 pkt,  # type: Packet
                 s,  # type: bytes
                 ):
        # type: (...) -> Tuple[bytes, bytes]
        len_str = 0
        while True:
            len_str = s.find(self.suffix, len_str)
            if len_str < 0:
                # DELIMITER not found: return empty
                return b"", s
            if len_str % self.ALIGNMENT:
                len_str += 1
            else:
                break
        return s[len_str + len(self.suffix):], self.m2i(pkt, s[:len_str])


class PPMTriplet(Packet):
    """PPM Triplet"""
    def __init__(self,
                 _pkt=b"",
                 post_transform=None,
                 _internal=0,
                 _underlayer=None,
                 _parent=None,
                 **fields
                 ):
        global TRIPLET_COUNT
        Packet.__init__(self, _pkt, post_transform, _internal, _underlayer, _parent)

        TRIPLET_COUNT += 1
        name = f"PPM Triplet {TRIPLET_COUNT}"
        self.name = name

    fields_desc = [
        StrDelimiterField("r", "0", suffix=" "),
        StrDelimiterField("g", "0", suffix=" "),
        StrDelimiterField("b", "0", suffix="\n"),
    ]

class PPM(Packet):
    """PPM Header"""

    name = "PPM Header"

    fields_desc = [
        StrDelimiterField("ppm_marker", "P1", suffix="\n"),
        StrDelimiterField("height", "0", suffix=" "),
        StrDelimiterField("width", "0", suffix="\n"),
        StrDelimiterField("colors", "0", suffix="\n"),
    ]
