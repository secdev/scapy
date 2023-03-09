"""
Implement PPM

https://en.wikipedia.org/wiki/Netpbm#File_formats
"""
from scapy.fields import StrField, StrEnumField
from scapy.packet import Packet
from scapy.utils import hexdump
import scapy.compat

class StrFieldWithSuffix(StrField):
    __slots__ = ["suffix"]
    def __init__(self, name, default, suffix):
        self.suffix = suffix
        super(StrField, self).__init__(name, default)

    def i2m(self, pkt, x):
        if x is None:
            return b""
        if not isinstance(x, bytes):
            return scapy.compat.bytes_encode(x)
        return x + self.suffix.encode()
    
    
class StrEnumFieldWithSuffix(StrEnumField):
    __slots__ = ["enum", "suffix"]
    def __init__(
            self,
            name,  # type: str
            default,  # type: bytes
            enum=None,  # type: Optional[Dict[str, str]]
            suffix="",
            **kwargs  # type: Any
    ):
        # type: (...) -> None
        StrEnumField.__init__(self, name, default, enum, **kwargs)  # type: ignore
        self.suffix = suffix

    def i2m(self, pkt, x):
        if x is None:
            return b""
        if not isinstance(x, bytes):
            return scapy.compat.bytes_encode(x)
        return x + self.suffix.encode()



class PPMHeader(Packet):
    """PPM Header"""

    name = "PPM Header"
    fields_desc = [
        StrEnumFieldWithSuffix("ppm_marker", "P3", enum=["P1", "P2", "P3"], suffix="\n"),
        StrFieldWithSuffix("height", "0", suffix=" "),
        StrFieldWithSuffix("width", "0", suffix="\n"),
        StrFieldWithSuffix("colors", "0", suffix="\n"),
    ]


class RGBTriplets(Packet):
    """RGB triplets"""

    name = "RGB triplets"
    fields_desc = [
        StrFieldWithSuffix("r", "0", suffix=" "),
        StrFieldWithSuffix("g", "0", suffix=" "),
        StrFieldWithSuffix("b", "0", suffix="\n"),
    ]


def test():
    ppm_test = PPMHeader()
    ppm_test.height = str(3)
    ppm_test.width = str(2)
    ppm_test.colors = str(255)

    triplet = RGBTriplets()
    triplet.r = str(255)
    triplet.g = str(0)
    triplet.b = str(0)
    ppm_test /=triplet

    triplet = RGBTriplets()
    triplet.r = str(0)
    triplet.g = str(255)
    triplet.b = str(0)
    ppm_test /=triplet

    triplet = RGBTriplets()
    triplet.r = str(0)
    triplet.g = str(0)
    triplet.b = str(255)
    ppm_test /=triplet

    triplet = RGBTriplets()
    triplet.r = str(255)
    triplet.g = str(255)
    triplet.b = str(0)
    ppm_test /=triplet

    triplet = RGBTriplets()
    triplet.r = str(255)
    triplet.g = str(255)
    triplet.b = str(255)
    ppm_test /=triplet

    triplet = RGBTriplets()
    triplet.r = str(0)
    triplet.g = str(0)
    triplet.b = str(0)
    ppm_test /=triplet

    generated = hexdump(ppm_test, dump=True)

    hex_encoded = (
        """
        50 33 0A 33 20 32 0A 32 35 35 0A 32 35 35 20 30
        20 30 0A 30 20 32 35 35 20 30 0A 30 20 30 20 32
        35 35 0A 32 35 35 20 32 35 35 20 30 0A 32 35 35
        20 32 35 35 20 32 35 35 0A 30 20 30 20 30 0A
        """
    )

    hex_decoded = hexdump(bytes.fromhex(hex_encoded), dump=True)

    if generated != hex_decoded:
        raise ValueError("Generator error")


test()