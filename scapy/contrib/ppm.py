"""
Implement PPM

https://en.wikipedia.org/wiki/Netpbm#File_formats
"""
from scapy.fields import StrField, FieldListField
from scapy.packet import Packet
from scapy.utils import hexdump
import scapy.layers.l2
import scapy.compat

TRIPLET_COUNT = 0

def reverse_string(string):
    ret = b''

    for c in string:
        ch = c ^ 0xff
        ret += chr(ch).encode('latin1')

    return ret

class FuzzingString(scapy.volatile.VolatileValue):
    min = 0
    max = 0
    state_pos = None
    suffix = None
    default_value = None
    
    fuzzing_states = [
        {"name": "default", "count": 1, "return": lambda val: val[0]},
        {"name": "Bit flip", "count": 1, "return": lambda val: reverse_string(val[0])},
        {"name": "'A' overflow", "count": 16, "return": lambda val : b"A" * pow(2, val[1])},
        {"name": "Number range", "count": 32, "return": lambda val: str(pow(2, val[1])).encode()},
    ]

    def __init__(self, default = None, suffix = None):
        self.suffix = suffix
        self.default_value = default
        
        for fuzzing_state in self.fuzzing_states:
            self.max += fuzzing_state['count']
        
    def _fix(self):
        if self.state_pos is None:
            if self.default_value is None:
                return b''

            if self.suffix is not None:
                return self.default_value + self.suffix
            
            return self.default_value

        count_so_far = 0
        current_fuzzing_state = None
        for fuzzing_state in self.fuzzing_states:
            if self.state_pos <= (fuzzing_state["count"] + count_so_far):
                current_fuzzing_state = fuzzing_state
                break

            count_so_far += fuzzing_state["count"]

        if current_fuzzing_state is None:
            self.state_pos = 0
            return self.default_value

        ret = current_fuzzing_state["return"]([self.default_value, self.state_pos - count_so_far])

        if self.suffix is not None:
            ret += self.suffix

        # print(f"{ret=}")
        return ret


class StrDelimiterField(StrField):
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

