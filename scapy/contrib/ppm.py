"""
Implement PPM

https://en.wikipedia.org/wiki/Netpbm#File_formats
"""
from scapy.fields import StrField, FieldListField
from scapy.packet import Packet
from scapy.utils import hexdump
import scapy.layers.l2
import scapy.compat

class FuzzingString(scapy.volatile.VolatileValue):
    min = 0
    max = 0
    state_pos = None
    suffix = None
    default_value = None
    
    fuzzing_states = [
        {"name": "default", "count": 1},
        {"name": "'A' overflow", "count": 128, "return": lambda cnt : b"A" * cnt},
        {"name": "Number range", "count": 128, "return": lambda cnt : str(pow(2, cnt)).encode()},
    ]

    def __init__(self, default = None, suffix = None):
        self.suffix = suffix
        self.default_value = default
        
        for fuzzing_state in self.fuzzing_states:
            self.max += fuzzing_state['count']
        
    def _fix(self):
        if self.state_pos is None or self.state_pos == 0:
            if self.default_value is None:
                return self.default_value

            if self.suffix is not None:
                return self.default_value + self.suffix
            else:
                return self.default_value

        count_so_far = 0
        current_fuzzing_state = None
        for fuzzing_state in self.fuzzing_states:
            if self.state_pos < fuzzing_state["count"] + count_so_far:
                current_fuzzing_state = fuzzing_state
                break

            count_so_far += fuzzing_state["count"]

        if current_fuzzing_state is None:
            self.state_pos = 0
            return self.default_value

        ret = current_fuzzing_state["return"](self.state_pos - count_so_far)

        if self.suffix is not None:
            return ret + self.suffix
        else:
            return ret


class FieldListFieldWithDelimiter(FieldListField):
    __slots__ = ["delimiter", "default_value"]

    def __init__(
            self,
            name,  # type: str
            default,  # type: Optional[List[AnyField]]
            field,
            delimiter,  # type: AnyField
    ):
        if default is None:
            default = []  # Create a new list for each instance
        self.delimiter = delimiter
        self.default_value = ""

        FieldListField.__init__(self, name, default, field)

    def any2i(self, pkt, x):
        self.default_value = x
        if self.delimiter is not None:
            self.default_value = self.delimiter.join(x)

        return self.default_value

    def randval(self):
        return FuzzingString(default=self.default_value, suffix=self.delimiter)


class CustomStrField(scapy.fields.StrField):
    __slots__ = ["suffix"]

    def __init__(self, name, default, fmt="H", suffix=b""):
        # type: (str, Optional[I], str, int) -> None
        scapy.fields.StrField.__init__(self, name, default, fmt)
        self.suffix = suffix

    def randval(self):
        return FuzzingString(default=self.default, suffix=self.suffix)

class PPM(Packet):
    """PPM"""

    name = "PPM"
    # fields_desc = [
    #     StrEnumFieldWithSuffix("ppm_marker", b"P3", enum=[b"P1", b"P2", b"P3"], suffix=b"\n"),
    #     StrFieldWithSuffix("height", b"0", suffix=b" "),
    #     StrFieldWithSuffix("width", b"0", suffix=b"\n"),
    #     StrFieldWithSuffix("colors", b"0", suffix=b"\n"),
    #     FieldListFieldWithDelimiter("triplets", [],
    #                                 StrFieldWithDelimiter('', "", delimiter=b" "),
    #                                 delimiter=b"\n")
    # ]

    fields_desc = [
        CustomStrField("ppm_marker", b"P1", suffix=b"\n"),
        CustomStrField("height", b"0", suffix=b" "),
        CustomStrField("width", b"0", suffix=b"\n"),
        CustomStrField("colors", b"0", suffix=b"\n"),
    ]


def test():
    ppm_test = PPM()

    packet_fuzz = scapy.packet.fuzz(ppm_test)
    states = packet_fuzz.prepare_combinations(2)
    packet_fuzz.forward(states)

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

if __name__ == "__main__":
    test()
