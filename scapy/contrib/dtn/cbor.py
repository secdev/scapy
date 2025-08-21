# scapy.contrib.description = Concise Binary Object Representation (CBOR)
# scapy.contrib.status = library

"""
    Concise Binary Object Representation (CBOR) utility
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :authors:    Timothy Recker, timothy.recker@nasa.gov
                 Tad Kollar, tad.kollar@nasa.gov
"""

from scapy.fields import (
    Field,
    BitField,
    BitEnumField,
    PacketField
)
from scapy.packet import Packet
from scapy.all import raw
import flynn
from typing import Tuple, List, Union

MajorTypes = {
    0: "unsigned",
    1: "negative",
    2: "byte string",
    3: "text string",
    4: "array",
    5: "map",
    6: "tag",
    7: "simple/float"
}


class MajorTypeException(Exception):
    """This exception indicates that a CBOR object has an unexpected value for its Major Type.

    Attributes:
        actual -- the integer value of the actual Major Type
        expected -- an integer or list of integers indicating the acceptable Major Type values"""
    def __init__(self, actual: int, expected: Union[int, List[int]]):

        message = f'[Error] Major type {actual} does not refer to a(n)'
        if isinstance(expected, int):
            typ = MajorTypes[expected]
            message += f' {typ}.'
        else:
            typ = MajorTypes[expected[0]]
            message += f' {typ}'
            for val in expected[1:]:
                typ = MajorTypes[val]
                message += f' or {typ}'
            message += '.'
        super().__init__(message)


class StopCodeException(Exception):
    def __init__(self, value):
        super().__init__(f'[Error] Major type {value} does not refer to a stop code.')


class AdditionalInfoException(Exception):
    """This exception indicates that a CBOR object has an unexpected value for its Additional Info."""
    def __init__(self):
        super().__init__('[Error] Invalid additional info.')


class UnhandledTypeException(Exception):
    def __init__(self, value, cls):
        super().__init__(f"[Error] Major type {value} is not handled by {cls}.")


# CBOR definitions
class CBORNull(Field):
    """This class exists so that it can be used in a MultipleTypeField containing CBOR values.
    Every option given to a MultipleTypeField must be a field with at least a name.
    Thus, if one of the MultipleType options should be that no field whatsoever is present,
    you need a field that produces no bytes when added to the packet.
    CBORNull can serve this purpose."""


class CBORBase(Field):
    @staticmethod
    def static_get_head_info(b):
        if len(b) == 0:
            return None, None

        head = b[0]
        major_type = head >> 5
        add_info = head & 0b00011111

        return major_type, add_info

    def get_head_info(self, b):
        return CBORBase.static_get_head_info(b)

    def addfield(self, pkt, s, val):
        return s + flynn.dumps(val)


class CBORInteger(CBORBase):
    @staticmethod
    def get_value(add_info, b):
        if add_info < 24:
            val_length = 1  # 1 byte head, argument=add_info
            val = add_info
        elif add_info == 24:
            val_length = 2  # 1 byte head + 1 byte argument
            val = b[1]
        elif add_info == 25:
            val_length = 3  # 1 byte head + 2 byte argument
            val = int.from_bytes(b[1:3], byteorder='big')
        elif add_info == 26:
            val_length = 5  # 4 byte argument
            val = int.from_bytes(b[1:5], byteorder='big')
        elif add_info == 27:
            val_length = 9  # 8 byte argument
            val = int.from_bytes(b[1:9], byteorder='big')
        else:
            raise AdditionalInfoException()

        return b[val_length:], val

    def getfield(self, pkt, s):
        major_type, add_info = self.get_head_info(s)

        if major_type != 0:
            raise MajorTypeException(major_type, 0)

        return CBORInteger.get_value(add_info, s)


class CBORStringBase(CBORBase):
    @staticmethod
    def get_value(add_info, b):
        if add_info < 24:
            arg_size = 0
            data_size = add_info  # argument = data size = additional info
        else:
            if add_info == 24:
                arg_size = 1
            elif add_info == 25:
                arg_size = 2
            elif add_info == 26:
                arg_size = 4
            elif add_info == 27:
                arg_size = 8
            else:
                raise AdditionalInfoException()

            # size of argument is known now, so
            # get value of the argument, which contains the size of the data
            data_size = int.from_bytes(b[1:1 + arg_size], byteorder='big')
        val_length = 1 + arg_size + data_size
        val = b[1 + arg_size:val_length]

        return b[val_length:], val


class CBORByteString(CBORStringBase):
    def getfield(self, pkt, s):
        major_type, add_info = self.get_head_info(s)

        if major_type != 2:
            raise MajorTypeException(major_type, 2)

        return CBORStringBase.get_value(add_info, s)


class CBORTextString(CBORStringBase):
    def getfield(self, pkt, s):
        major_type, add_info = self.get_head_info(s)

        if major_type != 3:
            raise MajorTypeException(major_type, 3)

        return CBORStringBase.get_value(add_info, s)


class CBORIntOrText(CBORBase):
    def getfield(self, pkt, s):
        major_type, add_info = self.get_head_info(s)

        if major_type == 0:
            return CBORInteger.get_value(add_info, s)
        if major_type == 3:
            return CBORStringBase.get_value(add_info, s)

        raise MajorTypeException(major_type, [0, 3])


class CBORStopCode(CBORBase):
    def addfield(self, pkt, s, val):
        return s + b'\xff'

    @staticmethod
    def get_value(add_info, b):
        return b[1:], add_info

    def getfield(self, pkt, s):
        major_type, add_info = self.get_head_info(s)
        if major_type != 7:
            raise StopCodeException(major_type)

        return CBORStopCode.get_value(add_info, s)


class CBORAny(CBORBase):
    def getfield(self, pkt, s):
        major_type, add_info = self.get_head_info(s)

        if major_type == 0:
            return CBORInteger.get_value(add_info, s)
        if major_type in [2, 3]:
            return CBORStringBase.get_value(add_info, s)
        if major_type == 7:
            return CBORStopCode.get_value(add_info, s)

        raise UnhandledTypeException(major_type, CBORAny)


class CBORArray(Packet):
    _major_type = BitEnumField("major_type", 4, 3, MajorTypes)
    _add = BitField("add", 0, 5)  # additional information = length

    # head fields
    fields_desc = [_major_type, _add]

    def count_additional_fields(self) -> int:
        """
        Return the number of fields other than the two head fields. This method does
        not work correctly with ConditionalFields and should be overridden when that
        field type is in use.
        """
        head_field_count = 2
        return len(self.default_fields) - head_field_count

    def set_additional_fields(self, pkt: Packet) -> bytes:
        """ For an, the add field is set to the number of elements minus the two head fields. """
        # pylint: disable=W0201
        # field (instance variable) initialization is handled via "fields_desc"
        self.add = self.count_additional_fields()
        head = (self.major_type << 5) | self.add

        return head.to_bytes(1, 'big') + pkt[1:]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        return self.set_additional_fields(pkt) + pay

    def extract_padding(self, s):
        return "", s


class CBORPacketField(PacketField):
    def i2m(self, pkt: Packet, i) -> bytes:
        if i is None:
            return b""

        return flynn.dumps(raw(i))

    def m2i(self, pkt: Packet, m):
        _, add_info = CBORBase.static_get_head_info(m)
        remain, decoded_m = CBORStringBase.get_value(add_info, m)
        try:
            # we want to set parent wherever possible
            return self.cls(decoded_m + remain, _parent=pkt)  # type: ignore
        except TypeError:
            return self.cls(decoded_m + remain)


class CBORPacketFieldWithRemain(CBORPacketField):
    """
    The regular Packet.getfield() never returns the remaining bytes, so the CRC or
    other following fields get lost. This getfield does return the remaining bytes.
    """
    def m2i(self, pkt: Packet, m):
        _, add_info = CBORBase.static_get_head_info(m)
        remain, decoded_m = CBORStringBase.get_value(add_info, m)
        try:
            # we want to set parent wherever possible
            return remain, self.cls(decoded_m + remain, _parent=pkt)  # type: ignore
        except TypeError:
            return remain, self.cls(decoded_m + remain)

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, Packet]:
        remain, i = self.m2i(pkt, s)
        return remain, i
