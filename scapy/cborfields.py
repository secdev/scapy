# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Brian Sipos <brian.sipos@gmail.com>

"""
Classes that implement CBOR leaf data structures.
"""

from typing import Any, Optional, List, Tuple, Type
from .fields import I, M, Field, AnyField
from .packet import Packet, Raw
from .volatile import RandNum, RandBin
from .cbor import (
    CborMajorType, CborSimpleValue, CborHead, CborChunk,
    cbor_chunk_int, cbor_chunk_bstr, cbor_encode_chunk, cbor_decode_chunk
)


class _CborItemBase:
    ''' Mixin class to decode and encode CBOR items into a CBOR packet. '''

    decode_recurse = False
    ''' If true, the chunk decoding is recursive. '''

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[I]) -> bytes
        mval = self.i2m(pkt, val)
        if mval is None:
            return s
        elif isinstance(mval, CborChunk):
            data = cbor_encode_chunk(mval)
            self._inc_seen(pkt)
            return s + bytes(data)
        else:
            return s + mval

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, I]
        buf = bytearray(s)
        _used, chunk = cbor_decode_chunk(buf, recurse=self.decode_recurse)
        self._inc_seen(pkt)
        return bytes(buf), self.m2i(pkt, chunk)

    def _inc_seen(self, pkt):
        ''' Increment the seen item counter on a CBOR packet. '''
        if hasattr(pkt, 'array_seen_items'):
            pkt.array_seen_items += 1


class CborAnyField(_CborItemBase, Field[CborChunk, CborChunk]):
    ''' Special case to handle sequences of chunks recursively. '''

    decode_recurse = True

    def __init__(self, name, default=None):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "H")

    def i2repr(self, _pkt, x):
        # type: (Optional[Packet], I) -> str
        return str(x)


class CborBoolField(_CborItemBase, Field[bool, CborChunk]):
    def __init__(self, name, default=None):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "H")

    def m2i(self, _pkt, x):
        # type: (Optional[Packet], M) -> I
        if x.head.major == CborMajorType.OTHERS:
            if x.head.argument == CborSimpleValue.TRUE:
                return True
            elif x.head.argument == CborSimpleValue.FALSE:
                return False

        raise TypeError

    def i2m(self, _pkt, x):
        # type: (Optional[Packet], Optional[I]) -> M
        return cbor_chunk_int(int(x))


class CborUintField(_CborItemBase, Field[int, CborChunk]):
    ''' Allow non-negative integer values. '''

    def __init__(self, name, default=None, maxval=None):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "H")
        self.maxval = maxval

    def m2i(self, _pkt, x):
        # type: (Optional[Packet], M) -> I
        if x is None:
            return None

        if x.head.major == CborMajorType.UINT:
            return x.head.argument

        raise ValueError(f'Can only accept uint values, got {x.head.major}')

    def i2m(self, _pkt, x):
        # type: (Optional[Packet], Optional[I]) -> M
        if x is None:
            return None

        if x >= 0:
            major = CborMajorType.UINT
            arg = x
        else:
            raise ValueError('Can only accept uint values')

        return CborChunk(head=CborHead(major=major, argument=arg))

    def randval(self):
        # type: () -> I
        return RandNum(0, self.maxval)


class CborEnumField(CborUintField):
    ''' An unsigned integer containing an enumerated value.

    :param enum: Available values for the field.
    :type enum: :py:cls:`enum.IntEnum`
    '''
    __slots__ = (
        'enum',
    )

    def __init__(self, name, default, enum):
        maxval = 0
        for val in enum:
            maxval = max(maxval, int(val))
        self.enum = enum

        CborUintField.__init__(self, name, default, maxval)

    def m2i(self, pkt, val):
        val = CborUintField.m2i(self, pkt, val)
        if val is not None:
            val = self.enum(val)
        return val


class CborFlagsField(CborUintField):
    ''' An unsigned integer containing enumerated flags.

    :param flags: Available flags for the field.
    :type flags: :py:cls:`enum.IntFlag`
    '''
    __slots__ = (
        'flags',
    )

    def __init__(self, name, default, flags):
        maxval = 0
        for val in flags:
            maxval |= int(val)
        self.flags = flags

        CborUintField.__init__(self, name, default, maxval)

    def m2i(self, pkt, x):
        x = CborUintField.m2i(self, pkt, x)
        if x is not None:
            x = self.flags(x)
        return x


class CborIntField(_CborItemBase, Field[int, CborChunk]):
    ''' Allow non-negative and negative integer values. '''

    def __init__(self, name, default=None):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, "H")

    def m2i(self, _pkt, x):
        # type: (Optional[Packet], M) -> I
        if x is None:
            return None

        if x.head.major == CborMajorType.UINT:
            return x.head.argument
        elif x.head.major == CborMajorType.NINT:
            return -1 - x.head.argument

        raise ValueError(f'Can only accept int values, got {x.head.major}')

    def i2m(self, _pkt, x):
        # type: (Optional[Packet], Optional[I]) -> M
        if x is None:
            return None

        if x >= 0:
            major = CborMajorType.UINT
            arg = x
        else:
            major = CborMajorType.NINT
            arg = -1 - x

        return CborChunk(head=CborHead(major=major, argument=arg))

    def randval(self):
        # type: () -> I
        return RandNum(-2**64, 2**64 - 1)


class _CborBstrBase(_CborItemBase):
    ''' Common byte string handling funcitons. '''

    decode_recurse = True
    ''' By default include the actual string content '''

    def m2i(self, _pkt, x):
        # type: (Optional[Packet], M) -> I
        if x is None:
            return None

        if x.head.major != CborMajorType.BSTR:
            raise ValueError('Can only accept bstr values')
        if self.maxlen is not None and len(x.content) > self.maxlen:
            raise ValueError(f'Length of bstr {len(x.content)} '
                             + f'longer than {self.maxlen}')
        return bytes(x.content)

    def i2m(self, _pkt, x):
        # type: (Optional[Packet], Optional[I]) -> M
        if x is None:
            return None

        return cbor_chunk_bstr(x)


class CborBstrField(_CborBstrBase, Field[bytes, CborChunk]):
    ''' Allow byte string values.

    The human form of this field is as a hex-encoded text.
    '''

    def __init__(self, name, default=None, maxlen=None):
        Field.__init__(self, name, default, "H")
        self.maxlen = maxlen

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], I) -> str
        if x is None:
            return None

        return x.hex()

    def i2h(self, _pkt, x):
        if x is None:
            return None

        return x.hex()

    def randval(self):
        # type: () -> I
        return RandBin(RandNum(0, self.maxlen or 256))


class CborPacketBstrField(_CborBstrBase, Field[Packet, CborChunk]):
    ''' Allow byte string values which are decoded as packet values.

    The internal and human forms are taken from the contained packet class.
    '''

    holds_packets = True

    @staticmethod
    def default_packet_cls(_pkt, _x):
        # type: (Optional[Packet], bytes) -> Type[Packet]
        return Raw

    def __init__(self, name, default=None, pkt_cls=None, maxlen=None):
        Field.__init__(self, name, default, "H")
        self.maxlen = maxlen
        self.pkt_cls = pkt_cls or CborPacketBstrField.default_packet_cls
    #
    # def i2repr(self, pkt, x):
    #     # type: (Optional[Packet], I) -> str
    #     if x is None:
    #         return None
    #
    #     if self._repr_size:
    #         return "{} byte content".format(len(x))
    #     else:
    #         return x.hex()

    def m2i(self, pkt, x):
        # type: (Optional[Packet], M) -> I
        if x is None:
            return None

        data = _CborBstrBase.m2i(self, pkt, x)
        return self.pkt_cls(pkt, data)(data)

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[I]) -> M
        if x is None:
            return None

        data = bytes(x)
        return _CborBstrBase.i2m(self, pkt, data)


class CborFieldArrayField(_CborItemBase, Field[List[Any], List[CborChunk]]):
    ''' A field which manages a list of sub-field values encoded in a
    definite-length array.
    '''
    islist = 1

    def __init__(
            self,
            name,  # type: str
            default,  # type: Optional[List[AnyField]]
            field,  # type: AnyField
            max_count=None,  # type: Optional[int]
    ):
        # type: (...) -> None
        if default is None:
            default = []  # Create a new list for each instance
        self.field = field
        Field.__init__(self, name, default)
        self.max_count = max_count

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[I]) -> bytes
        chunk = CborChunk(head=CborHead(CborMajorType.ARRAY, len(val)))
        data = cbor_encode_chunk(chunk)
        s += bytes(data)

        for ival in val:
            s = self.field.addfield(pkt, s, ival)

        return s

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, I]
        buf = bytearray(s)
        _used, chunk = cbor_decode_chunk(buf, recurse=self.decode_recurse)
        if chunk.head.major != CborMajorType.ARRAY:
            raise ValueError(f'Field must be an array, got {chunk.head.major}')

        if self.max_count is not None and chunk.head.argument > self.max_count:
            raise ValueError(f'Array size {chunk.head.argument} larger '
                             + f'than maximum {self.max_count}')

        ivals = []
        for _ix in range(chunk.head.argument):
            buf, ival = self.field.getfield(pkt, buf)
            ivals.append(ival)

        return bytes(buf), ivals
