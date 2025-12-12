# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Brian Sipos <brian.sipos@gmail.com>

"""
Classes that implement CBOR leaf data structures.
The current API is focused on definite-length strings and containers, but
does support indefinite-length variations.
"""

from dataclasses import dataclass, field
import enum
import itertools
import struct
from typing import Dict, List, Optional, Tuple, Union


@enum.unique
class CborMajorType(enum.IntEnum):
    ''' Major types defined in Section 3.1 of RFC 8949. '''

    UINT = 0
    ''' Unsigned integer '''
    NINT = 1
    ''' Negative integer '''
    BSTR = 2
    ''' Byte string '''
    TSTR = 3
    ''' Text string '''
    ARRAY = 4
    ''' Array of items '''
    MAP = 5
    ''' Map from item to item '''
    TAG = 6
    ''' Global tag value '''
    OTHERS = 7
    ''' Floats and simple values '''


@enum.unique
class CborSimpleValue(enum.IntEnum):
    ''' The defined argument values smaller than 256 for CborMajorType.OTHERS '''
    FALSE = 20
    TRUE = 21
    NULL = 22
    UNDEFINED = 23


CBOR_INDEF_BREAK = b'\xFF'
''' Encoded form of the indefinite break item. '''


@dataclass(frozen=True)
class CborHead:
    ''' The contents of a single CBOR head, which excludes the
    contents of string types or item containers.
    '''
    major: CborMajorType
    ''' The major type from the first three bits of the head. '''
    argument: Union[int, bytes, None]
    ''' The full argument value (unsigned integer), encoded float bytes,
    or None to indicate additional info 31.
    '''


CBOR_HEAD_UNDEFINED = CborHead(
    major=CborMajorType.OTHERS,
    argument=CborSimpleValue.UNDEFINED.value
)
''' Static definition of the default undefined value. '''


def cbor_encode_head(head: CborHead) -> bytearray:
    ''' Encode a single CBOR head (without content). '''
    # mutable initial byte with major type
    data = bytearray([int(head.major) << 5])

    if isinstance(head.argument, int):
        # normal unsigned arguments
        if head.argument < 24:
            addl = head.argument
            arglen = 0
        elif head.argument < 2**8:
            addl = 24
            arglen = 1
        elif head.argument < 2**16:
            addl = 25
            arglen = 2
        elif head.argument < 2**32:
            addl = 26
            arglen = 4
        elif head.argument < 2**64:
            addl = 27
            arglen = 8
        else:
            raise ValueError(f'invalid argument {head.argument}')

        if arglen:
            data += head.argument.to_bytes(arglen, 'big')

    elif isinstance(head.argument, bytes):
        # encoded floats
        arglen = len(head.argument)
        if arglen == 2:
            addl = 25
        elif arglen == 4:
            addl = 26
        elif arglen == 8:
            addl = 27
        else:
            raise ValueError(f'invalid argument {head.argument}')

        data += head.argument

    elif head.argument is None:
        addl = 31

    else:
        raise ValueError(f'invalid argument {head.argument}')

    # back-write additional info bits
    data[0] |= addl

    return data


def cbor_decode_head(data: bytearray) -> Tuple[int, Optional[CborHead]]:
    ''' Decode a single CBOR head (without content).

    :param data: The data to read and slice off the used portion.
    :return: A tuple of: the total size used and the decoded head object.
    '''
    try:
        init = int(data.pop(0))
    except (IndexError, TypeError):
        return 0, None
    used = 1
    major = CborMajorType(init >> 5)
    addl = init & 0x1F

    if addl < 24:
        arg = addl
    elif 24 <= addl <= 27:
        if addl == 24:
            arglen = 1
        elif addl == 25:
            arglen = 2
        elif addl == 26:
            arglen = 4
        elif addl == 27:
            arglen = 8

        if major == CborMajorType.OTHERS:
            # for encoded floats
            arg = bytes(data[:arglen])
        else:
            arg = int.from_bytes(data[:arglen], 'big')

        used += arglen
        del data[:arglen]
    elif 28 <= addl <= 30:
        raise ValueError('Not well defined CBOR')
    else:
        # addl value 31
        arg = None

    head = CborHead(
        major=major,
        argument=arg
    )
    return (used, head)


@dataclass(frozen=True)
class CborChunk:
    ''' The direct attributes of a CBOR head along with any tags on that item.
    This also contains a decoded semantically meaningful :py:attr:`content`
    interpreted according to the following uses.

    Major types UINT and NINT have content of :py:cls:`int` representing
    the decoded value. For UINT the content is identical to the head
    :py:attr:`CborHead.argument`, for NINT the content is the actual negative
    integer value.

    Major types BSTR and TSTR have content of :py:cls:`bytes` or :py:cls:`str` when
    decoding is performed recursively (TSTR can use pre-utf8-encoded bytes).

    Major types ARRAY and MAP have content of child :py:cls:`CborChunk` objects
    when decoding is performed recursively.

    Major type OTHERS has content of :py:cls:`CborSimpleValue` for specific
    enumerated simple values or :py:cls:`float` for floating point values.
    '''
    head: CborHead
    ''' A non-tag head value for this item. '''
    tags: Tuple[int] = field(default_factory=tuple)
    ''' Ordered list of tags from outer to inner for this item. '''
    content: Union[None,
                   int, bytes, str, CborSimpleValue, float,
                   List['CborChunk']] = None
    ''' Optional semantic content beyond the argument values. '''

    def is_break(self) -> bool:
        ''' Identify a break item for any indefinite-length container. '''
        return self.head.major == CborMajorType.OTHERS and self.head.argument is None

    def __str__(self) -> str:
        ''' Provide human-friendly representation inspired by
        CBOR Extended Diagnostic Notation (EDN).
        '''
        return 'CBOR({})'.format(self._diag())

    def _diag(self) -> str:
        ''' Internal recursive diagnostic notation for __str__. '''
        val = ''
        match self.head.major:
            case CborMajorType.UINT | CborMajorType.NINT:
                val = "{}".format(self.content)
            case CborMajorType.BSTR:
                val = "h'{}'".format(self.content.hex())
            case CborMajorType.TSTR:
                cnt = self.content
                if isinstance(cnt, bytes):
                    cnt = cnt.decode('utf8')
                val = '"{}"'.format(cnt)
            case CborMajorType.ARRAY:
                if self.content is not None:
                    val = '[{}]'.format(','.join(sub._diag() for sub in self.content))
                elif self.head.argument is None:
                    val = '[_'
                else:
                    val = '['
            case CborMajorType.OTHERS:
                match self.content:
                    case CborSimpleValue.FALSE:
                        val = 'false'
                    case CborSimpleValue.TRUE:
                        val = 'true'
                    case CborSimpleValue.NULL:
                        val = 'null'
                    case CborSimpleValue.UNDEFINED:
                        val = 'undefined'
                if isinstance(self.content, float):
                    val = '{:e}'.format(self.content)

        return val


def cbor_chunk_int(val: int) -> CborChunk:
    ''' Construct a consistent integer (possibly negative) value. '''
    if val >= 0:
        major = CborMajorType.UINT
        arg = val
    else:
        major = CborMajorType.NINT
        arg = -1 - val

    return CborChunk(
        head=CborHead(major=major, argument=arg),
        content=val
    )


def cbor_chunk_tstr(val: str) -> CborChunk:
    ''' Pre-encode and construct a consistent definite-length text string. '''
    data = val.encode('utf8')
    return CborChunk(
        head=CborHead(CborMajorType.TSTR, len(data)),
        content=data
    )


def cbor_chunk_bstr(val: bytes) -> CborChunk:
    ''' Construct a consistent definite-length byte string. '''
    val = bytes(val)
    return CborChunk(
        head=CborHead(CborMajorType.BSTR, len(val)),
        content=val
    )


def cbor_chunk_array(val: List[CborChunk]) -> CborChunk:
    ''' Construct a consistent definite-length array. '''
    return CborChunk(
        head=CborHead(CborMajorType.ARRAY, len(val)),
        content=list(val)
    )


def cbor_chunk_map(val: Dict[CborChunk, CborChunk]) -> CborChunk:
    ''' Construct a consistent definite-length map. '''
    return CborChunk(
        head=CborHead(CborMajorType.MAP, len(val)),
        content=[
            item for pair in val.items() for item in pair
        ]
    )


def cbor_chunk_simple(val: CborSimpleValue) -> CborChunk:
    ''' Construct a consistent simple value. '''
    return CborChunk(
        head=CborHead(major=CborMajorType.OTHERS, argument=val.value),
        content=CborSimpleValue(val)
    )


def cbor_chunk_float(val: float) -> CborChunk:
    ''' Construct a consistent floating point value. '''
    arg = struct.pack('!d', val)

    return CborChunk(
        head=CborHead(major=CborMajorType.OTHERS, argument=arg),
        content=float(val)
    )


def cbor_chunk_indef(major: CborMajorType, content=None) -> CborChunk:
    ''' Construct an indefinite-length start item.

    :param major: The major type enum.
    :param content: Optional content of the container.
        If not None, this will have a break item appended to it.
    :return: The chunk object.
    '''
    if content is not None:
        content = tuple(content) + (cbor_chunk_break(),)

    return CborChunk(
        head=CborHead(major=major, argument=None),
        content=content
    )


def cbor_chunk_break() -> CborChunk:
    ''' Construct an indefinite-length break item. '''
    return CborChunk(
        head=CborHead(major=CborMajorType.OTHERS, argument=None)
    )


def cbor_encode_chunk(chunk: CborChunk) -> bytearray:
    ''' Encode a chunk without recursion.

    :param chunk: The chunk to encode.
    :return: The serialized form of data.
    '''
    content = chunk.content
    if isinstance(content, (int, CborSimpleValue, float)):
        # not needed here
        content = None
    elif isinstance(content, str):
        # pre-encode text to get byte length
        content = content.encode('utf8')

    # use of argument for length must already be set before this
    buf = cbor_encode_head(chunk.head)

    # all other types than these are not encoded content but internal semantic use
    if isinstance(content, (bytes, bytearray)):
        buf += content
    elif isinstance(content, (list, tuple)):
        # recurse where possible
        for sub in content:
            buf += cbor_encode_chunk(sub)

    return buf


def cbor_decode_sequence(items: List[CborChunk], data: bytearray,
                         count: Union[int, None, False],
                         must_major: Optional[CborMajorType] = None) -> int:
    ''' Decode a CBOR sequence recursively.

    :param items: The list to append to.
        For an indefinite-length container, this will contain the break item.
    :param data: The data to read and slice off of.
    :param count: The number of items (top chunks) to decode or
        None to iterate until the CBOR break item is seen or
        False to iterate until the data is all read.
    :param must_major: If not None, the required major type for all items.
    :return: The total size of bytes read.
    '''
    if count is None or count is False:
        repeat = itertools.repeat(None)
    else:
        repeat = range(count)

    allused = 0
    for _ix in repeat:
        used, chunk = cbor_decode_chunk(data, recurse=True)
        if chunk is None:
            if count is False:
                break
            else:
                raise ValueError('Not enough items available')

        got_break = chunk.is_break()
        if got_break:
            if count is not None:
                raise ValueError('Got break item in definite-length sequence')
        else:
            if must_major is not None and chunk.head.major != must_major:
                raise ValueError(f'Require major type {must_major}'
                                 f' got {chunk.head.major}')

        allused += used
        items.append(chunk)
        # include the break item in the list
        if got_break:
            break

    return allused


def cbor_decode_chunk(data: bytearray,
                      recurse: bool = False) -> Tuple[int, Optional[CborChunk]]:
    ''' Decode a chunk by iterating through all tags until another
    major type is seen.

    :param data: The data to read and slice off the used portion.
    :param recurse: If true, recurse into the :py:attr:`CborChunk.content`
    after the head value.
    :return: A tuple of: the size slided off and the chunk which was read in.
    '''
    tags = []
    while True:
        used, head = cbor_decode_head(data)
        if head is None:
            return 0, None

        if head.major == CborMajorType.TAG:
            tags.append(head.argument)
        else:
            break

    # Handle content when requested
    cnt = None
    if head.major == CborMajorType.UINT:
        cnt = head.argument
    elif head.major == CborMajorType.NINT:
        cnt = -1 - head.argument
    elif head.major == CborMajorType.BSTR:
        if recurse:
            if head.argument is None:
                cnt = []
                used += cbor_decode_sequence(cnt, data, None, head.major)
            else:
                cnt = bytes(data[:head.argument])
                del data[:head.argument]
                used += head.argument

    elif head.major == CborMajorType.TSTR:
        if recurse:
            if head.argument is None:
                cnt = []
                used += cbor_decode_sequence(cnt, data, None, head.major)
            else:
                cnt = data[:head.argument].decode('utf8')
                del data[:head.argument]
                used += head.argument

    elif head.major == CborMajorType.ARRAY:
        if recurse:
            cnt = []
            used += cbor_decode_sequence(cnt, data, head.argument)

    elif head.major == CborMajorType.MAP:
        if recurse:
            # the map size is number of pairs, not items
            count = 2 * head.argument if head.argument is not None else None

            tmp = []
            used += cbor_decode_sequence(tmp, data, count)

            tmpit = iter(tmp)
            cnt = {}
            for key, sval in zip(tmpit, tmpit):
                cnt[key] = sval

    elif head.major == CborMajorType.OTHERS:
        if isinstance(head.argument, int):
            cnt = CborSimpleValue(head.argument)

        elif isinstance(head.argument, bytes):
            # float values decoded from the raw data
            arglen = len(head.argument)
            if arglen == 2:
                fmt = 'e'
            elif arglen == 4:
                fmt = 'f'
            elif arglen == 8:
                fmt = 'd'
            else:
                raise ValueError(f'invalid float length {arglen}')
            cnt = struct.unpack('!' + fmt, head.argument)[0]

        elif head.argument is None:
            cnt = None

        else:
            raise ValueError(f'invalid other argument type {type(head.argument)}')

    chunk = CborChunk(tags=tuple(tags), head=head, content=cnt)
    return used, chunk
