# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Brian Sipos <brian.sipos@gmail.com>


"""
Classes which support array-based CBOR packets.
"""

from typing import Callable, List, Optional, Tuple, Type
from .packet import Packet
from .cbor import (
    CBOR_INDEF_BREAK,
    CborMajorType, CborHead, cbor_encode_head, cbor_decode_chunk
)
from .cborfields import CborIntField


class CborSequencePacket(Packet):
    ''' A sequence of items, one item for each field in the packet.
    This packet does not include any head framing (e.g. an array) or
    any payload data.
    '''


class CborArrayPacket(CborSequencePacket):
    ''' An array of items, one for each field in the packet.
    Any additional bytes after the enclosing array are considered padding.

    The :py:inst:`cbor_use_indefinite` controls whether the encoded array is
    indefinite length or not.

    The decoder will handle indefinite-length arrays according to the data and
    store the original array argument (item count) in :py:inst:`array_head_arg`.
    For both encoding and decoding, the member :py:inst:`array_seen_items` is
    used to count the number of immediate items in the array.
    '''

    cbor_use_indefinite = False
    ''' By default encode to definite length array. '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.array_head_arg = None
        self.array_seen_items = 0

    def _inc_seen(self, pkt):
        # type: (Optional[Packet]) -> None
        ''' Increment the seen item counter on a parent CBOR packet. '''
        if hasattr(pkt, 'array_seen_items'):
            pkt.array_seen_items += 1

    def self_build(self):
        # type: () -> bytes
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache

        self.array_head_arg = None
        self.array_seen_items = 0

        seqdata = super().self_build()
        # notify parent of this array item
        self._inc_seen(self.parent)
        print('self_build', self.name, self.parent, getattr(self.parent, 'array_seen_items', None))

        # define prepended array framing
        if self.cbor_use_indefinite:
            head = bytes(cbor_encode_head(CborHead(CborMajorType.ARRAY, None)))
            tail = bytes(cbor_encode_head(CborHead(CborMajorType.OTHERS, None)))
        else:
            print('FIN', self.array_seen_items)
            head = bytes(cbor_encode_head(CborHead(CborMajorType.ARRAY,
                                                   self.array_seen_items)))
            tail = b''

        return head + seqdata + tail

    def do_build_payload(self):
        # type: () -> bytes
        return b''

    def do_dissect(self, x):
        # type: (bytes) -> bytes

        # inspect envelope
        buf = bytearray(x)
        _used, chunk = cbor_decode_chunk(buf, recurse=False)
        if chunk.head.major != CborMajorType.ARRAY:
            raise ValueError(f'Must have array head, got {chunk.head.major}')

        self.array_head_arg = chunk.head.argument
        self.array_seen_items = 0
        # notify parent of this array item
        self._inc_seen(self.parent)

        res = super().do_dissect(bytes(buf))

        if self.array_head_arg is None:
            # match an indefinite break with an indefinite array head
            try:
                nextres = res[0]
                res = res[1:]
            except IndexError:
                nextres = None
            if nextres != 0xff:
                raise ValueError(f'Array needs an indefinite break, have {nextres}')
        else:
            if self.array_seen_items != self.array_head_arg:
                raise ValueError(f'Array needs {self.array_head_arg} items, '
                                 f'have {self.array_seen_items}')

        # ensure the cache is the full original data
        self.raw_packet_cache = x
        return res

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return b'', s


def cbor_array_item_cb(pkt_cls: Type[Packet]) -> Callable:
    ''' Build a callback to satisfy the :py:cls:`PacketListField`
    parameter for `next_cls_cb`.

    :param pkt_cls: The class to decode when the array has not ended.
    :return: A callback function.
    '''

    def next_item_cb(pkt: Packet,
                     _lst: List[Packet],
                     _cur: Optional[Packet],
                     remain: bytes,
                     ) -> Optional[Type[Packet]]:
        ''' Determine if there is a next block to decode '''

        if isinstance(pkt, CborArrayPacket):
            if pkt.array_head_arg is not None:
                # definite length counter
                if pkt.array_seen_items < pkt.array_head_arg:
                    return pkt_cls
            else:
                # indefinite length until break
                if remain and not remain.startswith(CBOR_INDEF_BREAK):
                    print('REM', pkt.array_head_arg, remain.hex())
                    return pkt_cls
        return None

    return next_item_cb


class CborTestPkt(CborArrayPacket):
    ''' Dummy test packet '''
    fields_desc = [
        CborIntField('one', 5),
        CborIntField('two', None),
    ]
