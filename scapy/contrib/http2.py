# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016  Florian Maury <florian.maury@ssi.gouv.fr>

"""
http2

HTTP/2 support for Scapy
see RFC7540 and RFC7541 for more information

Implements packets and fields required to encode/decode HTTP/2 Frames
and HPack encoded headers
"""

# scapy.contrib.status=loads
# scapy.contrib.description=HTTP/2 (RFC 7540, RFC 7541)

# base_classes triggers an unwanted import warning

from __future__ import absolute_import
from __future__ import print_function
import abc
import re
from io import BytesIO
import struct
import scapy.libs.six as six
from scapy.compat import raw, plain_str, hex_bytes, orb, chb, bytes_encode

# Only required if using mypy-lang for static typing
# Most symbols are used in mypy-interpreted "comments".
# Sized must be one of the superclasses of a class implementing __len__
from scapy.compat import Optional, List, Union, Callable, Any, \
    Tuple, Sized, Pattern  # noqa: F401
from scapy.base_classes import Packet_metaclass  # noqa: F401

import scapy.fields as fields
import scapy.packet as packet
import scapy.config as config
import scapy.volatile as volatile
import scapy.error as error

###############################################################################
#                                                HPACK Integer Fields         #
###############################################################################


class HPackMagicBitField(fields.BitField):
    """ HPackMagicBitField is a BitField variant that cannot be assigned another
    value than the default one. This field must not be used where there is
    potential for fuzzing. OTOH, this field makes sense (for instance, if the
    magic bits are used by a dispatcher to select the payload class)
    """

    __slots__ = ['_magic']

    def __init__(self, name, default, size):
        # type: (str, int, int) -> None
        """
        :param str name: this field instance name.
        :param int default: this field only valid value.
        :param int size: this bitfield bitlength.
        :return: None
        :raises: AssertionError
        """
        assert default >= 0
        # size can be negative if encoding is little-endian (see rev property of bitfields)  # noqa: E501
        assert size != 0
        self._magic = default
        super(HPackMagicBitField, self).__init__(name, default, size)

    def addfield(self, pkt, s, val):
        # type: (Optional[packet.Packet], Union[str, Tuple[str, int, int]], int) -> Union[str, Tuple[str, int, int]]  # noqa: E501
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused.  # noqa: E501
        :param str|(str, int, long) s: either a str if 0 == size%8 or a tuple with the string to add this field to, the  # noqa: E501
          number of bits already generated and the generated value so far.
        :param int val: unused; must be equal to default value
        :return: str|(str, int, long): the s string extended with this field machine representation  # noqa: E501
        :raises: AssertionError
        """
        assert val == self._magic, 'val parameter must value {}; received: {}'.format(self._magic, val)  # noqa: E501
        return super(HPackMagicBitField, self).addfield(pkt, s, self._magic)

    def getfield(self, pkt, s):
        # type: (Optional[packet.Packet], Union[str, Tuple[str, int]]) -> Tuple[Union[Tuple[str, int], str], int]  # noqa: E501
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused.  # noqa: E501
        :param str|(str, int) s: either a str if size%8==0 or a tuple with the string to parse from and the number of  # noqa: E501
          bits already consumed by previous bitfield-compatible fields.
        :return: (str|(str, int), int): Returns the remaining string and the parsed value. May return a tuple if there  # noqa: E501
          are remaining bits to parse in the first byte. Returned value is equal to default value  # noqa: E501
        :raises: AssertionError
        """
        r = super(HPackMagicBitField, self).getfield(pkt, s)
        assert (
            isinstance(r, tuple) and
            len(r) == 2 and
            isinstance(r[1], six.integer_types)
        ), 'Second element of BitField.getfield return value expected to be an int or a long; API change detected'  # noqa: E501
        assert r[1] == self._magic, 'Invalid value parsed from s; error in class guessing detected!'  # noqa: E501
        return r

    def h2i(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused  # noqa: E501
        :param int x: unused; must be equal to default value
        :return: int; default value
        :raises: AssertionError
        """
        assert x == self._magic, \
            'EINVAL: x: This field is magic. Do not attempt to modify it. Expected value: {}'.format(self._magic)  # noqa: E501
        return super(HPackMagicBitField, self).h2i(pkt, self._magic)

    def i2h(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused  # noqa: E501
        :param int x: unused; must be equal to default value
        :return: int; default value
        :raises: AssertionError
        """
        assert x == self._magic, \
            'EINVAL: x: This field is magic. Do not attempt to modify it. Expected value: {}'.format(self._magic)  # noqa: E501
        return super(HPackMagicBitField, self).i2h(pkt, self._magic)

    def m2i(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused  # noqa: E501
        :param int x: must be the machine representatino of the default value
        :return: int; default value
        :raises: AssertionError
        """
        r = super(HPackMagicBitField, self).m2i(pkt, x)
        assert r == self._magic, 'Invalid value parsed from m2i; error in class guessing detected!'  # noqa: E501
        return r

    def i2m(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused  # noqa: E501
        :param int x: unused; must be equal to default value
        :return: int; default value
        :raises: AssertionError
        """
        assert x == self._magic, \
            'EINVAL: x: This field is magic. Do not attempt to modify it. Expected value: {}'.format(self._magic)  # noqa: E501
        return super(HPackMagicBitField, self).i2m(pkt, self._magic)

    def any2i(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused  # noqa: E501
        :param int x: unused; must be equal to default value
        :return: int; default value
        :raises: AssertionError
        """
        assert x == self._magic, \
            'EINVAL: x: This field is magic. Do not attempt to modify it. Expected value: {}'.format(self._magic)  # noqa: E501
        return super(HPackMagicBitField, self).any2i(pkt, self._magic)


class AbstractUVarIntField(fields.Field):
    """AbstractUVarIntField represents an integer as defined in RFC7541
    """

    __slots__ = ['_max_value', 'size', 'rev']
    """
    :var int size: the bit length of the prefix of this AbstractUVarIntField. It  # noqa: E501
        represents the complement of the number of MSB that are used in the
        current byte for other purposes by some other BitFields
    :var int _max_value: the maximum value that can be stored in the
        sole prefix. If the integer equals or exceeds this value, the max prefix
        value is assigned to the size first bits and the multibyte representation
        is used
    :var bool rev: is a fake property, also emulated for the sake of
        compatibility with Bitfields
    """

    def __init__(self, name, default, size):
        # type: (str, Optional[int], int) -> None
        """
        :param str name: the name of this field instance
        :param int|None default: positive, null or None default value for this field instance.  # noqa: E501
        :param int size: the number of bits to consider in the first byte. Valid range is ]0;8]  # noqa: E501
        :return: None
        :raises: AssertionError
        """
        assert default is None or (isinstance(default, six.integer_types) and default >= 0)  # noqa: E501
        assert 0 < size <= 8
        super(AbstractUVarIntField, self).__init__(name, default)
        self.size = size
        self._max_value = (1 << self.size) - 1

        # Configuring the fake property that is useless for this class but that is  # noqa: E501
        # expected from BitFields
        self.rev = False

    def h2i(self, pkt, x):
        # type: (Optional[packet.Packet], Optional[int]) -> Optional[int]
        """
        :param packet.Packet|None pkt: unused.
        :param int|None x: the value to convert.
        :return: int|None: the converted value.
        :raises: AssertionError
        """
        assert not isinstance(x, six.integer_types) or x >= 0
        return x

    def i2h(self, pkt, x):
        # type: (Optional[packet.Packet], Optional[int]) -> Optional[int]
        """
        :param packet.Packet|None pkt: unused.
        :param int|None x: the value to convert.
        :return:: int|None: the converted value.
        """
        return x

    def _detect_multi_byte(self, fb):
        # type: (str) -> bool
        """ _detect_multi_byte returns whether the AbstractUVarIntField is represented on  # noqa: E501
          multiple bytes or not.

          A multibyte representation is indicated by all of the first size bits being set  # noqa: E501

        :param str fb: first byte, as a character.
        :return: bool: True if multibyte repr detected, else False.
        :raises: AssertionError
        """
        assert isinstance(fb, int) or len(fb) == 1
        return (orb(fb) & self._max_value) == self._max_value

    def _parse_multi_byte(self, s):
        # type: (str) -> int
        """ _parse_multi_byte parses x as a multibyte representation to get the
          int value of this AbstractUVarIntField.

        :param str s: the multibyte string to parse.
        :return: int: The parsed int value represented by this AbstractUVarIntField.  # noqa: E501
        :raises:: AssertionError
        :raises:: Scapy_Exception if the input value encodes an integer larger than 1<<64  # noqa: E501
        """

        assert len(s) >= 2

        tmp_len = len(s)

        value = 0
        i = 1
        byte = orb(s[i])
        # For CPU sake, stops at an arbitrary large number!
        max_value = 1 << 64
        # As long as the MSG is set, an another byte must be read
        while byte & 0x80:
            value += (byte ^ 0x80) << (7 * (i - 1))
            if value > max_value:
                raise error.Scapy_Exception(
                    'out-of-bound value: the string encodes a value that is too large (>2^{{64}}): {}'.format(value)  # noqa: E501
                )
            i += 1
            assert i < tmp_len, 'EINVAL: x: out-of-bound read: the string ends before the AbstractUVarIntField!'  # noqa: E501
            byte = orb(s[i])
        value += byte << (7 * (i - 1))
        value += self._max_value

        assert value >= 0
        return value

    def m2i(self, pkt, x):
        # type: (Optional[packet.Packet], Union[str, Tuple[str, int]]) -> int
        """
          A tuple is expected for the "x" param only if "size" is different than 8. If a tuple is received, some bits  # noqa: E501
          were consumed by another field. This field consumes the remaining bits, therefore the int of the tuple must  # noqa: E501
          equal "size".

        :param packet.Packet|None pkt: unused.
        :param str|(str, int) x: the string to convert. If bits were consumed by a previous bitfield-compatible field.  # noqa: E501
        :raises: AssertionError
        """
        assert isinstance(x, bytes) or (isinstance(x, tuple) and x[1] >= 0)

        if isinstance(x, tuple):
            assert (8 - x[1]) == self.size, 'EINVAL: x: not enough bits remaining in current byte to read the prefix'  # noqa: E501
            val = x[0]
        else:
            assert isinstance(x, bytes) and self.size == 8, 'EINVAL: x: tuple expected when prefix_len is not a full byte'  # noqa: E501
            val = x

        if self._detect_multi_byte(val[0]):
            ret = self._parse_multi_byte(val)
        else:
            ret = orb(val[0]) & self._max_value

        assert ret >= 0
        return ret

    def i2m(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> str
        """
        :param packet.Packet|None pkt: unused.
        :param int x: the value to convert.
        :return: str: the converted value.
        :raises: AssertionError
        """
        assert x >= 0

        if x < self._max_value:
            return chb(x)
        else:
            # The sl list join is a performance trick, because string
            # concatenation is not efficient with Python immutable strings
            sl = [chb(self._max_value)]
            x -= self._max_value
            while x >= 0x80:
                sl.append(chb(0x80 | (x & 0x7F)))
                x >>= 7
            sl.append(chb(x))
            return b''.join(sl)

    def any2i(self, pkt, x):
        # type: (Optional[packet.Packet], Union[None, str, int]) -> Optional[int]  # noqa: E501
        """
          A "x" value as a string is parsed as a binary encoding of a UVarInt. An int is considered an internal value.  # noqa: E501
          None is returned as is.

        :param packet.Packet|None pkt: the packet containing this field; probably unused.  # noqa: E501
        :param str|int|None x: the value to convert.
        :return: int|None: the converted value.
        :raises: AssertionError
        """
        if isinstance(x, type(None)):
            return x
        if isinstance(x, six.integer_types):
            assert x >= 0
            ret = self.h2i(pkt, x)
            assert isinstance(ret, six.integer_types) and ret >= 0
            return ret
        elif isinstance(x, bytes):
            ret = self.m2i(pkt, x)
            assert (isinstance(ret, six.integer_types) and ret >= 0)
            return ret
        assert False, 'EINVAL: x: No idea what the parameter format is'

    def i2repr(self, pkt, x):
        # type: (Optional[packet.Packet], Optional[int]) -> str
        """
        :param packet.Packet|None pkt: probably unused.
        :param x: int|None: the positive, null or none value to convert.
        :return: str: the representation of the value.
        """
        return repr(self.i2h(pkt, x))

    def addfield(self, pkt, s, val):
        # type: (Optional[packet.Packet], Union[str, Tuple[str, int, int]], int) -> str  # noqa: E501
        """
          An AbstractUVarIntField prefix always consumes the remaining bits
          of a BitField;if no current BitField is in use (no tuple in
          entry) then the prefix length is 8 bits and the whole byte is to
          be consumed

        :param packet.Packet|None pkt: the packet containing this field.
          Probably unused.
        :param str|(str, int, long) s: the string to append this field to.
          A tuple indicates that some bits were already generated by another
          bitfield-compatible field. This MUST be the case if "size" is not 8.
          The int is the number of bits already generated in the first byte of
          the str. The long is the value that was generated by the previous
          bitfield-compatible fields.
        :param int val: the positive or null value to be added.
        :return: str: s concatenated with the machine representation of this
          field.
        :raises: AssertionError
        """
        assert val >= 0
        if isinstance(s, bytes):
            assert self.size == 8, 'EINVAL: s: tuple expected when prefix_len is not a full byte'  # noqa: E501
            return s + self.i2m(pkt, val)

        # s is a tuple
        # assert s[1] >= 0
        # assert s[2] >= 0
        # assert (8 - s[1]) == self.size, 'EINVAL: s: not enough bits remaining in current byte to read the prefix'  # noqa: E501

        if val >= self._max_value:
            return s[0] + chb((s[2] << self.size) + self._max_value) + self.i2m(pkt, val)[1:]  # noqa: E501
        # This AbstractUVarIntField is only one byte long; setting the prefix value  # noqa: E501
        # and appending the resulting byte to the string
        return s[0] + chb((s[2] << self.size) + orb(self.i2m(pkt, val)))

    @staticmethod
    def _detect_bytelen_from_str(s):
        # type: (str) -> int
        """ _detect_bytelen_from_str returns the length of the machine
          representation of an AbstractUVarIntField starting at the beginning
          of s and which is assumed to expand over multiple bytes
          (value > _max_prefix_value).

        :param str s: the string to parse. It is assumed that it is a multibyte int.  # noqa: E501
        :return: The bytelength of the AbstractUVarIntField.
        :raises: AssertionError
        """
        assert len(s) >= 2
        tmp_len = len(s)

        i = 1
        while orb(s[i]) & 0x80 > 0:
            i += 1
            assert i < tmp_len, 'EINVAL: s: out-of-bound read: unfinished AbstractUVarIntField detected'  # noqa: E501
        ret = i + 1

        assert ret >= 0
        return ret

    def i2len(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """
        :param packet.Packet|None pkt: unused.
        :param int x: the positive or null value whose binary size if requested.  # noqa: E501
        :raises: AssertionError
        """
        assert x >= 0
        if x < self._max_value:
            return 1

        # x is expressed over multiple bytes
        x -= self._max_value
        i = 1
        if x == 0:
            i += 1
        while x > 0:
            x >>= 7
            i += 1

        ret = i
        assert ret >= 0
        return ret

    def getfield(self, pkt, s):
        # type: (Optional[packet.Packet], Union[str, Tuple[str, int]]) -> Tuple[str, int]  # noqa: E501
        """
        :param packet.Packet|None pkt: the packet instance containing this
          field; probably unused.
        :param str|(str, int) s: the input value to get this field value from.
          If size is 8, s is a string, else it is a tuple containing the value
          and an int indicating the number of bits already consumed in the
          first byte of the str. The number of remaining bits to consume in the
          first byte must be equal to "size".
        :return: (str, int): the remaining bytes of s and the parsed value.
        :raises: AssertionError
        """
        if isinstance(s, tuple):
            assert len(s) == 2
            temp = s  # type: Tuple[str, int]
            ts, ti = temp
            assert ti >= 0
            assert 8 - ti == self.size, 'EINVAL: s: not enough bits remaining in current byte to read the prefix'  # noqa: E501
            val = ts
        else:
            assert isinstance(s, bytes) and self.size == 8, 'EINVAL: s: tuple expected when prefix_len is not a full byte'  # noqa: E501
            val = s

        if self._detect_multi_byte(val[0]):
            tmp_len = self._detect_bytelen_from_str(val)
        else:
            tmp_len = 1

        ret = val[tmp_len:], self.m2i(pkt, s)
        assert ret[1] >= 0
        return ret

    def randval(self):
        # type: () -> volatile.VolatileValue
        """
        :return: volatile.VolatileValue: a volatile value for this field "long"-compatible internal value.  # noqa: E501
        """
        return volatile.RandLong()


class UVarIntField(AbstractUVarIntField):
    def __init__(self, name, default, size):
        # type: (str, int, int) -> None
        """
        :param str name: the name of this field instance.
        :param default: the default value for this field instance. default must be positive or null.  # noqa: E501
        :raises: AssertionError
        """
        assert default >= 0
        assert 0 < size <= 8

        super(UVarIntField, self).__init__(name, default, size)
        self.size = size
        self._max_value = (1 << self.size) - 1

        # Configuring the fake property that is useless for this class but that is  # noqa: E501
        # expected from BitFields
        self.rev = False

    def h2i(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """ h2i is overloaded to restrict the acceptable x values (not None)

        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused.  # noqa: E501
        :param int x: the value to convert.
        :return: int: the converted value.
        :raises: AssertionError
        """
        ret = super(UVarIntField, self).h2i(pkt, x)
        assert not isinstance(ret, type(None)) and ret >= 0
        return ret

    def i2h(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> int
        """ i2h is overloaded to restrict the acceptable x values (not None)

        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused.  # noqa: E501
        :param int x: the value to convert.
        :return: int: the converted value.
        :raises: AssertionError
        """
        ret = super(UVarIntField, self).i2h(pkt, x)
        assert not isinstance(ret, type(None)) and ret >= 0
        return ret

    def any2i(self, pkt, x):
        # type: (Optional[packet.Packet], Union[str, int]) -> int
        """ any2i is overloaded to restrict the acceptable x values (not None)

        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused.  # noqa: E501
        :param str|int x: the value to convert.
        :return: int: the converted value.
        :raises: AssertionError
        """
        ret = super(UVarIntField, self).any2i(pkt, x)
        assert not isinstance(ret, type(None)) and ret >= 0
        return ret

    def i2repr(self, pkt, x):
        # type: (Optional[packet.Packet], int) -> str
        """ i2repr is overloaded to restrict the acceptable x values (not None)

        :param packet.Packet|None pkt: the packet instance containing this field instance; probably unused.  # noqa: E501
        :param int x: the value to convert.
        :return: str: the converted value.
        """
        return super(UVarIntField, self).i2repr(pkt, x)


class FieldUVarLenField(AbstractUVarIntField):
    __slots__ = ['_length_of', '_adjust']

    def __init__(self, name, default, size, length_of, adjust=lambda x: x):
        # type: (str, Optional[int], int, str, Callable[[int], int]) -> None
        """ Initializes a FieldUVarLenField

        :param str name: The name of this field instance.
        :param int|None default: the default value of this field instance.
        :param int size: the number of bits that are occupied by this field in the first byte of a binary string.  # noqa: E501
          size must be in the range ]0;8].
        :param str length_of: The name of the field this field value is measuring/representing.  # noqa: E501
        :param callable adjust: A function that modifies the value computed from the "length_of" field.  # noqa: E501

        adjust can be used for instance to add a constant to the length_of field  # noqa: E501
         length. For instance, let's say that i2len of the length_of field
         returns 2. If adjust is lambda x: x+1 In that case, this field will
         value 3 at build time.
        :return: None
        :raises: AssertionError
        """
        assert default is None or default >= 0
        assert 0 < size <= 8

        super(FieldUVarLenField, self).__init__(name, default, size)
        self._length_of = length_of
        self._adjust = adjust

    def addfield(self, pkt, s, val):
        # type: (Optional[packet.Packet], Union[str, Tuple[str, int, int]], Optional[int]) -> str  # noqa: E501
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance. This parameter must not be  # noqa: E501
          None if the val parameter is.
        :param str|(str, int, long) s: the string to append this field to. A tuple indicates that some bits were already  # noqa: E501
          generated by another bitfield-compatible field. This MUST be the case if "size" is not 8. The int is the  # noqa: E501
          number of bits already generated in the first byte of the str. The long is the value that was generated by the  # noqa: E501
          previous bitfield-compatible fields.
        :param int|None val: the positive or null value to be added. If None, the value is computed from pkt.  # noqa: E501
        :return: str: s concatenated with the machine representation of this field.  # noqa: E501
        :raises: AssertionError
        """
        if val is None:
            assert isinstance(pkt, packet.Packet), \
                'EINVAL: pkt: Packet expected when val is None; received {}'.format(type(pkt))  # noqa: E501
            val = self._compute_value(pkt)
        return super(FieldUVarLenField, self).addfield(pkt, s, val)

    def i2m(self, pkt, x):
        # type: (Optional[packet.Packet], Optional[int]) -> str
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance. This parameter must not be  # noqa: E501
          None if the x parameter is.
        :param int|None x: the positive or null value to be added. If None, the value is computed from pkt.  # noqa: E501
        :return: str
        :raises: AssertionError
        """
        if x is None:
            assert isinstance(pkt, packet.Packet), \
                'EINVAL: pkt: Packet expected when x is None; received {}'.format(type(pkt))  # noqa: E501
            x = self._compute_value(pkt)
        return super(FieldUVarLenField, self).i2m(pkt, x)

    def _compute_value(self, pkt):
        # type: (packet.Packet) -> int
        """ Computes the value of this field based on the provided packet and
        the length_of field and the adjust callback

        :param packet.Packet pkt: the packet from which is computed this field value.  # noqa: E501
        :return: int: the computed value for this field.
        :raises: KeyError: the packet nor its payload do not contain an attribute
          with the length_of name.
        :raises: AssertionError
        :raises: KeyError if _length_of is not one of pkt fields
        """
        fld, fval = pkt.getfield_and_val(self._length_of)
        val = fld.i2len(pkt, fval)
        ret = self._adjust(val)
        assert ret >= 0
        return ret

###############################################################################
#                                                HPACK String Fields          #
###############################################################################


@six.add_metaclass(abc.ABCMeta)
class HPackStringsInterface(Sized):  # type: ignore
    @abc.abstractmethod
    def __str__(self):
        pass

    def __bytes__(self):
        r = self.__str__()
        return bytes_encode(r)

    @abc.abstractmethod
    def origin(self):
        pass

    @abc.abstractmethod
    def __len__(self):
        pass


class HPackLiteralString(HPackStringsInterface):
    """ HPackLiteralString is a string. This class is used as a marker and
    implements an interface in common with HPackZString
    """
    __slots__ = ['_s']

    def __init__(self, s):
        # type: (str) -> None
        self._s = s

    def __str__(self):
        # type: () -> str
        return self._s

    def origin(self):
        # type: () -> str
        return plain_str(self._s)

    def __len__(self):
        # type: () -> int
        return len(self._s)


class EOS(object):
    """ Simple "marker" to designate the End Of String symbol in the huffman table
    """


class HuffmanNode(object):
    """ HuffmanNode is an entry of the binary tree used for encoding/decoding
    HPack compressed HTTP/2 headers
    """

    __slots__ = ['left', 'right']
    """@var l: the left branch of this node
    @var r: the right branch of this Node

    These variables can value None (leaf node), another HuffmanNode, or a
     symbol. Symbols are either a character or the End Of String symbol (class
     EOS)
    """

    def __init__(self, left, right):
        # type: (Union[None, HuffmanNode, EOS, str], Union[None, HuffmanNode, EOS, str]) -> None  # noqa: E501
        self.left = left
        self.right = right

    def __getitem__(self, b):
        # type: (int) -> Union[None, HuffmanNode, EOS, str]
        return self.right if b else self.left

    def __setitem__(self, b, val):
        # type: (int, Union[None, HuffmanNode, EOS, str]) -> None
        if b:
            self.right = val
        else:
            self.left = val

    def __str__(self):
        # type: () -> str
        return self.__repr__()

    def __repr__(self):
        # type: () -> str
        return '({}, {})'.format(self.left, self.right)


class InvalidEncodingException(Exception):
    """ InvalidEncodingException is raised when a supposedly huffman-encoded
     string is decoded and a decoding error arises
    """


class HPackZString(HPackStringsInterface):
    __slots__ = ['_s', '_encoded']

    # From RFC 7541
    # Tuple is (code,code bitlength)
    # The bitlength is required to know how long the left padding
    # (implicit 0's) there are
    static_huffman_code = [
        (0x1ff8, 13),
        (0x7fffd8, 23),
        (0xfffffe2, 28),
        (0xfffffe3, 28),
        (0xfffffe4, 28),
        (0xfffffe5, 28),
        (0xfffffe6, 28),
        (0xfffffe7, 28),
        (0xfffffe8, 28),
        (0xffffea, 24),
        (0x3ffffffc, 30),
        (0xfffffe9, 28),
        (0xfffffea, 28),
        (0x3ffffffd, 30),
        (0xfffffeb, 28),
        (0xfffffec, 28),
        (0xfffffed, 28),
        (0xfffffee, 28),
        (0xfffffef, 28),
        (0xffffff0, 28),
        (0xffffff1, 28),
        (0xffffff2, 28),
        (0x3ffffffe, 30),
        (0xffffff3, 28),
        (0xffffff4, 28),
        (0xffffff5, 28),
        (0xffffff6, 28),
        (0xffffff7, 28),
        (0xffffff8, 28),
        (0xffffff9, 28),
        (0xffffffa, 28),
        (0xffffffb, 28),
        (0x14, 6),
        (0x3f8, 10),
        (0x3f9, 10),
        (0xffa, 12),
        (0x1ff9, 13),
        (0x15, 6),
        (0xf8, 8),
        (0x7fa, 11),
        (0x3fa, 10),
        (0x3fb, 10),
        (0xf9, 8),
        (0x7fb, 11),
        (0xfa, 8),
        (0x16, 6),
        (0x17, 6),
        (0x18, 6),
        (0x0, 5),
        (0x1, 5),
        (0x2, 5),
        (0x19, 6),
        (0x1a, 6),
        (0x1b, 6),
        (0x1c, 6),
        (0x1d, 6),
        (0x1e, 6),
        (0x1f, 6),
        (0x5c, 7),
        (0xfb, 8),
        (0x7ffc, 15),
        (0x20, 6),
        (0xffb, 12),
        (0x3fc, 10),
        (0x1ffa, 13),
        (0x21, 6),
        (0x5d, 7),
        (0x5e, 7),
        (0x5f, 7),
        (0x60, 7),
        (0x61, 7),
        (0x62, 7),
        (0x63, 7),
        (0x64, 7),
        (0x65, 7),
        (0x66, 7),
        (0x67, 7),
        (0x68, 7),
        (0x69, 7),
        (0x6a, 7),
        (0x6b, 7),
        (0x6c, 7),
        (0x6d, 7),
        (0x6e, 7),
        (0x6f, 7),
        (0x70, 7),
        (0x71, 7),
        (0x72, 7),
        (0xfc, 8),
        (0x73, 7),
        (0xfd, 8),
        (0x1ffb, 13),
        (0x7fff0, 19),
        (0x1ffc, 13),
        (0x3ffc, 14),
        (0x22, 6),
        (0x7ffd, 15),
        (0x3, 5),
        (0x23, 6),
        (0x4, 5),
        (0x24, 6),
        (0x5, 5),
        (0x25, 6),
        (0x26, 6),
        (0x27, 6),
        (0x6, 5),
        (0x74, 7),
        (0x75, 7),
        (0x28, 6),
        (0x29, 6),
        (0x2a, 6),
        (0x7, 5),
        (0x2b, 6),
        (0x76, 7),
        (0x2c, 6),
        (0x8, 5),
        (0x9, 5),
        (0x2d, 6),
        (0x77, 7),
        (0x78, 7),
        (0x79, 7),
        (0x7a, 7),
        (0x7b, 7),
        (0x7ffe, 15),
        (0x7fc, 11),
        (0x3ffd, 14),
        (0x1ffd, 13),
        (0xffffffc, 28),
        (0xfffe6, 20),
        (0x3fffd2, 22),
        (0xfffe7, 20),
        (0xfffe8, 20),
        (0x3fffd3, 22),
        (0x3fffd4, 22),
        (0x3fffd5, 22),
        (0x7fffd9, 23),
        (0x3fffd6, 22),
        (0x7fffda, 23),
        (0x7fffdb, 23),
        (0x7fffdc, 23),
        (0x7fffdd, 23),
        (0x7fffde, 23),
        (0xffffeb, 24),
        (0x7fffdf, 23),
        (0xffffec, 24),
        (0xffffed, 24),
        (0x3fffd7, 22),
        (0x7fffe0, 23),
        (0xffffee, 24),
        (0x7fffe1, 23),
        (0x7fffe2, 23),
        (0x7fffe3, 23),
        (0x7fffe4, 23),
        (0x1fffdc, 21),
        (0x3fffd8, 22),
        (0x7fffe5, 23),
        (0x3fffd9, 22),
        (0x7fffe6, 23),
        (0x7fffe7, 23),
        (0xffffef, 24),
        (0x3fffda, 22),
        (0x1fffdd, 21),
        (0xfffe9, 20),
        (0x3fffdb, 22),
        (0x3fffdc, 22),
        (0x7fffe8, 23),
        (0x7fffe9, 23),
        (0x1fffde, 21),
        (0x7fffea, 23),
        (0x3fffdd, 22),
        (0x3fffde, 22),
        (0xfffff0, 24),
        (0x1fffdf, 21),
        (0x3fffdf, 22),
        (0x7fffeb, 23),
        (0x7fffec, 23),
        (0x1fffe0, 21),
        (0x1fffe1, 21),
        (0x3fffe0, 22),
        (0x1fffe2, 21),
        (0x7fffed, 23),
        (0x3fffe1, 22),
        (0x7fffee, 23),
        (0x7fffef, 23),
        (0xfffea, 20),
        (0x3fffe2, 22),
        (0x3fffe3, 22),
        (0x3fffe4, 22),
        (0x7ffff0, 23),
        (0x3fffe5, 22),
        (0x3fffe6, 22),
        (0x7ffff1, 23),
        (0x3ffffe0, 26),
        (0x3ffffe1, 26),
        (0xfffeb, 20),
        (0x7fff1, 19),
        (0x3fffe7, 22),
        (0x7ffff2, 23),
        (0x3fffe8, 22),
        (0x1ffffec, 25),
        (0x3ffffe2, 26),
        (0x3ffffe3, 26),
        (0x3ffffe4, 26),
        (0x7ffffde, 27),
        (0x7ffffdf, 27),
        (0x3ffffe5, 26),
        (0xfffff1, 24),
        (0x1ffffed, 25),
        (0x7fff2, 19),
        (0x1fffe3, 21),
        (0x3ffffe6, 26),
        (0x7ffffe0, 27),
        (0x7ffffe1, 27),
        (0x3ffffe7, 26),
        (0x7ffffe2, 27),
        (0xfffff2, 24),
        (0x1fffe4, 21),
        (0x1fffe5, 21),
        (0x3ffffe8, 26),
        (0x3ffffe9, 26),
        (0xffffffd, 28),
        (0x7ffffe3, 27),
        (0x7ffffe4, 27),
        (0x7ffffe5, 27),
        (0xfffec, 20),
        (0xfffff3, 24),
        (0xfffed, 20),
        (0x1fffe6, 21),
        (0x3fffe9, 22),
        (0x1fffe7, 21),
        (0x1fffe8, 21),
        (0x7ffff3, 23),
        (0x3fffea, 22),
        (0x3fffeb, 22),
        (0x1ffffee, 25),
        (0x1ffffef, 25),
        (0xfffff4, 24),
        (0xfffff5, 24),
        (0x3ffffea, 26),
        (0x7ffff4, 23),
        (0x3ffffeb, 26),
        (0x7ffffe6, 27),
        (0x3ffffec, 26),
        (0x3ffffed, 26),
        (0x7ffffe7, 27),
        (0x7ffffe8, 27),
        (0x7ffffe9, 27),
        (0x7ffffea, 27),
        (0x7ffffeb, 27),
        (0xffffffe, 28),
        (0x7ffffec, 27),
        (0x7ffffed, 27),
        (0x7ffffee, 27),
        (0x7ffffef, 27),
        (0x7fffff0, 27),
        (0x3ffffee, 26),
        (0x3fffffff, 30)
    ]

    static_huffman_tree = None  # type: HuffmanNode

    @classmethod
    def _huffman_encode_char(cls, c):
        # type: (Union[str, EOS]) -> Tuple[int, int]
        """ huffman_encode_char assumes that the static_huffman_tree was
        previously initialized

        :param str|EOS c: a symbol to encode
        :return: (int, int): the bitstring of the symbol and its bitlength
        :raises: AssertionError
        """
        if isinstance(c, EOS):
            return cls.static_huffman_code[-1]
        else:
            assert isinstance(c, int) or len(c) == 1
        return cls.static_huffman_code[orb(c)]

    @classmethod
    def huffman_encode(cls, s):
        # type: (str) -> Tuple[int, int]
        """ huffman_encode returns the bitstring and the bitlength of the
        bitstring representing the string provided as a parameter

        :param str s: the string to encode
        :return: (int, int): the bitstring of s and its bitlength
        :raises: AssertionError
        """
        i = 0
        ibl = 0
        for c in s:
            val, bl = cls._huffman_encode_char(c)
            i = (i << bl) + val
            ibl += bl

        padlen = 8 - (ibl % 8)
        if padlen != 8:
            val, bl = cls._huffman_encode_char(EOS())
            i = (i << padlen) + (val >> (bl - padlen))
            ibl += padlen

        ret = i, ibl
        assert ret[0] >= 0
        assert (ret[1] >= 0)
        return ret

    @classmethod
    def huffman_decode(cls, i, ibl):
        # type: (int, int) -> str
        """ huffman_decode decodes the bitstring provided as parameters.

        :param int i: the bitstring to decode
        :param int ibl: the bitlength of i
        :return: str: the string decoded from the bitstring
        :raises: AssertionError, InvalidEncodingException
        """
        assert i >= 0
        assert ibl >= 0

        if isinstance(cls.static_huffman_tree, type(None)):
            cls.huffman_compute_decode_tree()
        assert not isinstance(cls.static_huffman_tree, type(None))

        s = []
        j = 0
        interrupted = False
        cur = cls.static_huffman_tree
        cur_sym = 0
        cur_sym_bl = 0
        while j < ibl:
            b = (i >> (ibl - j - 1)) & 1
            cur_sym = (cur_sym << 1) + b
            cur_sym_bl += 1
            elmt = cur[b]

            if isinstance(elmt, HuffmanNode):
                interrupted = True
                cur = elmt
                if isinstance(cur, type(None)):
                    raise AssertionError()
            elif isinstance(elmt, EOS):
                raise InvalidEncodingException('Huffman decoder met the full EOS symbol')  # noqa: E501
            elif isinstance(elmt, bytes):
                interrupted = False
                s.append(elmt)
                cur = cls.static_huffman_tree
                cur_sym = 0
                cur_sym_bl = 0
            else:
                raise InvalidEncodingException('Should never happen, so incidentally it will')  # noqa: E501
            j += 1

        if interrupted:
            # Interrupted values true if the bitstring ends in the middle of a
            # symbol; this symbol must be, according to RFC7541 par5.2 the MSB
            # of the EOS symbol
            if cur_sym_bl > 7:
                raise InvalidEncodingException('Huffman decoder is detecting padding longer than 7 bits')  # noqa: E501
            eos_symbol = cls.static_huffman_code[-1]
            eos_msb = eos_symbol[0] >> (eos_symbol[1] - cur_sym_bl)
            if eos_msb != cur_sym:
                raise InvalidEncodingException('Huffman decoder is detecting unexpected padding format')  # noqa: E501
        return b''.join(s)

    @classmethod
    def huffman_conv2str(cls, bit_str, bit_len):
        # type: (int, int) -> str
        """ huffman_conv2str converts a bitstring of bit_len bitlength into a
        binary string. It DOES NOT compress/decompress the bitstring!

        :param int bit_str: the bitstring to convert.
        :param int bit_len: the bitlength of bit_str.
        :return: str: the converted bitstring as a bytestring.
        :raises: AssertionError
        """
        assert bit_str >= 0
        assert bit_len >= 0

        byte_len = bit_len // 8
        rem_bit = bit_len % 8
        if rem_bit != 0:
            bit_str <<= 8 - rem_bit
            byte_len += 1

        # As usual the list/join tricks is a performance trick to build
        # efficiently a Python string
        s = []  # type: List[str]
        i = 0
        while i < byte_len:
            s.insert(0, chb((bit_str >> (i * 8)) & 0xFF))
            i += 1
        return b''.join(s)

    @classmethod
    def huffman_conv2bitstring(cls, s):
        # type: (str) -> Tuple[int, int]
        """ huffman_conv2bitstring converts a string into its bitstring
        representation. It returns a tuple: the bitstring and its bitlength.
        This function DOES NOT compress/decompress the string!

        :param str s: the bytestring to convert.
        :return: (int, int): the bitstring of s, and its bitlength.
        :raises: AssertionError
        """
        i = 0
        ibl = len(s) * 8
        for c in s:
            i = (i << 8) + orb(c)

        ret = i, ibl
        assert ret[0] >= 0
        assert ret[1] >= 0
        return ret

    @classmethod
    def huffman_compute_decode_tree(cls):
        # type: () -> None
        """ huffman_compute_decode_tree initializes/builds the static_huffman_tree

        :return: None
        :raises: InvalidEncodingException if there is an encoding problem
        """
        cls.static_huffman_tree = HuffmanNode(None, None)
        i = 0
        for entry in cls.static_huffman_code:
            parent = cls.static_huffman_tree
            for idx in range(entry[1] - 1, -1, -1):
                b = (entry[0] >> idx) & 1
                if isinstance(parent[b], bytes):
                    raise InvalidEncodingException('Huffman unique prefix violation :/')  # noqa: E501
                if idx == 0:
                    parent[b] = chb(i) if i < 256 else EOS()
                elif parent[b] is None:
                    parent[b] = HuffmanNode(None, None)
                parent = parent[b]
            i += 1

    def __init__(self, s):
        # type: (str) -> None
        self._s = s
        i, ibl = type(self).huffman_encode(s)
        self._encoded = type(self).huffman_conv2str(i, ibl)

    def __str__(self):
        # type: () -> str
        return self._encoded

    def origin(self):
        # type: () -> str
        return plain_str(self._s)

    def __len__(self):
        # type: () -> int
        return len(self._encoded)


class HPackStrLenField(fields.Field):
    """ HPackStrLenField is a StrLenField variant specialized for HTTP/2 HPack

    This variant uses an internal representation that implements HPackStringsInterface.  # noqa: E501
    """
    __slots__ = ['_length_from', '_type_from']

    def __init__(self, name, default, length_from, type_from):
        # type: (str, HPackStringsInterface, Callable[[packet.Packet], int], str) -> None  # noqa: E501
        super(HPackStrLenField, self).__init__(name, default)
        self._length_from = length_from
        self._type_from = type_from

    def addfield(self, pkt, s, val):
        # type: (Optional[packet.Packet], str, HPackStringsInterface) -> str
        return s + self.i2m(pkt, val)

    @staticmethod
    def _parse(t, s):
        # type: (bool, str) -> HPackStringsInterface
        """
        :param bool t: whether this string is a huffman compressed string.
        :param str s: the string to parse.
        :return: HPackStringsInterface: either a HPackLiteralString or HPackZString, depending on t.  # noqa: E501
        :raises: InvalidEncodingException
        """
        if t:
            i, ibl = HPackZString.huffman_conv2bitstring(s)
            return HPackZString(HPackZString.huffman_decode(i, ibl))
        return HPackLiteralString(s)

    def getfield(self, pkt, s):
        # type: (packet.Packet, str) -> Tuple[str, HPackStringsInterface]
        """
        :param packet.Packet pkt: the packet instance containing this field instance.  # noqa: E501
        :param str s: the string to parse this field from.
        :return: (str, HPackStringsInterface): the remaining string after this field was carved out & the extracted  # noqa: E501
          value.
        :raises: KeyError if "type_from" is not a field of pkt or its payloads.
        :raises: InvalidEncodingException
        """
        tmp_len = self._length_from(pkt)
        t = pkt.getfieldval(self._type_from) == 1
        return s[tmp_len:], self._parse(t, s[:tmp_len])

    def i2h(self, pkt, x):
        # type: (Optional[packet.Packet], HPackStringsInterface) -> str
        fmt = ''
        if isinstance(x, HPackLiteralString):
            fmt = "HPackLiteralString({})"
        elif isinstance(x, HPackZString):
            fmt = "HPackZString({})"
        return fmt.format(x.origin())

    def h2i(self, pkt, x):
        # type: (packet.Packet, str) -> HPackStringsInterface
        return HPackLiteralString(x)

    def m2i(self, pkt, x):
        # type: (packet.Packet, str) -> HPackStringsInterface
        """
        :param packet.Packet pkt: the packet instance containing this field instance.  # noqa: E501
        :param str x: the string to parse.
        :return: HPackStringsInterface: the internal type of the value parsed from x.  # noqa: E501
        :raises: AssertionError
        :raises: InvalidEncodingException
        :raises: KeyError if _type_from is not one of pkt fields.
        """
        t = pkt.getfieldval(self._type_from)
        tmp_len = self._length_from(pkt)

        assert t is not None and tmp_len is not None, 'Conversion from string impossible: no type or length specified'  # noqa: E501

        return self._parse(t == 1, x[:tmp_len])

    def any2i(self, pkt, x):
        # type: (Optional[packet.Packet], Union[str, HPackStringsInterface]) -> HPackStringsInterface  # noqa: E501
        """
        :param packet.Packet|None pkt: the packet instance containing this field instance.  # noqa: E501
        :param str|HPackStringsInterface x: the value to convert
        :return: HPackStringsInterface: the Scapy internal value for this field
        :raises: AssertionError, InvalidEncodingException
        """
        if isinstance(x, bytes):
            assert isinstance(pkt, packet.Packet)
            return self.m2i(pkt, x)
        assert isinstance(x, HPackStringsInterface)
        return x

    def i2m(self, pkt, x):
        # type: (Optional[packet.Packet], HPackStringsInterface) -> str
        return raw(x)

    def i2len(self, pkt, x):
        # type: (Optional[packet.Packet], HPackStringsInterface) -> int
        return len(x)

    def i2repr(self, pkt, x):
        # type: (Optional[packet.Packet], HPackStringsInterface) -> str
        return repr(self.i2h(pkt, x))

###############################################################################
#                                                HPACK Packets                #
###############################################################################


class HPackHdrString(packet.Packet):
    """ HPackHdrString is a packet that that is serialized into a RFC7541 par5.2
    string literal repr.
    """
    name = 'HPack Header String'
    fields_desc = [
        fields.BitEnumField('type', None, 1, {0: 'Literal', 1: 'Compressed'}),
        FieldUVarLenField('len', None, 7, length_of='data'),
        HPackStrLenField(
            'data', HPackLiteralString(''),
            length_from=lambda pkt: pkt.getfieldval('len'),
            type_from='type'
        )
    ]

    def guess_payload_class(self, payload):
        # type: (str) -> Packet_metaclass
        # Trick to tell scapy that the remaining bytes of the currently
        # dissected string is not a payload of this packet but of some other
        # underlayer packet
        return config.conf.padding_layer

    def self_build(self, **kwargs):
        # type: (Any) -> str
        """self_build is overridden because type and len are determined at
        build time, based on the "data" field internal type
        """
        if self.getfieldval('type') is None:
            self.type = 1 if isinstance(self.getfieldval('data'), HPackZString) else 0  # noqa: E501
        return super(HPackHdrString, self).self_build(**kwargs)


class HPackHeaders(packet.Packet):
    """HPackHeaders uses the "dispatch_hook" trick of Packet_metaclass to select
    the correct HPack header packet type. For this, the first byte of the string  # noqa: E501
    to dissect is snooped on.
    """
    @classmethod
    def dispatch_hook(cls, s=None, *_args, **_kwds):
        # type: (Optional[str], *Any, **Any) -> Packet_metaclass
        """dispatch_hook returns the subclass of HPackHeaders that must be used
        to dissect the string.
        """
        if s is None:
            return config.conf.raw_layer
        fb = orb(s[0])
        if fb & 0x80 != 0:
            return HPackIndexedHdr
        if fb & 0x40 != 0:
            return HPackLitHdrFldWithIncrIndexing
        if fb & 0x20 != 0:
            return HPackDynamicSizeUpdate
        return HPackLitHdrFldWithoutIndexing

    def guess_payload_class(self, payload):
        # type: (str) -> Packet_metaclass
        return config.conf.padding_layer


class HPackIndexedHdr(HPackHeaders):
    """ HPackIndexedHdr implements RFC 7541 par6.1
    """
    name = 'HPack Indexed Header Field'
    fields_desc = [
        HPackMagicBitField('magic', 1, 1),
        UVarIntField('index', 2, 7)  # Default "2" is ":method GET"
    ]


class HPackLitHdrFldWithIncrIndexing(HPackHeaders):
    """ HPackLitHdrFldWithIncrIndexing implements RFC 7541 par6.2.1
    """
    name = 'HPack Literal Header With Incremental Indexing'
    fields_desc = [
        HPackMagicBitField('magic', 1, 2),
        UVarIntField('index', 0, 6),  # Default is New Name
        fields.ConditionalField(
            fields.PacketField('hdr_name', None, HPackHdrString),
            lambda pkt: pkt.getfieldval('index') == 0
        ),
        fields.PacketField('hdr_value', None, HPackHdrString)
    ]


class HPackLitHdrFldWithoutIndexing(HPackHeaders):
    """ HPackLitHdrFldWithIncrIndexing implements RFC 7541 par6.2.2
    and par6.2.3
    """
    name = 'HPack Literal Header Without Indexing (or Never Indexing)'
    fields_desc = [
        HPackMagicBitField('magic', 0, 3),
        fields.BitEnumField(
            'never_index', 0, 1,
            {0: "Don't Index", 1: 'Never Index'}
        ),
        UVarIntField('index', 0, 4),  # Default is New Name
        fields.ConditionalField(
            fields.PacketField('hdr_name', None, HPackHdrString),
            lambda pkt: pkt.getfieldval('index') == 0
        ),
        fields.PacketField('hdr_value', None, HPackHdrString)
    ]


class HPackDynamicSizeUpdate(HPackHeaders):
    """ HPackDynamicSizeUpdate implements RFC 7541 par6.3
    """
    name = 'HPack Dynamic Size Update'
    fields_desc = [
        HPackMagicBitField('magic', 1, 3),
        UVarIntField('max_size', 0, 5)
    ]

###############################################################################
#                                             HTTP/2 Frames                   #
###############################################################################


class H2FramePayload(packet.Packet):
    """ H2FramePayload is an empty class that is a super class of all Scapy
    HTTP/2 Frame Packets
    """

#                                             HTTP/2 Data Frame Packets                                                #  # noqa: E501


class H2DataFrame(H2FramePayload):
    """ H2DataFrame implements RFC7540 par6.1
    This packet is the Data Frame to use when there is no padding.
    """
    type_id = 0
    END_STREAM_FLAG = 0  # 0x1
    PADDED_FLAG = 3  # 0x8
    flags = {
        END_STREAM_FLAG: fields.MultiFlagsEntry('ES', 'End Stream'),
        PADDED_FLAG: fields.MultiFlagsEntry('P', 'Padded')
    }

    name = 'HTTP/2 Data Frame'
    fields_desc = [
        fields.StrField('data', '')
    ]


class H2PaddedDataFrame(H2DataFrame):
    """ H2DataFrame implements RFC7540 par6.1
    This packet is the Data Frame to use when there is padding.
    """
    __slots__ = ['s_len']

    name = 'HTTP/2 Padded Data Frame'
    fields_desc = [
        fields.FieldLenField('padlen', None, length_of='padding', fmt="B"),
        fields.StrLenField('data', '',
                           length_from=lambda pkt: pkt.get_data_len()
                           ),
        fields.StrLenField('padding', '',
                           length_from=lambda pkt: pkt.getfieldval('padlen')
                           )
    ]

    def get_data_len(self):
        # type: () -> int
        """ get_data_len computes the length of the data field

        To do this computation, the length of the padlen field and the actual
        padding is subtracted to the string that was provided to the pre_dissect  # noqa: E501
        fun of the pkt parameter
        :return: int; length of the data part of the HTTP/2 frame packet provided as parameter  # noqa: E501
        :raises: AssertionError
        """
        padding_len = self.getfieldval('padlen')
        fld, fval = self.getfield_and_val('padlen')
        padding_len_len = fld.i2len(self, fval)

        ret = self.s_len - padding_len_len - padding_len
        assert ret >= 0
        return ret

    def pre_dissect(self, s):
        # type: (str) -> str
        """pre_dissect is filling the s_len property of this instance. This
        property is later used during the getfield call of the "data" field when  # noqa: E501
        trying to evaluate the length of the StrLenField! This "trick" works
        because the underlayer packet (H2Frame) is assumed to override the
        "extract_padding" method and to only provide to this packet the data
        necessary for this packet. Tricky, tricky, will break some day probably!  # noqa: E501
        """
        self.s_len = len(s)
        return s


#                                             HTTP/2 Header Frame Packets                                              #  # noqa: E501

class H2AbstractHeadersFrame(H2FramePayload):
    """Superclass of all variants of HTTP/2 Header Frame Packets.
    May be used for type checking.
    """


class H2HeadersFrame(H2AbstractHeadersFrame):
    """ H2HeadersFrame implements RFC 7540 par6.2 Headers Frame
    when there is no padding and no priority information

    The choice of decomposing into four classes is probably preferable to having  # noqa: E501
    numerous conditional fields based on the underlayer :/
    """
    type_id = 1
    END_STREAM_FLAG = 0  # 0x1
    END_HEADERS_FLAG = 2  # 0x4
    PADDED_FLAG = 3  # 0x8
    PRIORITY_FLAG = 5  # 0x20
    flags = {
        END_STREAM_FLAG: fields.MultiFlagsEntry('ES', 'End Stream'),
        END_HEADERS_FLAG: fields.MultiFlagsEntry('EH', 'End Headers'),
        PADDED_FLAG: fields.MultiFlagsEntry('P', 'Padded'),
        PRIORITY_FLAG: fields.MultiFlagsEntry('+', 'Priority')
    }

    name = 'HTTP/2 Headers Frame'
    fields_desc = [
        fields.PacketListField('hdrs', [], HPackHeaders)
    ]


class H2PaddedHeadersFrame(H2AbstractHeadersFrame):
    """ H2PaddedHeadersFrame is the variant of H2HeadersFrame where padding flag
    is set and priority flag is cleared
    """
    __slots__ = ['s_len']

    name = 'HTTP/2 Headers Frame with Padding'
    fields_desc = [
        fields.FieldLenField('padlen', None, length_of='padding', fmt='B'),
        fields.PacketListField('hdrs', [], HPackHeaders,
                               length_from=lambda pkt: pkt.get_hdrs_len()
                               ),
        fields.StrLenField('padding', '',
                           length_from=lambda pkt: pkt.getfieldval('padlen')
                           )
    ]

    def get_hdrs_len(self):
        # type: () -> int
        """ get_hdrs_len computes the length of the hdrs field

        To do this computation, the length of the padlen field and the actual
        padding is subtracted to the string that was provided to the pre_dissect  # noqa: E501
        fun of the pkt parameter.
        :return: int; length of the data part of the HTTP/2 frame packet provided as parameter  # noqa: E501
        :raises: AssertionError
        """
        padding_len = self.getfieldval('padlen')
        fld, fval = self.getfield_and_val('padlen')
        padding_len_len = fld.i2len(self, fval)

        ret = self.s_len - padding_len_len - padding_len
        assert ret >= 0
        return ret

    def pre_dissect(self, s):
        # type: (str) -> str
        """pre_dissect is filling the s_len property of this instance. This
        property is later used during the parsing of the hdrs PacketListField
        when trying to evaluate the length of the PacketListField! This "trick"
        works because the underlayer packet (H2Frame) is assumed to override the  # noqa: E501
        "extract_padding" method and to only provide to this packet the data
        necessary for this packet. Tricky, tricky, will break some day probably!  # noqa: E501
        """
        self.s_len = len(s)
        return s


class H2PriorityHeadersFrame(H2AbstractHeadersFrame):
    """ H2PriorityHeadersFrame is the variant of H2HeadersFrame where priority flag
    is set and padding flag is cleared
    """
    __slots__ = ['s_len']

    name = 'HTTP/2 Headers Frame with Priority'
    fields_desc = [
        fields.BitField('exclusive', 0, 1),
        fields.BitField('stream_dependency', 0, 31),
        fields.ByteField('weight', 0),
        # This PacketListField will consume all remaining bytes; not a problem
        # because the underlayer (H2Frame) overrides "extract_padding" so that
        # this Packet only get to parser what it needs to
        fields.PacketListField('hdrs', [], HPackHeaders),
    ]


class H2PaddedPriorityHeadersFrame(H2AbstractHeadersFrame):
    """ H2PaddedPriorityHeadersFrame is the variant of H2HeadersFrame where
    both priority and padding flags are set
    """
    __slots__ = ['s_len']

    name = 'HTTP/2 Headers Frame with Padding and Priority'
    fields_desc = [
        fields.FieldLenField('padlen', None, length_of='padding', fmt='B'),
        fields.BitField('exclusive', 0, 1),
        fields.BitField('stream_dependency', 0, 31),
        fields.ByteField('weight', 0),
        fields.PacketListField('hdrs', [], HPackHeaders,
                               length_from=lambda pkt: pkt.get_hdrs_len()
                               ),
        fields.StrLenField('padding', '',
                           length_from=lambda pkt: pkt.getfieldval('padlen')
                           )
    ]

    def get_hdrs_len(self):
        # type: () -> int
        """ get_hdrs_len computes the length of the hdrs field

        To do this computation, the length of the padlen field, the priority
        information fields and the actual padding is subtracted to the string
        that was provided to the pre_dissect fun of the pkt parameter.
        :return: int: the length of the hdrs field
        :raises: AssertionError
        """

        padding_len = self.getfieldval('padlen')
        fld, fval = self.getfield_and_val('padlen')
        padding_len_len = fld.i2len(self, fval)
        bit_cnt = self.get_field('exclusive').size
        bit_cnt += self.get_field('stream_dependency').size
        fld, fval = self.getfield_and_val('weight')
        weight_len = fld.i2len(self, fval)
        ret = int(self.s_len -
                  padding_len_len -
                  padding_len -
                  (bit_cnt / 8) -
                  weight_len
                  )
        assert ret >= 0
        return ret

    def pre_dissect(self, s):
        # type: (str) -> str
        """pre_dissect is filling the s_len property of this instance. This
        property is later used during the parsing of the hdrs PacketListField
        when trying to evaluate the length of the PacketListField! This "trick"
        works because the underlayer packet (H2Frame) is assumed to override the  # noqa: E501
        "extract_padding" method and to only provide to this packet the data
        necessary for this packet. Tricky, tricky, will break some day probably!  # noqa: E501
        """
        self.s_len = len(s)
        return s

#                                           HTTP/2 Priority Frame Packets                                              #  # noqa: E501


class H2PriorityFrame(H2FramePayload):
    """ H2PriorityFrame implements RFC 7540 par6.3
    """
    type_id = 2
    name = 'HTTP/2 Priority Frame'
    fields_desc = [
        fields.BitField('exclusive', 0, 1),
        fields.BitField('stream_dependency', 0, 31),
        fields.ByteField('weight', 0)
    ]

#                                                 HTTP/2 Errors                                                        #  # noqa: E501


class H2ErrorCodes(object):
    """ H2ErrorCodes is an enumeration of the error codes defined in
    RFC7540 par7.
    This enumeration is not part of any frame because the error codes are in
    common with H2ResetFrame and H2GoAwayFrame.
    """

    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xa
    ENHANCE_YOUR_CALM = 0xb
    INADEQUATE_SECURITY = 0xc
    HTTP_1_1_REQUIRED = 0xd

    literal = {
        NO_ERROR: 'No error',
        PROTOCOL_ERROR: 'Protocol error',
        INTERNAL_ERROR: 'Internal error',
        FLOW_CONTROL_ERROR: 'Flow control error',
        SETTINGS_TIMEOUT: 'Settings timeout',
        STREAM_CLOSED: 'Stream closed',
        FRAME_SIZE_ERROR: 'Frame size error',
        REFUSED_STREAM: 'Refused stream',
        CANCEL: 'Cancel',
        COMPRESSION_ERROR: 'Compression error',
        CONNECT_ERROR: 'Control error',
        ENHANCE_YOUR_CALM: 'Enhance your calm',
        INADEQUATE_SECURITY: 'Inadequate security',
        HTTP_1_1_REQUIRED: 'HTTP/1.1 required'
    }


#                                           HTTP/2 Reset Frame Packets                                                 #  # noqa: E501

class H2ResetFrame(H2FramePayload):
    """ H2ResetFrame implements RFC 7540 par6.4
    """
    type_id = 3
    name = 'HTTP/2 Reset Frame'
    fields_desc = [
        fields.EnumField('error', 0, H2ErrorCodes.literal, fmt='!I')
    ]


#                                           HTTP/2 Settings Frame Packets                                              #  # noqa: E501

class H2Setting(packet.Packet):
    """ H2Setting implements a setting, as defined in RFC7540 par6.5.1
    """
    SETTINGS_HEADER_TABLE_SIZE = 0x1
    SETTINGS_ENABLE_PUSH = 0x2
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
    SETTINGS_INITIAL_WINDOW_SIZE = 0x4
    SETTINGS_MAX_FRAME_SIZE = 0x5
    SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

    name = 'HTTP/2 Setting'
    fields_desc = [
        fields.EnumField('id', 0, {
            SETTINGS_HEADER_TABLE_SIZE: 'Header table size',
            SETTINGS_ENABLE_PUSH: 'Enable push',
            SETTINGS_MAX_CONCURRENT_STREAMS: 'Max concurrent streams',
            SETTINGS_INITIAL_WINDOW_SIZE: 'Initial window size',
            SETTINGS_MAX_FRAME_SIZE: 'Max frame size',
            SETTINGS_MAX_HEADER_LIST_SIZE: 'Max header list size'
        }, fmt='!H'),
        fields.IntField('value', 0)
    ]

    def guess_payload_class(self, payload):
        # type: (str) -> Packet_metaclass
        return config.conf.padding_layer


class H2SettingsFrame(H2FramePayload):
    """ H2SettingsFrame implements RFC7540 par6.5
    """
    type_id = 4
    ACK_FLAG = 0  # 0x1
    flags = {
        ACK_FLAG: fields.MultiFlagsEntry('A', 'ACK')
    }

    name = 'HTTP/2 Settings Frame'
    fields_desc = [
        fields.PacketListField('settings', [], H2Setting)
    ]

    def __init__(self, *args, **kwargs):
        """__init__ initializes this H2SettingsFrame

        If a _pkt arg is provided (by keyword), then this is an initialization
        from a string to dissect and therefore the length of the string to
        dissect have distinctive characteristics that we might want to check.
        This is possible because the underlayer packet (H2Frame) overrides
        extract_padding method to provided only the string that must be parsed
        by this packet!
        :raises: AssertionError
        """

        # RFC7540 par6.5 p36
        assert (
            len(args) == 0 or (
                isinstance(args[0], bytes) and
                len(args[0]) % 6 == 0
            )
        ), 'Invalid settings frame; length is not a multiple of 6'
        super(H2SettingsFrame, self).__init__(*args, **kwargs)

#                                        HTTP/2 Push Promise Frame Packets                                             #  # noqa: E501


class H2PushPromiseFrame(H2FramePayload):
    """ H2PushPromiseFrame implements RFC7540 par6.6. This packet
    is the variant to use when the underlayer padding flag is cleared
    """
    type_id = 5
    END_HEADERS_FLAG = 2  # 0x4
    PADDED_FLAG = 3  # 0x8
    flags = {
        END_HEADERS_FLAG: fields.MultiFlagsEntry('EH', 'End Headers'),
        PADDED_FLAG: fields.MultiFlagsEntry('P', 'Padded')
    }

    name = 'HTTP/2 Push Promise Frame'
    fields_desc = [
        fields.BitField('reserved', 0, 1),
        fields.BitField('stream_id', 0, 31),
        fields.PacketListField('hdrs', [], HPackHeaders)
    ]


class H2PaddedPushPromiseFrame(H2PushPromiseFrame):
    """ H2PaddedPushPromiseFrame implements RFC7540 par6.6. This
    packet is the variant to use when the underlayer padding flag is set
    """
    __slots__ = ['s_len']

    name = 'HTTP/2 Padded Push Promise Frame'
    fields_desc = [
        fields.FieldLenField('padlen', None, length_of='padding', fmt='B'),
        fields.BitField('reserved', 0, 1),
        fields.BitField('stream_id', 0, 31),
        fields.PacketListField('hdrs', [], HPackHeaders,
                               length_from=lambda pkt: pkt.get_hdrs_len()
                               ),
        fields.StrLenField('padding', '',
                           length_from=lambda pkt: pkt.getfieldval('padlen')
                           )
    ]

    def get_hdrs_len(self):
        # type: () -> int
        """ get_hdrs_len computes the length of the hdrs field

        To do this computation, the length of the padlen field, reserved,
        stream_id and the actual padding is subtracted to the string that was
        provided to the pre_dissect fun of the pkt parameter.
        :return: int: the length of the hdrs field
        :raises: AssertionError
        """
        fld, padding_len = self.getfield_and_val('padlen')
        padding_len_len = fld.i2len(self, padding_len)
        bit_len = self.get_field('reserved').size
        bit_len += self.get_field('stream_id').size

        ret = int(self.s_len -
                  padding_len_len -
                  padding_len -
                  (bit_len / 8)
                  )
        assert ret >= 0
        return ret

    def pre_dissect(self, s):
        # type: (str) -> str
        """pre_dissect is filling the s_len property of this instance. This
        property is later used during the parsing of the hdrs PacketListField
        when trying to evaluate the length of the PacketListField! This "trick"
        works because the underlayer packet (H2Frame) is assumed to override the  # noqa: E501
        "extract_padding" method and to only provide to this packet the data
        necessary for this packet. Tricky, tricky, will break some day probably!  # noqa: E501
        """
        self.s_len = len(s)
        return s

#                                               HTTP/2 Ping Frame Packets                                              #  # noqa: E501


class H2PingFrame(H2FramePayload):
    """ H2PingFrame implements the RFC 7540 par6.7
    """
    type_id = 6
    ACK_FLAG = 0  # 0x1
    flags = {
        ACK_FLAG: fields.MultiFlagsEntry('A', 'ACK')
    }

    name = 'HTTP/2 Ping Frame'
    fields_desc = [
        fields.LongField('opaque', 0)
    ]

    def __init__(self, *args, **kwargs):
        """
        :raises: AssertionError
        """
        # RFC7540 par6.7 p42
        assert (
            len(args) == 0 or (
                isinstance(args[0], (bytes, str)) and
                len(args[0]) == 8
            )
        ), 'Invalid ping frame; length is not 8'
        super(H2PingFrame, self).__init__(*args, **kwargs)


#                                             HTTP/2 GoAway Frame Packets                                              #  # noqa: E501

class H2GoAwayFrame(H2FramePayload):
    """ H2GoAwayFrame implements the RFC 7540 par6.8
    """
    type_id = 7

    name = 'HTTP/2 Go Away Frame'
    fields_desc = [
        fields.BitField('reserved', 0, 1),
        fields.BitField('last_stream_id', 0, 31),
        fields.EnumField('error', 0, H2ErrorCodes.literal, fmt='!I'),
        fields.StrField('additional_data', '')
    ]

#                                      HTTP/2 Window Update Frame Packets                                              #  # noqa: E501


class H2WindowUpdateFrame(H2FramePayload):
    """ H2WindowUpdateFrame implements the RFC 7540 par6.9
    """
    type_id = 8

    name = 'HTTP/2 Window Update Frame'
    fields_desc = [
        fields.BitField('reserved', 0, 1),
        fields.BitField('win_size_incr', 0, 31)
    ]

    def __init__(self, *args, **kwargs):
        """
        :raises: AssertionError
        """
        # RFC7540 par6.9 p46
        assert (
            len(args) == 0 or (
                isinstance(args[0], (bytes, str)) and
                len(args[0]) == 4
            )
        ), 'Invalid window update frame; length is not 4'
        super(H2WindowUpdateFrame, self).__init__(*args, **kwargs)

#                                       HTTP/2 Continuation Frame Packets                                              #  # noqa: E501


class H2ContinuationFrame(H2FramePayload):
    """ H2ContinuationFrame implements the RFC 7540 par6.10
    """
    type_id = 9
    END_HEADERS_FLAG = 2  # Ox4
    flags = {
        END_HEADERS_FLAG: fields.MultiFlagsEntry('EH', 'End Headers')
    }

    name = 'HTTP/2 Continuation Frame'
    fields_desc = [
        fields.PacketListField('hdrs', [], HPackHeaders)
    ]

#                                          HTTP/2 Base Frame Packets                                                   #  # noqa: E501


_HTTP2_types = {
    0: 'DataFrm',
    1: 'HdrsFrm',
    2: 'PrioFrm',
    3: 'RstFrm',
    4: 'SetFrm',
    5: 'PushFrm',
    6: 'PingFrm',
    7: 'GoawayFrm',
    8: 'WinFrm',
    9: 'ContFrm'
}


class H2Frame(packet.Packet):
    """ H2Frame implements the frame structure as defined in RFC 7540 par4.1

    This packet may have a payload (one of the H2FramePayload) or none, in some
    rare cases such as settings acknowledgement)
    """
    name = 'HTTP/2 Frame'
    fields_desc = [
        fields.X3BytesField('len', None),
        fields.EnumField('type', None, _HTTP2_types, "b"),
        fields.MultiFlagsField('flags', set(), 8, {
            H2DataFrame.type_id: H2DataFrame.flags,
            H2HeadersFrame.type_id: H2HeadersFrame.flags,
            H2PushPromiseFrame.type_id: H2PushPromiseFrame.flags,
            H2SettingsFrame.type_id: H2SettingsFrame.flags,
            H2PingFrame.type_id: H2PingFrame.flags,
            H2ContinuationFrame.type_id: H2ContinuationFrame.flags,
        },
            depends_on=lambda pkt: pkt.getfieldval('type')
        ),
        fields.BitField('reserved', 0, 1),
        fields.BitField('stream_id', 0, 31)
    ]

    def guess_payload_class(self, payload):
        # type: (str) -> Packet_metaclass
        """ guess_payload_class returns the Class object to use for parsing a payload
        This function uses the H2Frame.type field value to decide which payload to parse. The implement cannot be  # noqa: E501
        performed using the simple bind_layers helper because sometimes the selection of which Class object to return  # noqa: E501
        also depends on the H2Frame.flags value.

        :param payload:
        :return::
        """
        if len(payload) == 0:
            return packet.NoPayload

        t = self.getfieldval('type')
        if t == H2DataFrame.type_id:
            if H2DataFrame.flags[H2DataFrame.PADDED_FLAG].short in self.getfieldval('flags'):  # noqa: E501
                return H2PaddedDataFrame
            return H2DataFrame

        if t == H2HeadersFrame.type_id:
            if H2HeadersFrame.flags[H2HeadersFrame.PADDED_FLAG].short in self.getfieldval('flags'):  # noqa: E501
                if H2HeadersFrame.flags[H2HeadersFrame.PRIORITY_FLAG].short in self.getfieldval('flags'):  # noqa: E501
                    return H2PaddedPriorityHeadersFrame
                else:
                    return H2PaddedHeadersFrame
            elif H2HeadersFrame.flags[H2HeadersFrame.PRIORITY_FLAG].short in self.getfieldval('flags'):  # noqa: E501
                return H2PriorityHeadersFrame
            return H2HeadersFrame

        if t == H2PriorityFrame.type_id:
            return H2PriorityFrame

        if t == H2ResetFrame.type_id:
            return H2ResetFrame

        if t == H2SettingsFrame.type_id:
            return H2SettingsFrame

        if t == H2PushPromiseFrame.type_id:
            if H2PushPromiseFrame.flags[H2PushPromiseFrame.PADDED_FLAG].short in self.getfieldval('flags'):  # noqa: E501
                return H2PaddedPushPromiseFrame
            return H2PushPromiseFrame

        if t == H2PingFrame.type_id:
            return H2PingFrame

        if t == H2GoAwayFrame.type_id:
            return H2GoAwayFrame

        if t == H2WindowUpdateFrame.type_id:
            return H2WindowUpdateFrame

        if t == H2ContinuationFrame.type_id:
            return H2ContinuationFrame

        return config.conf.padding_layer

    def extract_padding(self, s):
        # type: (str) -> Tuple[str, str]
        """
        :param str s: the string from which to tell the padding and the payload data apart  # noqa: E501
        :return: (str, str): the padding and the payload data strings
        :raises: AssertionError
        """
        assert isinstance(self.len, six.integer_types) and self.len >= 0, 'Invalid length: negative len?'  # noqa: E501
        assert len(s) >= self.len, 'Invalid length: string too short for this length'  # noqa: E501
        return s[:self.len], s[self.len:]

    def post_build(self, p, pay):
        # type: (str, str) -> str
        """
        :param str p: the stringified packet
        :param str pay: the stringified payload
        :return: str: the stringified packet and payload, with the packet length field "patched"  # noqa: E501
        :raises: AssertionError
        """
        # This logic, while awkward in the post_build and more reasonable in
        # a self_build is implemented here for performance tricks reason
        if self.getfieldval('len') is None:
            assert len(pay) < (1 << 24), 'Invalid length: payload is too long'
            p = struct.pack('!L', len(pay))[1:] + p[3:]
        return super(H2Frame, self).post_build(p, pay)


class H2Seq(packet.Packet):
    """ H2Seq is a helper packet that contains several H2Frames and their
    payload. This packet can be used, for instance, while reading manually from
    a TCP socket.
    """
    name = 'HTTP/2 Frame Sequence'
    fields_desc = [
        fields.PacketListField('frames', [], H2Frame)
    ]

    def guess_payload_class(self, payload):
        # type: (str) -> Packet_metaclass
        return config.conf.padding_layer


packet.bind_layers(H2Frame, H2DataFrame, {'type': H2DataFrame.type_id})
packet.bind_layers(H2Frame, H2PaddedDataFrame, {'type': H2DataFrame.type_id})
packet.bind_layers(H2Frame, H2HeadersFrame, {'type': H2HeadersFrame.type_id})
packet.bind_layers(H2Frame, H2PaddedHeadersFrame, {'type': H2HeadersFrame.type_id})  # noqa: E501
packet.bind_layers(H2Frame, H2PriorityHeadersFrame, {'type': H2HeadersFrame.type_id})  # noqa: E501
packet.bind_layers(H2Frame, H2PaddedPriorityHeadersFrame, {'type': H2HeadersFrame.type_id})  # noqa: E501
packet.bind_layers(H2Frame, H2PriorityFrame, {'type': H2PriorityFrame.type_id})
packet.bind_layers(H2Frame, H2ResetFrame, {'type': H2ResetFrame.type_id})
packet.bind_layers(H2Frame, H2SettingsFrame, {'type': H2SettingsFrame.type_id})
packet.bind_layers(H2Frame, H2PingFrame, {'type': H2PingFrame.type_id})
packet.bind_layers(H2Frame, H2PushPromiseFrame, {'type': H2PushPromiseFrame.type_id})  # noqa: E501
packet.bind_layers(H2Frame, H2PaddedPushPromiseFrame, {'type': H2PaddedPushPromiseFrame.type_id})  # noqa: E501
packet.bind_layers(H2Frame, H2GoAwayFrame, {'type': H2GoAwayFrame.type_id})
packet.bind_layers(H2Frame, H2WindowUpdateFrame, {'type': H2WindowUpdateFrame.type_id})  # noqa: E501
packet.bind_layers(H2Frame, H2ContinuationFrame, {'type': H2ContinuationFrame.type_id})  # noqa: E501


#                                          HTTP/2 Connection Preface                                                   #  # noqa: E501
# From RFC 7540 par3.5
H2_CLIENT_CONNECTION_PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')  # noqa: E501


###############################################################################
#                                                   HTTP/2 Helpers            #
###############################################################################

class HPackHdrEntry(Sized):
    """ HPackHdrEntry is an entry of the HPackHdrTable helper

    Each HPackHdrEntry instance is a header line (name and value). Names are
    normalized (lowercase), according to RFC 7540 par8.1.2
    """
    __slots__ = ['_name', '_len', '_value']

    def __init__(self, name, value):
        # type: (str, str) -> None
        """
        :raises: AssertionError
        """
        assert len(name) > 0

        self._name = name.lower()
        self._value = value

        # 32 bytes is an RFC-hardcoded value: see RFC 7541 par4.1
        self._len = (32 + len(self._name) + len(self._value))

    def name(self):
        # type: () -> str
        return self._name

    def value(self):
        # type: () -> str
        return self._value

    def size(self):
        # type: () -> int
        """ size returns the "length" of the header entry, as defined in
        RFC 7541 par4.1.
        """
        return self._len

    __len__ = size

    def __str__(self):
        # type: () -> str
        """ __str__ returns the header as it would be formatted in textual format
        """
        if self._name.startswith(':'):
            return "{} {}".format(self._name, self._value)
        else:
            return "{}: {}".format(self._name, self._value)

    def __bytes__(self):
        return bytes_encode(self.__str__())


class HPackHdrTable(Sized):
    """ HPackHdrTable is a helper class that implements some of the logic
    associated with indexing of headers (read and write operations in this
    "registry". THe HPackHdrTable also implements convenience functions to easily  # noqa: E501
    convert to and from textual representation and binary representation of
    a HTTP/2 requests
    """
    __slots__ = [
        '_dynamic_table',
        '_dynamic_table_max_size',
        '_dynamic_table_cap_size',
        '_regexp'
    ]
    """
    :var _dynamic_table: the list containing entries requested to be added by
        the peer and registered with a register() call
    :var _dynamic_table_max_size: the current maximum size of the dynamic table
        in bytes. This value is updated with the Dynamic Table Size Update
        messages defined in RFC 7541 par6.3
    :var _dynamic_table_cap_size: the maximum size of the dynamic table in
        bytes. This value is updated with the SETTINGS_HEADER_TABLE_SIZE HTTP/2
        setting.
    """

    # Manually imported from RFC 7541 Appendix A
    _static_entries = {
        1: HPackHdrEntry(':authority', ''),
        2: HPackHdrEntry(':method', 'GET'),
        3: HPackHdrEntry(':method', 'POST'),
        4: HPackHdrEntry(':path', '/'),
        5: HPackHdrEntry(':path', '/index.html'),
        6: HPackHdrEntry(':scheme', 'http'),
        7: HPackHdrEntry(':scheme', 'https'),
        8: HPackHdrEntry(':status', '200'),
        9: HPackHdrEntry(':status', '204'),
        10: HPackHdrEntry(':status', '206'),
        11: HPackHdrEntry(':status', '304'),
        12: HPackHdrEntry(':status', '400'),
        13: HPackHdrEntry(':status', '404'),
        14: HPackHdrEntry(':status', '500'),
        15: HPackHdrEntry('accept-charset', ''),
        16: HPackHdrEntry('accept-encoding', 'gzip, deflate'),
        17: HPackHdrEntry('accept-language', ''),
        18: HPackHdrEntry('accept-ranges', ''),
        19: HPackHdrEntry('accept', ''),
        20: HPackHdrEntry('access-control-allow-origin', ''),
        21: HPackHdrEntry('age', ''),
        22: HPackHdrEntry('allow', ''),
        23: HPackHdrEntry('authorization', ''),
        24: HPackHdrEntry('cache-control', ''),
        25: HPackHdrEntry('content-disposition', ''),
        26: HPackHdrEntry('content-encoding', ''),
        27: HPackHdrEntry('content-language', ''),
        28: HPackHdrEntry('content-length', ''),
        29: HPackHdrEntry('content-location', ''),
        30: HPackHdrEntry('content-range', ''),
        31: HPackHdrEntry('content-type', ''),
        32: HPackHdrEntry('cookie', ''),
        33: HPackHdrEntry('date', ''),
        34: HPackHdrEntry('etag', ''),
        35: HPackHdrEntry('expect', ''),
        36: HPackHdrEntry('expires', ''),
        37: HPackHdrEntry('from', ''),
        38: HPackHdrEntry('host', ''),
        39: HPackHdrEntry('if-match', ''),
        40: HPackHdrEntry('if-modified-since', ''),
        41: HPackHdrEntry('if-none-match', ''),
        42: HPackHdrEntry('if-range', ''),
        43: HPackHdrEntry('if-unmodified-since', ''),
        44: HPackHdrEntry('last-modified', ''),
        45: HPackHdrEntry('link', ''),
        46: HPackHdrEntry('location', ''),
        47: HPackHdrEntry('max-forwards', ''),
        48: HPackHdrEntry('proxy-authenticate', ''),
        49: HPackHdrEntry('proxy-authorization', ''),
        50: HPackHdrEntry('range', ''),
        51: HPackHdrEntry('referer', ''),
        52: HPackHdrEntry('refresh', ''),
        53: HPackHdrEntry('retry-after', ''),
        54: HPackHdrEntry('server', ''),
        55: HPackHdrEntry('set-cookie', ''),
        56: HPackHdrEntry('strict-transport-security', ''),
        57: HPackHdrEntry('transfer-encoding', ''),
        58: HPackHdrEntry('user-agent', ''),
        59: HPackHdrEntry('vary', ''),
        60: HPackHdrEntry('via', ''),
        61: HPackHdrEntry('www-authenticate', ''),
    }

    # The value of this variable cannot be determined at declaration time. It is  # noqa: E501
    # initialized by an init_static_table call
    _static_entries_last_idx = None  # type: int

    @classmethod
    def init_static_table(cls):
        # type: () -> None
        cls._static_entries_last_idx = max(cls._static_entries)

    def __init__(self, dynamic_table_max_size=4096, dynamic_table_cap_size=4096):  # noqa: E501
        # type: (int, int) -> None
        """
        :param int dynamic_table_max_size: the current maximum size of the dynamic entry table in bytes  # noqa: E501
        :param int dynamic_table_cap_size: the maximum-maximum size of the dynamic entry table in bytes  # noqa: E501
        :raises:s AssertionError
        """
        self._regexp = None  # type: Pattern
        if isinstance(type(self)._static_entries_last_idx, type(None)):
            type(self).init_static_table()

        assert dynamic_table_max_size <= dynamic_table_cap_size, \
            'EINVAL: dynamic_table_max_size too large; expected value is less or equal to dynamic_table_cap_size'  # noqa: E501

        self._dynamic_table = []  # type: List[HPackHdrEntry]
        self._dynamic_table_max_size = dynamic_table_max_size
        self._dynamic_table_cap_size = dynamic_table_cap_size

    def __getitem__(self, idx):
        # type: (int) -> HPackHdrEntry
        """Gets an element from the header tables (static or dynamic indifferently)

        :param int idx: the index number of the entry to retrieve. If the index
        value is superior to the last index of the static entry table, then the
        dynamic entry type is requested, following the procedure described in
        RFC 7541 par2.3.3
        :return: HPackHdrEntry: the entry defined at this requested index. If the entry does not exist, KeyError is  # noqa: E501
          raised
        :raises: KeyError, AssertionError
        """
        assert idx >= 0
        if idx > type(self)._static_entries_last_idx:
            idx -= type(self)._static_entries_last_idx + 1
            if idx >= len(self._dynamic_table):
                raise KeyError(
                    'EINVAL: idx: out-of-bound read: {}; maximum index: {}'.format(idx, len(self._dynamic_table))  # noqa: E501
                )
            return self._dynamic_table[idx]
        return type(self)._static_entries[idx]

    def resize(self, ns):
        # type: (int) -> None
        """Resize the dynamic table. If the new size (ns) must be between 0 and
        the cap size. If the new size is lower than the current size of the
        dynamic table, entries are evicted.
        :param int ns: the new size of the dynamic table
        :raises: AssertionError
        """
        assert 0 <= ns <= self._dynamic_table_cap_size, \
            'EINVAL: ns: out-of-range value; expected value is in the range [0;{}['.format(self._dynamic_table_cap_size)  # noqa: E501

        old_size = self._dynamic_table_max_size
        self._dynamic_table_max_size = ns
        if old_size > self._dynamic_table_max_size:
            self._reduce_dynamic_table()

    def recap(self, nc):
        # type: (int) -> None
        """recap changes the maximum size limit of the dynamic table. It also
        proceeds to a resize(), if the new size is lower than the previous one.
        :param int nc: the new cap of the dynamic table (that is the maximum-maximum size)  # noqa: E501
        :raises: AssertionError
        """
        assert nc >= 0
        t = self._dynamic_table_cap_size > nc
        self._dynamic_table_cap_size = nc

        if t:
            # The RFC is not clear about whether this resize should happen;
            # we do it anyway
            self.resize(nc)

    def _reduce_dynamic_table(self, new_entry_size=0):
        # type: (int) -> None
        """_reduce_dynamic_table evicts entries from the dynamic table until it
        fits in less than the current size limit. The optional parameter,
        new_entry_size, allows the resize to happen so that a new entry of this
        size fits in.
        :param int new_entry_size: if called before adding a new entry, the size of the new entry in bytes (following  # noqa: E501
        the RFC7541 definition of the size of an entry)
        :raises: AssertionError
        """
        assert new_entry_size >= 0
        cur_sz = len(self)
        dyn_tbl_sz = len(self._dynamic_table)
        while dyn_tbl_sz > 0 and cur_sz + new_entry_size > self._dynamic_table_max_size:  # noqa: E501
            last_elmt_sz = len(self._dynamic_table[-1])
            self._dynamic_table.pop()
            dyn_tbl_sz -= 1
            cur_sz -= last_elmt_sz

    def register(self, hdrs):
        # type: (Union[HPackLitHdrFldWithIncrIndexing, H2Frame, List[HPackHeaders]]) -> None  # noqa: E501
        """register adds to this table the instances of
        HPackLitHdrFldWithIncrIndexing provided as parameters.

        A H2Frame with a H2HeadersFrame payload can be provided, as much as a
        python list of HPackHeaders or a single HPackLitHdrFldWithIncrIndexing
        instance.
        :param HPackLitHdrFldWithIncrIndexing|H2Frame|list of HPackHeaders hdrs: the header(s) to register  # noqa: E501
        :raises: AssertionError
        """
        if isinstance(hdrs, H2Frame):
            hdrs = [hdr for hdr in hdrs.payload.hdrs if isinstance(hdr, HPackLitHdrFldWithIncrIndexing)]  # noqa: E501
        elif isinstance(hdrs, HPackLitHdrFldWithIncrIndexing):
            hdrs = [hdrs]
        else:
            hdrs = [hdr for hdr in hdrs if isinstance(hdr, HPackLitHdrFldWithIncrIndexing)]  # noqa: E501

        for hdr in hdrs:
            if hdr.index == 0:
                hdr_name = hdr.hdr_name.getfieldval('data').origin()
            else:
                idx = int(hdr.index)
                hdr_name = self[idx].name()
            hdr_value = hdr.hdr_value.getfieldval('data').origin()

            # Note: we do not delete any existing hdrentry with the same names
            # and values, as dictated by RFC 7541 par2.3.2

            entry = HPackHdrEntry(hdr_name, hdr_value)
            # According to RFC7541 par4.4, "Before a new entry is added to
            # the dynamic table, entries are evicted
            # from the end of the dynamic table until the size of the dynamic
            # table is less than or equal to (maximum size - new entry size)
            # or until the table is empty"
            # Also, "It is not an error to attempt to add an entry that is
            # larger than the maximum size; an attempt to add an entry larger
            # than the maximum size causes the table to be emptied of all
            # existing entries and results in an empty table"
            # For this reason, we first call the _reduce_dynamic_table and
            # then throw an assertion error if the new entry does not fit in
            new_entry_len = len(entry)
            self._reduce_dynamic_table(new_entry_len)
            assert new_entry_len <= self._dynamic_table_max_size
            self._dynamic_table.insert(0, entry)

    def get_idx_by_name(self, name):
        # type: (str) -> Optional[int]
        """ get_idx_by_name returns the index of a matching registered header

        This implementation will prefer returning a static entry index whenever
        possible. If multiple matching header name are found in the static
        table, there is insurance that the first entry (lowest index number)
        will be returned.
        If no matching header is found, this method returns None.
        """
        name = name.lower()
        for key, val in six.iteritems(type(self)._static_entries):
            if val.name() == name:
                return key
        for idx, val in enumerate(self._dynamic_table):
            if val.name() == name:
                return type(self)._static_entries_last_idx + idx + 1
        return None

    def get_idx_by_name_and_value(self, name, value):
        # type: (str, str) -> Optional[int]
        """ get_idx_by_name_and_value returns the index of a matching registered
        header

        This implementation will prefer returning a static entry index whenever
        possible. If multiple matching headers are found in the dynamic table,
        the lowest index is returned
        If no matching header is found, this method returns None.
        """
        name = name.lower()
        for key, val in six.iteritems(type(self)._static_entries):
            if val.name() == name and val.value() == value:
                return key
        for idx, val in enumerate(self._dynamic_table):
            if val.name() == name and val.value() == value:
                return type(self)._static_entries_last_idx + idx + 1
        return None

    def __len__(self):
        # type: () -> int
        """ __len__ returns the summed length of all dynamic entries
        """
        return sum(len(x) for x in self._dynamic_table)

    def gen_txt_repr(self, hdrs, register=True):
        # type: (Union[H2Frame, List[HPackHeaders]], Optional[bool]) -> str
        """
        gen_txt_repr returns a "textual" representation of the provided
        headers.
        The output of this function is compatible with the input of
        parse_txt_hdrs.

        :param H2Frame|list of HPackHeaders hdrs: the list of headers to
          convert to textual representation.
        :param bool: whether incremental headers should be added to the dynamic
          table as we generate the text representation
        :return: str: the textual representation of the provided headers
        :raises: AssertionError
        """
        lst = []
        if isinstance(hdrs, H2Frame):
            hdrs = hdrs.payload.hdrs

        for hdr in hdrs:
            try:
                if isinstance(hdr, HPackIndexedHdr):
                    lst.append('{}'.format(self[hdr.index]))
                elif isinstance(hdr, (
                    HPackLitHdrFldWithIncrIndexing,
                    HPackLitHdrFldWithoutIndexing
                )):
                    if hdr.index != 0:
                        name = self[hdr.index].name()
                    else:
                        name = hdr.hdr_name.getfieldval('data').origin()
                    if name.startswith(':'):
                        lst.append(
                            '{} {}'.format(
                                name,
                                hdr.hdr_value.getfieldval('data').origin()
                            )
                        )
                    else:
                        lst.append(
                            '{}: {}'.format(
                                name,
                                hdr.hdr_value.getfieldval('data').origin()
                            )
                        )
                if register and isinstance(hdr, HPackLitHdrFldWithIncrIndexing):  # noqa: E501
                    self.register(hdr)
            except KeyError as e:  # raised when an index is out-of-bound
                print(e)
                continue
        return '\n'.join(lst)

    @staticmethod
    def _optimize_header_length_and_packetify(s):
        # type: (str) -> HPackHdrString
        zs = HPackZString(s)
        if len(zs) >= len(s):
            return HPackHdrString(data=HPackLiteralString(s))
        return HPackHdrString(data=zs)

    def _convert_a_header_to_a_h2_header(self, hdr_name, hdr_value, is_sensitive, should_index):  # noqa: E501
        # type: (str, str, Callable[[str, str], bool], Callable[[str], bool]) -> Tuple[HPackHeaders, int]  # noqa: E501
        """ _convert_a_header_to_a_h2_header builds a HPackHeaders from a header
        name and a value. It returns a HPackIndexedHdr whenever possible. If not,  # noqa: E501
        it returns a HPackLitHdrFldWithoutIndexing or a
        HPackLitHdrFldWithIncrIndexing, based on the should_index callback.
        HPackLitHdrFldWithoutIndexing is forced if the is_sensitive callback
        returns True and its never_index bit is set.
        """

        # If both name and value are already indexed
        idx = self.get_idx_by_name_and_value(hdr_name, hdr_value)
        if idx is not None:
            return HPackIndexedHdr(index=idx), len(self[idx])

        # The value is not indexed for this headers

        _hdr_value = self._optimize_header_length_and_packetify(hdr_value)

        # Searching if the header name is indexed
        idx = self.get_idx_by_name(hdr_name)
        if idx is not None:
            if is_sensitive(
                hdr_name,
                _hdr_value.getfieldval('data').origin()
            ):
                return HPackLitHdrFldWithoutIndexing(
                    never_index=1,
                    index=idx,
                    hdr_value=_hdr_value
                ), len(
                    HPackHdrEntry(
                        self[idx].name(),
                        _hdr_value.getfieldval('data').origin()
                    )
                )
            if should_index(hdr_name):
                return HPackLitHdrFldWithIncrIndexing(
                    index=idx,
                    hdr_value=_hdr_value
                ), len(
                    HPackHdrEntry(
                        self[idx].name(),
                        _hdr_value.getfieldval('data').origin()
                    )
                )
            return HPackLitHdrFldWithoutIndexing(
                index=idx,
                hdr_value=_hdr_value
            ), len(
                HPackHdrEntry(
                    self[idx].name(),
                    _hdr_value.getfieldval('data').origin()
                )
            )

        _hdr_name = self._optimize_header_length_and_packetify(hdr_name)

        if is_sensitive(
            _hdr_name.getfieldval('data').origin(),
            _hdr_value.getfieldval('data').origin()
        ):
            return HPackLitHdrFldWithoutIndexing(
                never_index=1,
                index=0,
                hdr_name=_hdr_name,
                hdr_value=_hdr_value
            ), len(
                HPackHdrEntry(
                    _hdr_name.getfieldval('data').origin(),
                    _hdr_value.getfieldval('data').origin()
                )
            )
        if should_index(_hdr_name.getfieldval('data').origin()):
            return HPackLitHdrFldWithIncrIndexing(
                index=0,
                hdr_name=_hdr_name,
                hdr_value=_hdr_value
            ), len(
                HPackHdrEntry(
                    _hdr_name.getfieldval('data').origin(),
                    _hdr_value.getfieldval('data').origin()
                )
            )
        return HPackLitHdrFldWithoutIndexing(
            index=0,
            hdr_name=_hdr_name,
            hdr_value=_hdr_value
        ), len(
            HPackHdrEntry(
                _hdr_name.getfieldval('data').origin(),
                _hdr_value.getfieldval('data').origin()
            )
        )

    def _parse_header_line(self, line):
        # type: (str) -> Union[Tuple[None, None], Tuple[str, str]]

        if self._regexp is None:
            self._regexp = re.compile(br'^(?::([a-z\-0-9]+)|([a-z\-0-9]+):)\s+(.+)$')  # noqa: E501

        hdr_line = line.rstrip()
        grp = self._regexp.match(hdr_line)

        if grp is None or len(grp.groups()) != 3:
            return None, None

        if grp.group(1) is not None:
            hdr_name = b':' + grp.group(1)
        else:
            hdr_name = grp.group(2)
        return plain_str(hdr_name.lower()), plain_str(grp.group(3))

    def parse_txt_hdrs(self,
                       s,  # type: str
                       stream_id=1,  # type: int
                       body=None,  # type: Optional[str]
                       max_frm_sz=4096,  # type: int
                       max_hdr_lst_sz=0,  # type: int
                       is_sensitive=lambda n, v: False,  # type: Callable[[str, str], bool]  # noqa: E501
                       should_index=lambda x: False,  # type: Callable[[str], bool]  # noqa: E501
                       register=True,  # type: bool
                       ):
        # type: (...) -> H2Seq
        """
        parse_txt_hdrs parses headers expressed in text and converts them
        into a series of H2Frames with the "correct" flags. A body can be
        provided in which case, the data frames are added, bearing the End
        Stream flag, instead of the H2HeadersFrame/H2ContinuationFrame.
        The generated frames may respect max_frm_sz (SETTINGS_MAX_FRAME_SIZE)
        and max_hdr_lst_sz (SETTINGS_MAX_HEADER_LIST_SIZE) if provided.
        The headers are split into multiple headers fragment (and H2Frames)
        to respect these limits. Also, a callback can be provided to tell if
        a header should be never indexed (sensitive headers, such as cookies),
        and another callback say if the header should be registered into the
        index table at all.
        For an header to be registered, the is_sensitive callback must return
        False AND the should_index callback should return True. This is the
        default behavior.

        :param str s: the string to parse for headers
        :param int stream_id: the stream id to use in the generated H2Frames
        :param str/None body: the eventual body of the request, that is added
          to the generated frames
        :param int max_frm_sz: the maximum frame size. This is used to split
          the headers and data frames according to the maximum frame size
          negotiated for this connection.
        :param int max_hdr_lst_sz: the maximum size of a "header fragment" as
          defined in RFC7540
        :param callable is_sensitive: callback that returns True if the
          provided header is sensible and must be stored in a header packet
          requesting this header never to be indexed
        :param callable should_index: callback that returns True if the
          provided header should be stored in a header packet requesting
          indexation in the dynamic header table.
        :param bool register: whether to register new headers with incremental
          indexing as we parse them
        :raises: Exception
        """

        sio = BytesIO(s)

        base_frm_len = len(raw(H2Frame()))

        ret = H2Seq()
        cur_frm = H2HeadersFrame()  # type: Union[H2HeadersFrame, H2ContinuationFrame]  # noqa: E501
        cur_hdr_sz = 0

        # For each line in the headers str to parse
        for hdr_line in sio:
            hdr_name, hdr_value = self._parse_header_line(hdr_line)
            if hdr_name is None:
                continue

            new_hdr, new_hdr_len = self._convert_a_header_to_a_h2_header(
                hdr_name, hdr_value, is_sensitive, should_index
            )
            new_hdr_bin_len = len(raw(new_hdr))

            if register and isinstance(new_hdr, HPackLitHdrFldWithIncrIndexing):  # noqa: E501
                self.register(new_hdr)

            # The new header binary length (+ base frame size) must not exceed
            # the maximum frame size or it will just never fit. Also, the
            # header entry length (as specified in RFC7540 par6.5.2) must not
            # exceed the maximum length of a header fragment or it will just
            # never fit
            if (new_hdr_bin_len + base_frm_len > max_frm_sz or
                    (max_hdr_lst_sz != 0 and new_hdr_len > max_hdr_lst_sz)):
                raise Exception('Header too long: {}'.format(hdr_name))

            if (max_frm_sz < len(raw(cur_frm)) + base_frm_len + new_hdr_len or
                (
                    max_hdr_lst_sz != 0 and
                    max_hdr_lst_sz < cur_hdr_sz + new_hdr_len
            )
            ):
                flags = set()
                if isinstance(cur_frm, H2HeadersFrame) and not body:
                    flags.add('ES')
                ret.frames.append(H2Frame(stream_id=stream_id, flags=flags) / cur_frm)  # noqa: E501
                cur_frm = H2ContinuationFrame()
                cur_hdr_sz = 0

            hdr_list = cur_frm.hdrs
            hdr_list += new_hdr
            cur_hdr_sz += new_hdr_len

        flags = {'EH'}
        if isinstance(cur_frm, H2HeadersFrame) and not body:
            flags.add('ES')
        ret.frames.append(H2Frame(stream_id=stream_id, flags=flags) / cur_frm)

        if body:
            base_data_frm_len = len(raw(H2DataFrame()))
            sio = BytesIO(body)
            frgmt = sio.read(max_frm_sz - base_data_frm_len - base_frm_len)
            while frgmt:
                nxt_frgmt = sio.read(max_frm_sz - base_data_frm_len - base_frm_len)  # noqa: E501
                flags = set()
                if len(nxt_frgmt) == 0:
                    flags.add('ES')
                ret.frames.append(
                    H2Frame(stream_id=stream_id, flags=flags) / H2DataFrame(data=frgmt)  # noqa: E501
                )
                frgmt = nxt_frgmt
        return ret
