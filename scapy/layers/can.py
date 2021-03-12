# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license


"""A minimal implementation of the CANopen protocol, based on
Wireshark dissectors. See https://wiki.wireshark.org/CANopen

"""

import os
import gzip
import struct
import binascii

from scapy.compat import Tuple, Optional, Type, List, Union, Callable, IO, \
    Any, cast

import scapy.modules.six as six
from scapy.config import conf
from scapy.compat import orb
from scapy.data import DLT_CAN_SOCKETCAN
from scapy.fields import FieldLenField, FlagsField, StrLenField, \
    ThreeBytesField, XBitField, ScalingField, ConditionalField, LenField
from scapy.volatile import RandFloat, RandBinFloat
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import CookedLinux
from scapy.error import Scapy_Exception
from scapy.plist import PacketList
from scapy.supersocket import SuperSocket
from scapy.utils import _ByteStream

__all__ = ["CAN", "SignalPacket", "SignalField", "LESignedSignalField",
           "LEUnsignedSignalField", "LEFloatSignalField", "BEFloatSignalField",
           "BESignedSignalField", "BEUnsignedSignalField", "rdcandump",
           "CandumpReader", "SignalHeader", "CAN_MTU", "CAN_MAX_IDENTIFIER",
           "CAN_MAX_DLEN", "CAN_INV_FILTER"]

# CONSTANTS
CAN_MAX_IDENTIFIER = (1 << 29) - 1  # Maximum 29-bit identifier
CAN_MTU = 16
CAN_MAX_DLEN = 8
CAN_INV_FILTER = 0x20000000

# Mimics the Wireshark CAN dissector parameter 'Byte-swap the CAN ID/flags field'  # noqa: E501
#   set to True when working with PF_CAN sockets
conf.contribs['CAN'] = {'swap-bytes': False}


class CAN(Packet):
    """A minimal implementation of the CANopen protocol, based on
    Wireshark dissectors. See https://wiki.wireshark.org/CANopen

    """
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        FieldLenField('length', None, length_of='data', fmt='B'),
        ThreeBytesField('reserved', 0),
        StrLenField('data', b'', length_from=lambda pkt: int(pkt.length)),
    ]

    @staticmethod
    def inv_endianness(pkt):
        # type: (bytes) -> bytes
        """ Invert the order of the first four bytes of a CAN packet

        This method is meant to be used specifically to convert a CAN packet
        between the pcap format and the socketCAN format

        :param pkt: str of the CAN packet
        :return: packet str with the first four bytes swapped
        """
        len_partial = len(pkt) - 4  # len of the packet, CAN ID excluded
        return struct.pack('<I{}s'.format(len_partial),
                           *struct.unpack('>I{}s'.format(len_partial), pkt))

    def pre_dissect(self, s):
        # type: (bytes) -> bytes
        """ Implements the swap-bytes functionality when dissecting """
        if conf.contribs['CAN']['swap-bytes']:
            data = CAN.inv_endianness(s)  # type: bytes
            return data
        return s

    def post_dissect(self, s):
        # type: (bytes) -> bytes
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """ Implements the swap-bytes functionality when building

        this is based on a copy of the Packet.self_build default method.
        The goal is to affect only the CAN layer data and keep
        under layers (e.g LinuxCooked) unchanged
        """
        if conf.contribs['CAN']['swap-bytes']:
            data = CAN.inv_endianness(pkt)  # type: bytes
            return data + pay
        return pkt + pay

    def extract_padding(self, p):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return b'', p


conf.l2types.register(DLT_CAN_SOCKETCAN, CAN)
bind_layers(CookedLinux, CAN, proto=12)


class SignalField(ScalingField):
    __slots__ = ["start", "size"]

    def __init__(self, name, default, start, size, scaling=1, unit="",
                 offset=0, ndigits=3, fmt="B"):
        # type: (str, Union[int, float], int, int, Union[int, float], str, Union[int, float], int, str) -> None  # noqa: E501
        ScalingField.__init__(self, name, default, scaling, unit, offset,
                              ndigits, fmt)
        self.start = start
        self.size = abs(size)

        if fmt[-1] == "f" and self.size != 32:
            raise Scapy_Exception("SignalField size has to be 32 for floats")

    _lookup_table = [7, 6, 5, 4, 3, 2, 1, 0,
                     15, 14, 13, 12, 11, 10, 9, 8,
                     23, 22, 21, 20, 19, 18, 17, 16,
                     31, 30, 29, 28, 27, 26, 25, 24,
                     39, 38, 37, 36, 35, 34, 33, 32,
                     47, 46, 45, 44, 43, 42, 41, 40,
                     55, 54, 53, 52, 51, 50, 49, 48,
                     63, 62, 61, 60, 59, 58, 57, 56]

    @staticmethod
    def _msb_lookup(start):
        # type: (int) -> int
        try:
            return SignalField._lookup_table.index(start)
        except ValueError:
            raise Scapy_Exception("Only 64 bits for all SignalFields "
                                  "are supported")

    @staticmethod
    def _lsb_lookup(start, size):
        # type: (int, int) -> int
        try:
            return SignalField._lookup_table[SignalField._msb_lookup(start) +
                                             size - 1]
        except IndexError:
            raise Scapy_Exception("Only 64 bits for all SignalFields "
                                  "are supported")

    @staticmethod
    def _convert_to_unsigned(number, bit_length):
        # type: (int, int) -> int
        if number & (1 << (bit_length - 1)):
            mask = (2 ** bit_length)  # type: int
            return mask + number
        return number

    @staticmethod
    def _convert_to_signed(number, bit_length):
        # type: (int, int) -> int
        mask = (2 ** bit_length) - 1  # type: int
        if number & (1 << (bit_length - 1)):
            return number | ~mask
        return number & mask

    def _is_little_endian(self):
        # type: () -> bool
        return self.fmt[0] == "<"

    def _is_signed_number(self):
        # type: () -> bool
        return self.fmt[-1].islower()

    def _is_float_number(self):
        # type: () -> bool
        return self.fmt[-1] == "f"

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[Union[int, float]]) -> bytes
        if not isinstance(pkt, SignalPacket):
            raise Scapy_Exception("Only use SignalFields in a SignalPacket")

        val = self.i2m(pkt, val)

        if self._is_little_endian():
            msb_pos = self.start + self.size - 1
            lsb_pos = self.start
            shift = lsb_pos
            fmt = "<Q"
        else:
            msb_pos = self.start
            lsb_pos = self._lsb_lookup(self.start, self.size)
            shift = (64 - self._msb_lookup(msb_pos) - self.size)
            fmt = ">Q"

        field_len = max(msb_pos, lsb_pos) // 8 + 1
        if len(s) < field_len:
            s += b"\x00" * (field_len - len(s))

        if self._is_float_number():
            int_val = struct.unpack(self.fmt[0] + "I",
                                    struct.pack(self.fmt, val))[0]  # type: int
        elif self._is_signed_number():
            int_val = self._convert_to_unsigned(int(val), self.size)
        else:
            int_val = cast(int, val)

        pkt_val = struct.unpack(fmt, (s + b"\x00" * 8)[:8])[0]
        pkt_val |= int_val << shift
        tmp_s = struct.pack(fmt, pkt_val)
        return tmp_s[:len(s)]

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, Union[int, float]]
        if not isinstance(pkt, SignalPacket):
            raise Scapy_Exception("Only use SignalFields in a SignalPacket")

        if isinstance(s, tuple):
            s, _ = s

        if self._is_little_endian():
            msb_pos = self.start + self.size - 1
            lsb_pos = self.start
            shift = self.start
            fmt = "<Q"
        else:
            msb_pos = self.start
            lsb_pos = self._lsb_lookup(self.start, self.size)
            shift = (64 - self._msb_lookup(self.start) - self.size)
            fmt = ">Q"

        field_len = max(msb_pos, lsb_pos) // 8 + 1

        if pkt.wirelen is None:
            pkt.wirelen = field_len

        pkt.wirelen = max(pkt.wirelen, field_len)

        fld_val = struct.unpack(fmt, (s + b"\x00" * 8)[:8])[0] >> shift
        fld_val &= ((1 << self.size) - 1)

        if self._is_float_number():
            fld_val = struct.unpack(self.fmt,
                                    struct.pack(self.fmt[0] + "I", fld_val))[0]
        elif self._is_signed_number():
            fld_val = self._convert_to_signed(fld_val, self.size)

        return s, self.m2i(pkt, fld_val)

    def randval(self):
        # type: () -> Union[RandBinFloat, RandFloat]
        if self._is_float_number():
            return RandBinFloat(0, 0)

        if self._is_signed_number():
            min_val = -2**(self.size - 1)
            max_val = 2**(self.size - 1) - 1
        else:
            min_val = 0
            max_val = 2 ** self.size - 1

        min_val = round(min_val * self.scaling + self.offset, self.ndigits)
        max_val = round(max_val * self.scaling + self.offset, self.ndigits)

        return RandFloat(min(min_val, max_val), max(min_val, max_val))

    def i2len(self, pkt, x):
        # type: (Packet, Any) -> int
        return int(float(self.size) / 8)


class LEUnsignedSignalField(SignalField):
    def __init__(self, name, default, start, size, scaling=1, unit="",
                 offset=0, ndigits=3):
        # type: (str, Union[int, float], int, int, Union[int, float], str, Union[int, float], int) -> None  # noqa: E501
        SignalField.__init__(self, name, default, start, size,
                             scaling, unit, offset, ndigits, "<B")


class LESignedSignalField(SignalField):
    def __init__(self, name, default, start, size, scaling=1, unit="",
                 offset=0, ndigits=3):
        # type: (str, Union[int, float], int, int, Union[int, float], str, Union[int, float], int) -> None  # noqa: E501
        SignalField.__init__(self, name, default, start, size,
                             scaling, unit, offset, ndigits, "<b")


class BEUnsignedSignalField(SignalField):
    def __init__(self, name, default, start, size, scaling=1, unit="",
                 offset=0, ndigits=3):
        # type: (str, Union[int, float], int, int, Union[int, float], str, Union[int, float], int) -> None  # noqa: E501
        SignalField.__init__(self, name, default, start, size,
                             scaling, unit, offset, ndigits, ">B")


class BESignedSignalField(SignalField):
    def __init__(self, name, default, start, size, scaling=1, unit="",
                 offset=0, ndigits=3):
        # type: (str, Union[int, float], int, int, Union[int, float], str, Union[int, float], int) -> None  # noqa: E501
        SignalField.__init__(self, name, default, start, size,
                             scaling, unit, offset, ndigits, ">b")


class LEFloatSignalField(SignalField):
    def __init__(self, name, default, start, scaling=1, unit="",
                 offset=0, ndigits=3):
        # type: (str, Union[int, float], int, Union[int, float], str, Union[int, float], int) -> None  # noqa: E501
        SignalField.__init__(self, name, default, start, 32,
                             scaling, unit, offset, ndigits, "<f")


class BEFloatSignalField(SignalField):
    def __init__(self, name, default, start, scaling=1, unit="",
                 offset=0, ndigits=3):
        # type: (str, Union[int, float], int, Union[int, float], str, Union[int, float], int) -> None  # noqa: E501
        SignalField.__init__(self, name, default, start, 32,
                             scaling, unit, offset, ndigits, ">f")


class SignalPacket(Packet):
    def pre_dissect(self, s):
        # type: (bytes) -> bytes
        if not all(isinstance(f, SignalField) or
                   (isinstance(f, ConditionalField) and
                    isinstance(f.fld, SignalField))
                   for f in self.fields_desc):
            raise Scapy_Exception("Use only SignalFields in a SignalPacket")
        return s

    def post_dissect(self, s):
        # type: (bytes) -> bytes
        """ SignalFields can be dissected on packets with unordered fields.
        The order of SignalFields is defined from the start parameter.
        After a build, the consumed bytes of the length of all SignalFields
        have to be removed from the SignalPacket.
        """
        if self.wirelen is not None and self.wirelen > 8:
            raise Scapy_Exception("Only 64 bits for all SignalFields "
                                  "are supported")
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s[self.wirelen:]


class SignalHeader(CAN):
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        LenField('length', None, fmt='B'),
        ThreeBytesField('reserved', 0)
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return s, None


def rdcandump(filename, count=-1, interface=None):
    # type: (str, int, Optional[str]) -> PacketList
    """Read a candump log file and return a packet list

    filename: file to read
    count: read only <count> packets
    interfaces: return only packets from a specified interface
    """
    with CandumpReader(filename, interface) as fdesc:
        return fdesc.read_all(count=count)


class CandumpReader:
    """A stateful candump reader. Each packet is returned as a CAN packet"""

    nonblocking_socket = True

    def __init__(self, filename, interface=None):
        # type: (str, Optional[Union[List[str], str]]) -> None
        self.filename, self.f = self.open(filename)
        self.ifilter = None  # type: Optional[List[str]]
        if interface is not None:
            if isinstance(interface, six.string_types):
                self.ifilter = [interface]
            else:
                self.ifilter = cast(List[str], interface)

    def __iter__(self):
        # type: () -> CandumpReader
        return self

    @staticmethod
    def open(filename):
        # type: (Union[IO[bytes], str]) -> Tuple[str, _ByteStream]
        """Open (if necessary) filename."""
        if isinstance(filename, str):
            try:
                fdesc = gzip.open(filename, "rb")  # type: _ByteStream
                # try read to cause exception
                fdesc.read(1)
                fdesc.seek(0)
            except IOError:
                fdesc = open(filename, "rb")
            return filename, fdesc
        else:
            name = getattr(filename, "name", "No name")
            return name, filename

    def next(self):
        # type: () -> Packet
        """implement the iterator protocol on a set of packets
        """
        try:
            pkt = None
            while pkt is None:
                pkt = self.read_packet()
        except EOFError:
            raise StopIteration

        return pkt
    __next__ = next

    def read_packet(self, size=CAN_MTU):
        # type: (int) -> Optional[Packet]
        """return a single packet read from the file or None if filters apply

        raise EOFError when no more packets are available
        """
        line = self.f.readline()
        line = line.lstrip()
        if len(line) < 16:
            raise EOFError

        is_log_file_format = orb(line[0]) == orb(b"(")

        if is_log_file_format:
            t_b, intf, f = line.split()
            idn, data = f.split(b'#')
            le = None
            t = float(t_b[1:-1])  # type: Optional[float]
        else:
            h, data = line.split(b']')
            intf, idn, le = h.split()
            t = None

        if self.ifilter is not None and \
                intf.decode('ASCII') not in self.ifilter:
            return None

        data = data.replace(b' ', b'')
        data = data.strip()

        pkt = CAN(identifier=int(idn, 16), data=binascii.unhexlify(data))
        if le is not None:
            pkt.length = int(le[1:])
        else:
            pkt.length = len(pkt.data)

        if len(idn) > 3:
            pkt.flags = 0b100

        if t is not None:
            pkt.time = t

        return pkt

    def dispatch(self, callback):
        # type: (Callable[[Packet], None]) -> None
        """call the specified callback routine for each packet read

        This is just a convenience function for the main loop
        that allows for easy launching of packet processing in a
        thread.
        """
        for p in self:
            callback(p)

    def read_all(self, count=-1):
        # type: (int) -> PacketList
        """return a list of all packets in the candump file
        """
        res = []
        while count != 0:
            try:
                p = self.read_packet()
                if p is None:
                    continue
            except EOFError:
                break
            count -= 1
            res.append(p)
        return PacketList(res, name=os.path.basename(self.filename))

    def recv(self, size=CAN_MTU):
        # type: (int) -> Optional[Packet]
        """ Emulate a socket
        """
        return self.read_packet(size=size)

    def fileno(self):
        # type: () -> int
        return self.f.fileno()

    def close(self):
        # type: () -> Any
        return self.f.close()

    def __enter__(self):
        # type: () -> CandumpReader
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        # type: (Optional[Type[BaseException]], Optional[BaseException], Optional[Any]) -> None  # noqa: E501
        self.close()

    # emulate SuperSocket
    @staticmethod
    def select(sockets, remain=None):
        # type: (List[SuperSocket], Optional[int]) -> List[SuperSocket]
        return sockets
