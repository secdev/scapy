# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2016 Gauthier Sebaux

# scapy.contrib.description = DCE/RPC
# scapy.contrib.status = loads

"""
A basic dissector for DCE/RPC.
Isn't reliable for all packets and for building
"""

# TODO: namespace locally used fields
import re
import struct
from scapy.packet import Packet, Raw, bind_layers
from scapy.fields import Field, BitEnumField, ByteEnumField, ByteField, \
    FlagsField, IntField, LenField, ShortField, XByteField, XShortField
from scapy.volatile import RandField, RandNum, RandInt, RandShort, RandByte
import scapy.modules.six


# Fields
class EndiannessField(object):
    """Field which change the endianness of a sub-field"""
    __slots__ = ["fld", "endianess_from"]

    def __init__(self, fld, endianess_from):
        self.fld = fld
        self.endianess_from = endianess_from

    def set_endianess(self, pkt):
        """Add the endianness to the format"""
        end = self.endianess_from(pkt)
        if isinstance(end, str) and len(end) > 0:
            # fld.fmt should always start with a order specifier, cf field init
            self.fld.fmt = end[0] + self.fld.fmt[1:]

    def getfield(self, pkt, buf):
        """retrieve the field with endianness"""
        self.set_endianess(pkt)
        return self.fld.getfield(pkt, buf)

    def addfield(self, pkt, buf, val):
        """add the field with endianness to the buffer"""
        self.set_endianess(pkt)
        return self.fld.addfield(pkt, buf, val)

    def __getattr__(self, attr):
        return getattr(self.fld, attr)


class UUIDField(Field):
    """UUID Field"""
    __slots__ = ["reg"]

    def __init__(self, name, default):
        # create and compile the regex used to extract the uuid values from str
        reg = r"^\s*{0}-{1}-{1}-{2}{2}-{2}{2}{2}{2}{2}{2}\s*$".format(
            "([0-9a-f]{8})", "([0-9a-f]{4})", "([0-9a-f]{2})"
        )
        self.reg = re.compile(reg, re.I)

        Field.__init__(self, name, default, fmt="I2H8B")

    def i2m(self, pkt, val):
        if val is None:
            return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        if isinstance(val, bytearray) or isinstance(val, str):  # py3 concern
            # use the regex to extract the values
            match = self.reg.match(val)
            if match:
                # we return a tuple of values after parsing them to integer
                return tuple([int(i, 16) for i in match.groups()])
            else:
                return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        else:
            return val

    def m2i(self, pkt, val):
        return ("%08x-%04x-%04x-%02x%02x-" + "%02x" * 6) % val

    def any2i(self, pkt, val):
        if isinstance(val, bytearray) and len(val) == 16:
            return self.getfield(pkt, val)[1]
        elif isinstance(val, bytearray):
            return val.lower()
        return val

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, *self.i2m(pkt, val))

    def getfield(self, pkt, s):
        return s[16:], self.m2i(pkt, struct.unpack(self.fmt, s[:16]))

    @staticmethod
    def randval():
        return RandUUID()


class RandUUID(RandField):
    """generate a random UUID"""
    def __init__(self, template="*-*-*-**-******"):
        base = "([0-9a-f]{{{0}}}|\\*|[0-9a-f]{{{0}}}:[0-9a-f]{{{0}}})"
        reg = re.compile(
            r"^\s*{0}-{1}-{1}-{2}{2}-{2}{2}{2}{2}{2}{2}\s*$".format(
                base.format(8), base.format(4), base.format(2)
            ),
            re.I
        )

        tmp = reg.match(template)
        if tmp:
            template = tmp.groups()
        else:
            template = ["*"] * 11

        rnd_f = [RandInt] + [RandShort] * 2 + [RandByte] * 8
        self.uuid = ()
        for i in scapy.modules.six.moves.range(11):
            if template[i] == "*":
                val = rnd_f[i]()
            elif ":" in template[i]:
                mini, maxi = template[i].split(":")
                val = RandNum(int(mini, 16), int(maxi, 16))
            else:
                val = int(template[i], 16)
            self.uuid += (val,)

    def _fix(self):
        return ("%08x-%04x-%04x-%02x%02x-" + "%02x" * 6) % self.uuid


# DCE/RPC Packet
DCE_RPC_TYPE = ["request", "ping", "response", "fault", "working", "no_call",
                "reject", "acknowledge", "connectionless_cancel", "frag_ack",
                "cancel_ack"]
DCE_RPC_FLAGS1 = ["reserved_0", "last_frag", "frag", "no_frag_ack", "maybe",
                  "idempotent", "broadcast", "reserved_7"]
DCE_RPC_FLAGS2 = ["reserved_0", "cancel_pending", "reserved_2", "reserved_3",
                  "reserved_4", "reserved_5", "reserved_6", "reserved_7"]


def dce_rpc_endianess(pkt):
    """Determine the right endianness sign for a given DCE/RPC packet"""
    if pkt.endianness == 0:  # big endian
        return ">"
    elif pkt.endianness == 1:  # little endian
        return "<"
    else:
        return "!"


class DceRpc(Packet):
    """DCE/RPC packet"""
    name = "DCE/RPC"
    fields_desc = [
        ByteField("version", 4),
        ByteEnumField("type", 0, DCE_RPC_TYPE),
        FlagsField("flags1", 0, 8, DCE_RPC_FLAGS1),
        FlagsField("flags2", 0, 8, DCE_RPC_FLAGS2),
        BitEnumField("endianness", 0, 4, ["big", "little"]),
        BitEnumField("encoding", 0, 4, ["ASCII", "EBCDIC"]),
        ByteEnumField("float", 0, ["IEEE", "VAX", "CRAY", "IBM"]),
        ByteField("DataRepr_reserved", 0),
        XByteField("serial_high", 0),
        EndiannessField(UUIDField("object_uuid", None),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(UUIDField("interface_uuid", None),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(UUIDField("activity", None),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(IntField("boot_time", 0),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(IntField("interface_version", 1),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(IntField("sequence_num", 0),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(ShortField("opnum", 0),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(XShortField("interface_hint", 0xffff),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(XShortField("activity_hint", 0xffff),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(LenField("frag_len", None, fmt="H"),
                        endianess_from=dce_rpc_endianess),
        EndiannessField(ShortField("frag_num", 0),
                        endianess_from=dce_rpc_endianess),
        ByteEnumField("auth", 0, ["none"]),  # TODO other auth ?
        XByteField("serial_low", 0),
    ]


# Heuristically way to find the payload class
#
# To add a possible payload to a DCE/RPC packet, one must first create the
# packet class, then instead of binding layers using bind_layers, he must
# call DceRpcPayload.register_possible_payload() with the payload class as
# parameter.
#
# To be able to decide if the payload class is capable of handling the rest of
# the dissection, the classmethod can_handle() should be implemented in the
# payload class. This method is given the rest of the string to dissect as
# first argument, and the DceRpc packet instance as second argument. Based on
# this information, the method must return True if the class is capable of
# handling the dissection, False otherwise
class DceRpcPayload(Packet):
    """Dummy class which use the dispatch_hook to find the payload class"""
    _payload_class = []

    @classmethod
    def dispatch_hook(cls, _pkt, _underlayer=None, *args, **kargs):
        """dispatch_hook to choose among different registered payloads"""
        for klass in cls._payload_class:
            if hasattr(klass, "can_handle") and \
                    klass.can_handle(_pkt, _underlayer):
                return klass
        print("DCE/RPC payload class not found or undefined (using Raw)")
        return Raw

    @classmethod
    def register_possible_payload(cls, pay):
        """Method to call from possible DCE/RPC endpoint to register it as
        possible payload"""
        cls._payload_class.append(pay)


bind_layers(DceRpc, DceRpcPayload)
