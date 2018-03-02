# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license


"""
CANSocket.
"""

from scapy.config import conf
from scapy.data import DLT_CAN_SOCKETCAN
from scapy.fields import FieldLenField, FlagsField, StrLenField, XBitField, PadField, ThreeBytesField
from scapy.packet import Packet, bind_layers, RawVal
from scapy.supersocket import SuperSocket
from scapy.arch.linux import get_last_packet_timestamp
from scapy.error import Scapy_Exception, warning
import scapy.sendrecv as sendrecv
import struct
import scapy.modules.six as six
import socket
import time
from scapy.layers.l2 import CookedLinux

# Mimics the Wireshark CAN dissector parameter 'Byte-swap the CAN ID/flags field'
#   set to True when working with PF_CAN sockets
conf.contribs['CAN'] = {'swap-bytes': False}

############
## Consts ##
############
CAN_FRAME_SIZE = 16
CAN_INV_FILTER = 0x20000000


class CAN(Packet):
    fields_desc = [
        FlagsField("flags", 0, 3, ["error", "remote_transmission_request",
                                   "extended"]),
        XBitField("identifier", 0, 29),
        PadField(FieldLenField("length", None, length_of="data", fmt="B"), 4),
        PadField(StrLenField("data", "", length_from=lambda pkt: min(pkt.length, 8)), 8)
    ]

    @property
    def id(self):
        return self.identifier

    @property
    def dlc(self):
        return self.length

    def pre_dissect(self, s):
        """ Implements the swap-bytes functionality when dissecting """
        if conf.contribs['CAN']['swap-bytes']:
            return struct.pack('<I12s', *struct.unpack('>I12s', s))
        return s

    def self_build(self, field_pos_list=None):
        """ Implements the swap-bytes functionality when building

        this is based on a copy of the Packet.self_build default method.
        The goal is to affect only the CAN layer data and keep
        under layers (e.g LinuxCooked) unchanged
        """
        if self.raw_packet_cache is not None:
            for fname, fval in six.iteritems(self.raw_packet_cache_fields):
                if self.getfieldval(fname) != fval:
                    self.raw_packet_cache = None
                    self.raw_packet_cache_fields = None
                    break
            if self.raw_packet_cache is not None:
                if conf.contribs['CAN']['swap-bytes']:
                    return struct.pack('<I12s', *struct.unpack('>I12s', self.raw_packet_cache))
                return self.raw_packet_cache
        p = b""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            if isinstance(val, RawVal):
                sval = raw(val)
                p += sval
                if field_pos_list is not None:
                    field_pos_list.append((f.name, sval.encode('string_escape'), len(p), len(sval)))
            else:
                p = f.addfield(self, p, val)
        if conf.contribs['CAN']['swap-bytes']:
            return struct.pack('<I12s', *struct.unpack('>I12s', p))
        return p


class CANSocket(SuperSocket):
    desc = "read/write packets at a given CAN interface using PF_CAN sockets"

    def __init__(self, iface=None, receive_own_messages=False, filter=None):
        self.iface = conf.CANiface if iface is None else iface
        self.ins = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        try:
            self.ins.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_RECV_OWN_MSGS,
                                struct.pack("i", receive_own_messages))
        except Exception as e:
            Scapy_Exception("Could not modify receive own messages (%s)", e)

        if filter is None:
            filter = [{
                "can_id": 0,
                "can_mask": 0
            }]

        can_filter_fmt = "={}I".format(2 * len(filter))
        filter_data = []
        for can_filter in filter:
            filter_data.append(can_filter["can_id"])
            filter_data.append(can_filter["can_mask"])

        self.ins.setsockopt(socket.SOL_CAN_RAW,
                            socket.CAN_RAW_FILTER,
                            struct.pack(can_filter_fmt, *filter_data)
                            )

        self.ins.bind((iface,))
        self.outs = self.ins

    def recv(self, x=CAN_FRAME_SIZE):
        try:
            pkt, sa_ll = self.ins.recvfrom(x)
        except BlockingIOError:
            warning("Captured no data, socket in non-blocking mode.")
            return None
        except socket.timeout:
            warning("Captured no data, socket read timed out.")
            return None
        except OSError:
            # something bad happened (e.g. the interface went down)
            warning("Captured no data.")
            return None

        # need to change the byteoder of the first four bytes, required by the underlaying linux CAN frame format
        pkt = struct.pack("<I12s", *struct.unpack(">I12s", pkt))

        q = CAN(pkt)
        q.time = get_last_packet_timestamp(self.ins)
        return q

    def send(self, x):
        try:
            if hasattr(x, "sent_time"):
                x.sent_time = time.time()
            # need to change the byteoder of the first four bytes, required by the underlaying linux CAN frame format
            bs = struct.pack("<I12s", *struct.unpack(">I12s", bytes(x)))
            return SuperSocket.send(self, bs)
        except socket.error as msg:
            raise msg


@conf.commands.register
def srcan(pkt, iface=None, receive_own_messages=False, filter=None, *args, **kargs):
    if not "timeout" in kargs:
        kargs["timeout"] = -1
    s = conf.CANSocket(iface, receive_own_messages, filter)
    a, b = s.sr(pkt, *args, **kargs)
    s.close()
    return a, b


@conf.commands.register
def srcanloop(pkts, *args, **kargs):
    """Send a packet at can layer in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    return sendrecv.__sr_loop(srcan, pkts, *args, **kargs)


conf.CANiface = "can0"
conf.CANSocket = CANSocket
conf.l2types.register(DLT_CAN_SOCKETCAN, CAN)
bind_layers(CookedLinux, CAN, proto=12)
