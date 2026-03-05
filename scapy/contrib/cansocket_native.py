# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = Native CANSocket
# scapy.contrib.status = loads

"""
NativeCANSocket.
"""

import struct
import socket
import time

from scapy.config import conf
from scapy.data import SO_TIMESTAMPNS
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception, warning, log_runtime
from scapy.packet import Packet
from scapy.layers.can import CAN, CANXL, CAN_MTU, CAN_FD_MTU, CANXL_MTU
from scapy.compat import raw

from typing import (
    List,
    Dict,
    Type,
    Any,
    Optional,
    Tuple,
    cast,
)

conf.contribs['NativeCANSocket'] = {'channel': "can0"}


class NativeCANSocket(SuperSocket):
    """Initializes a Linux PF_CAN socket object.

    Example:
        >>> socket = NativeCANSocket(channel="vcan0", can_filters=[{'can_id': 0x200, 'can_mask': 0x7FF}])

    :param channel: Network interface name
    :param receive_own_messages: Messages, sent by this socket are will
                                 also be received.
    :param can_filters: A list of can filter dictionaries.
    :param basecls: Packet type in which received data gets interpreted.
    :param kwargs: Various keyword arguments for compatibility with
                   PythonCANSockets
    """  # noqa: E501
    desc = "read/write packets at a given CAN interface using PF_CAN sockets"

    # Socket option constants for CAN XL (not yet in Python's socket module)
    CAN_RAW_XL_FRAMES = 7     # enable CAN XL frames    (kernel >= 6.2)
    CAN_RAW_XL_VCID_OPTS = 8  # VCID pass-through opts  (kernel >= 6.11)

    # can_raw_vcid_options.flags bits
    CAN_RAW_XL_VCID_TX_SET = 0x01
    CAN_RAW_XL_VCID_TX_PASS = 0x02
    CAN_RAW_XL_VCID_RX_FILTER = 0x04

    def __init__(self,
                 channel=None,  # type: Optional[str]
                 receive_own_messages=False,  # type: bool
                 can_filters=None,  # type: Optional[List[Dict[str, int]]]
                 fd=False,  # type: bool
                 xl=False,  # type: bool
                 basecls=CAN,  # type: Type[Packet]
                 **kwargs  # type: Dict[str, Any]
                 ):
        # type: (...) -> None
        bustype = cast(Optional[str], kwargs.pop("bustype", None))
        if bustype and bustype != "socketcan":
            warning("You created a NativeCANSocket. "
                    "If you're providing the argument 'bustype', please use "
                    "the correct one to achieve compatibility with python-can"
                    "/PythonCANSocket. \n'bustype=socketcan'")

        self.MTU = CAN_MTU
        self.fd = fd
        self.xl = xl
        self.basecls = basecls
        self.channel = conf.contribs['NativeCANSocket']['channel'] if \
            channel is None else channel
        self.ins = socket.socket(socket.PF_CAN,
                                 socket.SOCK_RAW,
                                 socket.CAN_RAW)
        try:
            self.ins.setsockopt(socket.SOL_CAN_RAW,
                                socket.CAN_RAW_RECV_OWN_MSGS,
                                struct.pack("i", receive_own_messages))
        except Exception as exception:
            raise Scapy_Exception(
                "Could not modify receive own messages (%s)", exception
            )

        try:
            # Receive Auxiliary Data (Timestamps)
            self.ins.setsockopt(
                socket.SOL_SOCKET,
                SO_TIMESTAMPNS,
                1
            )
            self.auxdata_available = True
        except OSError:
            # Note: Auxiliary Data is only supported since
            #       Linux 2.6.21
            msg = "Your Linux Kernel does not support Auxiliary Data!"
            log_runtime.info(msg)

        if self.fd:
            try:
                self.ins.setsockopt(socket.SOL_CAN_RAW,
                                    socket.CAN_RAW_FD_FRAMES,
                                    1)
                self.MTU = CAN_FD_MTU
            except Exception as exception:
                raise Scapy_Exception(
                    "Could not enable CAN FD support (%s)", exception
                )

        if self.xl:
            # CAN_RAW_XL_FRAMES - required, kernel >= 6.2
            try:
                self.ins.setsockopt(socket.SOL_CAN_RAW,
                                    self.CAN_RAW_XL_FRAMES,
                                    struct.pack("i", 1))
                self.MTU = CANXL_MTU
            except OSError as exc:
                raise Scapy_Exception(
                    "Could not enable CAN XL frames "
                    "(kernel >= 6.2 required): %s" % exc
                )

            # CAN_RAW_XL_VCID_OPTS - optional, kernel >= 6.11
            # RX_FILTER with mask=0 passes all VCIDs; TX_PASS forwards
            # the VCID from the frame to the bus.
            vcid_flags = (self.CAN_RAW_XL_VCID_RX_FILTER |
                          self.CAN_RAW_XL_VCID_TX_PASS)
            try:
                vcid_opts = struct.pack("BBBB", vcid_flags, 0, 0, 0)
                self.ins.setsockopt(socket.SOL_CAN_RAW,
                                    self.CAN_RAW_XL_VCID_OPTS,
                                    vcid_opts)
            except OSError:
                warning("CAN_RAW_XL_VCID_OPTS not available "
                        "(kernel >= 6.11 required). "
                        "Frames with non-zero VCID may not be received.")

        if can_filters is None:
            can_filters = [{
                "can_id": 0,
                "can_mask": 0
            }]

        can_filter_fmt = "={}I".format(2 * len(can_filters))
        filter_data = []
        for can_filter in can_filters:
            filter_data.append(can_filter["can_id"])
            filter_data.append(can_filter["can_mask"])

        self.ins.setsockopt(socket.SOL_CAN_RAW,
                            socket.CAN_RAW_FILTER,
                            struct.pack(can_filter_fmt, *filter_data))

        self.ins.bind((self.channel,))
        self.outs = self.ins

    @staticmethod
    def _is_canxl(pkt):
        # type: (bytes) -> bool
        """Detect CAN XL frame by XLF flag (bit 7 of byte 4)."""
        return len(pkt) > 4 and bool(pkt[4] & 0x80)

    def recv_raw(self, x=CAN_MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        pkt = None
        ts = None
        try:
            pkt, _, ts = self._recv_raw(self.ins, self.MTU)
        except BlockingIOError:  # noqa: F821
            warning("Captured no data, socket in non-blocking mode.")
        except socket.timeout:
            warning("Captured no data, socket read timed out.")
        except OSError:
            # something bad happened (e.g. the interface went down)
            warning("Captured no data.")

        # CAN XL frames handle their own byte swapping in
        # CANXL.pre_dissect - skip the first-4-byte swap here.
        # CAN/CANFD still need the first-4-byte swap.
        if not conf.contribs['CAN']['swap-bytes'] and pkt \
                and not self._is_canxl(pkt):
            pack_fmt = "<I%ds" % (len(pkt) - 4)
            unpack_fmt = ">I%ds" % (len(pkt) - 4)
            pkt = struct.pack(pack_fmt, *struct.unpack(unpack_fmt, pkt))

        if pkt and ts is None:
            from scapy.arch.linux import get_last_packet_timestamp
            ts = get_last_packet_timestamp(self.ins)

        return self.basecls, pkt, ts

    def send(self, x):
        # type: (Packet) -> int
        if x is None:
            return 0

        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        bs = raw(x)

        if isinstance(x, CANXL):
            # CANXL.post_build already produces little endian wire bytes.
            # No MTU padding - kernel expects exact HDR_SIZE + len.
            pass
        else:
            # CAN/CANFD: swap first 4 bytes (CAN ID) big endian to litte endian
            if not conf.contribs['CAN']['swap-bytes']:
                pack_fmt = "<I%ds" % (len(bs) - 4)
                unpack_fmt = ">I%ds" % (len(bs) - 4)
                bs = struct.pack(pack_fmt, *struct.unpack(unpack_fmt, bs))
            # CAN/CANFD: pad to MTU
            bs = bs + b"\x00" * (self.MTU - len(bs))

        return super(NativeCANSocket, self).send(bs)  # type: ignore


CANSocket = NativeCANSocket
