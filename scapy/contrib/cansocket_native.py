# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Native CANSocket
# scapy.contrib.status = loads

"""
NativeCANSocket.
"""

import struct
import socket
import time

from scapy.config import conf
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception, warning
from scapy.packet import Packet
from scapy.layers.can import CAN, CAN_MTU
from scapy.arch.linux import get_last_packet_timestamp
from scapy.compat import List, Dict, Type, Any, Optional, Tuple, raw

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

    def __init__(self,
                 channel=None,  # type: Optional[str]
                 receive_own_messages=False,  # type: bool
                 can_filters=None,  # type: Optional[List[Dict[str, int]]]
                 basecls=CAN,  # type: Type[Packet]
                 **kwargs  # type: Dict[str, Any]
                 ):
        # type: (...) -> None
        bustype = kwargs.pop("bustype", "")
        if bustype != "socketcan":
            warning("You created a NativeCANSocket. "
                    "If you're providing the argument 'bustype', please use "
                    "the correct one to achieve compatibility with python-can"
                    "/PythonCANSocket. \n'bustype=socketcan'")

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

    def recv_raw(self, x=CAN_MTU):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]  # noqa: E501
        """Returns a tuple containing (cls, pkt_data, time)"""
        pkt = None
        try:
            pkt = self.ins.recv(x)
        except BlockingIOError:  # noqa: F821
            warning("Captured no data, socket in non-blocking mode.")
        except socket.timeout:
            warning("Captured no data, socket read timed out.")
        except OSError:
            # something bad happened (e.g. the interface went down)
            warning("Captured no data.")

        # need to change the byte order of the first four bytes,
        # required by the underlying Linux SocketCAN frame format
        if not conf.contribs['CAN']['swap-bytes'] and pkt is not None:
            pkt = struct.pack("<I12s", *struct.unpack(">I12s", pkt))

        return self.basecls, pkt, get_last_packet_timestamp(self.ins)

    def send(self, x):
        # type: (Packet) -> int
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        # need to change the byte order of the first four bytes,
        # required by the underlying Linux SocketCAN frame format
        bs = raw(x)
        if not conf.contribs['CAN']['swap-bytes']:
            bs = bs + b'\x00' * (CAN_MTU - len(bs))
            bs = struct.pack("<I12s", *struct.unpack(">I12s", bs))

        return super(NativeCANSocket, self).send(bs)  # type: ignore


CANSocket = NativeCANSocket
