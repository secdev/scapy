# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Python-Can CANSocket
# scapy.contrib.status = loads

"""
Python-CAN CANSocket Wrapper.
"""

import time
import struct
from scapy.config import conf
from scapy.supersocket import SuperSocket
from scapy.error import warning
from scapy.layers.can import CAN
from can import BusABC as can_BusABC
from can import Message as can_Message
from can import CanError as can_Error

CAN_FRAME_SIZE = 16
CAN_INV_FILTER = 0x20000000


class CANSocket(SuperSocket):
    nonblocking_socket = True
    desc = "read/write packets at a given CAN interface " \
           "using a python-can bus object"

    def __init__(self, iface=None, timeout=1.0, basecls=CAN):

        if issubclass(type(iface), can_BusABC):
            self.basecls = basecls
            self.iface = iface
            self.ins = None
            self.outs = None
            self.timeout = timeout
        else:
            warning("Provide a python-can interface")

    def recv_raw(self, x=0xffff):
        msg = self.iface.recv(timeout=self.timeout)
        if msg is None:
            return None, None, None
        hdr = msg.is_extended_id << 31 | msg.is_remote_frame << 30 | \
            msg.is_error_frame << 29 | msg.arbitration_id

        if conf.contribs['CAN']['swap-bytes']:
            hdr = struct.unpack("<I", struct.pack(">I", hdr))[0]

        dlc = msg.dlc << 24
        pkt_data = struct.pack("!II", hdr, dlc) + bytes(msg.data)
        return self.basecls, pkt_data, msg.timestamp

    def send(self, x):
        try:
            msg = can_Message(is_remote_frame=x.flags == 0x2,
                              extended_id=x.flags == 0x4,
                              is_error_frame=x.flags == 0x1,
                              arbitration_id=x.identifier,
                              dlc=x.length,
                              data=bytes(x)[8:])
            if hasattr(x, "sent_time"):
                x.sent_time = time.time()
            return self.iface.send(msg)
        except can_Error as ex:
            raise ex

    @staticmethod
    def select(sockets, remain=None):
        """This function is called during sendrecv() routine to select
        the available sockets.
        """
        if remain is not None:
            max_timeout = remain / len(sockets)
            for s in sockets:
                if s.timeout > max_timeout:
                    s.timeout = max_timeout

        # python-can sockets aren't selectable, so we return all of them
        # sockets, None (means use the socket's recv() )
        return sockets, None


@conf.commands.register
def srcan(pkt, iface=None, basecls=CAN, *args, **kargs):
    s = CANSocket(iface, basecls=basecls)
    a, b = s.sr(pkt, *args, **kargs)
    s.close()
    return a, b
