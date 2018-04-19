# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license


"""
Python-CAN CANSocket Wrapper.
"""

import time
from scapy.config import conf
from scapy.supersocket import SuperSocket
from scapy.error import warning, Scapy_Exception
from scapy.layers.can import CAN
from can import BusABC as can_BusABC
from can import Message as can_Message
from can import CanError as can_Error

CAN_FRAME_SIZE = 16
CAN_INV_FILTER = 0x20000000


class CANSocketTimeoutElapsed(Scapy_Exception):
    pass


class CANSocket(SuperSocket):
    desc = "read/write packets at a given CAN interface " \
           "using a python-can bus object"

    def __init__(self, iface=None):
        if issubclass(type(iface), can_BusABC):
            self.iface = iface
            self.ins = None
            self.outs = None
        else:
            warning("Provide a python-can interface")

    def recv(self):
        msg = self.iface.recv(timeout=1)
        if msg is None:
            raise CANSocketTimeoutElapsed
        frame = CAN(identifier=msg.arbitration_id,
                    length=msg.dlc,
                    data=bytes(msg.data))
        if msg.is_error_frame:
            frame.flags |= 0x1
        if msg.is_remote_frame:
            frame.flags |= 0x2
        if msg.is_extended_id:
            frame.flags |= 0x4
        frame.time = msg.timestamp
        return frame

    def send(self, x):
        try:
            if hasattr(x, "sent_time"):
                x.sent_time = time.time()

            msg = can_Message(is_remote_frame=x.flags == 0x2,
                              extended_id=x.flags == 0x4,
                              is_error_frame=x.flags == 0x1,
                              arbitration_id=x.identifier,
                              dlc=x.length,
                              data=x.data)
            return self.iface.send(msg)
        except can_Error as ex:
            raise ex

    @staticmethod
    def is_python_can_socket():
        """Function used to determine if a socket is a python-can CANSocket.
        This is used from sendrecv, to determine if a non standard _get_pkt()
        and _select() function needs to be used."""
        return True


@conf.commands.register
def srcan(pkt, iface=None, *args, **kargs):
    s = CANSocket(iface)
    a, b = s.sr(pkt, *args, **kargs)
    s.close()
    return a, b
