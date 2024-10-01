# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = HSFZ - BMW High-Speed-Fahrzeug-Zugang
# scapy.contrib.status = loads
import logging
import socket
import struct
import time
from typing import (
    Any,
    Optional,
    Tuple,
    Type,
    Iterable,
    List,
    Union,
)

from scapy.contrib.automotive import log_automotive
from scapy.contrib.automotive.uds import UDS, UDS_TP
from scapy.data import MTU
from scapy.fields import (IntField, ShortEnumField, XByteField,
                          ConditionalField, StrFixedLenField)
from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.supersocket import StreamSocket

"""
BMW HSFZ (High-Speed-Fahrzeug-Zugang / High-Speed-Car-Access).
BMW specific diagnostic over IP protocol implementation.
The physical interface for this connection is called ENET.
"""


# #########################HSFZ###################################


class HSFZ(Packet):
    control_words = {
        0x01: "diagnostic_req_res",
        0x02: "acknowledge_transfer",
        0x10: "terminal15",
        0x11: "vehicle_ident_data",
        0x12: "alive_check",
        0x13: "status_data_inquiry",
        0x40: "incorrect_tester_address",
        0x41: "incorrect_control_word",
        0x42: "incorrect_format",
        0x43: "incorrect_dest_address",
        0x44: "message_too_large",
        0x45: "diag_app_not_ready",
        0xFF: "out_of_memory"
    }
    name = 'HSFZ'
    fields_desc = [
        IntField('length', None),
        ShortEnumField('control', 1, control_words),
        ConditionalField(
            XByteField('source', 0), lambda p: p.control == 1),
        ConditionalField(
            XByteField('target', 0), lambda p: p.control == 1),
        ConditionalField(
            StrFixedLenField("identification_string",
                             None, None, lambda p: p.length),
            lambda p: p.control == 0x11)
    ]

    def hashret(self):
        # type: () -> bytes
        hdr_hash = struct.pack("B", self.source ^ self.target)
        pay_hash = self.payload.hashret()
        return hdr_hash + pay_hash

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return s[:self.length - 2], s[self.length - 2:]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """
        This will set the LenField 'length' to the correct value.
        """
        if self.length is None:
            pkt = struct.pack("!I", len(pay) + 2) + pkt[4:]
        return pkt + pay


bind_bottom_up(TCP, HSFZ, sport=6801)
bind_bottom_up(TCP, HSFZ, dport=6801)
bind_layers(TCP, HSFZ, sport=6801, dport=6801)

bind_bottom_up(UDP, HSFZ, sport=6811)
bind_bottom_up(UDP, HSFZ, dport=6811)
bind_layers(UDP, HSFZ, sport=6811, dport=6811)

bind_layers(HSFZ, UDS)


# ########################HSFZSocket###################################


class HSFZSocket(StreamSocket):
    def __init__(self, ip='127.0.0.1', port=6801):
        # type: (str, int) -> None
        self.ip = ip
        self.port = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((self.ip, self.port))
        StreamSocket.__init__(self, s, HSFZ)
        self.buffer = b""

    def recv(self, x=MTU, **kwargs):
        # type: (Optional[int], **Any) -> Optional[Packet]
        if self.buffer:
            len_data = self.buffer[:4]
        else:
            len_data = self.ins.recv(4, socket.MSG_PEEK)
            if len(len_data) != 4:
                return None

        len_int = struct.unpack(">I", len_data)[0]
        len_int += 6
        self.buffer += self.ins.recv(len_int - len(self.buffer))

        if len(self.buffer) != len_int:
            return None

        pkt = self.basecls(self.buffer, **kwargs)  # type: Packet
        self.buffer = b""
        return pkt


class UDS_HSFZSocket(HSFZSocket):
    def __init__(self, source, target, ip='127.0.0.1', port=6801, basecls=UDS):
        # type: (int, int, str, int, Type[Packet]) -> None
        super(UDS_HSFZSocket, self).__init__(ip, port)
        self.source = source
        self.target = target
        self.basecls = HSFZ
        self.outputcls = basecls

    def send(self, x):
        # type: (Packet) -> int
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        try:
            return super(UDS_HSFZSocket, self).send(
                HSFZ(source=self.source, target=self.target) / x)
        except Exception as e:
            # Workaround:
            # This catch block is currently necessary to detect errors
            # during send. In automotive application it's not uncommon that
            # a destination socket goes down. If any function based on
            # SndRcvHandler is used, all exceptions are silently handled
            # in the send part. This means, a caller of the SndRcvHandler
            # can not detect if an error occurred. This workaround closes
            # the socket if a send error was detected.
            log_automotive.exception("Exception: %s", e)
            self.close()
            return 0

    def recv(self, x=MTU, **kwargs):
        # type: (Optional[int], **Any) -> Optional[Packet]
        pkt = super(UDS_HSFZSocket, self).recv(x)
        if pkt:
            return self.outputcls(bytes(pkt.payload), **kwargs)
        else:
            return pkt


def hsfz_scan(ip,  # type: str
              scan_range=range(0x100),  # type: Iterable[int]
              source=0xf4,  # type: int
              timeout=0.1,  # type: Union[int, float]
              verbose=True  # type: bool
              ):
    # type: (...) -> List[UDS_HSFZSocket]
    """
    Helper function to scan for HSFZ endpoints.

    Example:
        >>> sockets = hsfz_scan("192.168.0.42")

    :param ip: IPv4 address of target to scan
    :param scan_range: Range for HSFZ destination address
    :param source: HSFZ source address, used during the scan
    :param timeout: Timeout for each request
    :param verbose: Show information during scan, if True
    :return: A list of open UDS_HSFZSockets
    """
    if verbose:
        log_automotive.setLevel(logging.DEBUG)
    results = list()
    for i in scan_range:
        with UDS_HSFZSocket(source, i, ip) as sock:
            try:
                resp = sock.sr1(UDS() / UDS_TP(),
                                timeout=timeout,
                                verbose=False)
                if resp:
                    results.append((i, resp))
                if resp:
                    log_automotive.debug(
                        "Found endpoint %s, source=0x%x, target=0x%x" % (ip, source, i))
            except Exception as e:
                log_automotive.exception(
                    "Error %s at destination address 0x%x" % (e, i))
    return [UDS_HSFZSocket(0xf4, target, ip) for target, _ in results]
