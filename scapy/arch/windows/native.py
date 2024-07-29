# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Native Microsoft Windows sockets (L3 only)

This uses Raw Sockets from winsock
https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2

.. note::

    Don't use this module.
    It is a proof of concept, and a worse-case-scenario failover, but you should
    consider that raw sockets on Windows don't work and install Npcap to avoid using
    it at all cost.
"""

import io
import socket
import struct
import time

from scapy.automaton import select_objects
from scapy.compat import raw
from scapy.config import conf
from scapy.data import MTU
from scapy.error import Scapy_Exception, log_runtime
from scapy.packet import Packet
from scapy.interfaces import resolve_iface, _GlobInterfaceType
from scapy.supersocket import SuperSocket

# Typing imports
from typing import (
    Any,
    List,
    Optional,
    Tuple,
    Type,
)

# Watch out for import loops (inet...)


class L3WinSocket(SuperSocket):
    """
    A L3 raw socket implementation native to Windows.

    Official "Windows Limitations" from MSDN:
        - TCP data cannot be sent over raw sockets.
        - UDP datagrams with an invalid source address cannot be sent over raw sockets.
        - For IPv6 (address family of AF_INET6), an application receives everything
          after the last IPv6 header in each received datagram [...]. The application
          does not receive any IPv6 headers using a raw socket.

    Unofficial limitations:
        - Turns out we actually don't see any incoming TCP data, only the outgoing.
          We do properly see UDP, ICMP, etc. both ways though.
        - To match IPv6 responses, one must use `conf.checkIPaddr = False` as we can't
          get the real destination.

    **To overcome those limitations, install Npcap.**
    """
    desc = "a native Layer 3 (IPv4) raw socket under Windows"
    nonblocking_socket = True
    __selectable_force_select__ = True  # see automaton.py
    __slots__ = ["promisc", "cls", "ipv6"]

    def __init__(self,
                 iface=None,  # type: Optional[_GlobInterfaceType]
                 ttl=128,  # type: int
                 ipv6=False,  # type: bool
                 promisc=True,  # type: bool
                 **kwargs  # type: Any
                 ):
        # type: (...) -> None
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        for kwarg in kwargs:
            log_runtime.warning("Dropping unsupported option: %s" % kwarg)
        self.iface = iface and resolve_iface(iface) or conf.iface
        if not self.iface.is_valid():
            log_runtime.warning("Interface is invalid. This will fail.")
        af = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.ipv6 = ipv6
        self.cls = IPv6 if ipv6 else IP
        # Promisc
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        # Notes:
        # - IPPROTO_RAW is broken. We don't use it.
        # - IPPROTO_IPV6 exists in MSDN docs, but using it will result in
        # no packets being received. Same for its options (IPV6_HDRINCL...)
        # However, using IPPROTO_IP with AF_INET6 will still receive
        # the IPv6 packets
        try:
            # Listening on AF_INET6 IPPROTO_IPV6 is broken. Use IPPROTO_IP
            self.outs = self.ins = socket.socket(
                af,
                socket.SOCK_RAW,
                socket.IPPROTO_IP,
            )
        except OSError as e:
            if e.errno == 13:
                raise OSError("Windows native L3 Raw sockets are only "
                              "usable as administrator ! "
                              "Please install Npcap to workaround !")
            raise
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        # set TTL
        self.ins.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        # Get as much data as possible: reduce what is cropped
        if ipv6:
            # IPV6_HDRINCL is broken. Use IP_HDRINCL even on IPv6
            self.outs.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, 1)
            try:  # Not all Windows versions
                self.ins.setsockopt(socket.IPPROTO_IPV6,
                                    socket.IPV6_RECVTCLASS, 1)
                self.ins.setsockopt(socket.IPPROTO_IPV6,
                                    socket.IPV6_HOPLIMIT, 1)
            except (OSError, socket.error):
                pass
        else:
            # IOCTL Include IP headers
            self.ins.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            try:  # Not Windows XP
                self.ins.setsockopt(socket.IPPROTO_IP,
                                    socket.IP_RECVDSTADDR, 1)
            except (OSError, socket.error):
                pass
            try:  # Windows 10+ recent builds only
                self.ins.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_RECVTTL,  # type: ignore
                    1
                )
            except (OSError, socket.error):
                pass
        # Bind on all ports
        if ipv6:
            from scapy.arch import get_if_addr6
            host = get_if_addr6(self.iface)
        else:
            from scapy.arch import get_if_addr
            host = get_if_addr(self.iface)
        self.ins.bind((host or socket.gethostname(), 0))
        # self.ins.setblocking(False)
        # Set promisc
        if promisc:
            # IOCTL Receive all packets
            self.ins.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def send(self, x):
        # type: (Packet) -> int
        data = raw(x)
        if self.cls not in x:
            raise Scapy_Exception("L3WinSocket can only send IP/IPv6 packets !"
                                  " Install Npcap/Winpcap to send more")
        from scapy.layers.inet import TCP
        if TCP in x:
            raise Scapy_Exception(
                "'TCP data cannot be sent over raw socket': "
                "https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2"  # noqa: E501
            )
        if not self.outs:
            raise Scapy_Exception("Socket not created")
        dst_ip = str(x[self.cls].dst)
        return self.outs.sendto(data, (dst_ip, 0))

    def nonblock_recv(self, x=MTU):
        # type: (int) -> Optional[Packet]
        try:
            return self.recv()
        except IOError:
            return None

    # https://docs.microsoft.com/en-us/windows/desktop/winsock/tcp-ip-raw-sockets-2  # noqa: E501
    # - For IPv4 (address family of AF_INET), an application receives the IP
    # header at the front of each received datagram regardless of the
    # IP_HDRINCL socket option.
    # - For IPv6 (address family of AF_INET6), an application receives
    # everything after the last IPv6 header in each received datagram
    # regardless of the IPV6_HDRINCL socket option. The application does
    # not receive any IPv6 headers using a raw socket.

    def recv_raw(self, x=MTU):
        # type: (int) -> Tuple[Type[Packet], bytes, float]
        try:
            data, address = self.ins.recvfrom(x)
        except io.BlockingIOError:
            return None, None, None  # type: ignore
        if self.ipv6:
            from scapy.layers.inet6 import IPv6
            # AF_INET6 does not return the IPv6 header. Let's build it
            # (host, port, flowinfo, scopeid)
            host, _, flowinfo, _ = address
            # We have to guess what the proto is. Ugly heuristics ahead :(
            # Waiting for https://github.com/python/cpython/issues/80398
            if len(data) > 6 and struct.unpack("!H", data[4:6])[0] == len(data):
                proto = socket.IPPROTO_UDP
            elif data and data[0] in range(128, 138):  # ugh
                proto = socket.IPPROTO_ICMPV6
            else:
                proto = socket.IPPROTO_TCP
            header = raw(
                IPv6(
                    src=host,
                    dst="::",
                    fl=flowinfo,
                    nh=proto or 0xFF,
                    plen=len(data)
                )
            )
            return IPv6, header + data, time.time()
        else:
            from scapy.layers.inet import IP
            return IP, data, time.time()

    def close(self):
        # type: () -> None
        if not self.closed and self.promisc:
            self.ins.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        super(L3WinSocket, self).close()

    @staticmethod
    def select(sockets, remain=None):
        # type: (List[SuperSocket], Optional[float]) -> List[SuperSocket]
        return select_objects(sockets, remain)


class L3WinSocket6(L3WinSocket):
    desc = "a native Layer 3 (IPv6) raw socket under Windows"

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        super(L3WinSocket6, self).__init__(
            ipv6=True,
            **kwargs,
        )
