# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Native Microsoft Windows sockets (L3 only)

## Notice: ICMP packets

DISCLAIMER: Please use Npcap/Winpcap to send/receive ICMP. It is going to work.
Below is some additional information, mainly implemented in a testing purpose.

When in native mode, everything goes through the Windows kernel.
This firstly requires that the Firewall is open. Be sure it allows ICMPv4/6
packets in and out.
Windows may drop packets that it finds wrong. for instance, answers to
ICMP packets with id=0 or seq=0 may be dropped. It means that sent packets
should (most of the time) be perfectly built.

A perfectly built ICMP req packet on Windows means that its id is 1, its
checksum (IP and ICMP) are correctly built, but also that its seq number is
in the "allowed range".
    In fact, every time an ICMP packet is sent on Windows, a global sequence
number is increased, which is only reset at boot time. The seq number of the
received ICMP packet must be in the range [current, current + 3] to be valid,
and received by the socket. The current number is quite hard to get, thus we
provide in this module the get_actual_icmp_seq() function.

Example:
    >>> conf.use_pcap = False
    >>> a = conf.L3socket()
    # This will (most likely) work:
    >>> current = get_current_icmp_seq()
    >>> a.sr(IP(dst="www.google.com", ttl=128)/ICMP(id=1, seq=current))
    # This won't:
    >>> a.sr(IP(dst="www.google.com", ttl=128)/ICMP())

PS: on computers where the firewall isn't open, Windows temporarily opens it
when using the `ping` util from cmd.exe. One can first call a ping on cmd,
then do custom calls through the socket using get_current_icmp_seq(). See
the tests (windows.uts) for an example.
"""
import io
import os
import socket
import subprocess
import time

from scapy.automaton import select_objects
from scapy.arch.windows.structures import GetIcmpStatistics
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
    desc = "a native Layer 3 (IPv4) raw socket under Windows"
    nonblocking_socket = True
    __selectable_force_select__ = True  # see automaton.py
    __slots__ = ["promisc", "cls", "ipv6", "proto"]

    def __init__(self,
                 iface=None,  # type: Optional[_GlobInterfaceType]
                 proto=None,  # type: Optional[int]
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
        af = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.ipv6 = ipv6
        # Proto and cls
        if proto is None:
            if self.ipv6:
                # On IPv6, the header isn't returned with recvfrom().
                # We don't want to guess if it's TCP, UDP or SCTP.. so ask for proto
                # (This would be fixable if Python supported recvmsg() on Windows)
                log_runtime.warning(
                    "Due to restrictions, 'proto' must be provided when "
                    "opening raw IPv6 sockets. Defaulting to socket.IPPROTO_UDP"
                )
                self.proto = socket.IPPROTO_UDP
            else:
                self.proto = socket.IPPROTO_IP
        elif self.ipv6 and proto == socket.IPPROTO_TCP:
            # Ah, sadly this isn't supported either.
            log_runtime.warning(
                "Be careful, socket.IPPROTO_TCP doesn't work in raw sockets on "
                "Windows, so this is equivalent to socket.IPPROTO_IP."
            )
            self.proto = socket.IPPROTO_IP
        else:
            self.proto = proto
        self.cls = IPv6 if ipv6 else IP
        # Promisc
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        # Notes:
        # - IPPROTO_RAW only works to send packets.
        # - IPPROTO_IPV6 exists in MSDN docs, but using it will result in
        # no packets being received. Same for its options (IPV6_HDRINCL...)
        # However, using IPPROTO_IP with AF_INET6 will still receive
        # the IPv6 packets
        try:
            # Listening on AF_INET6 IPPROTO_IPV6 is broken. Use IPPROTO_IP
            self.ins = socket.socket(af,
                                     socket.SOCK_RAW,
                                     socket.IPPROTO_IP)
            self.outs = socket.socket(af,
                                      socket.SOCK_RAW,
                                      socket.IPPROTO_RAW)
        except OSError as e:
            if e.errno == 13:
                raise OSError("Windows native L3 Raw sockets are only "
                              "usable as administrator ! "
                              "Please install Npcap to workaround !")
            raise
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        # set TTL
        self.ins.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        self.outs.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
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
            self.outs.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
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
            header = raw(
                IPv6(
                    src=host,
                    dst="::",
                    fl=flowinfo,
                    # when IPPROTO_IP (0) is selected, we have no idea what's nh,
                    # so set an invalid value.
                    nh=self.proto or 0xFF,
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


def open_icmp_firewall(host):
    # type: (str) -> int
    """Temporarily open the ICMP firewall. Tricks Windows into allowing
    ICMP packets for a short period of time (~ 1 minute)"""
    # We call ping with a timeout of 1ms: will return instantly
    with open(os.devnull, 'wb') as DEVNULL:
        return subprocess.Popen("ping -4 -w 1 -n 1 %s" % host,
                                shell=True,
                                stdout=DEVNULL,
                                stderr=DEVNULL).wait()


def get_current_icmp_seq():
    # type: () -> int
    """See help(scapy.arch.windows.native) for more information.
    Returns the current ICMP seq number."""
    return GetIcmpStatistics()['stats']['icmpOutStats']['dwEchos']
