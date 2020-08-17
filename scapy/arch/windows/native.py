# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

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

from scapy.automaton import SelectableObject
from scapy.arch.common import _select_nonblock
from scapy.arch.windows.structures import GetIcmpStatistics
from scapy.compat import raw
from scapy.config import conf
from scapy.data import MTU
from scapy.error import Scapy_Exception, warning
from scapy.supersocket import SuperSocket

# Watch out for import loops (inet...)


class L3WinSocket(SuperSocket, SelectableObject):
    desc = "a native Layer 3 (IPv4) raw socket under Windows"
    nonblocking_socket = True
    __slots__ = ["promisc", "cls", "ipv6", "proto"]

    def __init__(self, iface=None, proto=socket.IPPROTO_IP,
                 ttl=128, ipv6=False, promisc=True, **kwargs):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        for kwarg in kwargs:
            warning("Dropping unsupported option: %s" % kwarg)
        af = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.proto = proto
        if ipv6:
            from scapy.arch import get_if_addr6
            self.host_ip6 = get_if_addr6(conf.iface) or "::1"
            if proto == socket.IPPROTO_IP:
                # We'll restrict ourselves to UDP, as TCP isn't bindable
                # on AF_INET6
                self.proto = socket.IPPROTO_UDP
        # On Windows, with promisc=False, you won't get much
        self.ipv6 = ipv6
        self.cls = IPv6 if ipv6 else IP
        self.promisc = promisc
        # Notes:
        # - IPPROTO_RAW only works to send packets.
        # - IPPROTO_IPV6 exists in MSDN docs, but using it will result in
        # no packets being received. Same for its options (IPV6_HDRINCL...)
        # However, using IPPROTO_IP with AF_INET6 will still receive
        # the IPv6 packets
        try:
            self.ins = socket.socket(af,
                                     socket.SOCK_RAW,
                                     self.proto)
            self.outs = socket.socket(af,
                                      socket.SOCK_RAW,
                                      socket.IPPROTO_RAW)
        except OSError as e:
            if e.errno == 10013:
                raise OSError("Windows native L3 Raw sockets are only "
                              "usable as administrator ! "
                              "Install Winpcap/Npcap to workaround !")
            raise
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
        # IOCTL Include IP headers
        self.ins.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.outs.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # set TTL
        self.ins.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        self.outs.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        # Bind on all ports
        iface = iface or conf.iface
        host = iface.ip if iface.ip else socket.gethostname()
        self.ins.bind((host, 0))
        self.ins.setblocking(False)
        # Get as much data as possible: reduce what is cropped
        if ipv6:
            try:  # Not all Windows versions
                self.ins.setsockopt(socket.IPPROTO_IPV6,
                                    socket.IPV6_RECVTCLASS, 1)
                self.ins.setsockopt(socket.IPPROTO_IPV6,
                                    socket.IPV6_HOPLIMIT, 1)
            except (OSError, socket.error):
                pass
        else:
            try:  # Not Windows XP
                self.ins.setsockopt(socket.IPPROTO_IP,
                                    socket.IP_RECVDSTADDR, 1)
            except (OSError, socket.error):
                pass
            try:  # Windows 10+ recent builds only
                self.ins.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTTL, 1)
            except (OSError, socket.error):
                pass
        if promisc:
            # IOCTL Receive all packets
            self.ins.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def send(self, x):
        data = raw(x)
        if self.cls not in x:
            raise Scapy_Exception("L3WinSocket can only send IP/IPv6 packets !"
                                  " Install Npcap/Winpcap to send more")
        dst_ip = str(x[self.cls].dst)
        self.outs.sendto(data, (dst_ip, 0))

    def nonblock_recv(self, x=MTU):
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
        try:
            data, address = self.ins.recvfrom(x)
        except io.BlockingIOError:
            return None, None, None
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if self.ipv6:
            # AF_INET6 does not return the IPv6 header. Let's build it
            # (host, port, flowinfo, scopeid)
            host, _, flowinfo, _ = address
            header = raw(IPv6(src=host,
                              dst=self.host_ip6,
                              fl=flowinfo,
                              nh=self.proto,  # fixed for AF_INET6
                              plen=len(data)))
            return IPv6, header + data, time.time()
        else:
            return IP, data, time.time()

    def check_recv(self):
        return True

    def close(self):
        if not self.closed and self.promisc:
            self.ins.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        super(L3WinSocket, self).close()

    @staticmethod
    def select(sockets, remain=None):
        return _select_nonblock(sockets, remain=remain)


class L3WinSocket6(L3WinSocket):
    desc = "a native Layer 3 (IPv6) raw socket under Windows"

    def __init__(self, **kwargs):
        super(L3WinSocket6, self).__init__(ipv6=True, **kwargs)


def open_icmp_firewall(host):
    """Temporarily open the ICMP firewall. Tricks Windows into allowing
    ICMP packets for a short period of time (~ 1 minute)"""
    # We call ping with a timeout of 1ms: will return instantly
    with open(os.devnull, 'wb') as DEVNULL:
        return subprocess.Popen("ping -4 -w 1 -n 1 %s" % host,
                                shell=True,
                                stdout=DEVNULL,
                                stderr=DEVNULL).wait()


def get_current_icmp_seq():
    """See help(scapy.arch.windows.native) for more information.
    Returns the current ICMP seq number."""
    return GetIcmpStatistics()['stats']['icmpOutStats']['dwEchos']
