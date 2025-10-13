# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Michael Farrell <micolous+git@gmail.com>

"""
Implementation of TUN/TAP interfaces.

These allow Scapy to act as the remote side of a virtual network interface.
"""

import socket
import time
from fcntl import ioctl

from scapy.compat import bytes_encode, raw
from scapy.config import conf
from scapy.consts import BIG_ENDIAN, BSD, DARWIN, LINUX
from scapy.data import ETHER_TYPES, MTU
from scapy.error import log_runtime, warning
from scapy.fields import (
    BitField,
    Field,
    FlagsField,
    IntField,
    StrFixedLenField,
    XShortEnumField,
)
from scapy.interfaces import network_name
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IPv46
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.supersocket import SimpleSocket

# Linux-specific defines (/usr/include/linux/if_tun.h)
LINUX_TUNSETIFF = 0x400454ca
LINUX_IFF_TUN = 0x0001
LINUX_IFF_TAP = 0x0002
LINUX_IFF_NO_PI = 0x1000
LINUX_IFNAMSIZ = 16

# Darwin-specific defines (net/if_utun.h and sys/kern_control.h)
DARWIN_CTLIOCGINFO = 0xc0644e03
DARWIN_UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
DARWIN_MAX_KCTL_NAME = 96


class NativeShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "@H")


class TunPacketInfo(Packet):
    aliastypes = [Ether]


class LinuxTunIfReq(Packet):
    """
    Structure to request a specific device name for a tun/tap
    Linux  ``struct ifreq``.

    See linux/if.h (struct ifreq) and tuntap.txt for reference.
    """
    fields_desc = [
        # union ifr_ifrn
        StrFixedLenField("ifrn_name", b"", 16),
        # union ifr_ifru
        NativeShortField("ifru_flags", 0),
    ]


class DarwinUtunIfReq(Packet):
    """
    Structure for issuing Darwin ioctl commands (``struct ctl_info``).

    See net/if_utun.h and sys/kern_control.h for reference.
    """
    fields_desc = [
        BitField("ctl_id", 0, -32),
        StrFixedLenField("ctl_name", DARWIN_UTUN_CONTROL_NAME, DARWIN_MAX_KCTL_NAME)
    ]


class LinuxTunPacketInfo(TunPacketInfo):
    """
    Base for TUN packets.

    See linux/if_tun.h (struct tun_pi) for reference.
    """
    fields_desc = [
        # This is native byte order
        FlagsField("flags", 0,
                   (lambda _: 16 if BIG_ENDIAN else -16),
                   ["TUN_VNET_HDR"] +
                   ["reserved%d" % x for x in range(1, 16)]),
        # This is always network byte order
        XShortEnumField("type", 0x9000, ETHER_TYPES),
    ]


class DarwinUtunPacketInfo(Packet):
    fields_desc = [
        IntField("addr_family", socket.AF_INET)
    ]


class TunTapInterface(SimpleSocket):
    """
    A socket to act as the host's peer of a tun / tap interface.

    This implements kernel interfaces for tun and tap devices.

    :param iface: The name of the interface to use, eg: 'tun0'
    :param mode_tun: If True, create as TUN interface (layer 3).
                     If False, creates a TAP interface (layer 2).
                     If not supplied, attempts to detect from the ``iface``
                     name.
    :type mode_tun: bool
    :param strip_packet_info: If True (default), strips any TunPacketInfo from
                              the packet. If False, leaves it in tact. Some
                              operating systems and tunnel types don't include
                              this sort of data.
    :type strip_packet_info: bool

    FreeBSD references:

    * tap(4): https://www.freebsd.org/cgi/man.cgi?query=tap&sektion=4
    * tun(4): https://www.freebsd.org/cgi/man.cgi?query=tun&sektion=4

    Linux references:

    * https://www.kernel.org/doc/Documentation/networking/tuntap.txt

    """
    desc = "Act as the host's peer of a tun / tap interface"

    def __init__(self, iface=None, mode_tun=None, default_read_size=MTU,
                 strip_packet_info=True, *args, **kwargs):
        self.iface = bytes_encode(
            network_name(conf.iface) if iface is None else iface
        )

        self.mode_tun = mode_tun
        if self.mode_tun is None:
            if self.iface.startswith(b"tun") or self.iface.startswith(b"utun"):
                self.mode_tun = True
            elif self.iface.startswith(b"tap"):
                self.mode_tun = False
            else:
                raise ValueError(
                    "Could not determine interface type for %r; set "
                    "`mode_tun` explicitly." % (self.iface,))

        self.strip_packet_info = bool(strip_packet_info)

        # This is non-zero when there is some kernel-specific packet info.
        # We add this to any MTU value passed to recv(), and use it to
        # remove leading bytes when strip_packet_info=True.
        self.mtu_overhead = 0

        # The TUN packet specification sends raw IP at us, and doesn't specify
        # which version.
        self.kernel_packet_class = IPv46 if self.mode_tun else Ether

        if LINUX:
            devname = b"/dev/net/tun"

            # Having an EtherType always helps on Linux, then we don't need
            # to use auto-detection of IP version.
            if self.mode_tun:
                self.kernel_packet_class = LinuxTunPacketInfo
                self.mtu_overhead = 4  # len(LinuxTunPacketInfo)
            else:
                warning("tap devices on Linux do not include packet info!")
                self.strip_packet_info = True

            if len(self.iface) > LINUX_IFNAMSIZ:
                warning("Linux interface names are limited to %d bytes, "
                        "truncating!" % (LINUX_IFNAMSIZ,))
                self.iface = self.iface[:LINUX_IFNAMSIZ]
            sock = open(devname, "r+b", buffering=0)
        elif BSD:  # also DARWIN
            if self.iface.startswith(b"utun"):  # allowed for Darwin
                if not DARWIN:
                    raise ValueError('`utun` iface prefix is only allowed for Darwin')
                self.kernel_packet_class = DarwinUtunPacketInfo
                self.mtu_overhead = 4
                interface_num = int(self.iface[4:])

                utun_socket = socket.socket(
                    socket.PF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
                ctl_info = ioctl(utun_socket, DARWIN_CTLIOCGINFO,
                                 raw(DarwinUtunIfReq()))
                utun_socket.connect(
                    (DarwinUtunIfReq(ctl_info).getfieldval("ctl_id"), interface_num + 1)
                )

                sock = utun_socket.makefile(mode="rwb", buffering=0)
            elif self.iface.startswith(b"tap") or self.iface.startswith(b"tun"):
                devname = b"/dev/" + self.iface
                if not self.strip_packet_info:
                    warning("tun/tap devices on BSD and Darwin never include "
                            "packet info!")
                    self.strip_packet_info = True
                sock = open(devname, "r+b", buffering=0)
            else:
                raise ValueError("Interface names must start with `tun` or "
                                 "`tap` on BSD and Darwin or `utun` on Darwin")
        else:
            raise NotImplementedError("TunTapInterface is not supported on "
                                      "this platform!")

        if LINUX:
            if self.mode_tun:
                flags = LINUX_IFF_TUN
            else:
                # Linux can send us LinuxTunPacketInfo for TAP interfaces, but
                # the kernel sends the wrong information!
                #
                # Instead of type=1 (Ether), it sends that of the payload
                # (eg: 0x800 for IPv4 or 0x86dd for IPv6).
                #
                # tap interfaces always send Ether frames, which include a
                # type parameter for the IPv4/v6/etc. payload, so we set
                # IFF_NO_PI.
                flags = LINUX_IFF_TAP | LINUX_IFF_NO_PI

            tsetiff = raw(LinuxTunIfReq(
                ifrn_name=self.iface,
                ifru_flags=flags))

            ioctl(sock, LINUX_TUNSETIFF, tsetiff)

        self.closed = False
        self.default_read_size = default_read_size
        super(TunTapInterface, self).__init__(sock)

    def __call__(self, *arg, **karg):
        """Needed when using an instantiated TunTapInterface object for
        conf.L2listen, conf.L2socket or conf.L3socket.

        """
        return self

    def recv_raw(self, x=None):
        if x is None:
            x = self.default_read_size

        x += self.mtu_overhead

        dat = self.ins.read(x)
        r = self.kernel_packet_class, dat, time.time()
        if self.mtu_overhead > 0 and self.strip_packet_info:
            # Get the packed class of the payload, without triggering a full
            # decode of the payload data.
            cls = r[0](r[1][:self.mtu_overhead]).guess_payload_class(b'')

            # Return the payload data only
            return cls, r[1][self.mtu_overhead:], r[2]
        else:
            return r

    def send(self, x):
        # type: (Packet) -> int
        if hasattr(x, "sent_time"):
            x.sent_time = time.time()

        if self.kernel_packet_class == IPv46:
            # IPv46 is an auto-detection wrapper; we should just push through
            # packets normally if we got IP or IPv6.
            if not isinstance(x, (IP, IPv6)):
                x = IP() / x
        elif not isinstance(x, self.kernel_packet_class):
            x = self.kernel_packet_class() / x

        sx = raw(x)

        try:
            r = self.outs.write(sx)
            self.outs.flush()
            return r
        except socket.error:
            log_runtime.error("%s send",
                              self.__class__.__name__, exc_info=True)


# Bindings #
bind_layers(DarwinUtunPacketInfo, IP, addr_family=socket.AF_INET)
bind_layers(DarwinUtunPacketInfo, IPv6, addr_family=socket.AF_INET6)
