# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
This file implements the PF_ROUTE API that is used to read the network
configuration of the machine.
"""

import ctypes
import ctypes.util
import socket
import struct

from scapy.consts import BIG_ENDIAN, BSD, NETBSD, OPENBSD, DARWIN
from scapy.config import conf
from scapy.error import log_runtime
from scapy.packet import (
    Packet,
    bind_layers,
)
from scapy.utils import atol
from scapy.utils6 import in6_mask2cidr, in6_getscope

from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FlagsField,
    IP6Field,
    IPField,
    MACField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    FieldListField,
    PadField,
    StrField,
    StrFixedLenField,
    StrLenField,
    XStrLenField,
)
from scapy.pton_ntop import inet_pton

# Typing imports
from typing import (
    Any,
    Dict,
    Optional,
    List,
    Tuple,
    Type,
)

# Missing attributes
if not hasattr(socket, "PF_ROUTE"):
    socket.PF_ROUTE = 17

# ctypes definitions

if BSD:  # Can be imported for testing.
    LIBC = ctypes.cdll.LoadLibrary(ctypes.util.find_library("c"))
    LIBC.sysctl.argtypes = [
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    LIBC.sysctl.restype = ctypes.c_int
else:
    LIBC = None

_bsd_iff_flags = [
    "UP",
    "BROADCAST",
    "DEBUG",
    "LOOPBACK",
    "POINTOPOINT",
    "NEEDSEPOCH",  # UNNUMBERED on NetBSD
    "DRV_RUNNING",
    "NOARP",
    "PROMISC",
    "ALLMULTI",
    "DRV_OACTIVE",
    "SIMPLEX",
    "LINK0",
    "LINK1",
    "LINK2",
    "MULTICAST",
    "CANTCONFIG",
    "PPROMISC",
    "MONITOR",
    "STATICARP",
    "STICKYARP",
    "DYING",
    "RENAMING",
    "SPARE",
    "NETLINK_1",
]

if NETBSD:
    _RTM_TYPE = {
        # man 4 route
        0x01: "RTM_ADD",
        0x02: "RTM_DELETE",
        0x03: "RTM_CHANGE",
        0x04: "RTM_GET",
        0x05: "RTM_LOSING",
        0x06: "RTM_REDIRECT",
        0x07: "RTM_MISS",
        0x08: "RTM_LOCK",
        0x09: "RTM_OLDADD",
        0x0A: "RTM_OLDDEL",
        0x0B: "RTM_RESOLVE",
        0x0C: "RTM_ONEWADDR",
        0x0D: "RTM_ODELADDR",
        0x0E: "RTM_OOIFINFO",
        0x0F: "RTM_OIFINFO",
        0x10: "RTM_IFANNOUNCE",
        0x11: "RTM_IEEE80211",
        0x12: "RTM_SETGATE",
        0x13: "RTM_LLINFO_UPD",
        0x14: "RTM_IFINFO",
        0x15: "RTM_OCHGADDR",
        0x16: "RTM_NEWADDR",
        0x17: "RTM_DELADDR",
        0x18: "RTM_CHGADDR",
    }
elif OPENBSD:
    _RTM_TYPE = {
        # man 4 route
        0x01: "RTM_ADD",
        0x02: "RTM_DELETE",
        0x03: "RTM_CHANGE",
        0x04: "RTM_GET",
        0x05: "RTM_LOSING",
        0x06: "RTM_REDIRECT",
        0x07: "RTM_MISS",
        0x08: "RTM_LOCK",
        0x09: "RTM_OLDADD",
        0x0A: "RTM_OLDDEL",
        0x0B: "RTM_RESOLVE",
        0x0C: "RTM_NEWADDR",
        0x0D: "RTM_DELADDR",
        0x0E: "RTM_IFINFO",
        0x0F: "RTM_IFANNOUNCE",
        0x10: "RTM_DESYNC",
        0x11: "RTM_INVALIDATE",
    }
elif DARWIN:
    _RTM_TYPE = {
        # man 4 route
        0x01: "RTM_ADD",
        0x02: "RTM_DELETE",
        0x03: "RTM_CHANGE",
        0x04: "RTM_GET",
        0x05: "RTM_LOSING",
        0x06: "RTM_REDIRECT",
        0x07: "RTM_MISS",
        0x08: "RTM_LOCK",
        0x09: "RTM_OLDADD",
        0x0A: "RTM_OLDDEL",
        0x0B: "RTM_RESOLVE",
        0x0C: "RTM_NEWADDR",
        0x0D: "RTM_DELADDR",
        0x0E: "RTM_IFINFO",
        0x0F: "RTM_NEWMADDR",
        0x10: "RTM_DELMADDR",
        0x12: "RTM_IFINFO2",
        0x13: "RTM_NEWMADDR2",
        0x14: "RTM_GET2",
    }
else:  # FreeBSD
    _RTM_TYPE = {
        # man 4 route
        0x01: "RTM_ADD",
        0x02: "RTM_DELETE",
        0x03: "RTM_CHANGE",
        0x04: "RTM_GET",
        0x05: "RTM_LOSING",
        0x06: "RTM_REDIRECT",
        0x07: "RTM_MISS",
        0x08: "RTM_LOCK",
        0x09: "RTM_OLDADD",
        0x0A: "RTM_OLDDEL",
        0x0B: "RTM_RESOLVE",
        0x0C: "RTM_NEWADDR",
        0x0D: "RTM_DELADDR",
        0x0E: "RTM_IFINFO",
        0x0F: "RTM_NEWMADDR",
        0x10: "RTM_DELMADDR",
        0x11: "RTM_IFANNOUNCE",
        0x12: "RTM_IEEE80211",
    }

_RTM_ADDRS = {
    0x01: "RTA_DST",
    0x02: "RTA_GATEWAY",
    0x04: "RTA_NETMASK",
    0x08: "RTA_GENMASK",
    0x10: "RTA_IFP",
    0x20: "RTA_IFA",
    0x40: "RTA_AUTHOR",
    0x80: "RTA_BRD",
    0x100: "RTA_SRC",
    0x200: "RTA_SRCMASK",
    0x400: "RTA_LABEL",
    0x800: "RTA_BFD",
    0x1000: "RTA_DNS",
    0x2000: "RTA_STATIC",
    0x4000: "RTA_SEARCH",
}

_RTM_FLAGS = {
    0x01: "RTF_UP",
    0x02: "RTF_GATEWAY",
    0x04: "RTF_HOST",
    0x08: "RTF_REJECT",
    0x10: "RTF_DYNAMIC",
    0x20: "RTF_MODIFIED",
    0x40: "RTF_DONE",
    0x80: "RTF_MASK",  # NetBSD
    0x100: "RTF_CONNECTED",  # NetBSD
    0x200: "RTF_XRESOLVE",
    0x400: "RTF_LLDATA",
    0x800: "RTF_STATIC",
    0x1000: "RTF_BLACKHOLE",
    0x4000: "RTF_PROTO2",
    0x8000: "RTF_PROTO1",
    **(
        {
            0x10000: "RTF_PRCLONING",
            0x20000: "RTF_WASCLONED",
        }
        if DARWIN
        else {
            0x10000: "RTF_SRC",  # NetBSD
            0x20000: "RTF_ANNOUNCE",  # NetBSD
        }
    ),
    0x40000: "RTF_PROTO3",
    0x80000: "RTF_FIXEDMTU",
    0x100000: "RTF_PINNED",
    0x200000: "RTF_LOCAL",
    0x400000: "RTF_BROADCAST",
    0x800000: "RTF_MULTICAST",
    **(
        {
            0x1000000: "RTF_IFSCOPE",
            0x2000000: "RTF_CONDEMNED",
            0x4000000: "RTF_IFREF",
            0x8000000: "RTF_PROXY",
            0x10000000: "RTF_ROUTER",
            0x20000000: "RTF_DEAD",
            0x40000000: "RTF_GLOBAL",
        }
        if DARWIN
        else {
            0x1000000: "RTF_STICKY",
            0x4000000: "RTF_RNH_LOCKED",  # deprecated
            0x8000000: "RTF_GWFLAG_COMPAT",
        }
    ),
}

_IFCAP = {
    0x00000001: "IFCAP_CSUM_IPv4",
    0x00000002: "IFCAP_CSUM_TCPv4",
    0x00000004: "IFCAP_CSUM_UDPv4",
    0x00000010: "IFCAP_VLAN_MTU",
    0x00000020: "IFCAP_VLAN_HWTAGGING",
    0x00000080: "IFCAP_CSUM_TCPv6",
    0x00000100: "IFCAP_CSUM_UDPv6",
    0x00001000: "IFCAP_TSOv4",
    0x00002000: "IFCAP_TSOv6",
    0x00004000: "IFCAP_LRO",
    0x00008000: "IFCAP_WOL",
}

# Common Header


class pfmsghdr(Packet):
    fields_desc = [
        Field("rtm_msglen", 0, fmt="=H"),
        ByteField("rtm_version", 5),
        ByteEnumField("rtm_type", 0, _RTM_TYPE),
    ] + (
        # It begins... the IFs apocalypse
        [Field("rtm_hdrlen", 0, fmt="=H")]
        if OPENBSD
        else []
    )

    if OPENBSD:

        def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
            if self.rtm_msglen < 6:
                return s, b""
            return s[: self.rtm_msglen - 6], s[self.rtm_msglen - 6 :]

    else:

        def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
            if self.rtm_msglen < 4:
                return s, b""
            return s[: self.rtm_msglen - 4], s[self.rtm_msglen - 4 :]


bind_layers(pfmsghdr, conf.raw_layer, rtm_msglen=0)  # padding


# END


class sockaddr(Packet):
    fields_desc = [
        # socket.h
        ByteField("sa_len", 0),
        ByteEnumField("sa_family", 0, socket.AddressFamily),
        # sockaddr_in
        ConditionalField(
            Field("sin_port", 0, fmt="=H"), lambda pkt: pkt.sa_family == socket.AF_INET
        ),
        ConditionalField(
            IPField("sin_addr", 0), lambda pkt: pkt.sa_family == socket.AF_INET
        ),
        ConditionalField(
            StrFixedLenField("sin_zero", "", length=8),
            lambda pkt: pkt.sa_family == socket.AF_INET and pkt.sa_len > 7,
        ),
        # sockaddr_in6
        ConditionalField(
            Field("sin6_port", 0, fmt="=H"),
            lambda pkt: pkt.sa_family == socket.AF_INET6,
        ),
        ConditionalField(
            Field("sin6_flowinfo", 0, fmt="=I"),
            lambda pkt: pkt.sa_family == socket.AF_INET6,
        ),
        ConditionalField(
            IP6Field("sin6_addr", "::"), lambda pkt: pkt.sa_family == socket.AF_INET6
        ),
        ConditionalField(
            Field("sin6_scope_id", 0, fmt="=I"),
            lambda pkt: pkt.sa_family == socket.AF_INET6,
        ),
        # sockaddr_dl
        ConditionalField(
            Field("sdl_index", 0, fmt="=H"), lambda pkt: pkt.sa_family == socket.AF_LINK
        ),
        ConditionalField(
            Field("sdl_type", 0, fmt="=B"), lambda pkt: pkt.sa_family == socket.AF_LINK
        ),
        ConditionalField(
            Field("sdl_nlen", 0, fmt="=B"), lambda pkt: pkt.sa_family == socket.AF_LINK
        ),
        ConditionalField(
            Field("sdl_alen", 0, fmt="=B"), lambda pkt: pkt.sa_family == socket.AF_LINK
        ),
        ConditionalField(
            Field("sdl_slen", 0, fmt="=B"), lambda pkt: pkt.sa_family == socket.AF_LINK
        ),
        ConditionalField(
            StrLenField("sdl_iface", "", length_from=lambda pkt: pkt.sdl_nlen),
            lambda pkt: pkt.sa_family == socket.AF_LINK,
        ),
        ConditionalField(
            MultipleTypeField(
                [(MACField("sdl_addr", None), lambda pkt: pkt.sdl_alen == 6)],
                StrLenField("sdl_addr", "", length_from=lambda pkt: pkt.sdl_alen),
            ),
            lambda pkt: pkt.sa_family == socket.AF_LINK,
        ),
        ConditionalField(
            StrLenField("sdl_sel", "", length_from=lambda pkt: pkt.sdl_slen),
            lambda pkt: pkt.sa_family == socket.AF_LINK,
        ),
        ConditionalField(
            XStrLenField(
                "sdl_data",
                "",
                length_from=lambda pkt: max(
                    pkt.sa_len - pkt.sdl_nlen - pkt.sdl_alen - pkt.sdl_slen - 8, 0
                ),
            ),
            lambda pkt: pkt.sa_family == socket.AF_LINK,
        ),
        ConditionalField(
            XStrLenField("sdl_pad", b"", length_from=lambda pkt: 16 - pkt.sa_len),
            lambda pkt: pkt.sa_len < 16 and pkt.sa_family == socket.AF_LINK,
        ),
        # others
        ConditionalField(
            XStrLenField(
                "sa_data",
                "",
                length_from=lambda pkt: pkt.sa_len - 2 if pkt.sa_len >= 2 else 0,
            ),
            lambda pkt: pkt.sa_family
            not in [
                socket.AF_INET,
                socket.AF_INET6,
                socket.AF_LINK,
            ],
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class SockAddrsField(FieldListField):
    holds_packets = 1

    def __init__(self, name):
        if DARWIN:
            align = 4
        else:
            align = 8
        super(SockAddrsField, self).__init__(
            name,
            [],
            PadField(PacketField("", None, sockaddr), align),
        )


if OPENBSD:

    class if_data(Packet):
        # net/if.h
        fields_desc = [
            ByteField("ifi_type", 0),
            ByteField("ifi_addrlen", 0),
            ByteField("ifi_hdrlen", 0),
            ByteField("ifi_link_state", 0),
            Field("ifi_mtu", 0, fmt="=I"),
            Field("ifi_metric", 0, fmt="=I"),
            Field("ifi_rdomain", 0, fmt="=I"),
            Field("ifi_baudrate", 0, fmt="=Q"),
            Field("ifi_ipackets", 0, fmt="=Q"),
            Field("ifi_ierrors", 0, fmt="=Q"),
            Field("ifi_opackets", 0, fmt="=Q"),
            Field("ifi_oerrors", 0, fmt="=Q"),
            Field("ifi_collision", 0, fmt="=Q"),
            Field("ifi_ibytes", 0, fmt="=Q"),
            Field("ifi_obytes", 0, fmt="=Q"),
            Field("ifi_imcasts", 0, fmt="=Q"),
            Field("ifi_omcasts", 0, fmt="=Q"),
            Field("ifi_iqdrops", 0, fmt="=Q"),
            Field("ifi_oqdrops", 0, fmt="=Q"),
            Field("ifi_noproto", 0, fmt="=Q"),
            FlagsField(
                "ifi_capabilities",
                0,
                32 if BIG_ENDIAN else -32,
                _IFCAP,
            ),
            StrFixedLenField("ifi_lastchange", 0, length=16),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer

elif NETBSD:

    class if_data(Packet):
        # net/if.h
        fields_desc = [
            ByteField("ifi_type", 0),
            ByteField("ifi_addrlen", 0),
            ByteField("ifi_hdrlen", 0),
            Field("ifi_link_state", 0, fmt="=I"),
            Field("ifi_mtu", 0, fmt="=Q"),
            Field("ifi_metric", 0, fmt="=Q"),
            Field("ifi_baudrate", 0, fmt="=Q"),
            Field("ifi_ipackets", 0, fmt="=Q"),
            Field("ifi_ierrors", 0, fmt="=Q"),
            Field("ifi_opackets", 0, fmt="=Q"),
            Field("ifi_oerrors", 0, fmt="=Q"),
            Field("ifi_collision", 0, fmt="=Q"),
            Field("ifi_ibytes", 0, fmt="=Q"),
            Field("ifi_obytes", 0, fmt="=Q"),
            Field("ifi_imcasts", 0, fmt="=Q"),
            Field("ifi_omcasts", 0, fmt="=Q"),
            Field("ifi_iqdrops", 0, fmt="=Q"),
            Field("ifi_noproto", 0, fmt="=Q"),
            StrFixedLenField("ifi_lastchange", 0, length=16),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer

elif DARWIN:

    class if_data(Packet):
        # if_var.h
        fields_desc = [
            ByteField("ifi_type", 0),
            ByteField("ifi_typelen", 0),
            ByteField("ifi_physical", 0),
            ByteField("ifi_addrlen", 0),
            ByteField("ifi_hdrlen", 0),
            ByteField("ifi_recvquota", 0),
            ByteField("ifi_xmitquota", 0),
            ByteField("ifi_unused", 0),
            Field("ifi_mtu", 0, fmt="=I"),
            Field("ifi_metric", 0, fmt="=I"),
            Field("ifi_baudrate", 0, fmt="=I"),
            Field("ifi_ipackets", 0, fmt="=I"),
            Field("ifi_ierrors", 0, fmt="=I"),
            Field("ifi_opackets", 0, fmt="=I"),
            Field("ifi_oerrors", 0, fmt="=I"),
            Field("ifi_collision", 0, fmt="=I"),
            Field("ifi_ibytes", 0, fmt="=I"),
            Field("ifi_obytes", 0, fmt="=I"),
            Field("ifi_imcasts", 0, fmt="=I"),
            Field("ifi_omcasts", 0, fmt="=I"),
            Field("ifi_iqdrops", 0, fmt="=I"),
            Field("ifi_noproto", 0, fmt="=I"),
            Field("ifi_recvtiming", 0, fmt="=I"),
            Field("ifi_xmittiming", 0, fmt="=I"),
            Field("ifi_lastchange", 0, fmt="=Q"),
            Field("ifi_unused2", 0, fmt="=I"),
            Field("ifi_hwassist", 0, fmt="=I"),
            Field("ifi_reserved", 0, fmt="=Q"),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer

else:
    # FreeBSD

    class if_data(Packet):
        # net/if.h
        fields_desc = [
            ByteField("ifi_type", 0),
            ByteField("ifi_physical", 0),
            ByteField("ifi_addrlen", 0),
            ByteField("ifi_hdrlen", 0),
            ByteField("ifi_link_state", 0),
            ByteField("ifi_vhid", 0),
            Field("ifi_datalen", 0, fmt="=H"),
            Field("ifi_mtu", 0, fmt="=I"),
            Field("ifi_metric", 0, fmt="=I"),
            Field("ifi_baudrate", 0, fmt="=Q"),
            Field("ifi_ipackets", 0, fmt="=Q"),
            Field("ifi_ierrors", 0, fmt="=Q"),
            Field("ifi_opackets", 0, fmt="=Q"),
            Field("ifi_oerrors", 0, fmt="=Q"),
            Field("ifi_collision", 0, fmt="=Q"),
            Field("ifi_ibytes", 0, fmt="=Q"),
            Field("ifi_obytes", 0, fmt="=Q"),
            Field("ifi_imcasts", 0, fmt="=Q"),
            Field("ifi_omcasts", 0, fmt="=Q"),
            Field("ifi_iqdrops", 0, fmt="=Q"),
            Field("ifi_oqdrops", 0, fmt="=Q"),
            Field("ifi_noproto", 0, fmt="=Q"),
            Field("ifi_hwassist", 0, fmt="=Q"),
            Field("tt", 0, fmt="=Q"),
            StrFixedLenField("tv", 0, length=16),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer


if OPENBSD:

    class if_msghdr(Packet):
        fields_desc = [
            Field("ifm_index", 0, fmt="=H"),
            Field("ifm_tableid", 0, fmt="=H"),
            Field("_ifm_pad", 0, fmt="=H"),
            FlagsField(
                "ifm_addrs",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_ADDRS,
            ),
            FlagsField(
                "ifm_flags",
                0,
                32 if BIG_ENDIAN else -32,
                _bsd_iff_flags,
            ),
            Field("ifm_xflags", 0, fmt="=I"),
            PadField(
                PacketField("ifm_data", [], if_data),
                8,
            ),
            SockAddrsField("addrs"),
        ]

else:

    class if_msghdr(Packet):
        fields_desc = [
            FlagsField(
                "ifm_addrs",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_ADDRS,
            ),
            FlagsField(
                "ifm_flags",
                0,
                32 if BIG_ENDIAN else -32,
                _bsd_iff_flags,
            ),
            Field("ifm_index", 0, fmt="=H"),
            Field("_ifm_spare1", 0, fmt="=H"),
            PadField(
                PacketField("ifm_data", [], if_data),
                8,
            ),
            SockAddrsField("addrs"),
        ]


bind_layers(pfmsghdr, if_msghdr, rtm_type=0x0E)
if NETBSD:
    bind_layers(pfmsghdr, if_msghdr, rtm_type=0x14)


if OPENBSD:

    class ifa_msghdr(Packet):
        fields_desc = if_msghdr.fields_desc[:5] + [
            Field("ifam_metric", 0, fmt="=I"),
            SockAddrsField("addrs"),
        ]

elif NETBSD:

    class ifa_msghdr(Packet):
        fields_desc = [
            Field("ifm_index", 0, fmt="=H"),
            Field("_rtm_spare1", 0, fmt="=H"),
            FlagsField(
                "ifm_flags",
                0,
                32 if BIG_ENDIAN else -32,
                _bsd_iff_flags,
            ),
            FlagsField(
                "ifm_addrs",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_ADDRS,
            ),
            Field("ifam_pid", 0, fmt="=I"),
            Field("ifam_addrflags", 0, fmt="=I"),
            PadField(
                Field("ifam_metric", 0, fmt="=I"),
                8,
            ),
            SockAddrsField("addrs"),
        ]

else:  # FreeBSD, Darwin

    class ifa_msghdr(Packet):
        fields_desc = if_msghdr.fields_desc[:4] + [
            Field("ifam_metric", 0, fmt="=I"),
            SockAddrsField("addrs"),
        ]


bind_layers(pfmsghdr, ifa_msghdr, rtm_type=0x0C)
bind_layers(pfmsghdr, ifa_msghdr, rtm_type=0x0D)
if NETBSD:
    bind_layers(pfmsghdr, ifa_msghdr, rtm_type=0x16)
    bind_layers(pfmsghdr, ifa_msghdr, rtm_type=0x17)


class ifma_msghdr(Packet):
    fields_desc = if_msghdr.fields_desc[:4]


bind_layers(pfmsghdr, ifma_msghdr, rtm_type=0x0F)
bind_layers(pfmsghdr, ifma_msghdr, rtm_type=0x10)


class if_announcemsghdr(Packet):
    fields_desc = [
        Field("ifan_index", 0, fmt="=H"),
        StrField("ifan_name", ""),
        Field("ifan_what", 0, fmt="=H"),
    ]


bind_layers(pfmsghdr, ifma_msghdr, rtm_type=0x11)


if OPENBSD:

    class rt_metrics(Packet):
        fields_desc = [
            Field("rmx_pksent", 0, fmt="=Q"),
            Field("rmx_expire", 0, fmt="=q"),
            Field("rmx_locks", 0, fmt="=I"),
            Field("rmx_mtu", 0, fmt="=I"),
            Field("rmx_refcnt", 0, fmt="=I"),
            Field("rmx_hopcount", 0, fmt="=I"),
            Field("rmx_recvpipe", 0, fmt="=I"),
            Field("rmx_sendpipe", 0, fmt="=I"),
            Field("rmx_sshthresh", 0, fmt="=I"),
            Field("rmx_rtt", 0, fmt="=I"),
            Field("rmx_rttvar", 0, fmt="=I"),
            Field("rmx_pad", 0, fmt="=I"),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer

elif NETBSD:

    class rt_metrics(Packet):
        fields_desc = [
            Field("rmx_locks", 0, fmt="=Q"),
            Field("rmx_mtu", 0, fmt="=Q"),
            Field("rmx_hopcount", 0, fmt="=Q"),
            Field("rmx_recvpipe", 0, fmt="=Q"),
            Field("rmx_sendpipe", 0, fmt="=Q"),
            Field("rmx_sshthresh", 0, fmt="=Q"),
            Field("rmx_rtt", 0, fmt="=Q"),
            Field("rmx_rttvar", 0, fmt="=Q"),
            Field("rmx_expire", 0, fmt="=Q"),
            Field("rmx_pksent", 0, fmt="=Q"),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer

elif DARWIN:

    class rt_metrics(Packet):
        fields_desc = [
            Field("rmx_locks", 0, fmt="=I"),
            Field("rmx_mtu", 0, fmt="=I"),
            Field("rmx_hopcount", 0, fmt="=I"),
            Field("rmx_expire", 0, fmt="=i"),
            Field("rmx_recvpipe", 0, fmt="=I"),
            Field("rmx_sendpipe", 0, fmt="=I"),
            Field("rmx_sshthresh", 0, fmt="=I"),
            Field("rmx_rtt", 0, fmt="=I"),
            Field("rmx_rttvar", 0, fmt="=I"),
            Field("rmx_pksent", 0, fmt="=I"),
            StrFixedLenField("rmx_filler", b"", length=16),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer

else:

    class rt_metrics(Packet):
        fields_desc = [
            Field("rmx_locks", 0, fmt="=Q"),
            Field("rmx_mtu", 0, fmt="=Q"),
            Field("rmx_hopcount", 0, fmt="=Q"),
            Field("rmx_expire", 0, fmt="=Q"),
            Field("rmx_recvpipe", 0, fmt="=Q"),
            Field("rmx_sendpipe", 0, fmt="=Q"),
            Field("rmx_sshthresh", 0, fmt="=Q"),
            Field("rmx_rtt", 0, fmt="=Q"),
            Field("rmx_rttvar", 0, fmt="=Q"),
            Field("rmx_pksent", 0, fmt="=Q"),
            Field("rmx_weight", 0, fmt="=Q"),
            Field("rmx_nhidx", 0, fmt="=Q"),
            StrFixedLenField("rmx_filler", b"", length=16),
        ]

        def default_payload_class(self, payload: bytes) -> Type[Packet]:
            return conf.padding_layer


if OPENBSD:

    class rt_msghdr(Packet):
        fields_desc = [
            Field("rtm_index", 0, fmt="=H"),
            Field("rtm_tableid", 0, fmt="=H"),
            ByteField("rtm_priority", 0),
            ByteField("rtm_mpls", 0),
            FlagsField(
                "rtm_addrs",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_ADDRS,
            ),
            FlagsField(
                "rtm_flags",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_FLAGS,
            ),
            Field("rtm_fmask", 0, fmt="=I"),
            Field("rtm_pid", 0, fmt="=I"),
            Field("rtm_seq", 0, fmt="=I"),
            Field("rtm_errno", 0, fmt="=I"),
            Field("rtm_inits", 0, fmt="=I"),
            PadField(
                PacketField("rtm_rmx", rt_metrics(), rt_metrics),
                8,
            ),
            SockAddrsField("addrs"),
        ]

elif NETBSD:

    class rt_msghdr(Packet):
        fields_desc = [
            Field("rtm_index", 0, fmt="=H"),
            Field("_rtm_spare1", 0, fmt="=H"),
            FlagsField(
                "rtm_flags",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_FLAGS,
            ),
            FlagsField(
                "rtm_addrs",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_ADDRS,
            ),
            Field("rtm_pid", 0, fmt="=I"),
            Field("rtm_seq", 0, fmt="=I"),
            Field("rtm_errno", 0, fmt="=I"),
            Field("rtm_use", 0, fmt="=I"),
            PadField(
                Field("rtm_inits", 0, fmt="=I"),
                8,
            ),
            PadField(
                PacketField("rtm_rmx", rt_metrics(), rt_metrics),
                8,
            ),
            SockAddrsField("addrs"),
        ]

elif DARWIN:

    class rt_msghdr(Packet):
        # actually rt_msghdr2 (we need parentflags)
        fields_desc = [
            Field("rtm_index", 0, fmt="=H"),
            Field("_rtm_spare1", 0, fmt="=H"),
            FlagsField(
                "rtm_flags",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_FLAGS,
            ),
            FlagsField(
                "rtm_addrs",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_ADDRS,
            ),
            Field("rtm_refcnt", 0, fmt="=I"),
            FlagsField(
                "rtm_parentflags",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_FLAGS,
            ),
            Field("rtm_reserved", 0, fmt="=I"),
            Field("rtm_use", 0, fmt="=I"),
            Field("rtm_inits", 0, fmt="=I"),
            PadField(
                PacketField("rtm_rmx", rt_metrics(), rt_metrics),
                4,
            ),
            SockAddrsField("addrs"),
        ]

else:

    class rt_msghdr(Packet):
        fields_desc = [
            Field("rtm_index", 0, fmt="=H"),
            Field("_rtm_spare1", 0, fmt="=H"),
            FlagsField(
                "rtm_flags",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_FLAGS,
            ),
            FlagsField(
                "rtm_addrs",
                0,
                32 if BIG_ENDIAN else -32,
                _RTM_ADDRS,
            ),
            Field("rtm_pid", 0, fmt="=I"),
            Field("rtm_seq", 0, fmt="=I"),
            Field("rtm_errno", 0, fmt="=I"),
            Field("rtm_fmask", 0, fmt="=I"),
            Field("rtm_inits", 0, fmt="=Q"),
            PadField(
                PacketField("rtm_rmx", rt_metrics(), rt_metrics),
                8,
            ),
            SockAddrsField("addrs"),
        ]


bind_layers(pfmsghdr, rt_msghdr)  # else


class pfmsghdrs(Packet):
    fields_desc = [
        PacketListField(
            "msgs",
            [],
            pfmsghdr,
            # 65535 / len(pfmsghdr)
            max_count=4096,
        ),
    ]


# Utils

CTL_NET = 4
if DARWIN:
    NET_RT_DUMP = 7  # NET_RT_DUMP2
else:
    NET_RT_DUMP = 1
NET_RT_TABLE = 5
if NETBSD:
    NET_RT_IFLIST = 6
else:
    NET_RT_IFLIST = 3


def _sr1_bsdsysctl(mib) -> List[Packet]:
    """
    Send / Receive a BSD sysctl
    """
    # Request routes
    # 1. estimate needed size
    oldplen = ctypes.c_size_t()
    r = LIBC.sysctl(
        mib,
        len(mib),
        None,
        ctypes.byref(oldplen),
        None,
        0,
    )
    if r != 0:
        return None
    # 2. ask for real
    oldp = ctypes.create_string_buffer(oldplen.value)
    r = LIBC.sysctl(
        mib,
        len(mib),
        oldp,
        ctypes.byref(oldplen),
        None,
        0,
    )
    if r != 0:
        return None
    # Parse response
    return pfmsghdrs(bytes(oldp))


def read_routes():
    """
    Read the IPv4 routes using PF_ROUTE
    """
    mib = [
        CTL_NET,
        socket.PF_ROUTE,
        0,
        int(socket.AF_INET),
        NET_RT_DUMP,
        0,
    ]
    if not NETBSD and not DARWIN:
        # NetBSD / OSX is missing the fib
        if OPENBSD:
            fib = 0  # default table
        else:  # FreeBSD
            fib = -1  # means 'all'
        mib.append(fib)
    mib = (ctypes.c_int * len(mib))(*mib)
    resp = _sr1_bsdsysctl(mib)
    if not resp:
        return []
    ifaces = _get_if_list()
    routes = []
    for msg in resp.msgs:
        if msg.rtm_type != 0x4 and (not DARWIN or msg.rtm_type != 0x14):  # RTM_GET(2)
            continue
        # Parse route. addrs contains what addresses are present
        flags = msg.rtm_flags
        if not flags.RTF_UP:
            continue
        if DARWIN and flags.RTF_WASCLONED and msg.rtm_parentflags.RTF_PRCLONING:
            # OSX needs filtering
            continue
        addrs = msg.rtm_addrs
        net = 0
        mask = 0xFFFFFFFF
        gw = 0
        iface = ""
        addr = ""
        metric = 1
        i = 0
        try:
            if addrs.RTA_DST:
                net = atol(msg.addrs[i].sin_addr)
                i += 1
            if addrs.RTA_GATEWAY:
                if msg.addrs[i].sa_family == socket.AF_LINK:
                    gw = "0.0.0.0"
                else:
                    gw = msg.addrs[i].sin_addr or "0.0.0.0"
                i += 1
            if addrs.RTA_NETMASK:
                nm = msg.addrs[i]
                if nm.sa_family == socket.AF_INET:
                    mask = atol(nm.sin_addr)
                elif nm.sa_family in [0x00, 0xFF]:  # NetBSD
                    mask = struct.unpack("<I", nm.sa_data[:4].rjust(4, b"\x00"))[0]
                else:
                    mask = int.from_bytes(nm.sa_data[:4], "big")
                i += 1
            if addrs.RTA_GENMASK:
                i += 1
            if addrs.RTA_IFP:
                iface = msg.addrs[i].sdl_iface.decode(errors="ignore")
                i += 1
            if addrs.RTA_IFA:
                addr = msg.addrs[i].sin_addr
                i += 1
        except Exception:
            log_runtime.debug("Failed to read route %s" % repr(msg))
            continue
        if not iface:
            iface = ifaces[msg.rtm_index]["name"]
        routes.append((net, mask, gw, iface, addr, metric))
    if OPENBSD or DARWIN:
        # OpenBSD and OSX include multicast routes
        return routes
    # Add multicast routes, as those are missing by default
    for _iface in ifaces.values():
        if _iface["flags"].MULTICAST:
            try:
                addr = next(
                    x["address"]
                    for x in _iface["ips"]
                    if x["af_family"] == socket.AF_INET
                )
            except StopIteration:
                continue
            routes.append(
                (0xE0000000, 0xF0000000, "0.0.0.0", _iface["name"], addr, 250)
            )
    return routes


def read_routes6():
    """
    Read the IPv6 routes using PF_ROUTE
    """
    mib = [
        CTL_NET,
        socket.PF_ROUTE,
        0,
        int(socket.AF_INET6),
        NET_RT_DUMP,
        0,
    ]
    if not NETBSD and not DARWIN:
        # NetBSD / OSX is missing the fib
        if OPENBSD:
            fib = 0  # default table
        else:  # FreeBSD
            fib = -1  # means 'all'
        mib.append(fib)
    mib = (ctypes.c_int * len(mib))(*mib)
    resp = _sr1_bsdsysctl(mib)
    if not resp:
        return []
    ifaces = _get_if_list()
    routes = []
    for msg in resp.msgs:
        if msg.rtm_type != 0x4 and (not DARWIN or msg.rtm_type != 0x14):  # RTM_GET(2)
            continue
        # Parse route. addrs contains what addresses are present
        flags = msg.rtm_flags
        if not flags.RTF_UP:
            continue
        if DARWIN and flags.RTF_WASCLONED and msg.rtm_parentflags.RTF_PRCLONING:
            # OSX needs filtering
            continue
        addrs = msg.rtm_addrs
        prefix = "::"
        plen = 128
        nh = "::"
        iface = ""
        metric = 1
        candidates = []
        i = 0
        try:
            if addrs.RTA_DST:
                prefix = msg.addrs[i].sin6_addr
                i += 1
            if addrs.RTA_GATEWAY:
                if msg.addrs[i].sa_family == socket.AF_LINK:
                    nh = "::"
                else:
                    nh = msg.addrs[i].sin6_addr or "::"
                i += 1
            if addrs.RTA_NETMASK:
                nm = msg.addrs[i]
                if nm.sa_family == socket.AF_INET6:
                    plen = in6_mask2cidr(
                        inet_pton(socket.AF_INET6, msg.addrs[i].sin6_addr)
                    )
                elif nm.sa_family in [0xFF, 0x00]:  # NetBSD
                    plen = in6_mask2cidr(
                        # The 6 first octets seem to be garbage. This is weird
                        nm.sa_data[6:].ljust(16, b"\x00")
                    )
                else:
                    plen = int.from_bytes(nm.sa_data, "big")
                i += 1
            if addrs.RTA_GENMASK:
                i += 1
            if addrs.RTA_IFP:
                iface = msg.addrs[i].sdl_iface.decode(errors="ignore")
                i += 1
            if addrs.RTA_IFA:
                candidates.append(msg.addrs[i].sin6_addr)
                i += 1
        except Exception:
            log_runtime.debug("Failed to read route %s" % repr(msg))
            continue
        if not iface:
            iface = ifaces[msg.rtm_index]["name"]
        routes.append((prefix, plen, nh, iface, candidates, metric))
    if OPENBSD or DARWIN:
        # OpenBSD and OSX include multicast routes
        return routes
    # Add multicast routes, as those are missing by default
    for _iface in ifaces.values():
        if _iface["flags"].MULTICAST:
            addrs = [
                x["address"] for x in _iface["ips"] if x["af_family"] == socket.AF_INET6
            ]
            if not addrs:
                continue
            routes.append(("ff00::", 8, "::", _iface["name"], addrs, 250))
    return routes


def _get_if_list():
    # type: () -> Dict[int, Dict[str, Any]]
    """
    Read the interfaces list using a PF_ROUTE socket.
    """
    mib = (ctypes.c_int * 6)(
        CTL_NET,
        socket.PF_ROUTE,
        0,
        int(socket.AF_UNSPEC),
        NET_RT_IFLIST,
        0,
    )
    resp = _sr1_bsdsysctl(mib)
    if not resp:
        return {}
    lifips = {}
    for msg in resp.msgs:
        if msg.rtm_type not in [0x0C, 0x16]:  # RTM_NEWADDR
            continue
        if not msg.ifm_addrs.RTA_IFA:
            continue
        ifindex = msg.ifm_index
        addrindex = (
            msg.ifm_addrs.RTA_DST
            + msg.ifm_addrs.RTA_GATEWAY
            + msg.ifm_addrs.RTA_NETMASK
            + msg.ifm_addrs.RTA_GENMASK
        )
        addr = msg.addrs[addrindex]
        if addr.sa_family not in [socket.AF_INET, socket.AF_INET6]:
            continue
        data = {
            "af_family": addr.sa_family,
            "index": ifindex,
            "address": addr.sin_addr,
        }
        if addr.sa_family == socket.AF_INET:  # ipv4
            data["address"] = addr.sin_addr
        else:  # ipv6
            data.update(
                {
                    "address": addr.sin6_addr,
                    "scope": in6_getscope(addr.sin6_addr),
                }
            )
        lifips.setdefault(ifindex, list()).append(data)
    interfaces = {}
    for msg in resp.msgs:
        if msg.rtm_type != 0xE and (not NETBSD or msg.rtm_type != 0x14):  # RTM_IFINFO
            continue
        ifindex = msg.ifm_index
        ifname = None
        mac = "00:00:00:00:00:00"
        ifflags = msg.ifm_flags
        ips = []
        for addr in msg.addrs:
            if addr.sa_family == socket.AF_LINK:
                ifname = addr.sdl_iface.decode()
                if addr.sdl_addr:
                    mac = addr.sdl_addr
        if ifname is not None:
            if ifindex in lifips:
                ips = lifips[ifindex]
            interfaces[ifindex] = {
                "name": ifname,
                "index": ifindex,
                "flags": ifflags,
                "mac": mac,
                "ips": ips,
            }
    return interfaces
