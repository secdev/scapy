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

from scapy.consts import BIG_ENDIAN
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
    IPField,
    IP6Field,
    MACField,
    MultipleTypeField,
    PacketField,
    PacketListField,
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

# Missing PF_ROUTE
if not hasattr(socket, "PF_ROUTE"):
    socket.PF_ROUTE = 17

# ctypes definitions

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

_bsd_iff_flags = [
    "UP",
    "BROADCAST",
    "DEBUG",
    "LOOPBACK",
    "POINTOPOINT",
    "NEEDSEPOCH",
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

_RTM_ADDRS = {
    0x01: "RTA_DST",
    0x02: "RTA_GATEWAY",
    0x04: "RTA_NETMASK",
    0x08: "RTA_GENMASK",
    0x10: "RTA_IFP",
    0x20: "RTA_IFA",
    0x40: "RTA_AUTHOR",
    0x80: "RTA_BRD",
}

# Common Header


class pfmsghdr(Packet):
    fields_desc = [
        Field("rtm_msglen", None, fmt="=H"),
        ByteField("rtm_version", 5),
        ByteEnumField(
            "rtm_type",
            0,
            {
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
            },
        ),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        pkt += pay
        if self.rtm_msglen is None:
            pkt = struct.pack("=H", len(pkt)) + pkt[2:]
        return pkt

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return s[: self.rtm_msglen - 4], s[self.rtm_msglen - 4 :]


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
            lambda pkt: pkt.sa_family == socket.AF_INET,
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
        ConditionalField(
            Field("sin6_pad", 0, fmt="=I"), lambda pkt: pkt.sa_family == socket.AF_INET6
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
                "sdl_pad",
                "",
                length_from=lambda pkt: pkt.sa_len
                - pkt.sdl_nlen
                - pkt.sdl_alen
                - pkt.sdl_slen
                - 8,
            ),
            lambda pkt: pkt.sa_family == socket.AF_LINK,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


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
        PacketField("ifm_data", [], if_data),
        PacketListField("addrs", [], sockaddr),
    ]


bind_layers(pfmsghdr, if_msghdr, rtm_type=0x0E)


class ifa_msghdr(Packet):
    fields_desc = if_msghdr.fields_desc[:4] + [
        Field("ifam_metric", 0, fmt="=I"),
        PacketListField("addrs", [], sockaddr),
    ]


bind_layers(pfmsghdr, ifa_msghdr, rtm_type=0x0C)
bind_layers(pfmsghdr, ifa_msghdr, rtm_type=0x0D)


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


class rt_msghdr(Packet):
    fields_desc = [
        Field("rtm_index", 0, fmt="=H"),
        Field("_rtm_spare1", 0, fmt="=H"),
        FlagsField(
            "rtm_flags",
            0,
            32 if BIG_ENDIAN else -32,
            {
                0x01: "RTF_UP",
                0x02: "RTF_GATEWAY",
                0x04: "RTF_HOST",
                0x08: "RTF_REJECT",
                0x10: "RTF_DYNAMIC",
                0x20: "RTF_MODIFIED",
                0x40: "RTF_DONE",
                0x80: "RTF_DELCLONE",  # deprecated
                0x100: "RTF_CLONING",  # deprecated
                0x200: "RTF_XRESOLVE",
                0x400: "RTF_LLDATA",
                0x800: "RTF_STATIC",
                0x1000: "RTF_BLACKHOLE",
                0x4000: "RTF_PROTO2",
                0x8000: "RTF_PROTO1",
                0x10000: "RTF_PRCLONING",  # deprecated
                0x20000: "RTF_WASCLONED",  # deprecated
                0x40000: "RTF_PROTO3",
                0x80000: "RTF_FIXEDMTU",
                0x100000: "RTF_PINNED",
                0x200000: "RTF_LOCAL",
                0x400000: "RTF_BROADCAST",
                0x800000: "RTF_MULTICAST",
                0x1000000: "RTF_STICKY",
                0x4000000: "RTF_RNH_LOCKED",  # deprecated
                0x8000000: "RTF_GWFLAG_COMPAT",
            },
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
        PacketField("rtm_rmx", rt_metrics(), rt_metrics),
        PacketListField("addrs", [], sockaddr),
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
NET_RT_DUMP = 1
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
    fib = -1
    mib = (ctypes.c_int * 7)(
        CTL_NET,
        socket.PF_ROUTE,
        0,
        int(socket.AF_INET),
        NET_RT_DUMP,
        0,
        fib,
    )
    resp = _sr1_bsdsysctl(mib)
    if not resp:
        return []
    ifaces = _get_if_list()
    routes = []
    for msg in resp.msgs:
        if msg.rtm_type != 4:
            continue
        # Parse route. addrs contains what addresses are present
        flags = msg.rtm_flags
        if not flags.RTF_UP:
            continue
        addrs = msg.rtm_addrs
        net = 0
        mask = 0xFFFFFFFF
        gw = 0
        iface = ""
        addr = 0
        metric = 1
        i = 0
        try:
            if addrs.RTA_DST:
                net = atol(msg.addrs[i].sin_addr)
                i += 1
            if addrs.RTA_GATEWAY:
                gw = msg.addrs[i].sin_addr or "0.0.0.0"
                i += 1
            if addrs.RTA_NETMASK:
                mask = atol(msg.addrs[i].sin_addr)
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
            log_runtime.debug("Failed to read route %s" % repr(msg.addrs[i]))
            continue
        routes.append((net, mask, gw, iface, addr, metric))
    # Add multicast routes, as those are missing by default
    for _iface in ifaces.values():
        if _iface['flags'].MULTICAST:
            try:
                addr = next(
                    x["address"]
                    for x in _iface["ips"]
                    if x["af_family"] == socket.AF_INET
                )
            except StopIteration:
                continue
            routes.append((
                0xe0000000, 0xf0000000, "0.0.0.0", _iface["name"], addr, 250
            ))
    return routes


def read_routes6():
    """
    Read the IPv6 routes using PF_ROUTE
    """
    fib = -1
    mib = (ctypes.c_int * 7)(
        CTL_NET,
        socket.PF_ROUTE,
        0,
        int(socket.AF_INET6),
        NET_RT_DUMP,
        0,
        fib,
    )
    resp = _sr1_bsdsysctl(mib)
    if not resp:
        return []
    ifaces = _get_if_list()
    routes = []
    for msg in resp.msgs:
        if msg.rtm_type != 4:
            continue
        # Parse route. addrs contains what addresses are present
        flags = msg.rtm_flags
        if not flags.RTF_UP:
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
                nh = msg.addrs[i].sin6_addr or "::"
                i += 1
            if addrs.RTA_NETMASK:
                plen = in6_mask2cidr(inet_pton(socket.AF_INET6, msg.addrs[i].sin6_addr))
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
            log_runtime.debug("Failed to read route %s" % repr(msg.addrs[i]))
            continue
        routes.append((prefix, plen, nh, iface, candidates, metric))
    # Add multicast routes, as those are missing by default
    for _iface in ifaces.values():
        if _iface['flags'].MULTICAST:
            addrs = [
                x["address"]
                for x in _iface["ips"]
                if x["af_family"] == socket.AF_INET6
            ]
            if not addrs:
                continue
            routes.append((
                "ff00::", 8, "::", _iface["name"], addrs, 250
            ))
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
        if msg.rtm_type != 12:  # RTM_NEWADDR
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
        if addr.sa_family not in [2, 28]:
            continue
        data = {
            "af_family": addr.sa_family,
            "index": ifindex,
            "address": addr.sin_addr,
        }
        if addr.sa_family == 2:  # ipv4
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
        if msg.rtm_type != 14:  # RTM_IFINFO
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
