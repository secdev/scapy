# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
This file implements the rtnetlink API that is used to read the network
configuration of the machine.
"""

import socket
import struct
import time

import scapy.utils6

from scapy.consts import BIG_ENDIAN
from scapy.config import conf
from scapy.error import log_loading
from scapy.packet import (
    Packet,
    bind_layers,
)
from scapy.utils import atol, itom

from scapy.fields import (
    ByteEnumField,
    ByteField,
    EnumField,
    Field,
    FieldLenField,
    FlagsField,
    IP6Field,
    IPField,
    LenField,
    MACField,
    MayEnd,
    MultipleTypeField,
    PacketListField,
    PadField,
    StrLenField,
    XStrLenField,
)

from scapy.arch.common import _iff_flags

# Typing imports
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
)

# from <linux/netlink.h> and <linux/rtnetlink.h>


# Common header


class rtmsghdr(Packet):
    fields_desc = [
        LenField("nlmsg_len", None, fmt="=L"),
        EnumField(
            "nlmsg_type",
            0,
            {
                # netlink.h
                3: "NLMSG_DONE",
                # rtnetlink.h
                16: "RTM_NEWLINK",
                17: "RTM_DELLINK",
                18: "RTM_GETLINK",
                19: "RTM_SETLINK",
                20: "RTM_NEWADDR",
                21: "RTM_DELADDR",
                22: "RTM_GETADDR",
                # 23: unused
                24: "RTM_NEWROUTE",
                25: "RTM_DELROUTE",
                26: "RTM_GETROUTE",
                # 27: unused
            },
            fmt="=H",
        ),
        FlagsField(
            "nlmsg_flags",
            0,
            16 if BIG_ENDIAN else -16,
            {
                0x01: "NLM_F_REQUEST",
                0x02: "NLM_F_MULTI",
                0x04: "NLM_F_ACK",
                0x08: "NLM_F_ECHO",
                0x10: "NLM_F_DUMP_INTR",
                0x20: "NLM_F_DUMP_FILTERED",
                # GET modifiers
                0x100: "NLM_F_ROOT",
                0x200: "NLM_F_MATCH",
                0x400: "NLM_F_ATOMIC",
            },
        ),
        Field("nlmsg_seq", 0, fmt="=L"),
        Field("nlmsg_pid", 0, fmt="=L"),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        pkt += pay
        if self.nlmsg_len is None:
            pkt = struct.pack("=L", len(pkt)) + pkt[4:]
        return pkt

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return s[: self.nlmsg_len - 16], s[self.nlmsg_len - 16 :]

    def answers(self, other: Packet) -> bool:
        return bool(other.nlmsg_seq == self.nlmsg_seq)


# DONE


class nlmsgerr_rtattr(Packet):
    fields_desc = [
        FieldLenField(
            "rta_len", None, length_of="rta_data", fmt="=H", adjust=lambda _, x: x + 4
        ),
        EnumField(
            "rta_type",
            0,
            {},
            fmt="=H",
        ),
        PadField(
            MultipleTypeField(
                [],
                StrLenField(
                    "rta_data",
                    b"",
                    length_from=lambda pkt: pkt.rta_len - 4,
                ),
            ),
            align=4,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class nlmsgerr(Packet):
    fields_desc = [
        MayEnd(Field("status", 0, fmt="=L")),
        # Pay
        PacketListField("data", [], nlmsgerr_rtattr),
    ]


bind_layers(rtmsghdr, nlmsgerr, nlmsg_type=3)


# LINK messages


class ifla_af_spec_inet_rtattr(Packet):
    fields_desc = [
        FieldLenField(
            "rta_len", None, length_of="rta_data", fmt="=H", adjust=lambda _, x: x + 4
        ),
        EnumField(
            "rta_type",
            0,
            {
                0x00: "IFLA_INET_UNSPEC",
                0x01: "IFLA_INET_CONF",
            },
            fmt="=H",
        ),
        PadField(
            MultipleTypeField(
                [],
                XStrLenField(
                    "rta_data",
                    b"",
                    length_from=lambda pkt: pkt.rta_len - 4,
                ),
            ),
            align=4,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class ifla_af_spec_inet6_rtattr(Packet):
    fields_desc = [
        FieldLenField(
            "rta_len", None, length_of="rta_data", fmt="=H", adjust=lambda _, x: x + 4
        ),
        EnumField(
            "rta_type",
            0,
            {
                0x00: "IFLA_INET6_UNSPEC",
                0x01: "IFLA_INET6_FLAGS",
                0x02: "IFLA_INET6_CONF",
                0x03: "IFLA_INET6_STATS",
                0x04: "IFLA_INET6_MCAST",
                0x05: "IFLA_INET6_CACHEINFO",
                0x06: "IFLA_INET6_ICMP6STATS",
                0x07: "IFLA_INET6_TOKEN",
                0x08: "IFLA_INET6_ADDR_GEN_MODE",
                0x09: "IFLA_INET6_RA_MTU",
            },
            fmt="=H",
        ),
        PadField(
            MultipleTypeField(
                [],
                XStrLenField(
                    "rta_data",
                    b"",
                    length_from=lambda pkt: pkt.rta_len - 4,
                ),
            ),
            align=4,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class ifla_af_spec_rtattr(Packet):
    fields_desc = [
        FieldLenField(
            "rta_len", None, length_of="rta_data", fmt="=H", adjust=lambda _, x: x + 4
        ),
        EnumField("rta_type", 0, socket.AddressFamily, fmt="=H"),
        PadField(
            MultipleTypeField(
                [
                    (
                        # AF_INET
                        PacketListField(
                            "rta_data",
                            [],
                            ifla_af_spec_inet_rtattr,
                            length_from=lambda pkt: pkt.rta_len - 4,
                        ),
                        lambda pkt: pkt.rta_type == 2,
                    ),
                    (
                        # AF_INET6
                        PacketListField(
                            "rta_data",
                            [],
                            ifla_af_spec_inet6_rtattr,
                            length_from=lambda pkt: pkt.rta_len - 4,
                        ),
                        lambda pkt: pkt.rta_type == 10,
                    ),
                ],
                XStrLenField(
                    "rta_data",
                    b"",
                    length_from=lambda pkt: pkt.rta_len - 4,
                ),
            ),
            align=4,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class ifinfomsg_rtattr(Packet):
    fields_desc = [
        FieldLenField(
            "rta_len", None, length_of="rta_data", fmt="=H", adjust=lambda _, x: x + 4
        ),
        EnumField(
            "rta_type",
            0,
            {
                0x00: "IFLA_UNSPEC",
                0x01: "IFLA_ADDRESS",
                0x02: "IFLA_BROADCAST",
                0x03: "IFLA_IFNAME",
                0x04: "IFLA_MTU",
                0x05: "IFLA_LINK",
                0x06: "IFLA_QDISC",
                0x07: "IFLA_STATS",
                0x08: "IFLA_COST",
                0x09: "IFLA_PRIORITY",
                0x0A: "IFLA_MASTER",
                0x0B: "IFLA_WIRELESS",
                0x0C: "IFLA_PROTINFO",
                0x0D: "IFLA_TXQLEN",
                0x0E: "IFLA_MAP",
                0x0F: "IFLA_WEIGHT",
                0x10: "IFLA_OPERSTATE",
                0x11: "IFLA_LINKMODE",
                0x12: "IFLA_LINKINFO",
                0x13: "IFLA_NET_NS_PID",
                0x14: "IFLA_IFALIAS",
                0x15: "IFLA_NUM_VS",
                0x16: "IFLA_VFINFO_LIST",
                0x17: "IFLA_STATS64",
                0x18: "IFLA_VF_PORTS",
                0x19: "IFLA_PORT_SELF",
                0x1A: "IFLA_AF_SPEC",
                0x1B: "IFLA_GROUP",
                0x1C: "IFLA_NET_NS_FD",
                0x1D: "IFLA_EXT_MASK",
                0x1E: "IFLA_PROMISCUITY",
                0x1F: "IFLA_NUM_TX_QUEUES",
                0x20: "IFLA_NUM_RX_QUEUES",
                0x21: "IFLA_CARRIER",
                0x22: "IFLA_PHYS_PORT_ID",
                0x23: "IFLA_CARRIER_CHANGES",
                0x24: "IFLA_PHYS_SWITCH_ID",
                0x25: "IFLA_LINK_NETNSID",
                0x26: "IFLA_PHYS_PORT_NAME",
                0x27: "IFLA_PROTO_DOWN",
                0x28: "IFLA_GSO_MAX_SEGS",
                0x29: "IFLA_GSO_MAX_SIZE",
                0x2A: "IFLA_PAD",
                0x2B: "IFLA_XDP",
                0x2C: "IFLA_EVENT",
                0x2D: "IFLA_NEW_NETNSID",
                0x2E: "IFLA_IF_NETNSID",
                0x2F: "IFLA_CARRIER_UP_COUNT",
                0x30: "IFLA_CARRIER_DOWN_COUNT",
                0x31: "IFLA_NEW_IFINDEX",
                0x32: "IFLA_MIN_MTU",
                0x33: "IFLA_MAX_MTU",
                0x34: "IFLA_PROP_LIST",
                0x35: "IFLA_ALT_IFNAME",
                0x36: "IFLA_PERM_ADDRESS",
                0x37: "IFLA_PROTO_DOWN_REASON",
                0x38: "IFLA_PARENT_DEV_NAME",
                0x39: "IFLA_PARENT_DEV_BUS_NAME",
                0x3A: "IFLA_GRO_MAX_SIZE",
                0x3B: "IFLA_TSO_MAX_SIZE",
                0x3C: "IFLA_TSO_MAX_SEGS",
                0x3D: "IFLA_ALLMULTI",
            },
            fmt="=H",
        ),
        PadField(
            MultipleTypeField(
                [
                    (
                        # IFLA_ADDRESS
                        MACField("rta_data", "00:00:00:00:00:00"),
                        lambda pkt: pkt.rta_type in [0x01, 0x36],
                    ),
                    (
                        # IFLA_IFNAME
                        StrLenField(
                            "rta_data", b"", length_from=lambda pkt: pkt.rta_len - 4
                        ),
                        lambda pkt: pkt.rta_type in [0x03],
                    ),
                    (
                        # IFLA_AF_SPEC
                        PacketListField(
                            "rta_data",
                            [],
                            ifla_af_spec_rtattr,
                            length_from=lambda pkt: pkt.rta_len - 4,
                        ),
                        lambda pkt: pkt.rta_type == 0x1A,
                    ),
                ],
                XStrLenField(
                    "rta_data",
                    b"",
                    length_from=lambda pkt: pkt.rta_len - 4,
                ),
            ),
            align=4,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class ifinfomsg(Packet):
    fields_desc = [
        ByteEnumField("ifi_family", 0, socket.AddressFamily),  # type: ignore
        ByteField("res", 0),
        Field("ifi_type", 0, fmt="=H"),
        Field("ifi_index", 0, fmt="=i"),
        FlagsField(
            "ifi_flags",
            0,
            32 if BIG_ENDIAN else -32,
            _iff_flags,
        ),
        Field("ifi_change", 0, fmt="=I"),
        # Pay
        PacketListField("data", [], ifinfomsg_rtattr),
    ]


bind_layers(rtmsghdr, ifinfomsg, nlmsg_type=16)
bind_layers(rtmsghdr, ifinfomsg, nlmsg_type=17)
bind_layers(rtmsghdr, ifinfomsg, nlmsg_type=18)
bind_layers(rtmsghdr, ifinfomsg, nlmsg_type=19)


# ADDR messages


class ifaddrmsg_rtattr(Packet):
    fields_desc = [
        FieldLenField(
            "rta_len", None, length_of="rta_data", fmt="=H", adjust=lambda _, x: x + 4
        ),
        EnumField(
            "rta_type",
            0,
            {
                0x00: "IFA_UNSPEC",
                0x01: "IFA_ADDRESS",
                0x02: "IFA_LOCAL",
                0x03: "IFA_LABEL",
                0x04: "IFA_BROADCAST",
                0x05: "IFA_ANYCAST",
                0x06: "IFA_CACHEINFO",
                0x07: "IFA_MULTICAST",
                0x08: "IFA_FLAGS",
                0x09: "IFA_RT_PRIORITY",
                0x0A: "IFA_TARGET_NETNSID",
                0x0B: "IFA_PROTO",
            },
            fmt="=H",
        ),
        PadField(
            MultipleTypeField(
                [
                    # IFA_ADDRESS, IFA_LOCAL, IFA_BROADCAST
                    (
                        IPField("rta_data", "0.0.0.0"),
                        lambda pkt: pkt.parent
                        and pkt.parent.ifa_family == 2
                        and pkt.rta_type in [0x01, 0x02, 0x04],
                    ),
                    (
                        IP6Field("rta_data", "::"),
                        lambda pkt: pkt.parent
                        and pkt.parent.ifa_family == 10
                        and pkt.rta_type in [0x01, 0x02, 0x04],
                    ),
                    (
                        # IFA_LABEL
                        StrLenField(
                            "rta_data", b"", length_from=lambda pkt: pkt.rta_len - 4
                        ),
                        lambda pkt: pkt.rta_type in [0x03],
                    ),
                ],
                XStrLenField(
                    "rta_data",
                    b"",
                    length_from=lambda pkt: pkt.rta_len - 4,
                ),
            ),
            align=4,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class ifaddrmsg(Packet):
    fields_desc = [
        ByteEnumField("ifa_family", 0, socket.AddressFamily),  # type: ignore
        ByteField("ifa_prefixlen", 0),
        FlagsField(
            "ifa_flags",
            0,
            -8,
            {
                0x01: "IFA_F_SECONDARY",
                0x02: "IFA_F_NODAD",
                0x04: "IFA_F_OPTIMISTIC",
                0x08: "IFA_F_DADFAILED",
                0x10: "IFA_F_HOMEADDRESS",
                0x20: "IFA_F_DEPRECATED",
                0x40: "IFA_F_TENTATIVE",
                0x80: "IFA_F_PERMANENT",
            },
        ),
        ByteField("ifa_scope", 0),
        Field("ifa_index", 0, fmt="=L"),
        # Pay
        PacketListField("data", [], ifaddrmsg_rtattr),
    ]


bind_layers(rtmsghdr, ifaddrmsg, nlmsg_type=20)
bind_layers(rtmsghdr, ifaddrmsg, nlmsg_type=21)
bind_layers(rtmsghdr, ifaddrmsg, nlmsg_type=22)


# ROUTE messages


RT_CLASS = {
    0: "RT_TABLE_UNSPEC",
    252: "RT_TABLE_COMPAT",
    253: "RT_TABLE_DEFAULT",
    254: "RT_TABLE_MAIN",
    255: "RT_TABLE_LOCAL",
}


class rtmsg_rtattr(Packet):
    fields_desc = [
        FieldLenField(
            "rta_len", None, length_of="rta_data", fmt="=H", adjust=lambda _, x: x + 4
        ),
        EnumField(
            "rta_type",
            0,
            {
                0x00: "RTA_UNSPEC",
                0x01: "RTA_DST",
                0x02: "RTS_SRC",
                0x03: "RTS_IIF",
                0x04: "RTS_OIF",
                0x05: "RTA_GATEWAY",
                0x06: "RTA_PRIORITY",
                0x07: "RTA_PREFSRC",
                0x08: "RTA_METRICS",
                0x09: "RTA_MULTIPATH",
                0x0B: "RTA_FLOW",
                0x0C: "RTA_CACHEINFO",
                0x0F: "RTA_TABLE",
                0x10: "RTA_MARK",
                0x11: "RTA_MFC_STATS",
                0x12: "RTA_VIA",
                0x13: "RTA_NEWDST",
                0x14: "RTA_PREF",
                0x15: "RTA_ENCAP_TYPE",
                0x16: "RTA_ENCAP",
                0x17: "RTA_EXPIRES",
                0x18: "RTA_PAD",
                0x19: "RTA_UID",
                0x1A: "RTA_TTL_PROPAGATE",
                0x1B: "RTA_IP_PROTO",
                0x1C: "RTA_SPORT",
                0x1D: "RTA_DPORT",
                0x1E: "RTA_NH_ID",
            },
            fmt="=H",
        ),
        PadField(
            MultipleTypeField(
                [
                    # RTA_DST, RTA_SRC, RTA_PREFSRC, RTA_GATEWAY
                    (
                        IPField("rta_data", "0.0.0.0"),
                        lambda pkt: pkt.parent
                        and pkt.parent.rtm_family == 2
                        and pkt.rta_type in [0x01, 0x02, 0x05, 0x07],
                    ),
                    (
                        IP6Field("rta_data", "::"),
                        lambda pkt: pkt.parent
                        and pkt.parent.rtm_family == 10
                        and pkt.rta_type in [0x01, 0x02, 0x05, 0x07],
                    ),
                    # RTS_OIF, RTA_PRIORITY
                    (
                        Field("rta_data", 0, fmt="=I"),
                        lambda pkt: pkt.rta_type in [0x04, 0x06, 0x10],
                    ),
                    # RTA_TABLE
                    (
                        EnumField("rta_data", 0, RT_CLASS, fmt="=I"),
                        lambda pkt: pkt.rta_type in [0x0F],
                    ),
                ],
                XStrLenField(
                    "rta_data",
                    b"",
                    length_from=lambda pkt: pkt.rta_len - 4,
                ),
            ),
            align=4,
        ),
    ]

    def default_payload_class(self, payload: bytes) -> Type[Packet]:
        return conf.padding_layer


class rtmsg(Packet):
    fields_desc = [
        ByteEnumField("rtm_family", 0, socket.AddressFamily),  # type: ignore
        ByteField("rtm_dst_len", 0),
        ByteField("rtm_src_len", 0),
        ByteField("rtm_tos", 0),
        ByteEnumField(
            "rtm_table",
            0,
            RT_CLASS,
        ),
        ByteEnumField(
            "rtm_protocol",
            0,
            {
                0x00: "RTPROT_UNSPEC",
                0x01: "RTPROT_REDIRECT",
                0x02: "RTPROT_KERNEL",
                0x03: "RTPROT_BOOT",
                0x04: "RTPROT_STATIC",
            },
        ),
        ByteEnumField(
            "rtm_scope",
            0,
            {
                0: "RT_SCOPE_UNIVERSE",
                200: "RT_SCOPE_SITE",
                253: "RT_SCOPE_LINK",
                254: "RT_SCOPE_HOST",
                255: "RT_SCOPE_NOWHERE",
            },
        ),
        ByteEnumField(
            "rtm_type",
            0,
            {
                0x00: "RTN_UNSPEC",
                0x01: "RTN_UNICAST",
                0x02: "RTN_LOCAL",
                0x03: "RTN_BROADCAST",
                0x04: "RTN_ANYCAST",
                0x05: "RTN_MULTICAST",
                0x06: "RTN_BLACKHOLE",
                0x07: "RTN_UNREACHABLE",
                0x08: "RTN_PROHIBIT",
                0x09: "RTN_THROW",
                0x0A: "RTN_NAT",
                0x0B: "RTN_XRESOLVE",
            },
        ),
        FlagsField(
            "rtm_flags",
            0,
            32 if BIG_ENDIAN else -32,
            {
                0x100: "RTM_F_NOTIFY",
                0x200: "RTM_F_CLONED",
                0x400: "RTM_F_EQUALIZE",
                0x800: "RTM_F_PREFIX",
                0x1000: "RTM_F_LOOKUP_TABLE",
                0x2000: "RTM_F_FIB_MATCH",
                0x4000: "RTM_F_OFFLOAD",
                0x8000: "RTM_F_TRAP",
                0x20000000: "RTM_F_OFFLOAD_FAILED",
            },
        ),
        # Pay
        PacketListField("data", [], rtmsg_rtattr),
    ]


bind_layers(rtmsghdr, rtmsg, nlmsg_type=24)
bind_layers(rtmsghdr, rtmsg, nlmsg_type=25)
bind_layers(rtmsghdr, rtmsg, nlmsg_type=26)


class rtmsghdrs(Packet):
    fields_desc = [
        PacketListField(
            "msgs",
            [],
            rtmsghdr,
            # 65535 / len(rtmsghdr)
            max_count=4096,
        ),
    ]


# Utils


SOL_NETLINK = 270
NETLINK_EXT_ACK = 11
NETLINK_GET_STRICT_CHK = 12


def _sr1_rtrequest(pkt: Packet) -> List[Packet]:
    """
    Send / Receive a rtnetlink request
    """
    # Create socket
    sock = socket.socket(
        socket.AF_NETLINK,
        socket.SOCK_RAW | socket.SOCK_CLOEXEC,
        socket.NETLINK_ROUTE,
    )
    # Configure socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
    try:
        sock.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, 1)
    except OSError:
        # Linux 4.12+ only
        pass
    sock.bind((0, 0))  # bind to kernel
    try:
        sock.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
    except OSError:
        # Linux 4.20+ only
        pass
    # Request routes
    sock.send(bytes(rtmsghdrs(msgs=[pkt])))
    results: List[Packet] = []
    try:
        while True:
            msgs = rtmsghdrs(sock.recv(65535))
            if not msgs:
                log_loading.warning("Failed to read the routes using RTNETLINK !")
                return []
            for msg in msgs.msgs:
                # Keep going until we find the end of the MULTI format
                if not msg.nlmsg_flags.NLM_F_MULTI or msg.nlmsg_type == 3:
                    if msg.nlmsg_type == 3 and nlmsgerr in msg and msg.status != 0:
                        # NLMSG_DONE with errors
                        if msg.data and msg.data[0].rta_type == 1:
                            log_loading.debug(
                                "Scapy RTNETLINK error on %s: '%s'. Please report !",
                                pkt.sprintf("%nlmsg_type%"),
                                msg.data[0].rta_data.decode(),
                            )
                            return []
                    return results
                results.append(msg)
    finally:
        sock.close()


def _get_ips(af_family=socket.AF_UNSPEC):
    # type: (socket.AddressFamily) -> Dict[int, List[Dict[str, Any]]]
    """
    Return a mapping of all interfaces IP using a NETLINK socket.
    """
    results = _sr1_rtrequest(
        rtmsghdr(
            nlmsg_type="RTM_GETADDR",
            nlmsg_flags="NLM_F_REQUEST+NLM_F_ROOT+NLM_F_MATCH",
            nlmsg_seq=int(time.time()),
        )
        / ifaddrmsg(
            ifa_family=af_family,
            data=[],
        )
    )
    ips: Dict[int, List[Dict[str, Any]]] = {}
    for msg in results:
        ifindex = msg.ifa_index
        address = None
        family = msg.ifa_family
        for attr in msg.data:
            if attr.rta_type == 0x01:  # IFA_ADDRESS
                address = attr.rta_data
                break
        if address is not None:
            data = {
                "af_family": family,
                "index": ifindex,
                "address": address,
            }
            if family == 10:  # ipv6
                data["scope"] = scapy.utils6.in6_getscope(address)
            ips.setdefault(ifindex, list()).append(data)
    return ips


def _get_if_list():
    # type: () -> Dict[int, Dict[str, Any]]
    """
    Read the interfaces list using a NETLINK socket.
    """
    results = _sr1_rtrequest(
        rtmsghdr(
            nlmsg_type="RTM_GETLINK",
            nlmsg_flags="NLM_F_REQUEST+NLM_F_ROOT+NLM_F_MATCH",
            nlmsg_seq=int(time.time()),
        )
        / ifinfomsg(
            data=[],
        )
    )
    lifips = _get_ips()
    interfaces = {}
    for msg in results:
        ifindex = msg.ifi_index
        ifname = None
        mac = "00:00:00:00:00:00"
        itype = msg.ifi_type
        ifflags = msg.ifi_flags
        ips = []
        for attr in msg.data:
            if attr.rta_type == 0x01:  # IFLA_ADDRESS
                mac = attr.rta_data
            elif attr.rta_type == 0x03:  # IFLA_NAME
                ifname = attr.rta_data[:-1].decode()
        if ifname is not None:
            if ifindex in lifips:
                ips = lifips[ifindex]
            interfaces[ifindex] = {
                "name": ifname,
                "index": ifindex,
                "flags": ifflags,
                "mac": mac,
                "type": itype,
                "ips": ips,
            }
    return interfaces


def in6_getifaddr():
    # type: () -> List[Tuple[str, int, str]]
    """
    Returns a list of 3-tuples of the form (addr, scope, iface) where
    'addr' is the address of scope 'scope' associated to the interface
    'iface'.

    This is the list of all addresses of all interfaces available on
    the system.
    """
    ips = _get_ips(af_family=socket.AF_INET6)
    ifaces = _get_if_list()
    result = []
    for intip in ips.values():
        for ip in intip:
            if ip["index"] in ifaces:
                result.append((ip["address"], ip["scope"], ifaces[ip["index"]]["name"]))
    return result


def _read_routes(af_family):
    # type: (socket.AddressFamily) -> List[Packet]
    """
    Read routes using a NETLINK socket.
    """
    results = []
    for rttable in ["RT_TABLE_LOCAL", "RT_TABLE_MAIN"]:
        results.extend(
            _sr1_rtrequest(
                rtmsghdr(
                    nlmsg_type="RTM_GETROUTE",
                    nlmsg_flags="NLM_F_REQUEST+NLM_F_ROOT+NLM_F_MATCH",
                    nlmsg_seq=int(time.time()),
                )
                / rtmsg(
                    rtm_family=af_family,
                    data=[
                        rtmsg_rtattr(rta_type="RTA_TABLE", rta_data=rttable),
                    ],
                )
            )
        )
    return [msg for msg in results if msg.nlmsg_type == 24]  # RTM_NEWROUTE


def read_routes():
    # type: () -> List[Tuple[int, int, str, str, str, int]]
    """
    Read IPv4 routes for current process
    """
    routes = []
    ifaces = _get_if_list()
    results = _read_routes(socket.AF_INET)
    for msg in results:
        # Omit stupid answers (some OS conf appears to lead to this)
        if msg.rtm_family != socket.AF_INET:
            continue
        # Process the RTM_NEWROUTE
        net = 0
        mask = itom(msg.rtm_dst_len)
        gw = "0.0.0.0"
        iface = ""
        addr = "0.0.0.0"
        metric = 0
        for attr in msg.data:
            if attr.rta_type == 0x01:  # RTA_DST
                net = atol(attr.rta_data)
            elif attr.rta_type == 0x04:  # RTS_OIF
                index = attr.rta_data
                if index in ifaces:
                    iface = ifaces[index]["name"]
                else:
                    iface = str(index)
            elif attr.rta_type == 0x05:  # RTA_GATEWAY
                gw = attr.rta_data
            elif attr.rta_type == 0x06:  # RTA_PRIORITY
                metric = attr.rta_data
            elif attr.rta_type == 0x07:  # RTA_PREFSRC
                addr = attr.rta_data
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
    # type: () -> List[Tuple[str, int, str, str, List[str], int]]
    """
    Read IPv6 routes for current process
    """
    routes = []
    ifaces = _get_if_list()
    results = _read_routes(socket.AF_INET6)
    lifaddr = _get_ips(af_family=socket.AF_INET6)
    for msg in results:
        # Omit stupid answers (some OS conf appears to lead to this)
        if msg.rtm_family != socket.AF_INET6:
            continue
        # Process the RTM_NEWROUTE
        prefix = "::"
        plen = msg.rtm_dst_len
        nh = "::"
        index = 0
        iface = ""
        metric = 0
        for attr in msg.data:
            if attr.rta_type == 0x01:  # RTA_DST
                prefix = attr.rta_data
            elif attr.rta_type == 0x04:  # RTS_OIF
                index = attr.rta_data
                if index in ifaces:
                    iface = ifaces[index]["name"]
                else:
                    iface = str(index)
            elif attr.rta_type == 0x05:  # RTA_GATEWAY
                nh = attr.rta_data
            elif attr.rta_type == 0x06:  # RTA_PRIORITY
                metric = attr.rta_data
        devaddrs = ((x["address"], x["scope"], iface) for x in lifaddr.get(index, []))
        cset = scapy.utils6.construct_source_candidate_set(prefix, plen, devaddrs)
        if cset:
            routes.append((prefix, plen, nh, iface, cset, metric))
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
