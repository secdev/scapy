# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
PFLog: OpenBSD PF packet filter logging.
"""

from scapy.data import DLT_PFLOG
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IntField, \
    IPField, IP6Field, MultipleTypeField, PadField, ShortField, \
    SignedIntField, StrFixedLenField, YesNoByteField
from scapy.layers.inet import IP
from scapy.config import conf
if conf.ipv6_enabled:
    from scapy.layers.inet6 import IPv6

# from OpenBSD src/sys/sys/socket.h
# define	AF_INET		2
# define	AF_INET6	24
OPENBSD_AF_INET = 2
OPENBSD_AF_INET6 = 24

# from OpenBSD src/sys/net/if_pflog.h
# define PFLOG_HDRLEN		sizeof(struct pfloghdr)
PFLOG_HDRLEN = 100


class PFLog(Packet):
    """
    Class for handling PFLog headers
    """
    name = "PFLog"
    # from OpenBSD src/sys/net/pfvar.h
    # and src/sys/net/if_pflog.h (struct pfloghdr)
    fields_desc = [ByteField("hdrlen", PFLOG_HDRLEN),
                   ByteEnumField("addrfamily", 2, {OPENBSD_AF_INET: "IPv4",
                                                   OPENBSD_AF_INET6: "IPv6"}),
                   ByteEnumField("action", 1, {0: "pass", 1: "drop",
                                               2: "scrub", 3: "no-scrub",
                                               4: "nat", 5: "no-nat",
                                               6: "binat", 7: "no-binat",
                                               8: "rdr", 9: "no-rdr",
                                               10: "syn-proxy-drop"}),
                   ByteEnumField("reason", 0, {0: "match", 1: "bad-offset",
                                               2: "fragment", 3: "short",
                                               4: "normalize", 5: "memory",
                                               6: "bad-timestamp",
                                               7: "congestion",
                                               8: "ip-options",
                                               9: "proto-cksum",
                                               10: "state-mismatch",
                                               11: "state-insert",
                                               12: "state-limit",
                                               13: "src-limit",
                                               14: "syn-proxy"}),
                   StrFixedLenField("iface", "", 16),
                   StrFixedLenField("ruleset", "", 16),
                   SignedIntField("rulenumber", 0),
                   SignedIntField("subrulenumber", 0),
                   SignedIntField("uid", 0),
                   IntField("pid", 0),
                   SignedIntField("ruleuid", 0),
                   IntField("rulepid", 0),
                   ByteEnumField("direction", 255, {0: "inout", 1: "in",
                                                    2: "out", 255: "unknown"}),
                   YesNoByteField("rewritten", 0),
                   ByteEnumField("naddrfamily", 2, {OPENBSD_AF_INET: "IPv4",
                                                    OPENBSD_AF_INET6: "IPv6"}),
                   StrFixedLenField("pad", b"\x00", 1),
                   MultipleTypeField(
                       [
                           (PadField(IPField("saddr", "127.0.0.1"),
                                     16, padwith=b"\x00"),
                            lambda pkt: pkt.addrfamily == OPENBSD_AF_INET),
                           (IP6Field("saddr", "::1"),
                            lambda pkt: pkt.addrfamily == OPENBSD_AF_INET6),
                       ],
                       PadField(IPField("saddr", "127.0.0.1"),
                                16, padwith=b"\x00"),),
                   MultipleTypeField(
                       [
                           (PadField(IPField("daddr", "127.0.0.1"),
                                     16, padwith=b"\x00"),
                            lambda pkt: pkt.addrfamily == OPENBSD_AF_INET),
                           (IP6Field("daddr", "::1"),
                            lambda pkt: pkt.addrfamily == OPENBSD_AF_INET6),
                       ],
                       PadField(IPField("daddr", "127.0.0.1"),
                                16, padwith=b"\x00"),),
                   ShortField("sport", 0),
                   ShortField("dport", 0), ]

    def mysummary(self):
        return self.sprintf("%PFLog.addrfamily% %PFLog.action% on %PFLog.iface% by rule %PFLog.rulenumber%")  # noqa: E501


bind_layers(PFLog, IP, addrfamily=OPENBSD_AF_INET)
bind_layers(PFLog, IPv6, addrfamily=OPENBSD_AF_INET6)

conf.l2types.register(DLT_PFLOG, PFLog)
