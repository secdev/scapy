## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP
if conf.ipv6_enabled:
    from scapy.layers.inet6 import IPv6
from scapy.config import conf

class PFLog(Packet):
    name = "PFLog"
    # from OpenBSD src/sys/net/pfvar.h and src/sys/net/if_pflog.h
    fields_desc = [ ByteField("hdrlen", 0),
                    ByteEnumField("addrfamily", 2, {socket.AF_INET: "IPv4",
                                                    socket.AF_INET6: "IPv6"}),
                    ByteEnumField("action", 1, {0: "pass", 1: "drop",
                                                2: "scrub", 3: "no-scrub",
                                                4: "nat", 5: "no-nat",
                                                6: "binat", 7: "no-binat",
                                                8: "rdr", 9: "no-rdr",
                                                10: "syn-proxy-drop" }),
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
                                                14: "syn-proxy" }),
                    StrFixedLenField("iface", "", 16),
                    StrFixedLenField("ruleset", "", 16),
                    SignedIntField("rulenumber", 0),
                    SignedIntField("subrulenumber", 0),
                    SignedIntField("uid", 0),
                    IntField("pid", 0),
                    SignedIntField("ruleuid", 0),
                    IntField("rulepid", 0),
                    ByteEnumField("direction", 255, {0: "inout", 1: "in",
                                                     2:"out", 255: "unknown"}),
                    StrFixedLenField("pad", "\x00\x00\x00", 3 ) ]
    def mysummary(self):
        return self.sprintf("%PFLog.addrfamily% %PFLog.action% on %PFLog.iface% by rule %PFLog.rulenumber%")

bind_layers(PFLog, IP, addrfamily=socket.AF_INET)
if conf.ipv6_enabled:
    bind_layers(PFLog, IPv6, addrfamily=socket.AF_INET6)

conf.l2types.register(117, PFLog)
