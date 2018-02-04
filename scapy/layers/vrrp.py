## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Copyright (C) 6WIND <olivier.matz@6wind.com>
## This program is published under a GPLv2 license

"""
VRRP (Virtual Router Redundancy Protocol).
"""

from scapy.packet import *
from scapy.fields import *
from scapy.compat import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.error import warning

IPPROTO_VRRP=112

# RFC 3768 - Virtual Router Redundancy Protocol (VRRP)
class VRRP(Packet):
    fields_desc = [
        BitField("version", 2, 4),
        BitField("type", 1, 4),
        ByteField("vrid", 1),
        ByteField("priority", 100),
        FieldLenField("ipcount", None, count_of="addrlist", fmt="B"),
        ByteField("authtype", 0),
        ByteField("adv", 1),
        XShortField("chksum", None),
        FieldListField("addrlist", [], IPField("", "0.0.0.0"),
                       count_from = lambda pkt: pkt.ipcount),
        IntField("auth1", 0),
        IntField("auth2", 0) ]

    def post_build(self, p, pay):
        if self.chksum is None:
            ck = checksum(p)
            p = p[:6]+chb(ck>>8)+chb(ck&0xff)+p[8:]
        return p

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 9:
            ver_n_type = orb(_pkt[0])
            if ver_n_type >= 48 and ver_n_type <= 57: # Version == 3
                return VRRPv3
        return VRRP


# RFC 5798 -  Virtual Router Redundancy Protocol (VRRP) Version 3
class VRRPv3(Packet):
    fields_desc = [
        BitField("version", 3, 4),
        BitField("type", 1, 4),
        ByteField("vrid", 1),
        ByteField("priority", 100),
        FieldLenField("ipcount", None, count_of="addrlist", fmt="B"),
        BitField("res", 0, 4),
        BitField("adv", 100, 12),
        XShortField("chksum", None),
        # FIXME: addrlist should also allow IPv6 addresses :/
        FieldListField("addrlist", [], IPField("", "0.0.0.0"),
                       count_from = lambda pkt: pkt.ipcount)]

    def post_build(self, p, pay):
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                ck = in4_chksum(112, self.underlayer, p)
            elif isinstance(self.underlayer, IPv6):
                ck = in6_chksum(112, self.underlayer, p)
            else:
                warning("No IP(v6) layer to compute checksum on VRRP. Leaving null")
                ck = 0
            p = p[:6]+chb(ck>>8)+chb(ck&0xff)+p[8:]
        return p

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 16:
            ver_n_type = orb(_pkt[0])
            if ver_n_type < 48 or ver_n_type > 57: # Version != 3
                return VRRP
        return VRRPv3

# IPv6 is supported only on VRRPv3
# Warning: those layers need to be un-binded in the CARP contrib module.
# If you add/remove any, remember to also edit the one in CARP.py
bind_layers( IP,            VRRP,          proto=IPPROTO_VRRP)
bind_layers( IP,            VRRPv3,        proto=IPPROTO_VRRP)
bind_layers( IPv6,          VRRPv3,        nh=IPPROTO_VRRP)
