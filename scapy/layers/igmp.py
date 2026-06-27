# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Internet Group Management Protocol v1/v2/v3
# scapy.contrib.status = loads

"""
IGMP v1/v2/v3 as per RFC2236 and RFC9776

Example: IGMPv1 Membership Report (=Join)

    >>> send(IP() / IGMP_MR(gaddr="224.0.0.251"))

Example: IGMPv3 Membership Report (=Join)

    >>> send(IP() / IGMPv3_MR(records=[IGMPv3_MR_Group(rtype=4, maddr="224.0.0.251")]))

Example: IGMPv1/v2 Membership Query

    >>> sr(IP() / IGMP_MQ(gaddr="224.0.0.251"), multi=True)

Example: IGMPv3 Membership Query

    >>> sr(IP() / IGMPv3_MQ(gaddr="224.0.0.251"), multi=True)

Example: IGMPv2 Leave

    >>> send(IP() / IGMP_LG(gaddr="225.0.0.251"))
"""

import struct

from scapy.config import conf
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IPField,
    PacketListField,
    ScalingField,
    ShortField,
    XShortField,
)
from scapy.packet import bind_layers, Packet, bind_top_down
from scapy.plist import PacketList
from scapy.sendrecv import sr, send
from scapy.utils import checksum

from scapy.layers.inet import IP, IPOption_Router_Alert, DestIPField


class _MRCodeField(ScalingField):
    """
    Max Resp Code field.

    """

    def i2m(self, pkt, x):
        if x is None:
            if pkt.type == 0x11:  # Membership Query
                return 20
            else:
                return 0
        if pkt.type == 0x11 and isinstance(pkt, IGMPv3):
            # IGMP v3 - RFC9776 sect 4.1.1
            if x < 128:
                return x
            else:
                exp = 0
                x >>= 3
                while x > 31:
                    exp += 1
                    x >>= 1
                exp <<= 4
                return 0x80 | exp | (x & 0x0F)
        return super(_MRCodeField, self).i2m(pkt, x)

    def i2h(self, pkt, x):
        return super(_MRCodeField, self).i2h(pkt, self.i2m(pkt, x))

    def m2i(self, pkt, x):
        if pkt.type == 0x11 and isinstance(pkt, IGMPv3):
            # IGMP v3 - RFC9776 sect 4.1.1
            if x < 128:
                return x
            else:
                mant, exp = (x & 0x0F), (x >> 4) & 0x7
                return (mant | 0x10) << (exp + 3)
        return super(_MRCodeField, self).i2m(pkt, x)


class IGMP(Packet):
    """
    General IGMP v1/v2 message.
    """

    fields_desc = [
        ByteEnumField(
            "type",
            0x11,
            {
                0x11: "Group Membership Query",
                0x12: "Version 1 - Membership Report",
                0x16: "Version 2 - Membership Report",
                0x17: "Leave Group",
            },
        ),
        _MRCodeField("mrcode", None, unit="1/10sec"),
        XShortField("chksum", None),
        IPField("gaddr", "0.0.0.0"),
    ]

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            p = p[:2] + struct.pack("!H", checksum(p)) + p[4:]
        return p

    def add_underlayer(self, underlayer):
        # Add option to parent IP layer
        if isinstance(underlayer, IP):
            if not underlayer.options:
                underlayer.options.append(IPOption_Router_Alert())
        super(IGMP, self).add_underlayer(underlayer)

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        typ = None

        # Get packet type from build or dissection
        if "type" in kargs:
            typ = kargs["type"]
        elif _pkt and len(_pkt) >= 4:
            typ = _pkt[0]

        # Return the proper class depending on the packet type
        if typ is not None:
            if typ == 0x11:
                if (_pkt and len(_pkt) >= 12) or (not _pkt and issubclass(cls, IGMPv3)):
                    return IGMPv3_MQ
                else:
                    return IGMP_MQ
            elif typ == 0x12:
                return IGMP_MR
            elif typ == 0x16:
                return IGMPv2_MR
            elif typ == 0x17:
                return IGMPv2_LG
            elif typ == 0x22:
                return IGMPv3_MR
            elif typ == 0x30:
                return IGMPv3_MRA
            elif typ == 0x31:
                return IGMPv3_MRS
            elif typ == 0x32:
                return IGMPv3_MRT

        return IGMP_MQ

    def answers(self, other):
        if other.type == 0x11:
            return self.type in [0x12, 0x16, 0x22]
        elif other.type == 0x31:
            return self.type == 0x30
        return False

    def mysummary(self):
        t = self.__class__.__name__
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf(
                f"IGMP: %IP.src% > %IP.dst% %{t}.type% %{t}.gaddr%"
            )
        else:
            return self.sprintf(f"IGMP %{t}.type% %{t}.gaddr%")


class IGMP_MQ(IGMP):
    """
    IGMPv1/v2 Membership Query
    """

    name = "IGMPv1/v2 Membership Query"
    match_subclass = True
    type = 0x11


class IGMPv2_LG(IGMP):
    """
    IGMPv2 Leave Group
    """

    name = "IGMPv2 Leave Group"
    match_subclass = True
    type = 0x17


class IGMP_MR(IGMP):
    """
    IGMPv1 Membership Report
    """

    name = "IGMPv1 Membership Report"
    type = 0x12
    match_subclass = True


class IGMPv2_MR(IGMP):
    """
    IGMPv2 Membership Report
    """

    name = "IGMPv2 Membership Report"
    type = 0x16
    match_subclass = True


class IGMPv3(IGMP):
    """
    IGMP Message Class for v3
    """

    name = "IGMPv3"

    fields_desc = [
        ByteEnumField(
            "type",
            0x11,
            {
                0x11: "Membership Query",
                0x22: "Version 3 - Membership Report",
                # RFC 4286
                0x30: "Multicast Router Advertisement",
                0x31: "Multicast Router Solicitation",
                0x32: "Multicast Router Termination",
            },
        ),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return super(IGMPv3, cls).dispatch_hook(_pkt=_pkt, *args, **kargs)

    def mysummary(self):
        """Display a summary of the IGMPv3 object."""
        t = self.__class__.__name__
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf(f"IGMPv3: %IP.src% > %IP.dst% %{t}.type%")
        else:
            return self.sprintf(f"IGMPv3 %{t}.type%")


class IGMPv3_MQ(IGMPv3):
    """
    IGMPv3 Membership Query
    """

    type = 0x11
    name = "IGMPv3 Membership Query"
    match_subclass = True

    fields_desc = [
        IGMPv3,
        _MRCodeField("mrcode", 20, unit="1/10sec"),
        XShortField("chksum", None),
        IPField("gaddr", "0.0.0.0"),
        FlagsField(
            "flags",
            0,
            4,
            {
                0x8: "extended",
            },
        ),
        BitField("s", 0, 1),
        BitField("qrv", 0, 3),
        ByteField("qqic", 0),
        FieldLenField("numsrc", None, count_of="srcaddrs"),
        FieldListField(
            "srcaddrs",
            None,
            IPField("sa", "0.0.0.0"),
            count_from=lambda x: x.numsrc,
        ),
    ]


class IGMPv3_MR_Group(Packet):
    """
    IGMP Group Record for IGMPv3 Membership Report

    This class should be added in the records of an instantiation of class IGMPv3_MR.
    """

    name = "IGMPv3 Group Record"
    fields_desc = [
        ByteEnumField(
            "rtype",
            4,
            {
                1: "Mode Is Include",
                2: "Mode Is Exclude",
                3: "Change To Include Mode",
                4: "Change To Exclude Mode",
                5: "Allow New Sources",
                6: "Block Old Sources",
            },
        ),
        ByteField("auxdlen", 0),
        FieldLenField("numsrc", None, count_of="srcaddrs"),
        IPField("maddr", "0.0.0.0"),
        FieldListField(
            "srcaddrs",
            [],
            IPField("sa", "0.0.0.0"),
            count_from=lambda x: x.numsrc,
        ),
    ]

    def mysummary(self):
        """Display a summary of the IGMPv3 group record."""
        return self.sprintf(
            "IGMPv3 Group Record %IGMPv3gr.type% %IGMPv3gr.maddr%"
        )  # noqa: E501

    def default_payload_class(self, payload):
        return conf.padding_layer


class IGMPv3_MR(IGMPv3):
    """
    IGMP Membership Report extension for IGMPv3
    """

    type = 0x22
    name = "IGMPv3 Membership Report"
    match_subclass = True

    fields_desc = [
        IGMPv3,
        ByteField("reserved", 0),
        XShortField("chksum", None),
        FlagsField(
            "flags",
            0,
            16,
            {
                0x8000: "extended",
            },
        ),
        FieldLenField("numgrp", None, count_of="records"),
        PacketListField(
            "records",
            [],
            IGMPv3_MR_Group,
            count_from=lambda x: x.numgrp,
        ),
    ]


class IGMPv3_MRA(IGMPv3):
    """
    IGMP Multicast Router Advertisement per RFC4286
    """

    type = 0x30
    name = "IGMPv3_MRA"
    match_subclass = True

    fields_desc = [
        IGMPv3,
        ByteField("advIntvl", 0),
        XShortField("chksum", None),
        ShortField("qryIntvl", 0),
        ShortField("robust", 0),
    ]


class IGMPv3_MRS(IGMPv3):
    """
    IGMP Multicast Router Solicitation per RFC4286
    """

    type = 0x31
    name = "IGMPv3_MRS"
    match_subclass = True

    fields_desc = [
        IGMPv3,
        ByteField("reserved", 0),
        XShortField("chksum", None),
    ]


class IGMPv3_MRT(IGMPv3):
    """
    IGMP Multicast Router Termination per RFC4286
    """

    type = 0x31
    name = "IGMPv3_MRT"
    match_subclass = True

    fields_desc = [
        IGMPv3,
        ByteField("reserved", 0),
        XShortField("chksum", None),
    ]


bind_layers(IP, IGMP, proto=2)
bind_top_down(IP, IGMP, proto=2, ttl=1, tos=0xC0)


def _igmp_mq_addr(pkt):
    if pkt.gaddr == "0.0.0.0":
        # General Query
        return "224.0.0.1"
    else:
        return pkt.gaddr


DestIPField.bind_addr(IGMP_MQ, _igmp_mq_addr)
DestIPField.bind_addr(IGMPv3_MQ, _igmp_mq_addr)
DestIPField.bind_addr(IGMPv2_LG, "224.0.0.2")
DestIPField.bind_addr(IGMP_MR, lambda pkt: pkt.gaddr)
DestIPField.bind_addr(IGMPv2_MR, lambda pkt: pkt.gaddr)
DestIPField.bind_addr(IGMPv3_MR, "224.0.0.22")

# RFC4286
DestIPField.bind_addr(IGMPv3_MRA, "224.0.0.106")
DestIPField.bind_addr(IGMPv3_MRT, "224.0.0.106")
DestIPField.bind_addr(IGMPv3_MRS, "224.0.0.2")


@conf.commands.register
def igmp_join(gaddr: str, version=2, psrc=None, iface=None):
    """
    Send a IGMP Membership Report to join a multicast group

    :param gaddr: the IPv4 of the group to join
    :param version: whether to use IGMPv1, IGMPv2 or IGMPv3. Default: both 2 and 3
    :param psrc: (optional) the source IP
    """
    if version == 1:
        pkt = IP(src=psrc) / IGMP_MR(gaddr=gaddr)
    elif version == 2:
        pkt = IP(src=psrc) / IGMPv2_MR(gaddr=gaddr)
    elif version == 3:
        pkt = IP(src=psrc) / IGMPv3_MR(records=[IGMPv3_MR_Group(rtype=4, maddr=gaddr)])
    send(pkt, iface=iface)


@conf.commands.register
def igmp_leave(gaddr: str, version=2, psrc=None, iface=None):
    """
    Send a IGMP Leave Group to leave a multicast group

    :param gaddr: the IPv4 of the group to leave
    :param psrc: (optional) the source IP
    """
    if version == 1:
        raise ValueError("IGMPv1 does not include a mechanism to leave !")
    elif version == 2:
        pkt = IP(src=psrc) / IGMPv2_LG(gaddr=gaddr)
    elif version == 3:
        pkt = IP(src=psrc) / IGMPv3_MR(records=[IGMPv3_MR_Group(rtype=3, maddr=gaddr)])
    send(pkt, iface=iface)


class IGMPMQResult(PacketList):
    def __init__(
        self,
        res=None,
        name="IGMP-MR",
        stats=None,
    ):
        PacketList.__init__(self, res, name, stats)


@conf.commands.register
def igmp_query(gaddr: str = None, version=2, timeout=2):
    """
    Send/receive a Membership Query to get the members of a multicast group

    :param gaddr: the IPv4 of the group to query

    Example::

        >>> pkts = igmp_query("224.0.0.251")
        >>> pkts.show()

    Example 2::

        >>> pkts = igmp_query("239.255.255.250", version=3)
        >>> pkts.show()
    """
    if version == 1:
        pkt = IP() / IGMP_MQ(mrcode=0, gaddr=gaddr)
    elif version == 2:
        pkt = IP() / IGMP_MQ(mrcode=timeout * 10, gaddr=gaddr)
    elif version == 3:
        pkt = IP() / IGMPv3_MQ(mrcode=timeout * 10, gaddr=gaddr)

    _old_checkIPaddr = conf.checkIPaddr
    conf.checkIPaddr = False
    try:
        return IGMPMQResult(
            [x.answer for x in sr(pkt, multi=True, timeout=timeout + 1)[0]]
        )
    finally:
        conf.checkIPaddr = _old_checkIPaddr
