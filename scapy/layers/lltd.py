# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""LLTD Protocol

https://msdn.microsoft.com/en-us/library/cc233983.aspx

"""

from array import array

from scapy.fields import BitField, FlagsField, ByteField, ByteEnumField, \
    ShortField, ShortEnumField, ThreeBytesField, IntField, IntEnumField, \
    LongField, MultiEnumField, FieldLenField, FieldListField, \
    PacketListField, StrLenField, StrLenFieldUtf16, ConditionalField, MACField
from scapy.packet import Packet, Padding, bind_layers
from scapy.plist import PacketList
from scapy.layers.l2 import Ether
from scapy.layers.inet import IPField
from scapy.layers.inet6 import IP6Field
from scapy.data import ETHER_ANY
from scapy.compat import orb, chb


# Protocol layers
##################


class LLTD(Packet):
    name = "LLTD"
    answer_hashret = {
        # (tos, function) tuple mapping (answer -> query), used by
        # .hashret()
        (1, 1): (0, 0),
        (0, 12): (0, 11),
    }
    fields_desc = [
        ByteField("version", 1),
        ByteEnumField("tos", 0, {
            0: "Topology discovery",
            1: "Quick discovery",
            2: "QoS diagnostics",
        }),
        ByteField("reserved", 0),
        MultiEnumField("function", 0, {
            0: {
                0: "Discover",
                1: "Hello",
                2: "Emit",
                3: "Train",
                4: "Probe",
                5: "Ack",
                6: "Query",
                7: "QueryResp",
                8: "Reset",
                9: "Charge",
                10: "Flat",
                11: "QueryLargeTlv",
                12: "QueryLargeTlvResp",
            },
            1: {
                0: "Discover",
                1: "Hello",
                8: "Reset",
            },
            2: {
                0: "QosInitializeSink",
                1: "QosReady",
                2: "QosProbe",
                3: "QosQuery",
                4: "QosQueryResp",
                5: "QosReset",
                6: "QosError",
                7: "QosAck",
                8: "QosCounterSnapshot",
                9: "QosCounterResult",
                10: "QosCounterLease",
            },
        }, depends_on=lambda pkt: pkt.tos, fmt="B"),
        MACField("real_dst", None),
        MACField("real_src", None),
        ConditionalField(ShortField("xid", 0),
                         lambda pkt: pkt.function in [0, 8]),
        ConditionalField(ShortField("seq", 0),
                         lambda pkt: pkt.function not in [0, 8]),
    ]

    def post_build(self, pkt, pay):
        if (self.real_dst is None or self.real_src is None) and \
           isinstance(self.underlayer, Ether):
            eth = self.underlayer
            if self.real_dst is None:
                pkt = (pkt[:4] + eth.fields_desc[0].i2m(eth, eth.dst) +
                       pkt[10:])
            if self.real_src is None:
                pkt = (pkt[:10] + eth.fields_desc[1].i2m(eth, eth.src) +
                       pkt[16:])
        return pkt + pay

    def mysummary(self):
        if isinstance(self.underlayer, Ether):
            return self.underlayer.sprintf(
                'LLTD %src% > %dst% %LLTD.tos% - %LLTD.function%'
            )
        else:
            return self.sprintf('LLTD %tos% - %function%')

    def hashret(self):
        tos, function = self.tos, self.function
        return b"%c%c" % self.answer_hashret.get((tos, function),
                                                 (tos, function))

    def answers(self, other):
        if not isinstance(other, LLTD):
            return False
        if self.tos == 0:
            if self.function == 0 and isinstance(self.payload, LLTDDiscover) \
               and len(self[LLTDDiscover].stations_list) == 1:
                # "Topology discovery - Discover" with one MAC address
                # discovered answers a "Quick discovery - Hello"
                return other.tos == 1 and \
                    other.function == 1 and \
                    LLTDAttributeHostID in other and \
                    other[LLTDAttributeHostID].mac == \
                    self[LLTDDiscover].stations_list[0]
            elif self.function == 12:
                # "Topology discovery - QueryLargeTlvResp" answers
                # "Topology discovery - QueryLargeTlv" with same .seq
                # value
                return other.tos == 0 and other.function == 11 \
                    and other.seq == self.seq
        elif self.tos == 1:
            if self.function == 1 and isinstance(self.payload, LLTDHello):
                # "Quick discovery - Hello" answers a "Topology
                # discovery - Discover"
                return other.tos == 0 and other.function == 0 and \
                    other.real_src == self.current_mapper_address
        return False


class LLTDHello(Packet):
    name = "LLTD - Hello"
    show_summary = False
    fields_desc = [
        ShortField("gen_number", 0),
        MACField("current_mapper_address", ETHER_ANY),
        MACField("apparent_mapper_address", ETHER_ANY),
    ]


class LLTDDiscover(Packet):
    name = "LLTD - Discover"
    fields_desc = [
        ShortField("gen_number", 0),
        FieldLenField("stations_count", None, count_of="stations_list",
                      fmt="H"),
        FieldListField("stations_list", [], MACField("", ETHER_ANY),
                       count_from=lambda pkt: pkt.stations_count)
    ]

    def mysummary(self):
        return (self.sprintf("Stations: %stations_list%")
                if self.stations_list else "No station", [LLTD])


class LLTDEmiteeDesc(Packet):
    name = "LLTD - Emitee Desc"
    fields_desc = [
        ByteEnumField("type", 0, {0: "Train", 1: "Probe"}),
        ByteField("pause", 0),
        MACField("src", None),
        MACField("dst", ETHER_ANY),
    ]


class LLTDEmit(Packet):
    name = "LLTD - Emit"
    fields_desc = [
        FieldLenField("descs_count", None, count_of="descs_list",
                      fmt="H"),
        PacketListField("descs_list", [], LLTDEmiteeDesc,
                        count_from=lambda pkt: pkt.descs_count),
    ]

    def mysummary(self):
        return ", ".join(desc.sprintf("%src% > %dst%")
                         for desc in self.descs_list), [LLTD]


class LLTDRecveeDesc(Packet):
    name = "LLTD - Recvee Desc"
    fields_desc = [
        ShortEnumField("type", 0, {0: "Probe", 1: "ARP or ICMPv6"}),
        MACField("real_src", ETHER_ANY),
        MACField("ether_src", ETHER_ANY),
        MACField("ether_dst", ETHER_ANY),
    ]


class LLTDQueryResp(Packet):
    name = "LLTD - Query Response"
    fields_desc = [
        FlagsField("flags", 0, 2, "ME"),
        BitField("descs_count", None, 14),
        PacketListField("descs_list", [], LLTDRecveeDesc,
                        count_from=lambda pkt: pkt.descs_count),
    ]

    def post_build(self, pkt, pay):
        if self.descs_count is None:
            # descs_count should be a FieldLenField but has an
            # unsupported format (14 bits)
            flags = orb(pkt[0]) & 0xc0
            count = len(self.descs_list)
            pkt = chb(flags + (count >> 8)) + chb(count % 256) + pkt[2:]
        return pkt + pay

    def mysummary(self):
        return self.sprintf("%d response%s" % (
            self.descs_count,
            "s" if self.descs_count > 1 else "")), [LLTD]


class LLTDQueryLargeTlv(Packet):
    name = "LLTD - Query Large Tlv"
    fields_desc = [
        ByteEnumField("type", 14, {
            14: "Icon image",
            17: "Friendly Name",
            19: "Hardware ID",
            22: "AP Association Table",
            24: "Detailed Icon Image",
            26: "Component Table",
            28: "Repeater AP Table",
        }),
        ThreeBytesField("offset", 0),
    ]

    def mysummary(self):
        return self.sprintf("%type% (offset %offset%)"), [LLTD]


class LLTDQueryLargeTlvResp(Packet):
    name = "LLTD - Query Large Tlv Response"
    fields_desc = [
        FlagsField("flags", 0, 2, "RM"),
        BitField("len", None, 14),
        StrLenField("value", "", length_from=lambda pkt: pkt.len)
    ]

    def post_build(self, pkt, pay):
        if self.len is None:
            # len should be a FieldLenField but has an unsupported
            # format (14 bits)
            flags = orb(pkt[0]) & 0xc0
            length = len(self.value)
            pkt = chb(flags + (length >> 8)) + chb(length % 256) + pkt[2:]
        return pkt + pay

    def mysummary(self):
        return self.sprintf("%%len%% bytes%s" % (
            " (last)" if not self.flags & 2 else ""
        )), [LLTD]


class LLTDAttribute(Packet):
    name = "LLTD Attribute"
    show_indent = False
    show_summary = False
    # section 2.2.1.1
    fields_desc = [
        ByteEnumField("type", 0, {
            0: "End Of Property",
            1: "Host ID",
            2: "Characteristics",
            3: "Physical Medium",
            7: "IPv4 Address",
            9: "802.11 Max Rate",
            10: "Performance Counter Frequency",
            12: "Link Speed",
            14: "Icon Image",
            15: "Machine Name",
            18: "Device UUID",
            20: "QoS Characteristics",
            21: "802.11 Physical Medium",
            24: "Detailed Icon Image",
        }),
        FieldLenField("len", None, length_of="value", fmt="B"),
        StrLenField("value", "", length_from=lambda pkt: pkt.len),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *_, **kargs):
        if _pkt:
            cmd = orb(_pkt[0])
        elif "type" in kargs:
            cmd = kargs["type"]
            if isinstance(cmd, str):
                cmd = cls.fields_desc[0].s2i[cmd]
        else:
            return cls
        return SPECIFIC_CLASSES.get(cmd, cls)


SPECIFIC_CLASSES = {}


def _register_lltd_specific_class(*attr_types):
    """This can be used as a class decorator; if we want to support Python
    2.5, we have to replace

@_register_lltd_specific_class(x[, y[, ...]])
class LLTDAttributeSpecific(LLTDAttribute):
[...]

by

class LLTDAttributeSpecific(LLTDAttribute):
[...]
LLTDAttributeSpecific = _register_lltd_specific_class(x[, y[, ...]])(
    LLTDAttributeSpecific
)

    """
    def _register(cls):
        for attr_type in attr_types:
            SPECIFIC_CLASSES[attr_type] = cls
        type_fld = LLTDAttribute.fields_desc[0].copy()
        type_fld.default = attr_types[0]
        cls.fields_desc = [type_fld] + cls.fields_desc
        return cls
    return _register


@_register_lltd_specific_class(0)
class LLTDAttributeEOP(LLTDAttribute):
    name = "LLTD Attribute - End Of Property"
    fields_desc = []


@_register_lltd_specific_class(1)
class LLTDAttributeHostID(LLTDAttribute):
    name = "LLTD Attribute - Host ID"
    fields_desc = [
        ByteField("len", 6),
        MACField("mac", ETHER_ANY),
    ]

    def mysummary(self):
        return "ID: %s" % self.mac, [LLTD, LLTDAttributeMachineName]


@_register_lltd_specific_class(2)
class LLTDAttributeCharacteristics(LLTDAttribute):
    name = "LLTD Attribute - Characteristics"
    fields_desc = [
        # According to MS doc, "this field MUST be set to 0x02". But
        # according to MS implementation, that's wrong.
        # ByteField("len", 2),
        FieldLenField("len", None, length_of="reserved2", fmt="B",
                      adjust=lambda _, x: x + 2),
        FlagsField("flags", 0, 5, "PXFML"),
        BitField("reserved1", 0, 11),
        StrLenField("reserved2", "", length_from=lambda x: x.len - 2)
    ]


@_register_lltd_specific_class(3)
class LLTDAttributePhysicalMedium(LLTDAttribute):
    name = "LLTD Attribute - Physical Medium"
    fields_desc = [
        ByteField("len", 4),
        IntEnumField("medium", 6, {
            # https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
            1: "other",
            2: "regular1822",
            3: "hdh1822",
            4: "ddnX25",
            5: "rfc877x25",
            6: "ethernetCsmacd",
            7: "iso88023Csmacd",
            8: "iso88024TokenBus",
            9: "iso88025TokenRing",
            10: "iso88026Man",
            11: "starLan",
            12: "proteon10Mbit",
            13: "proteon80Mbit",
            14: "hyperchannel",
            15: "fddi",
            16: "lapb",
            17: "sdlc",
            18: "ds1",
            19: "e1",
            20: "basicISDN",
            21: "primaryISDN",
            22: "propPointToPointSerial",
            23: "ppp",
            24: "softwareLoopback",
            25: "eon",
            26: "ethernet3Mbit",
            27: "nsip",
            28: "slip",
            29: "ultra",
            30: "ds3",
            31: "sip",
            32: "frameRelay",
            33: "rs232",
            34: "para",
            35: "arcnet",
            36: "arcnetPlus",
            37: "atm",
            38: "miox25",
            39: "sonet",
            40: "x25ple",
            41: "iso88022llc",
            42: "localTalk",
            43: "smdsDxi",
            44: "frameRelayService",
            45: "v35",
            46: "hssi",
            47: "hippi",
            48: "modem",
            49: "aal5",
            50: "sonetPath",
            51: "sonetVT",
            52: "smdsIcip",
            53: "propVirtual",
            54: "propMultiplexor",
            55: "ieee80212",
            56: "fibreChannel",
            57: "hippiInterface",
            58: "frameRelayInterconnect",
            59: "aflane8023",
            60: "aflane8025",
            61: "cctEmul",
            62: "fastEther",
            63: "isdn",
            64: "v11",
            65: "v36",
            66: "g703at64k",
            67: "g703at2mb",
            68: "qllc",
            69: "fastEtherFX",
            70: "channel",
            71: "ieee80211",
            72: "ibm370parChan",
            73: "escon",
            74: "dlsw",
            75: "isdns",
            76: "isdnu",
            77: "lapd",
            78: "ipSwitch",
            79: "rsrb",
            80: "atmLogical",
            81: "ds0",
            82: "ds0Bundle",
            83: "bsc",
            84: "async",
            85: "cnr",
            86: "iso88025Dtr",
            87: "eplrs",
            88: "arap",
            89: "propCnls",
            90: "hostPad",
            91: "termPad",
            92: "frameRelayMPI",
            93: "x213",
            94: "adsl",
            95: "radsl",
            96: "sdsl",
            97: "vdsl",
            98: "iso88025CRFPInt",
            99: "myrinet",
            100: "voiceEM",
            101: "voiceFXO",
            102: "voiceFXS",
            103: "voiceEncap",
            104: "voiceOverIp",
            105: "atmDxi",
            106: "atmFuni",
            107: "atmIma",
            108: "pppMultilinkBundle",
            109: "ipOverCdlc",
            110: "ipOverClaw",
            111: "stackToStack",
            112: "virtualIpAddress",
            113: "mpc",
            114: "ipOverAtm",
            115: "iso88025Fiber",
            116: "tdlc",
            117: "gigabitEthernet",
            118: "hdlc",
            119: "lapf",
            120: "v37",
            121: "x25mlp",
            122: "x25huntGroup",
            123: "transpHdlc",
            124: "interleave",
            125: "fast",
            126: "ip",
            127: "docsCableMaclayer",
            128: "docsCableDownstream",
            129: "docsCableUpstream",
            130: "a12MppSwitch",
            131: "tunnel",
            132: "coffee",
            133: "ces",
            134: "atmSubInterface",
            135: "l2vlan",
            136: "l3ipvlan",
            137: "l3ipxvlan",
            138: "digitalPowerline",
            139: "mediaMailOverIp",
            140: "dtm",
            141: "dcn",
            142: "ipForward",
            143: "msdsl",
            144: "ieee1394",
            145: "if-gsn",
            146: "dvbRccMacLayer",
            147: "dvbRccDownstream",
            148: "dvbRccUpstream",
            149: "atmVirtual",
            150: "mplsTunnel",
            151: "srp",
            152: "voiceOverAtm",
            153: "voiceOverFrameRelay",
            154: "idsl",
            155: "compositeLink",
            156: "ss7SigLink",
            157: "propWirelessP2P",
            158: "frForward",
            159: "rfc1483",
            160: "usb",
            161: "ieee8023adLag",
            162: "bgppolicyaccounting",
            163: "frf16MfrBundle",
            164: "h323Gatekeeper",
            165: "h323Proxy",
            166: "mpls",
            167: "mfSigLink",
            168: "hdsl2",
            169: "shdsl",
            170: "ds1FDL",
            171: "pos",
            172: "dvbAsiIn",
            173: "dvbAsiOut",
            174: "plc",
            175: "nfas",
            176: "tr008",
            177: "gr303RDT",
            178: "gr303IDT",
            179: "isup",
            180: "propDocsWirelessMaclayer",
            181: "propDocsWirelessDownstream",
            182: "propDocsWirelessUpstream",
            183: "hiperlan2",
            184: "propBWAp2Mp",
            185: "sonetOverheadChannel",
            186: "digitalWrapperOverheadChannel",
            187: "aal2",
            188: "radioMAC",
            189: "atmRadio",
            190: "imt",
            191: "mvl",
            192: "reachDSL",
            193: "frDlciEndPt",
            194: "atmVciEndPt",
            195: "opticalChannel",
            196: "opticalTransport",
            197: "propAtm",
            198: "voiceOverCable",
            199: "infiniband",
            200: "teLink",
            201: "q2931",
            202: "virtualTg",
            203: "sipTg",
            204: "sipSig",
            205: "docsCableUpstreamChannel",
            206: "econet",
            207: "pon155",
            208: "pon622",
            209: "bridge",
            210: "linegroup",
            211: "voiceEMFGD",
            212: "voiceFGDEANA",
            213: "voiceDID",
            214: "mpegTransport",
            215: "sixToFour",
            216: "gtp",
            217: "pdnEtherLoop1",
            218: "pdnEtherLoop2",
            219: "opticalChannelGroup",
            220: "homepna",
            221: "gfp",
            222: "ciscoISLvlan",
            223: "actelisMetaLOOP",
            224: "fcipLink",
            225: "rpr",
            226: "qam",
            227: "lmp",
            228: "cblVectaStar",
            229: "docsCableMCmtsDownstream",
            230: "adsl2",
            231: "macSecControlledIF",
            232: "macSecUncontrolledIF",
            233: "aviciOpticalEther",
            234: "atmbond",
            235: "voiceFGDOS",
            236: "mocaVersion1",
            237: "ieee80216WMAN",
            238: "adsl2plus",
            239: "dvbRcsMacLayer",
            240: "dvbTdm",
            241: "dvbRcsTdma",
            242: "x86Laps",
            243: "wwanPP",
            244: "wwanPP2",
            245: "voiceEBS",
            246: "ifPwType",
            247: "ilan",
            248: "pip",
            249: "aluELP",
            250: "gpon",
            251: "vdsl2",
            252: "capwapDot11Profile",
            253: "capwapDot11Bss",
            254: "capwapWtpVirtualRadio",
            255: "bits",
            256: "docsCableUpstreamRfPort",
            257: "cableDownstreamRfPort",
            258: "vmwareVirtualNic",
            259: "ieee802154",
            260: "otnOdu",
            261: "otnOtu",
            262: "ifVfiType",
            263: "g9981",
            264: "g9982",
            265: "g9983",
            266: "aluEpon",
            267: "aluEponOnu",
            268: "aluEponPhysicalUni",
            269: "aluEponLogicalLink",
            271: "aluGponPhysicalUni",
            272: "vmwareNicTeam",
            277: "docsOfdmDownstream",
            278: "docsOfdmaUpstream",
            279: "gfast",
            280: "sdci",
        }),
    ]


@_register_lltd_specific_class(7)
class LLTDAttributeIPv4Address(LLTDAttribute):
    name = "LLTD Attribute - IPv4 Address"
    fields_desc = [
        ByteField("len", 4),
        IPField("ipv4", "0.0.0.0"),
    ]


@_register_lltd_specific_class(8)
class LLTDAttributeIPv6Address(LLTDAttribute):
    name = "LLTD Attribute - IPv6 Address"
    fields_desc = [
        ByteField("len", 16),
        IP6Field("ipv6", "::"),
    ]


@_register_lltd_specific_class(9)
class LLTDAttribute80211MaxRate(LLTDAttribute):
    name = "LLTD Attribute - 802.11 Max Rate"
    fields_desc = [
        ByteField("len", 2),
        ShortField("rate", 0),
    ]


@_register_lltd_specific_class(10)
class LLTDAttributePerformanceCounterFrequency(LLTDAttribute):
    name = "LLTD Attribute - Performance Counter Frequency"
    fields_desc = [
        ByteField("len", 8),
        LongField("freq", 0),
    ]


@_register_lltd_specific_class(12)
class LLTDAttributeLinkSpeed(LLTDAttribute):
    name = "LLTD Attribute - Link Speed"
    fields_desc = [
        ByteField("len", 4),
        IntField("speed", 0),
    ]


@_register_lltd_specific_class(14, 24, 26)
class LLTDAttributeLargeTLV(LLTDAttribute):
    name = "LLTD Attribute - Large TLV"
    fields_desc = [
        ByteField("len", 0),
    ]


@_register_lltd_specific_class(15)
class LLTDAttributeMachineName(LLTDAttribute):
    name = "LLTD Attribute - Machine Name"
    fields_desc = [
        FieldLenField("len", None, length_of="hostname", fmt="B"),
        StrLenFieldUtf16("hostname", "", length_from=lambda pkt: pkt.len),
    ]

    def mysummary(self):
        return (f"Hostname: {self.hostname!r}",
                [LLTD, LLTDAttributeHostID])


@_register_lltd_specific_class(18)
class LLTDAttributeDeviceUUID(LLTDAttribute):
    name = "LLTD Attribute - Device UUID"
    fields_desc = [
        FieldLenField("len", None, length_of="uuid", fmt="B"),
        StrLenField("uuid", b"\x00" * 16, length_from=lambda pkt: pkt.len),
    ]


@_register_lltd_specific_class(20)
class LLTDAttributeQOSCharacteristics(LLTDAttribute):
    name = "LLTD Attribute - QoS Characteristics"
    fields_desc = [
        ByteField("len", 4),
        FlagsField("flags", 0, 3, "EQP"),
        BitField("reserved1", 0, 13),
        ShortField("reserved2", 0),
    ]


@_register_lltd_specific_class(21)
class LLTDAttribute80211PhysicalMedium(LLTDAttribute):
    name = "LLTD Attribute - 802.11 Physical Medium"
    fields_desc = [
        ByteField("len", 1),
        ByteEnumField("medium", 0, {
            0: "Unknown",
            1: "FHSS 2.4 GHz",
            2: "DSSS 2.4 GHz",
            3: "IR Baseband",
            4: "OFDM 5 GHz",
            5: "HRDSSS",
            6: "ERP",
        }),
    ]


@_register_lltd_specific_class(25)
class LLTDAttributeSeesList(LLTDAttribute):
    name = "LLTD Attribute - Sees List Working Set"
    fields_desc = [
        ByteField("len", 2),
        ShortField("max_entries", 0),
    ]


bind_layers(Ether, LLTD, type=0x88d9)
bind_layers(LLTD, LLTDDiscover, tos=0, function=0)
bind_layers(LLTD, LLTDDiscover, tos=1, function=0)
bind_layers(LLTD, LLTDHello, tos=0, function=1)
bind_layers(LLTD, LLTDHello, tos=1, function=1)
bind_layers(LLTD, LLTDEmit, tos=0, function=2)
bind_layers(LLTD, LLTDQueryResp, tos=0, function=7)
bind_layers(LLTD, LLTDQueryLargeTlv, tos=0, function=11)
bind_layers(LLTD, LLTDQueryLargeTlvResp, tos=0, function=12)
bind_layers(LLTDHello, LLTDAttribute)
bind_layers(LLTDAttribute, LLTDAttribute)
bind_layers(LLTDAttribute, Padding, type=0)
bind_layers(LLTDEmiteeDesc, Padding)
bind_layers(LLTDRecveeDesc, Padding)


# Utils
########

class LargeTlvBuilder(object):
    """An object to build content fetched through LLTDQueryLargeTlv /
    LLTDQueryLargeTlvResp packets.

    Usable with a PacketList() object:
    >>> p = LargeTlvBuilder()
    >>> p.parse(rdpcap('capture_file.cap'))

    Or during a network capture:
    >>> p = LargeTlvBuilder()
    >>> sniff(filter="ether proto 0x88d9", prn=p.parse)

    To get the result, use .get_data()

    """

    def __init__(self):
        self.types_offsets = {}
        self.data = {}

    def parse(self, plist):
        """Update the builder using the provided `plist`. `plist` can
        be either a Packet() or a PacketList().

        """
        if not isinstance(plist, PacketList):
            plist = PacketList(plist)
        for pkt in plist[LLTD]:
            if LLTDQueryLargeTlv in pkt:
                key = "%s:%s:%d" % (pkt.real_dst, pkt.real_src, pkt.seq)
                self.types_offsets[key] = (pkt[LLTDQueryLargeTlv].type,
                                           pkt[LLTDQueryLargeTlv].offset)
            elif LLTDQueryLargeTlvResp in pkt:
                try:
                    key = "%s:%s:%d" % (pkt.real_src, pkt.real_dst, pkt.seq)
                    content, offset = self.types_offsets[key]
                except KeyError:
                    continue
                loc = slice(offset, offset + pkt[LLTDQueryLargeTlvResp].len)
                key = "%s > %s [%s]" % (
                    pkt.real_src, pkt.real_dst,
                    LLTDQueryLargeTlv.fields_desc[0].i2s.get(content, content),
                )
                data = self.data.setdefault(key, array("B"))
                datalen = len(data)
                if datalen < loc.stop:
                    data.extend(array("B", b"\x00" * (loc.stop - datalen)))
                data[loc] = array("B", pkt[LLTDQueryLargeTlvResp].value)

    def get_data(self):
        """Returns a dictionary object, keys are strings "source >
        destincation [content type]", and values are the content
        fetched, also as a string.

        """
        return {key: "".join(chr(byte) for byte in data)
                for key, data in self.data.items()}
