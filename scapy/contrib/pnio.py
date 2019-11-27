# coding: utf8
# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2016 Gauthier Sebaux

# scapy.contrib.description = ProfinetIO RTC (+Profisafe) layer
# scapy.contrib.status = loads
import copy
from scapy.compat import raw
from scapy.error import Scapy_Exception
from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from scapy.fields import (
    XShortEnumField, BitEnumField, XBitField,
    BitField, StrField, PacketListField,
    StrFixedLenField, ShortField,
    FlagsField, ByteField, XIntField, X3BytesField
)
from scapy.modules import six

PNIO_FRAME_IDS = {
    0x0020: "PTCP-RTSyncPDU-followup",
    0x0080: "PTCP-RTSyncPDU",
    0xFC01: "Alarm High",
    0xFE01: "Alarm Low",
    0xFEFC: "DCP-Hello-Req",
    0xFEFD: "DCP-Get-Set",
    0xFEFE: "DCP-Identify-ReqPDU",
    0xFEFF: "DCP-Identify-ResPDU",
    0xFF00: "PTCP-AnnouncePDU",
    0xFF20: "PTCP-FollowUpPDU",
    0xFF40: "PTCP-DelayReqPDU",
    0xFF41: "PTCP-DelayResPDU-followup",
    0xFF42: "PTCP-DelayFuResPDU",
    0xFF43: "PTCP-DelayResPDU",
}


def i2s_frameid(x):
    """ Get representation name of a pnio frame ID

    :param x: a key of the PNIO_FRAME_IDS dictionary
    :returns: str
    """
    try:
        return PNIO_FRAME_IDS[x]
    except KeyError:
        pass
    if 0x0100 <= x < 0x1000:
        return "RT_CLASS_3 (%4x)" % x
    if 0x8000 <= x < 0xC000:
        return "RT_CLASS_1 (%4x)" % x
    if 0xC000 <= x < 0xFC00:
        return "RT_CLASS_UDP (%4x)" % x
    if 0xFF80 <= x < 0xFF90:
        return "FragmentationFrameID (%4x)" % x
    return x


def s2i_frameid(x):
    """ Get pnio frame ID from a representation name

    Performs a reverse look-up in PNIO_FRAME_IDS dictionary

    :param x: a value of PNIO_FRAME_IDS dict
    :returns: integer
    """
    try:
        return {
            "RT_CLASS_3": 0x0100,
            "RT_CLASS_1": 0x8000,
            "RT_CLASS_UDP": 0xC000,
            "FragmentationFrameID": 0xFF80,
        }[x]
    except KeyError:
        pass
    try:
        return next(key for key, value in six.iteritems(PNIO_FRAME_IDS)
                    if value == x)
    except StopIteration:
        pass
    return x


#################
#  PROFINET IO  #
#################

class ProfinetIO(Packet):
    """ Basic PROFINET IO dispatcher """
    fields_desc = [
        XShortEnumField("frameID", 0, (i2s_frameid, s2i_frameid))
    ]

    def guess_payload_class(self, payload):
        # For frameID in the RT_CLASS_* range, use the RTC packet as payload
        if self.frameID in [0xfefe, 0xfeff, 0xfefd]:
            from scapy.contrib.pnio_dcp import ProfinetDCP
            return ProfinetDCP
        elif (
                (0x0100 <= self.frameID < 0x1000) or
                (0x8000 <= self.frameID < 0xFC00)


        ):
            return PNIORealTimeCyclicPDU
        return super(ProfinetIO, self).guess_payload_class(payload)


bind_layers(Ether, ProfinetIO, type=0x8892)
bind_layers(UDP, ProfinetIO, dport=0x8892)


#####################################
#  PROFINET Real-Time Data Packets  #
#####################################

conf.contribs["PNIO_RTC"] = {}


class PNIORealTime_IOxS(Packet):
    """ IOCS and IOPS packets for PROFINET Real-Time payload """
    name = "PNIO RTC IOxS"
    fields_desc = [
        # IOxS.DataState -- IEC-61158 - 6 - 10 / FDIS ED 3, Table 181
        BitEnumField("dataState", 1, 1, ["bad", "good"]),
        # IOxS.Instance -- IEC-61158 - 6 - 10 / FDIS ED 3, Table 180
        BitEnumField("instance", 0, 2,
                     ["subslot", "slot", "device", "controller"]),
        # IOxS.reserved -- IEC-61158 - 6 - 10 / FDIS ED 3, line 2649
        XBitField("reserved", 0, 4),
        # IOxS.Extension -- IEC-61158-6-10/FDIS ED 3, Table 179
        BitField("extension", 0, 1),
    ]

    @classmethod
    def is_extension_set(cls, _pkt, _lst, p, _remain):
        ret = cls if isinstance(p, type(None)) or p.extension != 0 else None
        return ret

    @classmethod
    def get_len(cls):
        return sum(type(fld).i2len(None, 0) for fld in cls.fields_desc)

    def guess_payload_class(self, p):
        return conf.padding_layer


class PNIORealTimeCyclicDefaultRawData(Packet):
    name = "PROFINET IO Real Time Cyclic Default Raw Data"
    fields_desc = [
        # 4 is the sum of the size of the CycleCounter + DataStatus
        #     + TransferStatus trailing from PNIORealTimeCyclicPDU
        StrField("data", '', remain=4)
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class PNIORealTimeCyclicPDU(Packet):
    """ PROFINET cyclic real-time """
    __slots__ = ["_len", "_layout"]
    name = "PROFINET Real-Time"

    fields_desc = [
        # C_SDU ^ CSF_SDU -- IEC-61158-6-10/FDIS ED 3, Table 163
        PacketListField(
            "data", [],
            next_cls_cb=lambda pkt, lst, p, remain: pkt.next_cls_cb(
                lst, p, remain)
        ),
        # RTCPadding -- IEC - 61158 - 6 - 10 / FDIS ED 3, Table 163
        StrFixedLenField("padding", '',
                         length_from=lambda p: p.get_padding_length()),
        # APDU_Status -- IEC-61158-6-10/FDIS ED 3, Table 164
        ShortField("cycleCounter", 0),
        FlagsField("dataStatus", 0x35, 8, [
            "primary",
            "redundancy",
            "validData",
            "reserved_1",
            "run",
            "no_problem",
            "reserved_2",
            "ignore",
        ]),
        ByteField("transferStatus", 0)
    ]

    def pre_dissect(self, s):
        # Constraint from IEC-61158-6-10/FDIS ED 3, line 690
        self._len = min(1440, len(s))
        return s

    def get_padding_length(self):
        if hasattr(self, "_len"):
            pad_len = (
                self._len -
                sum(len(raw(pkt)) for pkt in self.getfieldval("data")) -
                2 -  # Cycle Counter size (ShortField)
                1 -  # DataStatus size (FlagsField over 8 bits)
                1  # TransferStatus (ByteField)
            )
        else:
            pad_len = len(self.getfieldval("padding"))

        # Constraints from IEC-61158-6-10/FDIS ED 3, Table 163
        assert(0 <= pad_len <= 40)
        q = self
        while not isinstance(q, UDP) and hasattr(q, "underlayer"):
            q = q.underlayer
        if isinstance(q, UDP):
            assert(0 <= pad_len <= 12)
        return pad_len

    def next_cls_cb(self, _lst, _p, _remain):
        if hasattr(self, "_layout") and isinstance(self._layout, list):
            try:
                return self._layout.pop(0)
            except IndexError:
                self._layout = None
                return None

        ether_layer = None
        q = self
        while not isinstance(q, Ether) and hasattr(q, "underlayer"):
            q = q.underlayer
        if isinstance(q, Ether):
            ether_layer = q

        pnio_layer = None
        q = self
        while not isinstance(q, ProfinetIO) and hasattr(q, "underlayer"):
            q = q.underlayer
        if isinstance(q, ProfinetIO):
            pnio_layer = q

        self._layout = [PNIORealTimeCyclicDefaultRawData]
        if not (ether_layer is None and pnio_layer is None):
            # Get from config the layout for these hosts and frameid
            layout = type(self).get_layout_from_config(
                ether_layer.src,
                ether_layer.dst,
                pnio_layer.frameID)
            if not isinstance(layout, type(None)):
                self._layout = layout

        return self._layout.pop(0)

    @staticmethod
    def get_layout_from_config(ether_src, ether_dst, frame_id):
        try:
            return copy.deepcopy(
                conf.contribs["PNIO_RTC"][(ether_src, ether_dst, frame_id)]
            )
        except KeyError:
            return None

    @staticmethod
    def build_fixed_len_raw_type(length):
        return type(
            "FixedLenRawPacketLen{}".format(length),
            (conf.raw_layer,),
            {
                "name": "FixedLenRawPacketLen{}".format(length),
                "fields_desc": [StrFixedLenField("data", '', length=length)],
                "get_data_length": lambda _: length,
                "guess_payload_class": lambda self, p: conf.padding_layer,
            }
        )


# From IEC 61784-3-3 Ed. 3 PROFIsafe v.2.6, Figure 20
profisafe_control_flags = [
    "iPar_EN", "OA_Req", "R_cons_nr", "Use_TO2",
    "activate_FV", "Toggle_h", "ChF_Ack", "Loopcheck"
]
# From IEC 61784-3-3 Ed. 3 PROFIsafe v.2.6, Figure 19
profisafe_status_flags = [
    "iPar_OK", "Device_Fault/ChF_Ack_Req", "CE_CRC",
    "WD_timeout", "FV_activated", "Toggle_d", "cons_nr_R", "reserved"
]


class PROFIsafeCRCSeed(Packet):
    __slots__ = ["_len"] + Packet.__slots__

    def guess_payload_class(self, p):
        return conf.padding_layer

    def get_data_length(self):
        """ Must be overridden in a subclass to return the correct value """
        raise Scapy_Exception(
            "This method must be overridden in a specific subclass"
        )

    def get_mandatory_fields_len(self):
        # 5 is the len of the control/status byte + the CRC length
        return 5

    @staticmethod
    def get_max_data_length():
        # Constraints from IEC-61784-3-3 ED 3, Figure 18
        return 13


class PROFIsafeControlCRCSeed(PROFIsafeCRCSeed):
    name = "PROFISafe Control Message with F_CRC_Seed=1"
    fields_desc = [
        StrFixedLenField("data", '',
                         length_from=lambda p: p.get_data_length()),
        FlagsField("control", 0, 8, profisafe_control_flags),
        XIntField("crc", 0)
    ]


class PROFIsafeStatusCRCSeed(PROFIsafeCRCSeed):
    name = "PROFISafe Status Message with F_CRC_Seed=1"
    fields_desc = [
        StrFixedLenField("data", '',
                         length_from=lambda p: p.get_data_length()),
        FlagsField("status", 0, 8, profisafe_status_flags),
        XIntField("crc", 0)
    ]


class PROFIsafe(Packet):
    __slots__ = ["_len"] + Packet.__slots__

    def guess_payload_class(self, p):
        return conf.padding_layer

    def get_data_length(self):
        """ Must be overridden in a subclass to return the correct value """
        raise Scapy_Exception(
            "This method must be overridden in a specific subclass"
        )

    def get_mandatory_fields_len(self):
        # 4 is the len of the control/status byte + the CRC length
        return 4

    @staticmethod
    def get_max_data_length():
        # Constraints from IEC-61784-3-3 ED 3, Figure 18
        return 12

    @staticmethod
    def build_PROFIsafe_class(cls, data_length):
        assert(cls.get_max_data_length() >= data_length)
        return type(
            "{}Len{}".format(cls.__name__, data_length),
            (cls,),
            {
                "get_data_length": lambda _: data_length,
            }
        )


class PROFIsafeControl(PROFIsafe):
    name = "PROFISafe Control Message with F_CRC_Seed=0"
    fields_desc = [
        StrFixedLenField("data", '',
                         length_from=lambda p: p.get_data_length()),
        FlagsField("control", 0, 8, profisafe_control_flags),
        X3BytesField("crc", 0)
    ]


class PROFIsafeStatus(PROFIsafe):
    name = "PROFISafe Status Message with F_CRC_Seed=0"
    fields_desc = [
        StrFixedLenField("data", '',
                         length_from=lambda p: p.get_data_length()),
        FlagsField("status", 0, 8, profisafe_status_flags),
        X3BytesField("crc", 0)
    ]
