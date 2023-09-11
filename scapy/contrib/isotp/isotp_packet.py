# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = ISO-TP (ISO 15765-2) Packet Definitions
# scapy.contrib.status = library

import struct
import logging

from scapy.config import conf
from scapy.packet import Packet
from scapy.fields import BitField, FlagsField, StrLenField, \
    ThreeBytesField, XBitField, ConditionalField, \
    BitEnumField, ByteField, XByteField, BitFieldLenField, StrField, \
    FieldLenField, IntField, ShortField
from scapy.compat import chb, orb
from scapy.layers.can import CAN, CAN_FD_MAX_DLEN as CAN_FD_MAX_DLEN
from scapy.error import Scapy_Exception

# Typing imports
from typing import (
    Optional,
    List,
    Tuple,
    Any,
    Type,
    cast,
)

log_isotp = logging.getLogger("scapy.contrib.isotp")

CAN_MAX_IDENTIFIER = (1 << 29) - 1  # Maximum 29-bit identifier
CAN_MTU = 16
CAN_MAX_DLEN = 8
ISOTP_MAX_DLEN_2015 = (1 << 32) - 1  # Maximum for 32-bit FF_DL
ISOTP_MAX_DLEN = (1 << 12) - 1  # Maximum for 12-bit FF_DL
ISOTP_TYPES = {0: 'single',
               1: 'first',
               2: 'consecutive',
               3: 'flow_control'}

N_PCI_SF = 0x00  # /* single frame */
N_PCI_FF = 0x10  # /* first frame */
N_PCI_CF = 0x20  # /* consecutive frame */
N_PCI_FC = 0x30  # /* flow control */


class ISOTP(Packet):
    """Packet class for ISOTP messages. This class contains additional
    slots for source address (tx_id), destination address (rx_id),
    extended source address (ext_address) and
    extended destination address (rx_ext_address) information. This information
    gets filled from ISOTPSockets or the ISOTPMessageBuilder, if it
    is available. Address information is not used for Packet comparison.

    :param args: Arguments for Packet init, for example bytes string
    :param kwargs: Keyword arguments for Packet init.
    """
    name = 'ISOTP'
    fields_desc = [
        StrField('data', b"")
    ]
    __slots__ = Packet.__slots__ + ["tx_id", "rx_id", "ext_address", "rx_ext_address"]  # noqa: E501

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        self.tx_id = kwargs.pop("tx_id", None)  # type: Optional[int]
        self.rx_id = kwargs.pop("rx_id", None)  # type: Optional[int]
        self.ext_address = kwargs.pop("ext_address", None)  # type: Optional[int]  # noqa: E501
        self.rx_ext_address = kwargs.pop("rx_ext_address", None)  # type: Optional[int]  # noqa: E501
        Packet.__init__(self, *args, **kwargs)
        self.validate_fields()

    def validate_fields(self):
        # type: () -> None
        """Helper function to validate information in tx_id, rx_id,
        ext_address and rx_ext_address slots
        """
        if self.tx_id is not None:
            if not 0 <= self.tx_id <= CAN_MAX_IDENTIFIER:
                raise Scapy_Exception("tx_id is not a valid CAN identifier")
        if self.rx_id is not None:
            if not 0 <= self.rx_id <= CAN_MAX_IDENTIFIER:
                raise Scapy_Exception("rx_id is not a valid CAN identifier")
        if self.ext_address is not None:
            if not 0 <= self.ext_address <= 0xff:
                raise Scapy_Exception("ext_address is not a byte")
        if self.rx_ext_address is not None:
            if not 0 <= self.rx_ext_address <= 0xff:
                raise Scapy_Exception("rx_ext_address is not a byte")

    def fragment(self, *args, **kargs):
        # type: (*Any, **Any) -> List[Packet]
        """Helper function to fragment an ISOTP message into multiple
        CAN frames.

        :param fd: type: Optional[bool]: will fragment the can frames
            with size CAN_FD_MAX_DLEN

        :return: A list of CAN frames
        """

        fd = kargs.pop("fd", False)

        def _get_data_len():
            # type: () -> int
            return CAN_MAX_DLEN if not fd else CAN_FD_MAX_DLEN

        data_bytes_in_frame = _get_data_len() - 1
        if self.rx_ext_address is not None:
            data_bytes_in_frame = data_bytes_in_frame - 1

        if len(self.data) > ISOTP_MAX_DLEN_2015:
            raise Scapy_Exception("Too much data in ISOTP message")

        if len(self.data) <= data_bytes_in_frame:
            # We can do this in a single frame
            frame_data = struct.pack('B', len(self.data)) + self.data
            if self.rx_ext_address:
                frame_data = struct.pack('B', self.rx_ext_address) + frame_data

            if self.rx_id is None or self.rx_id <= 0x7ff:
                pkt = CAN(identifier=self.rx_id, data=frame_data)
            else:
                pkt = CAN(identifier=self.rx_id, flags="extended",
                          data=frame_data)
            return [pkt]

        # Construct the first frame
        if len(self.data) <= ISOTP_MAX_DLEN:
            frame_header = struct.pack(">H", len(self.data) + 0x1000)
        else:
            frame_header = struct.pack(">HI", 0x1000, len(self.data))
        if self.rx_ext_address:
            frame_header = struct.pack('B', self.rx_ext_address) + frame_header
        idx = _get_data_len() - len(frame_header)
        frame_data = self.data[0:idx]
        if self.rx_id is None or self.rx_id <= 0x7ff:
            frame = CAN(identifier=self.rx_id, data=frame_header + frame_data)
        else:
            frame = CAN(identifier=self.rx_id, flags="extended",
                        data=frame_header + frame_data)

        # Construct consecutive frames
        n = 1
        pkts = [frame]
        while idx < len(self.data):
            frame_data = self.data[idx:idx + data_bytes_in_frame]
            frame_header = struct.pack("b", (n % 16) + N_PCI_CF)

            n += 1
            idx += len(frame_data)

            if self.rx_ext_address:
                frame_header = struct.pack('B', self.rx_ext_address) + frame_header  # noqa: E501
            if self.rx_id is None or self.rx_id <= 0x7ff:
                pkt = CAN(identifier=self.rx_id, data=frame_header + frame_data)  # noqa: E501
            else:
                pkt = CAN(identifier=self.rx_id, flags="extended",
                          data=frame_header + frame_data)
            pkts.append(pkt)
        return cast(List[Packet], pkts)

    @staticmethod
    def defragment(can_frames, use_extended_addressing=None):
        # type: (List[Packet], Optional[bool]) -> Optional[ISOTP]
        """Helper function to defragment a list of CAN frames to one ISOTP
        message

        :param can_frames: A list of CAN frames
        :param use_extended_addressing: Specify if extended ISO-TP addressing
                                        is used in the packets for
                                        defragmentation.
        :return: An ISOTP message containing the data of the CAN frames or None
        """
        from scapy.contrib.isotp.isotp_utils import ISOTPMessageBuilder

        if len(can_frames) == 0:
            raise Scapy_Exception("ISOTP.defragment called with 0 frames")

        dst = can_frames[0].identifier
        if any(frame.identifier != dst for frame in can_frames):
            log_isotp.warning("Not all CAN frames have the same identifier")

        parser = ISOTPMessageBuilder(use_extended_addressing)
        parser.feed(can_frames)

        results = []
        for p in parser:
            if (use_extended_addressing is True and
                p.rx_ext_address is not None) \
                    or (use_extended_addressing is False and
                        p.rx_ext_address is None) \
                    or (use_extended_addressing is None):
                results.append(p)

        if not results:
            return None

        if len(results) > 1:
            log_isotp.warning(
                "More than one ISOTP frame could be defragmented from the "
                "provided CAN frames, only returning the first one.")

        return results[0]


class ISOTPHeader(CAN):
    name = 'ISOTPHeader'
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        ByteField('length', None),
        ThreeBytesField('reserved', 0)
    ]

    def extract_padding(self, p):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return p, None

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """
        This will set the ByteField 'length' to the correct value.
        """
        if self.length is None:
            pkt = pkt[:4] + chb(len(pay)) + pkt[5:]

        if conf.contribs['CAN']['swap-bytes']:
            data = CAN.inv_endianness(pkt)  # type: bytes
            return data + pay
        return pkt + pay

    def guess_payload_class(self, payload):
        # type: (bytes) -> Type[Packet]
        """ISO-TP encodes the frame type in the first nibble of a frame. This
        is used to determine the payload_class

        :param payload: payload bytes string
        :return: Type of payload class
        """
        if len(payload) < 1:
            return self.default_payload_class(payload)

        t = (orb(payload[0]) & 0xf0) >> 4
        if t == 0:
            length = (orb(payload[0]) & 0x0f)
            if length == 0:
                return ISOTP_SF_FD
            else:
                return ISOTP_SF
        elif t == 1:
            if len(payload) < 2:
                return self.default_payload_class(payload)
            length = ((orb(payload[0]) & 0x0f) << 12) + orb(payload[1])
            if length == 0:
                return ISOTP_FF_FD
            else:
                return ISOTP_FF
        elif t == 2:
            return ISOTP_CF
        else:
            return ISOTP_FC


class ISOTPHeader_FD(ISOTPHeader):
    name = 'ISOTPHeaderFD'
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        ByteField('length', None),
        FlagsField('fd_flags', 4, 8, ['bit_rate_switch',
                                      'error_state_indicator',
                                      'fd_frame']),
        ShortField('reserved', 0),
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes

        data = super().post_build(pkt, pay)

        length = data[4]

        if 8 < length <= 24:
            wire_length = length + (-length) % 4
        elif 24 < length <= 64:
            wire_length = length + (-length) % 8
        elif length > 64:
            raise NotImplementedError
        else:
            wire_length = length

        pad = b"\x00" * (wire_length - length)

        return data[0:4] + chb(wire_length) + data[5:] + pad


class ISOTPHeaderEA(ISOTPHeader):
    name = 'ISOTPHeaderExtendedAddress'
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        ByteField('length', None),
        ThreeBytesField('reserved', 0),
        XByteField('extended_address', 0)
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """
        This will set the ByteField 'length' to the correct value.
        'chb(len(pay) + 1)' is required, because the field 'extended_address'
        is counted as payload on the CAN layer
        """
        if self.length is None:
            pkt = pkt[:4] + chb(len(pay) + 1) + pkt[5:]

        if conf.contribs['CAN']['swap-bytes']:
            data = CAN.inv_endianness(pkt)  # type: bytes
            return data + pay
        return pkt + pay


class ISOTPHeaderEA_FD(ISOTPHeaderEA):
    name = 'ISOTPHeaderExtendedAddressFD'
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        ByteField('length', None),
        FlagsField('fd_flags', 4, 8, ['bit_rate_switch',
                                      'error_state_indicator',
                                      'fd_frame']),
        ShortField('reserved', 0),
        XByteField('extended_address', 0)
    ]

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes

        data = super().post_build(pkt, pay)

        length = data[4]

        if 8 < length <= 24:
            wire_length = length + (-length) % 4
        elif 24 < length <= 64:
            wire_length = length + (-length) % 8
        elif length > 64:
            raise NotImplementedError
        else:
            wire_length = length

        pad = b"\x00" * (wire_length - length)

        return data[0:4] + chb(wire_length) + data[5:] + pad


ISOTP_TYPE = {0: 'single',
              1: 'first',
              2: 'consecutive',
              3: 'flow_control'}


class ISOTP_SF(Packet):
    name = 'ISOTPSingleFrame'
    fields_desc = [
        BitEnumField('type', 0, 4, ISOTP_TYPE),
        BitFieldLenField('message_size', None, 4, length_of='data'),
        StrLenField('data', b'', length_from=lambda pkt: pkt.message_size)
    ]


class ISOTP_SF_FD(Packet):
    name = 'ISOTPSingleFrameFD'
    fields_desc = [
        BitEnumField('type', 0, 4, ISOTP_TYPE),
        BitField('zero_field', 0, 4),
        FieldLenField('message_size', None, length_of='data', fmt="B"),
        StrLenField('data', b'', length_from=lambda pkt: pkt.message_size)
    ]


class ISOTP_FF(Packet):
    name = 'ISOTPFirstFrame'
    fields_desc = [
        BitEnumField('type', 1, 4, ISOTP_TYPE),
        BitField('message_size', 0, 12),
        ConditionalField(IntField('extended_message_size', 0),
                         lambda pkt: pkt.message_size == 0),
        StrField('data', b'', fmt="B")
    ]


class ISOTP_FF_FD(Packet):
    name = 'ISOTPFirstFrame'
    fields_desc = [
        BitEnumField('type', 1, 4, ISOTP_TYPE),
        BitField('zero_field', 0, 12),
        IntField('message_size', 0),
        StrField('data', b'', fmt="B")
    ]


class ISOTP_CF(Packet):
    name = 'ISOTPConsecutiveFrame'
    fields_desc = [
        BitEnumField('type', 2, 4, ISOTP_TYPE),
        BitField('index', 0, 4),
        StrField('data', b'', fmt="B")
    ]


class ISOTP_FC(Packet):
    name = 'ISOTPFlowControlFrame'
    fields_desc = [
        BitEnumField('type', 3, 4, ISOTP_TYPE),
        BitEnumField('fc_flag', 0, 4, {0: 'continue',
                                       1: 'wait',
                                       2: 'abort'}),
        ByteField('block_size', 0),
        ByteField('separation_time', 0),
    ]
