# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = AUTOSAR Secure On-Board Communication PDUs
# scapy.contrib.status = loads

"""
SecOC PDU
"""
import struct

from scapy.config import conf
from scapy.contrib.automotive.autosar.secoc import SecOCMixin, PduPayloadField
from scapy.base_classes import Packet_metaclass
from scapy.fields import (XByteField, FieldLenField, XStrFixedLenField,
                          FlagsField, XBitField, ShortField)
from scapy.layers.can import CANFD
from scapy.packet import Raw, Packet

# Typing imports
from typing import (
    Any,
    Optional,
    Tuple,
)


class SecOC_CANFD(CANFD, SecOCMixin):
    name = 'SecOC_CANFD'
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        XBitField('identifier', 0, 29),
        FieldLenField('length', None, length_of='pdu_payload',
                      fmt='B', adjust=lambda pkt, x: x + 4),
        FlagsField('fd_flags', 4, 8, [
            'bit_rate_switch', 'error_state_indicator', 'fd_frame']),
        ShortField('reserved', 0),
        PduPayloadField('pdu_payload',
                        Raw(),
                        guess_pkt_cls=lambda pkt, data: SecOC_CANFD.get_pdu_payload_cls(pkt, data),  # noqa: E501
                        length_from=lambda pkt: pkt.length - 4),
        XByteField("tfv", 0),  # truncated freshness value
        XStrFixedLenField("tmac", None, length=3)]  # truncated message authentication code # noqa: E501

    def secoc_authenticate(self) -> None:
        self.tfv = struct.unpack(">B", self.get_secoc_freshness_value()[-1:])[0]
        self.tmac = self.get_message_authentication_code()[0:3]

    def secoc_verify(self) -> bool:
        return self.get_message_authentication_code()[0:3] == self.tmac

    def get_secoc_payload(self) -> bytes:
        """Override this method for customization
        """
        return bytes(self.pdu_payload)

    @classmethod
    def dispatch_hook(cls, s=None, *_args, **_kwds):
        # type: (Optional[bytes], Any, Any) -> Packet_metaclass
        """dispatch_hook determines if PDU is protected by SecOC.
        If PDU is protected, SecOC_PDU will be returned, otherwise AutoSAR PDU
        will be returned.
        """
        if s is None:
            return SecOC_CANFD
        if len(s) < 4:
            return Raw
        identifier = struct.unpack('>I', s[0:4])[0] & 0x1FFFFFFF
        if identifier in cls.secoc_protected_pdus_by_identifier:
            return SecOC_CANFD
        else:
            return CANFD

    @classmethod
    def get_pdu_payload_cls(cls,
                            pkt: Packet,
                            data: bytes
                            ) -> Packet:
        try:
            klass = cls.pdu_payload_cls_by_identifier[pkt.identifier]
        except KeyError:
            klass = conf.raw_layer
        return klass(data, _parent=pkt)

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return b"", s
