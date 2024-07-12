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
from scapy.contrib.automotive.autosar.pdu import PDU
from scapy.fields import (XByteField, XIntField, PacketListField,
                          FieldLenField, XStrFixedLenField)
from scapy.packet import Packet, Raw

# Typing imports
from typing import (
    Any,
    Optional,
    Tuple,
    Type,
)


class SecOC_PDU(Packet, SecOCMixin):
    name = 'SecOC_PDU'
    fields_desc = [
        XIntField('pdu_id', 0),
        FieldLenField('pdu_payload_len', None,
                      fmt="I",
                      length_of="pdu_payload",
                      adjust=lambda pkt, x: x + 4),
        PduPayloadField('pdu_payload',
                        Raw(),
                        guess_pkt_cls=lambda pkt, data: SecOC_PDU.get_pdu_payload_cls(pkt, data),  # noqa: E501
                        length_from=lambda pkt: pkt.pdu_payload_len - 4),
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
        return self.pdu_payload

    @classmethod
    def dispatch_hook(cls, s=None, *_args, **_kwds):
        # type: (Optional[bytes], Any, Any) -> Packet_metaclass
        """dispatch_hook determines if PDU is protected by SecOC.
        If PDU is protected, SecOC_PDU will be returned, otherwise AutoSAR PDU
        will be returned.
        """
        if s is None:
            return SecOC_PDU
        if len(s) < 4:
            return Raw
        identifier = struct.unpack('>I', s[0:4])[0]
        if identifier in cls.secoc_protected_pdus_by_identifier:
            return SecOC_PDU
        else:
            return PDU

    @classmethod
    def get_pdu_payload_cls(cls,
                            pkt: Packet,
                            data: bytes
                            ) -> Packet:
        try:
            klass = cls.pdu_payload_cls_by_identifier[pkt.pdu_id]
        except KeyError:
            klass = conf.raw_layer
        return klass(data, _parent=pkt)

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return b"", s


class SecOC_PDUTransport(Packet):
    """
    Packet representing SecOC_PDUTransport containing multiple PDUs
    """

    name = 'SecOC_PDUTransport'
    fields_desc = [
        PacketListField("pdus", [SecOC_PDU()], pkt_cls=SecOC_PDU)
    ]

    @staticmethod
    def register_secoc_protected_pdu(pdu_id: int,
                                     pdu_payload_cls: Type[Packet] = Raw
                                     ) -> None:
        SecOC_PDU.register_secoc_protected_pdu(pdu_id, pdu_payload_cls)

    @staticmethod
    def unregister_secoc_protected_pdu(pdu_id: int) -> None:
        SecOC_PDU.unregister_secoc_protected_pdu(pdu_id)
