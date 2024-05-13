# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = AUTOSAR Secure On-Board Communication
# scapy.contrib.status = loads

"""
SecOC
"""
from collections import defaultdict

from scapy.fields import (XByteField, X3BytesField, XIntField, PacketListField,
                          FieldLenField, PacketLenField)
from scapy.packet import Packet, Raw

# Typing imports
from typing import (
    Dict,
    Optional,
    Type,
    Callable,
    Union,
    Tuple
)


class PduPayloadField(PacketLenField):

    def __init__(self,
                 name,  # type: str
                 default,  # type: Packet
                 guess_pkt_cls,  # type: Union[Callable[[Packet, bytes], Packet], Type[Packet]]  # noqa: E501
                 length_from=None  # type: Optional[Callable[[Packet], int]]  # noqa: E501
                 ):
        # type: (...) -> None
        super(PacketLenField, self).__init__(name, default, guess_pkt_cls)
        self.length_from = length_from or (lambda x: 0)

    def m2i(self, pkt, m):  # type: ignore
        # type: (Optional[Packet], bytes) -> Packet
        try:
            # we want to set parent wherever possible
            return self.cls(self, m, _parent=pkt)  # type: ignore
        except TypeError:
            return self.cls(self, m)


class SecOC_PDU(Packet):
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
        XByteField("freshness_value", 0),
        X3BytesField("message_authentication_code", 0)]

    pdu_payload_cls_by_identifier: Dict[int, Type[Packet]] = {}
    freshness_values_by_identifier: Dict[int, int] = defaultdict(int)
    secret_keys_by_identifier: Dict[int, bytes] = {}

    def post_dissect(self, s):  # type: (bytes) -> bytes
        try:
            SecOC_PDU.freshness_values_by_identifier[self.pdu_id] = self.freshness_value
        except KeyError:
            pass
        return s

    @staticmethod
    def get_pdu_payload_cls(pkt: Packet,
                            data: bytes
                            ) -> Packet:
        try:
            cls = SecOC_PDU.pdu_payload_cls_by_identifier[pkt.pdu_id]
            return cls(data)
        except Exception:
            pass
        return Raw(data)

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return "", s


class SecOC_PDUTransport(Packet):
    """
    Packet representing SecOC_PDUTransport containing multiple PDUs
    """

    # TODO: add dict to distinguish between secOC and standard PDU frames
    name = 'SecOC_PDUTransport'
    fields_desc = [
        PacketListField("pdus", [SecOC_PDU()], pkt_cls=SecOC_PDU)
    ]
