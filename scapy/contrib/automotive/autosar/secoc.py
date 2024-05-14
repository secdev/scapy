# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = AUTOSAR Secure On-Board Communication
# scapy.contrib.status = loads

"""
SecOC
"""
import struct
from collections import defaultdict

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

from scapy.contrib.automotive.autosar.pdu import PDU
from scapy.fields import (XByteField, X3BytesField, XIntField, PacketListField,
                          FieldLenField, PacketLenField, XStrFixedLenField)
from scapy.packet import Packet, Raw

# Typing imports
from typing import (
    Dict,
    Optional,
    Type,
    Callable,
    Union,
    Tuple, List, Set
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
        XStrFixedLenField("message_authentication_code", None, length=3)]

    pdu_payload_cls_by_identifier: Dict[int, Type[Packet]] = defaultdict(Raw)
    freshness_values_by_identifier: Dict[int, int] = defaultdict(int)
    secret_keys_by_identifier: Dict[int, bytes] = defaultdict(lambda: b"\x00" * 16)
    secoc_protected_pdus_by_identifier: Set[int] = set()

    def secoc_authenticate(self, freshness_value: Optional[int] = None) -> None:
        if freshness_value:
            fv = freshness_value
        else:
            self.freshness_values_by_identifier[self.pdu_id] += 1
            fv = self.freshness_values_by_identifier[self.pdu_id]

        self.freshness_value = fv

        mac = self.get_message_authentication_code()
        self.message_authentication_code = mac[0:3]

    def secoc_verify(self) -> bool:
        return self.get_message_authentication_code() == bytes(self)[-3:]

    def get_message_authentication_code(self):
        payload = bytes(self)[:-3]
        c = cmac.CMAC(algorithms.AES(self.secret_keys_by_identifier[self.pdu_id]))
        c.update(payload)
        mac = c.finalize()
        return mac

    @classmethod
    def register_secoc_protected_pdu(cls,
                                     pdu_id: int,
                                     secret_key: bytes = b"\x00" * 16,
                                     pdu_payload_cls: Type[Packet] = Raw
                                     ) -> None:
        cls.secoc_protected_pdus_by_identifier.insert(0, pdu_id)
        cls.secret_keys_by_identifier[pdu_id] = secret_key
        cls.pdu_payload_cls_by_identifier[pdu_id] = pdu_payload_cls

    @classmethod
    def unregister_secoc_protected_pdu(cls, pdu_id: int) -> None:
        cls.secoc_protected_pdus_by_identifier.remove(pdu_id)
        del cls.secret_keys_by_identifier[pdu_id]

    @classmethod
    def dispatch_hook(cls, s=None, *_args, **_kwds):
        # type: (Optional[bytes], *Any, **Any) -> Packet_metaclass
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

    def post_dissect(self, s):  # type: (bytes) -> bytes
        SecOC_PDU.freshness_values_by_identifier[self.pdu_id] = self.freshness_value
        return s

    @staticmethod
    def get_pdu_payload_cls(pkt: Packet,
                            data: bytes
                            ) -> Packet:
        return SecOC_PDU.pdu_payload_cls_by_identifier[pkt.pdu_id](data)

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
                                     secret_key: bytes = b"\x00" * 16,
                                     pdu_payload_cls: Type[Packet] = Raw
                                     ) -> None:
        SecOC_PDU.register_secoc_protected_pdu(pdu_id, secret_key, pdu_payload_cls)

    @staticmethod
    def unregister_secoc_protected_pdu(pdu_id: int) -> None:
        SecOC_PDU.unregister_secoc_protected_pdu(pdu_id)
