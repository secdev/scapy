# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = AUTOSAR Secure On-Board Communication
# scapy.contrib.status = library

"""
SecOC
"""
from scapy.config import conf
from scapy.error import log_loading

if conf.crypto_valid:
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
else:
    log_loading.info("Can't import python-cryptography v1.7+. "
                     "Disabled SecOC calculate_cmac.")

from scapy.config import conf
from scapy.fields import PacketLenField
from scapy.packet import Packet, Raw

# Typing imports
from typing import (
    Callable,
    Dict,
    Optional,
    Set,
    Type,
)


class SecOCMixin:

    pdu_payload_cls_by_identifier: Dict[int, Type[Packet]] = dict()
    secoc_protected_pdus_by_identifier: Set[int] = set()

    def secoc_authenticate(self) -> None:
        raise NotImplementedError

    def secoc_verify(self) -> bool:
        raise NotImplementedError

    def get_secoc_payload(self) -> bytes:
        """Override this method for customization
        """
        raise NotImplementedError

    def get_secoc_key(self) -> bytes:
        """Override this method for customization
        """
        return b"\x00" * 16

    def get_secoc_freshness_value(self) -> bytes:
        """Override this method for customization
        """
        return b"\x00" * 4

    def get_message_authentication_code(self):
        payload = self.get_secoc_payload()
        key = self.get_secoc_key()
        freshness_value = self.get_secoc_freshness_value()
        return self.calculate_cmac(key, payload, freshness_value)

    @staticmethod
    def calculate_cmac(key: bytes, payload: bytes, freshness_value: bytes) -> bytes:
        c = cmac.CMAC(algorithms.AES128(key))
        c.update(payload + freshness_value)
        return c.finalize()

    @classmethod
    def register_secoc_protected_pdu(cls,
                                     pdu_id: int,
                                     pdu_payload_cls: Type[Packet] = Raw
                                     ) -> None:
        cls.secoc_protected_pdus_by_identifier.add(pdu_id)
        cls.pdu_payload_cls_by_identifier[pdu_id] = pdu_payload_cls

    @classmethod
    def unregister_secoc_protected_pdu(cls, pdu_id: int) -> None:
        cls.secoc_protected_pdus_by_identifier.remove(pdu_id)
        del cls.pdu_payload_cls_by_identifier[pdu_id]


class PduPayloadField(PacketLenField):
    __slots__ = ["guess_pkt_cls"]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Packet
                 guess_pkt_cls,  # type: Callable[[Packet, bytes], Packet]  # noqa: E501
                 length_from=None  # type: Optional[Callable[[Packet], int]]  # noqa: E501
                 ):
        # type: (...) -> None
        super(PacketLenField, self).__init__(name, default, Raw)
        self.length_from = length_from or (lambda x: 0)
        self.guess_pkt_cls = guess_pkt_cls

    def m2i(self, pkt, m):  # type: ignore
        # type: (Optional[Packet], bytes) -> Packet
        return self.guess_pkt_cls(pkt, m)
