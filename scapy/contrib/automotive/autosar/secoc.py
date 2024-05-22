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

from scapy.config import conf
from scapy.error import log_loading

if conf.crypto_valid:
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
else:
    log_loading.info("Can't import python-cryptography v1.7+. "
                     "Disabled SecOC calculate_cmac.")

from scapy.base_classes import Packet_metaclass
from scapy.config import conf
from scapy.contrib.automotive.autosar.pdu import PDU
from scapy.fields import (XByteField, XIntField, PacketListField,
                          FieldLenField, PacketLenField, XStrFixedLenField)
from scapy.packet import Packet, Raw

# Typing imports
from typing import (
    Any,
    Callable,
    Dict,
    Optional,
    Set,
    Tuple,
    Type,
)


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
        XByteField("tfv", 0),  # truncated freshness value
        XStrFixedLenField("tmac", None, length=3)]  # truncated message authentication code # noqa: E501

    pdu_payload_cls_by_identifier: Dict[int, Type[Packet]] = dict()
    secoc_protected_pdus_by_identifier: Set[int] = set()

    def secoc_authenticate(self) -> None:
        self.tfv = struct.unpack(">B", self.get_secoc_freshness_value()[-1:])[0]
        self.tmac = self.get_message_authentication_code()[0:3]

    def secoc_verify(self) -> bool:
        return self.get_message_authentication_code()[0:3] == self.tmac

    def get_secoc_payload(self) -> bytes:
        """Override this method for customization
        """
        return self.pdu_payload

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
        del cls.secret_keys_by_identifier[pdu_id]

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

    @staticmethod
    def get_pdu_payload_cls(pkt: Packet,
                            data: bytes
                            ) -> Packet:
        try:
            cls = SecOC_PDU.pdu_payload_cls_by_identifier[pkt.pdu_id]
        except KeyError:
            cls = conf.raw_layer
        return cls(data, _parent=pkt)

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
