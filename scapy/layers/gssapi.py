# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Generic Security Services (GSS) API

Implements parts of:

    - GSSAPI: RFC4121 / RFC2743
    - GSSAPI C bindings: RFC2744

This is implemented in the following SSPs:

    - :class:`~scapy.layers.ntlm.NTLMSSP`
    - :class:`~scapy.layers.kerberos.KerberosSSP`
    - :class:`~scapy.layers.spnego.SPNEGOSSP`
    - :class:`~scapy.layers.msrpce.msnrpc.NetlogonSSP`

.. note::
    You will find more complete documentation for this layer over at
    `GSSAPI <https://scapy.readthedocs.io/en/latest/layers/gssapi.html>`_
"""

import abc

from dataclasses import dataclass
from enum import IntEnum, IntFlag

from scapy.asn1.asn1 import (
    ASN1_SEQUENCE,
    ASN1_Class_UNIVERSAL,
    ASN1_Codecs,
)
from scapy.asn1.ber import BERcodec_SEQUENCE
from scapy.asn1.mib import conf  # loads conf.mib
from scapy.asn1fields import (
    ASN1F_OID,
    ASN1F_PACKET,
    ASN1F_SEQUENCE,
)
from scapy.asn1packet import ASN1_Packet
from scapy.fields import (
    FieldLenField,
    LEIntEnumField,
    PacketField,
    StrLenField,
)
from scapy.packet import Packet

# Type hints
from typing import (
    Any,
    List,
    Optional,
    Tuple,
)

# https://datatracker.ietf.org/doc/html/rfc1508#page-48


class ASN1_Class_GSSAPI(ASN1_Class_UNIVERSAL):
    name = "GSSAPI"
    APPLICATION = 0x60


class ASN1_GSSAPI_APPLICATION(ASN1_SEQUENCE):
    tag = ASN1_Class_GSSAPI.APPLICATION


class BERcodec_GSSAPI_APPLICATION(BERcodec_SEQUENCE):
    tag = ASN1_Class_GSSAPI.APPLICATION


class ASN1F_GSSAPI_APPLICATION(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_GSSAPI.APPLICATION


# GSS API Blob
# https://datatracker.ietf.org/doc/html/rfc4121

# Filled by providers
_GSSAPI_OIDS = {}
_GSSAPI_SIGNATURE_OIDS = {}

# section 4.1


class GSSAPI_BLOB(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_GSSAPI_APPLICATION(
        ASN1F_OID("MechType", "1.3.6.1.5.5.2"),
        ASN1F_PACKET(
            "innerToken",
            None,
            None,
            next_cls_cb=lambda pkt: _GSSAPI_OIDS.get(pkt.MechType.val, conf.raw_layer),
        ),
    )

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 1:
            if ord(_pkt[:1]) & 0xA0 >= 0xA0:
                from scapy.layers.spnego import SPNEGO_negToken

                # XXX: sometimes the token is raw, we should look from
                # the session what to use here. For now: hardcode SPNEGO
                # (THIS IS A VERY STRONG ASSUMPTION)
                return SPNEGO_negToken
            if _pkt[:7] == b"NTLMSSP":
                from scapy.layers.ntlm import NTLM_Header

                # XXX: if no mechTypes are provided during SPNEGO exchange,
                # Windows falls back to a plain NTLM_Header.
                return NTLM_Header.dispatch_hook(_pkt=_pkt, *args, **kargs)
        return cls


# Same but to store the signatures (e.g. DCE/RPC)


class GSSAPI_BLOB_SIGNATURE(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_GSSAPI_APPLICATION(
        ASN1F_OID("MechType", "1.3.6.1.5.5.2"),
        ASN1F_PACKET(
            "innerToken",
            None,
            None,
            next_cls_cb=lambda pkt: _GSSAPI_SIGNATURE_OIDS.get(
                pkt.MechType.val, conf.raw_layer
            ),  # noqa: E501
        ),
    )

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            # Sometimes the token is raw. Detect that with educated
            # heuristics.
            if _pkt[:2] in [b"\x04\x04", b"\x05\x04"]:
                from scapy.layers.kerberos import KRB_InnerToken

                return KRB_InnerToken
            elif len(_pkt) >= 4 and _pkt[:4] == b"\x01\x00\x00\x00":
                from scapy.layers.ntlm import NTLMSSP_MESSAGE_SIGNATURE

                return NTLMSSP_MESSAGE_SIGNATURE
        return cls


class _GSSAPI_Field(PacketField):
    """
    PacketField that contains a GSSAPI_BLOB_SIGNATURE, but one that can
    have a payload when not encrypted.
    """
    __slots__ = ["pay_cls"]

    def __init__(self, name, pay_cls):
        self.pay_cls = pay_cls
        super().__init__(
            name,
            None,
            GSSAPI_BLOB_SIGNATURE,
        )

    def getfield(self, pkt, s):
        remain, val = super().getfield(pkt, s)
        if remain and val:
            val.payload = self.pay_cls(remain)
            return b"", val
        return remain, val


# RFC2744 sect 3.9 - Status Values

GSS_S_COMPLETE = 0

# These errors are encoded into the 32-bit GSS status code as follows:
#   MSB                                                        LSB
#   |------------------------------------------------------------|
#   |  Calling Error | Routine Error  |    Supplementary Info    |
#   |------------------------------------------------------------|
# Bit 31            24 23            16 15                       0

GSS_C_CALLING_ERROR_OFFSET = 24
GSS_C_ROUTINE_ERROR_OFFSET = 16
GSS_C_SUPPLEMENTARY_OFFSET = 0

# Calling errors:

GSS_S_CALL_INACCESSIBLE_READ = 1 << GSS_C_CALLING_ERROR_OFFSET
GSS_S_CALL_INACCESSIBLE_WRITE = 2 << GSS_C_CALLING_ERROR_OFFSET
GSS_S_CALL_BAD_STRUCTURE = 3 << GSS_C_CALLING_ERROR_OFFSET

# Routine errors:

GSS_S_BAD_MECH = 1 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_BAD_NAME = 2 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_BAD_NAMETYPE = 3 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_BAD_BINDINGS = 4 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_BAD_STATUS = 5 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_BAD_SIG = 6 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_BAD_MIC = GSS_S_BAD_SIG
GSS_S_NO_CRED = 7 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_NO_CONTEXT = 8 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_DEFECTIVE_TOKEN = 9 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_DEFECTIVE_CREDENTIAL = 10 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_CREDENTIALS_EXPIRED = 11 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_CONTEXT_EXPIRED = 12 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_FAILURE = 13 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_BAD_QOP = 14 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_UNAUTHORIZED = 15 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_UNAVAILABLE = 16 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_DUPLICATE_ELEMENT = 17 << GSS_C_ROUTINE_ERROR_OFFSET
GSS_S_NAME_NOT_MN = 18 << GSS_C_ROUTINE_ERROR_OFFSET

# Supplementary info bits:

GSS_S_CONTINUE_NEEDED = 1 << (GSS_C_SUPPLEMENTARY_OFFSET + 0)
GSS_S_DUPLICATE_TOKEN = 1 << (GSS_C_SUPPLEMENTARY_OFFSET + 1)
GSS_S_OLD_TOKEN = 1 << (GSS_C_SUPPLEMENTARY_OFFSET + 2)
GSS_S_UNSEQ_TOKEN = 1 << (GSS_C_SUPPLEMENTARY_OFFSET + 3)
GSS_S_GAP_TOKEN = 1 << (GSS_C_SUPPLEMENTARY_OFFSET + 4)

# Address families (RFC2744 sect 3.11)

_GSS_ADDRTYPE = {
    0: "GSS_C_AF_UNSPEC",
    1: "GSS_C_AF_LOCAL",
    2: "GSS_C_AF_INET",
    3: "GSS_C_AF_IMPLINK",
    4: "GSS_C_AF_PUP",
    5: "GSS_C_AF_CHAOS",
    6: "GSS_C_AF_NS",
    7: "GSS_C_AF_NBS",
    8: "GSS_C_AF_ECMA",
    9: "GSS_C_AF_DATAKIT",
    10: "GSS_C_AF_CCITT",
    11: "GSS_C_AF_SNA",
    12: "GSS_C_AF_DECnet",
    13: "GSS_C_AF_DLI",
    14: "GSS_C_AF_LAT",
    15: "GSS_C_AF_HYLINK",
    16: "GSS_C_AF_APPLETALK",
    17: "GSS_C_AF_BSC",
    18: "GSS_C_AF_DSS",
    19: "GSS_C_AF_OSI",
    21: "GSS_C_AF_X25",
    255: "GSS_C_AF_NULLADDR",
}


# GSS Structures


class GssBufferDesc(Packet):
    name = "gss_buffer_desc"
    fields_desc = [
        FieldLenField("length", None, length_of="value", fmt="<I"),
        StrLenField("value", "", length_from=lambda pkt: pkt.length),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class GssChannelBindings(Packet):
    name = "gss_channel_bindings_struct"
    fields_desc = [
        LEIntEnumField("initiator_addrtype", 0, _GSS_ADDRTYPE),
        PacketField("initiator_address", GssBufferDesc(), GssBufferDesc),
        LEIntEnumField("acceptor_addrtype", 0, _GSS_ADDRTYPE),
        PacketField("acceptor_address", GssBufferDesc(), GssBufferDesc),
        PacketField("application_data", None, GssBufferDesc),
    ]


# --- The base GSSAPI SSP base class


class GSS_C_FLAGS(IntFlag):
    """
    Authenticator Flags per RFC2744 req_flags
    """

    GSS_C_DELEG_FLAG = 0x01
    GSS_C_MUTUAL_FLAG = 0x02
    GSS_C_REPLAY_FLAG = 0x04
    GSS_C_SEQUENCE_FLAG = 0x08
    GSS_C_CONF_FLAG = 0x10  # confidentiality
    GSS_C_INTEG_FLAG = 0x20  # integrity
    # RFC4757
    GSS_C_DCE_STYLE = 0x1000
    GSS_C_IDENTIFY_FLAG = 0x2000
    GSS_C_EXTENDED_ERROR_FLAG = 0x4000


class SSP:
    """
    The general SSP class
    """

    auth_type = 0x00

    def __init__(self, **kwargs):
        if kwargs:
            raise ValueError("Unknown SSP parameters: " + ",".join(list(kwargs)))

    def __repr__(self):
        return "<%s>" % self.__class__.__name__

    class CONTEXT:
        """
        A Security context i.e. the 'state' of the secure negotiation
        """

        __slots__ = ["state", "_flags", "passive"]

        def __init__(self, req_flags: Optional[GSS_C_FLAGS] = None):
            if req_flags is None:
                # Default
                req_flags = (
                    GSS_C_FLAGS.GSS_C_EXTENDED_ERROR_FLAG
                    | GSS_C_FLAGS.GSS_C_MUTUAL_FLAG
                )
            self.flags = req_flags
            self.passive = False

        def clifailure(self):
            # This allows to reset the client context without discarding it.
            pass

        # 'flags' is the most important attribute. Use a setter to sanitize it.

        @property
        def flags(self):
            return self._flags

        @flags.setter
        def flags(self, x):
            self._flags = GSS_C_FLAGS(int(x))

        def __repr__(self):
            return "[Default SSP]"

    class STATE(IntEnum):
        """
        An Enum that contains the states of an SSP
        """

    @abc.abstractmethod
    def GSS_Init_sec_context(
        self, Context: CONTEXT, val=None, req_flags: Optional[GSS_C_FLAGS] = None
    ):
        """
        GSS_Init_sec_context: client-side call for the SSP
        """
        raise NotImplementedError

    @abc.abstractmethod
    def GSS_Accept_sec_context(self, Context: CONTEXT, val=None):
        """
        GSS_Accept_sec_context: server-side call for the SSP
        """
        raise NotImplementedError

    # Passive

    @abc.abstractmethod
    def GSS_Passive(self, Context: CONTEXT, val=None):
        """
        GSS_Passive: client/server call for the SSP in passive mode
        """
        raise NotImplementedError

    def GSS_Passive_set_Direction(self, Context: CONTEXT, IsAcceptor=False):
        """
        GSS_Passive_set_Direction: used to swap the direction in passive mode
        """
        pass

    # MS additions (*Ex functions)

    @dataclass
    class WRAP_MSG:
        conf_req_flag: bool
        sign: bool
        data: bytes

    @abc.abstractmethod
    def GSS_WrapEx(
        self, Context: CONTEXT, msgs: List[WRAP_MSG], qop_req: int = 0
    ) -> Tuple[List[WRAP_MSG], Any]:
        """
        GSS_WrapEx

        :param Context: the SSP context
        :param qop_req: int (0 specifies default QOP)
        :param msgs: list of WRAP_MSG

        :returns: (data, signature)
        """
        raise NotImplementedError

    @abc.abstractmethod
    def GSS_UnwrapEx(
        self, Context: CONTEXT, msgs: List[WRAP_MSG], signature
    ) -> List[WRAP_MSG]:
        """
        :param Context: the SSP context
        :param msgs: list of WRAP_MSG
        :param signature: the signature

        :raises ValueError: if MIC failure.
        :returns: data
        """
        raise NotImplementedError

    @dataclass
    class MIC_MSG:
        sign: bool
        data: bytes

    @abc.abstractmethod
    def GSS_GetMICEx(
        self, Context: CONTEXT, msgs: List[MIC_MSG], qop_req: int = 0
    ) -> Any:
        """
        GSS_GetMICEx

        :param Context: the SSP context
        :param qop_req: int (0 specifies default QOP)
        :param msgs: list of VERIF_MSG

        :returns: signature
        """
        raise NotImplementedError

    @abc.abstractmethod
    def GSS_VerifyMICEx(self, Context: CONTEXT, msgs: List[MIC_MSG], signature) -> None:
        """
        :param Context: the SSP context
        :param msgs: list of VERIF_MSG
        :param signature: the signature

        :raises ValueError: if MIC failure.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def MaximumSignatureLength(self, Context: CONTEXT):
        """
        Returns the Maximum Signature length.

        This will be used in auth_len in DceRpc5, and is necessary for
        PFC_SUPPORT_HEADER_SIGN to work properly.
        """
        raise NotImplementedError

    # RFC 2743

    # sect 2.3.1

    def GSS_GetMIC(self, Context: CONTEXT, message: bytes, qop_req: int = 0):
        return self.GSS_GetMICEx(
            Context,
            [
                self.MIC_MSG(
                    sign=True,
                    data=message,
                )
            ],
            qop_req=qop_req,
        )

    # sect 2.3.2

    def GSS_VerifyMIC(self, Context: CONTEXT, message: bytes, signature):
        self.GSS_VerifyMICEx(
            Context,
            [
                self.MIC_MSG(
                    sign=True,
                    data=message,
                )
            ],
            signature,
        )

    # sect 2.3.3

    def GSS_Wrap(
        self,
        Context: CONTEXT,
        input_message: bytes,
        conf_req_flag: bool,
        qop_req: int = 0,
    ):
        _msgs, signature = self.GSS_WrapEx(
            Context,
            [
                self.WRAP_MSG(
                    conf_req_flag=conf_req_flag,
                    sign=True,
                    data=input_message,
                )
            ],
            qop_req=qop_req,
        )
        if _msgs[0].data:
            signature /= _msgs[0].data
        return signature

    # sect 2.3.4

    def GSS_Unwrap(self, Context: CONTEXT, signature):
        data = b""
        if signature.payload:
            # signature has a payload that is the data. Let's get that payload
            # in its original form, and use it for verifying the checksum.
            if signature.payload.original:
                data = signature.payload.original
            else:
                data = bytes(signature.payload)
            signature = signature.copy()
            signature.remove_payload()
        return self.GSS_UnwrapEx(
            Context,
            [
                self.WRAP_MSG(
                    conf_req_flag=True,
                    sign=True,
                    data=data,
                )
            ],
            signature,
        )[0].data

    # MISC

    def NegTokenInit2(self):
        """
        Server-Initiation
        See [MS-SPNG] sect 3.2.5.2
        """
        return None, None

    def canMechListMIC(self, Context: CONTEXT):
        """
        Returns whether or not mechListMIC can be computed
        """
        return False

    def getMechListMIC(self, Context, input):
        """
        Compute mechListMIC
        """
        return bytes(self.GSS_GetMIC(Context, input))

    def verifyMechListMIC(self, Context, otherMIC, input):
        """
        Verify mechListMIC
        """
        return self.GSS_VerifyMIC(Context, input, otherMIC)

    def LegsAmount(self, Context: CONTEXT):
        """
        Returns the amount of 'legs' (how MS calls it) of the SSP.

        i.e. 2 for Kerberos, 3 for NTLM and Netlogon
        """
        return 2
