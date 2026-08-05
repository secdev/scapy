# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Brian Sipos <brian.sipos@gmail.com>

# scapy.contrib.description = Bundle Protocol Version 7 (BPv7)
# scapy.contrib.status = loads

from dataclasses import dataclass
import datetime
import enum
import struct
from typing import Optional, Union, cast, ClassVar, Callable
from scapy import config, volatile
from scapy.packet import Packet
from scapy.error import log_runtime
from scapy.cbor.cborcodec import CBOR_decode_head, CBOR_MajorTypes
from scapy.cbor import (
    CBORF_field,
    CBORF_ANY,
    CBORF_UNSIGNED_INTEGER,
    CBORF_INTEGER,
    CBORF_ARRAY,
    CBORF_ARRAY_OF,
    CBORF_ARRAY_INDEFINITE,
    CBORF_BYTE_STRING,
    CBORF_CONDITIONAL,
    CBORF_SEQUENCE,
    CBORF_SEQUENCE_OF,
    CBORF_PACKET,
    CBORF_BYTE_STRING_PACKET,
    CBORF_UNSIGNED_ENUM,
    CBORF_UNSIGNED_FLAGS,
    CBORcodec_ARRAY,
    CBOR_UNSIGNED_INTEGER,
    CBOR_TEXT_STRING,
    CBOR_ARRAY,
    CBOR_Object,
)
from scapy.cborpacket import (
    CBOR_Packet,
)
from scapy.libs.crc import CRC, CRC_16_X25, CRC_32C


class DtnTimeField(CBORF_INTEGER):
    """A DTN time value representing number of milliseconds from the
    DTN epoch 2000-01-01T00:00:00Z.

    This value is automatically converted from a
    :py:cls:`datetime.datetime` object and human friendly text in ISO8601
    format.
    The special human value "zero" represents the zero value time.
    """

    # Epoch reference for DTN Time
    DTN_EPOCH = datetime.datetime(2000, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

    @staticmethod
    def datetime_to_dtntime(val: "Optional[datetime.datetime]") -> int:
        if val is None:
            return 0
        delta = val - DtnTimeField.DTN_EPOCH
        return int(delta / datetime.timedelta(milliseconds=1))

    @staticmethod
    def dtntime_to_datetime(val):
        if val == 0 or val is None:
            return None
        delta = datetime.timedelta(milliseconds=val)
        return delta + DtnTimeField.DTN_EPOCH

    def i2h(self, pkt, x):
        dtval = DtnTimeField.dtntime_to_datetime(x)
        if dtval is None:
            return "zero"
        return dtval.isoformat(timespec="milliseconds")

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def h2i(self, pkt, x):
        return self.any2i(pkt, x)

    def any2i(self, pkt, x):
        if x is None:
            return None

        elif isinstance(x, datetime.datetime):
            return DtnTimeField.datetime_to_dtntime(x)

        elif isinstance(x, (str, bytes)):
            return DtnTimeField.datetime_to_dtntime(datetime.datetime.fromisoformat(x))

        elif isinstance(x, CBOR_UNSIGNED_INTEGER):
            return x.val

        return int(x)

    def randval(self):
        return volatile.RandNum(0, int(2**16))


class BundleTimestamp(CBOR_Packet):
    """A structured representation of an DTN Timestamp.
    The timestamp is a two-tuple of (time, sequence number)
    The creation time portion is automatically converted from a
    :py:cls:`datetime.datetime` object and text.
    """

    CBOR_root = CBORF_ARRAY(
        DtnTimeField("dtntime", default=0),
        CBORF_UNSIGNED_INTEGER("seqno", default=0),
    )


@enum.unique
class EidScheme(enum.IntEnum):
    """Handled EID scheme names and values."""

    dtn = 1
    ipn = 2


_DTN_WELL_KNOWN_SSP = {
    0: "none",
}
"""Compressed SSP encoding."""


@dataclass
class EidStruct:
    """
    Internal state for the :class:`BundleEidField` class.
    """

    scheme: EidScheme
    """ Scheme code point """
    ssp: Union[int, str, list[int]]
    """ Scheme-specific part """

    @staticmethod
    def from_text(text: str) -> "EidStruct":
        scheme_name, ssp_text = text.split(":", 1)

        try:
            scheme = EidScheme[scheme_name.lower()]
        except KeyError:
            raise ValueError(f"BP EID scheme {scheme_name} not understood")
        ssp = None
        if scheme == EidScheme.dtn:
            # some SSP values are well-known and compressed
            for key, val in _DTN_WELL_KNOWN_SSP.items():
                if ssp_text == val:
                    ssp = key
                    break
            if ssp is None:
                ssp = ssp_text

        elif scheme == EidScheme.ipn:
            # force handling as decimal
            parts = [int(part, 10) for part in ssp_text.split(".")]
            if not 2 <= len(parts) <= 3:
                raise ValueError("IPN SSP must be 2 or 3 elements")
            ssp = parts

        else:
            raise ValueError("Invalid scheme state")

        return EidStruct(scheme=scheme, ssp=ssp)

    def to_text(self) -> str:
        if self.scheme == EidScheme.dtn:
            # DTN scheme
            if isinstance(self.ssp, int):
                ssp = _DTN_WELL_KNOWN_SSP[self.ssp]
            else:
                ssp = str(self.ssp)
            return "dtn:" + ssp
        elif self.scheme == EidScheme.ipn:
            # IPN scheme, 2 or 3 element forms
            return "ipn:" + ".".join(["{:d}".format(part) for part in self.ssp])
        else:
            raise ValueError("Invalid scheme state")

    @staticmethod
    def from_cbor(item: CBOR_Object) -> "EidStruct":
        if not isinstance(item, CBOR_ARRAY):
            raise TypeError(f"Need an array, have {item}")
        scheme_id, ssp_item = item.val
        try:
            scheme = EidScheme(scheme_id)
        except ValueError:
            raise ValueError(f"BP EID scheme {scheme_id} not understood")

        if scheme == EidScheme.dtn:
            ssp = ssp_item.val
        elif scheme == EidScheme.ipn:
            ssp = [int(item.val) for item in ssp_item.val]
        else:
            raise ValueError("Invalid scheme state")

        return EidStruct(scheme=scheme, ssp=ssp)

    def to_cbor(self) -> CBOR_Object:
        if self.scheme == EidScheme.dtn:
            if isinstance(self.ssp, int):
                ssp_item = CBOR_UNSIGNED_INTEGER(self.ssp)
            else:
                ssp_item = CBOR_TEXT_STRING(self.ssp)
        elif self.scheme == EidScheme.ipn:
            ssp_item = [CBOR_UNSIGNED_INTEGER(part) for part in self.ssp]
        else:
            raise ValueError("Invalid scheme state")

        return CBOR_ARRAY([CBOR_UNSIGNED_INTEGER(int(self.scheme)), ssp_item])


class BundleEidField(CBORF_field[EidStruct, CBOR_ARRAY]):
    """Provide a human-friendly representation of a BP Endpoint ID (EID) as
    a single field.
    The EID is a two-item array of (scheme ID, scheme-specific part).
    """

    def _wrap(self, val):
        # type: (Any) -> _A
        return self.any2i(None, val)

    def i2h(self, _pkt, x):
        # type: (CBOR_Packet, _I) -> Any
        # Translate to text form for known schemes
        if x is None:
            return None

        if not isinstance(x, EidStruct):
            raise ValueError(f"EID must be decoded into an EidStruct")
        x = cast(EidStruct, x)

        return x.to_text()

    def h2i(self, _pkt, x):
        # type: (Optional[Packet], Any) -> I
        if x is None:
            return None

        return EidStruct.from_text(x)

    def any2i(self, pkt, x):
        if x is None:
            return None

        if isinstance(x, str):
            return self.h2i(pkt, x)
        return x

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def _encode(self, x):
        # type: (Any) -> bytes
        if isinstance(x, str):
            x = EidStruct.from_text(x)
        return (
            CBORcodec_ARRAY.enc(x) if isinstance(x, CBOR_Object) else x.to_cbor().enc()
        )

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[_A, bytes]
        item, remain = CBORcodec_ARRAY.dec(s)
        return EidStruct.from_cbor(item), remain


@enum.unique
class CrcType(enum.IntEnum):
    """
    CRC type values defined in RFC 9171.
    """

    NONE = 0
    CRC16 = 1
    CRC32 = 2


@dataclass
class CrcInfo:
    """
    Processing for a specific :class:`CrcType`
    """

    cls: CRC
    encode: "Callable[[int], bytes]"


_CRC_DEFN: dict[CrcType, CrcInfo] = {
    CrcType.CRC16: CrcInfo(
        # BPv7 CRC-16 X.25
        cls=CRC_16_X25,
        encode=lambda val: struct.pack(">H", val),
    ),
    CrcType.CRC32: CrcInfo(
        # BPv7 CRC-32 Castagnoli
        cls=CRC_32C,
        encode=lambda val: struct.pack(">L", val),
    ),
}
"""Map from available CRC type to info."""


def _enum_dict(cls: type[enum.IntEnum]) -> dict[int, str]:
    return {item.value: item.name for item in cls}


class AbstractBlock:
    """Represent an abstract block internal interface mixin.

    .. py:attribute:: crc_type_name
        The name of the CRC-type field.
    .. py:attribute:: crc_value_name
        The name of the CRC-value field.
    """

    _crc_type_name = "crc_type"
    """ Field name of the CRC Type in the leaf packet class. """
    _crc_value_name = "crc_value"
    """ Field name of the CRC Value in the leaf packet class. """

    def has_crc(self):
        """
        Match the signature for CBORF_CONDITIONAL on the CRC Value field.
        """
        crc_type = self.getfieldval(self._crc_type_name).val
        return crc_type != CrcType.NONE.value

    def update_crc(self, keep_existing=True):
        """
        Update this block's CRC field from the current field data
        only if the current CRC (field not default) value is None.
        """
        crc_type = getattr(self, self._crc_type_name).val
        crc_value = getattr(self, self._crc_value_name)
        if crc_type == CrcType.NONE:
            # there should not be a value
            crc_value = None
        elif crc_value is None or not keep_existing:
            # there should be a value
            defn = _CRC_DEFN[crc_type]
            # Encode with a zero-valued CRC field
            self.setfieldval(self._crc_value_name, defn.encode(0))
            pre_crc = self.do_build()
            crc_int = defn.cls(pre_crc)
            crc_value = defn.encode(crc_int)

        self.setfieldval(self._crc_value_name, crc_value)

    def check_crc(self) -> bool:
        """Check the current CRC value, if enabled.
        :return: True if the CRC is disabled or it is valid.
        """

        crc_type = getattr(self, self._crc_type_name).val
        crc_value = getattr(self, self._crc_value_name) or b""
        if crc_type == CrcType.NONE:
            expect = b""
            valid = not crc_value
        else:
            defn = _CRC_DEFN[crc_type]
            # Encode and substitute with a zero-valued CRC field
            pre_crc = self.do_build()

            crc_obj: CRC = defn.cls.create_context()
            crc_obj.update(pre_crc[: -(crc_obj.size // 8)])
            crc_obj.update(defn.encode(0))
            crc_int = crc_obj.finish()
            expect = defn.encode(crc_int)
            valid = crc_value.val == expect

        if not valid:
            log_runtime.warning(
                "CRC check failed! Expected %s got %s" % (expect.hex(), crc_value.hex())
            )

        return valid


class PrimaryBlock(CBOR_Packet, AbstractBlock):
    """The primary block definition"""

    @enum.unique
    class Flag(enum.IntFlag):
        """Bundle processing control flags."""

        REQ_DELETION_REPORT = 0x040000
        """ bundle deletion status reports are requested. """
        REQ_DELIVERY_REPORT = 0x020000
        """ bundle delivery status reports are requested. """
        REQ_FORWARDING_REPORT = 0x010000
        """ bundle forwarding status reports are requested. """
        REQ_RECEPTION_REPORT = 0x004000
        """ bundle reception status reports are requested. """
        REQ_STATUS_TIME = 0x000040
        """ status time is requested in all status reports. """
        USER_APP_ACK = 0x000020
        """ user application acknowledgement is requested. """
        NO_FRAGMENT = 0x000004
        """ bundle must not be fragmented. """
        PAYLOAD_ADMIN = 0x000002
        """ payload is an administrative record. """
        IS_FRAGMENT = 0x000001
        """ bundle is a fragment. """

    def is_fragment(self) -> bool:
        """Determine if this bundle is an ADU fragment."""
        flags = self.getfieldval("bundle_flags").val
        return bool(flags & PrimaryBlock.Flag.IS_FRAGMENT)

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("version", default=7),
        CBORF_UNSIGNED_FLAGS(
            "bundle_flags", default=0, size=64, names=_enum_dict(Flag)
        ),
        CBORF_UNSIGNED_ENUM("crc_type", default=CrcType.NONE, enum=CrcType),
        BundleEidField("destination", default="dtn:none"),
        BundleEidField("source", default="dtn:none"),
        BundleEidField("report_to", default="dtn:none"),
        CBORF_PACKET("create_ts", default=BundleTimestamp(), cls=BundleTimestamp),
        CBORF_UNSIGNED_INTEGER("lifetime", default=0),
        CBORF_CONDITIONAL(
            CBORF_UNSIGNED_INTEGER("fragment_offset", default=0), cond=is_fragment
        ),
        CBORF_CONDITIONAL(
            CBORF_UNSIGNED_INTEGER("total_app_data_len", default=0), cond=is_fragment
        ),
        CBORF_CONDITIONAL(
            CBORF_BYTE_STRING("crc_value", default=None), cond=AbstractBlock.has_crc
        ),
    )

    def self_build(self):
        # type: () -> bytes
        self.update_crc(keep_existing=True)
        return super().self_build()


class CanonicalBlock(CBOR_Packet, AbstractBlock):
    """The canonical block definition with a block-type-specific data (BTSD)
    field containing a dissected Packet.
    """

    @enum.unique
    class Flag(enum.IntFlag):
        """Block processing control flags"""

        REMOVE_IF_NO_PROCESS = 0x10
        """ block must be removed from bundle if it can't be processed. """
        DELETE_IF_NO_PROCESS = 0x04
        """ bundle must be deleted if block can't be processed. """
        STATUS_IF_NO_PROCESS = 0x02
        """ transmission of a status report is requested if block can't be
        processed. """
        REPLICATE_IN_FRAGMENT = 0x01
        """ block must be replicated in every fragment. """

    _reg_types: ClassVar[dict[int, Packet]] = {}
    """ Known block types. """

    @classmethod
    def register_type(cls, type_code: int) -> Callable[[type[Packet]], type[Packet]]:
        """
        Decorator to register a BTSD decoder for a specific block type
        """

        def reg(pkt_cls: type[Packet]) -> type[Packet]:
            cls._reg_types[type_code] = pkt_cls
            return pkt_cls

        return reg

    def btsd_class(self, data: bytes):
        cls = None
        type_code = self.getfieldval("type_code")
        if type_code is not None:
            try:
                cls = self._reg_types[type_code.val]
            except KeyError:
                pass
        return cls

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("type_code", default=None),
        CBORF_UNSIGNED_INTEGER("block_num", default=None),
        CBORF_UNSIGNED_FLAGS("block_flags", default=0, size=64, names=_enum_dict(Flag)),
        CBORF_UNSIGNED_ENUM("crc_type", default=CrcType.NONE, enum=CrcType),
        CBORF_BYTE_STRING_PACKET("btsd", default=None, cls_cb=btsd_class),
        CBORF_CONDITIONAL(
            CBORF_BYTE_STRING("crc_value", default=None), cond=AbstractBlock.has_crc
        ),
    )

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return None, s

    def self_build(self):
        # type: () -> bytes

        self.update_crc(keep_existing=True)
        return super().self_build()


@CanonicalBlock.register_type(6)
class PreviousNodeBlock(CBOR_Packet):
    """Block data content from Section 4.4.1 of RFC 9171."""

    CBOR_root = BundleEidField("node", default=None)


@CanonicalBlock.register_type(7)
class BundleAgeBlock(CBOR_Packet):
    """Block data content from Section 4.4.2 of RFC 9171."""

    CBOR_root = CBORF_UNSIGNED_INTEGER("age", default=None)


@CanonicalBlock.register_type(10)
class HopCountBlock(CBOR_Packet):
    """Block data content from Section 4.4.3 of RFC 9171."""

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("limit", default=None),
        CBORF_UNSIGNED_INTEGER("count", default=0),
    )


class BpsecKeyValPair(CBOR_Packet):
    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("key", default=None),
        CBORF_ANY("val", default=None),
    )


#@CanonicalBlock.register_type(11)
#@CanonicalBlock.register_type(12)
class AbstractSecurityBock(CBOR_Packet):
    """Block data content from Section 3.6 of RFC 9172."""

    @enum.unique
    class Flag(enum.IntFlag):
        """ASB flags.
        Defined in Section 3.6 of RFC 9172.
        """

        PARAMETERS = 0x01
        """ Security context parameters present. """

    CBOR_root = CBORF_SEQUENCE(
        CBORF_ARRAY_OF(
            "targets", [], cls=CBORF_UNSIGNED_INTEGER("blk_num", default=None)
        ),
        CBORF_INTEGER("context_id", default=None),
        CBORF_UNSIGNED_FLAGS("flags", default=0, size=64, names=_enum_dict(Flag)),
        BundleEidField("source", default=None),
        CBORF_CONDITIONAL(
            CBORF_ARRAY_OF("parameters", [], cls=CBORF_PACKET('kvp', default=None, cls=BpsecKeyValPair)),
            cond=lambda pkt: pkt.flags.val & AbstractSecurityBock.Flag.PARAMETERS,
        ),
        # one packet in this list per target
        CBORF_ARRAY_OF(
            "tgt_results", [], cls=CBORF_ARRAY_OF("results", [], cls=CBORF_PACKET('kvp', default=None, cls=BpsecKeyValPair))
        ),
    )


class BundleV7(CBOR_Packet):
    """An entire decoded bundle contents.

    Bundles with administrative records are handled specially in that the
    AdminRecord object will be made a (scapy) payload of the "payload block"
    which is block type code 1.
    """

    BLOCK_TYPE_PAYLOAD = 1
    BLOCK_NUM_PAYLOAD = 1

    def _block_until_break(self, data: bytes):
        """
        Callback to read canonical blocks until the outer indefinite break
        """
        major_type, arg, _ = CBOR_decode_head(data)
        if major_type == CBOR_MajorTypes.SIMPLE_AND_FLOAT and arg is None:
            return None
        print("new block")
        return CanonicalBlock

    CBOR_root = CBORF_ARRAY_INDEFINITE(
        CBORF_PACKET("primary", default=PrimaryBlock(), cls=PrimaryBlock),
        CBORF_SEQUENCE_OF("blocks", default=[], cls_cb=_block_until_break),
    )

    def check_crc(self) -> bool:
        return self.primary.check_crc() and all(blk.check_crc() for blk in self.blocks)


config.conf.debug_dissector = True
