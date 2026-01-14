# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Bundle Protocol version 7 (BPv7)
# scapy.contrib.status = loads

"""
Bundle Protocol version 7 (BPv7) layer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:authors:    Timothy Recker, timothy.recker@nasa.gov
             Tad Kollar, tad.kollar@nasa.gov
"""

from scapy.packet import Packet
from scapy.fields import (
    PacketField,
    MultipleTypeField,
    BitEnumField,
    PacketListField,
    ConditionalField,
    FieldListField,
    BitField,
    BitFieldLenField,
)
from scapy.all import raw
from scapy.contrib.dtn.cbor import (
    CBORInteger,
    CBORByteString,
    CBORIntOrText,
    CBORArray,
    CBORNull,
    CBORStopCode,
    CBORAny,
    CBORPacketField,
    CBORPacketFieldWithRemain,
)
import scapy.contrib.dtn.common as Common

import time
import crcmod.predefined
from enum import IntFlag
from typing import Tuple, List
import re


class InvalidCRCType(Exception):
    """
    Exception raised when an invalid CRC type code is
    encountered.

    Attributes:
        type_code: the invalid type code
    """

    def __init__(self, type_code):
        super().__init__(
            f"Tried to compute a CRC using an invalid type code: {type_code}"
        )


def compute_crc(crc_type: int, pkt: bytes, ignore_existing: bool = True):
    # prepare parameters
    if crc_type == CrcTypes.CRC32C:
        size = 4
        crcfun = crcmod.predefined.mkCrcFun("crc-32c")
    elif crc_type == CrcTypes.CRC16:
        size = 2
        crcfun = crcmod.predefined.mkCrcFun("x-25")
    else:
        raise InvalidCRCType(crc_type)

    crc_index = len(pkt) - size

    # Wipe anything in existing crc field
    if ignore_existing:
        pkt = pkt[:crc_index] + b"\x00" * size

    return crcfun(pkt).to_bytes(size, "big"), crc_index


class PacketFieldWithRemain(PacketField):
    """
    The regular Packet.getfield() never returns the remaining bytes, so the CRC or
    other following fields get lost. This getfield does return the remaining bytes.
    """

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, Packet]:
        i = self.m2i(pkt, s)
        remain_size = len(s) - len(raw(i))
        remain = s[-remain_size:]
        return remain, i


class IPN(CBORArray):
    fields_desc = CBORArray.fields_desc + [
        CBORInteger("node_id", 1),
        CBORInteger("service_number", 1),
    ]

    ipn_re = re.compile(r"ipn:(.*)\.(.*)")

    # pylint: disable=W0201
    # field (instance variable) initialization is handled via "fields_desc"
    def from_string(self, ipn_str: str):
        result = IPN.ipn_re.search(ipn_str)
        self.node_id = int(result.group(1))
        self.service_number = int(result.group(2))

        return self

    def __str__(self):
        return f"ipn:{self.node_id}.{self.service_number}"  # noqa: E231

    def __eq__(self, other):
        if isinstance(other, IPN):
            return (self.node_id == other.node_id) and (
                self.service_number == other.service_number
            )
        return False


class DTN(Packet):
    fields_desc = [
        CBORIntOrText("uri", 0)  # can be 0 (type Int) or a string (type String)
    ]

    def extract_padding(self, s):
        return "", s

    def __eq__(self, other):
        if isinstance(other, DTN):
            return self.uri == other.uri
        return False


class EndpointID(CBORArray):
    fields_desc = CBORArray.fields_desc + [
        CBORInteger("scheme_code", 2),
        MultipleTypeField(
            [
                (
                    PacketFieldWithRemain("ssp", DTN(), DTN),
                    lambda pkt: pkt.scheme_code == 1,
                ),
                (
                    PacketFieldWithRemain("ssp", IPN(), IPN),
                    lambda pkt: pkt.scheme_code == 2,
                ),
            ],
            PacketFieldWithRemain("ssp", IPN(), IPN),
        ),
    ]

    def dissect(self, s: bytes):
        """This dissect doesn't process the payload, because there is none."""
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)

    def __eq__(self, other):
        if isinstance(other, EndpointID):
            return (self.scheme_code == other.scheme_code) and (self.ssp == other.ssp)
        return False


# pylint: disable=R0903
# Packet types are not intended to have many(any) public functions
class Timestamp(CBORArray):
    fields_desc = CBORArray.fields_desc + [CBORInteger("t", 0), CBORInteger("seq", 0)]

    def __ge__(self, other):
        if isinstance(other, Timestamp):
            return (self.t >= other.t) and (self.seq >= other.seq)
        return False

    def __gt__(self, other):
        if isinstance(other, Timestamp):
            return (self.t > other.t) or (self.t == other.t and (self.seq > other.seq))
        return False


class BlockTypes:
    """
    Bundle block type codes
    """

    PRIMARY = 0
    PAYLOAD = 1
    AUTHENTICATION = 2
    INTEGRITY = 3
    CONFIDENTIALITY = 4
    PREV_HOP = 5
    PREV_NODE = 6
    AGE = 7
    HOP_COUNT = 10
    BLOCK_INTEGRITY = 11
    BLOCK_CONFIDENTIALITY = 12


class CrcTypes:
    """
    Bundle CRC type codes
    """

    NONE = 0
    CRC16 = 1
    CRC32C = 2


# pylint: disable=R0903
# Packet types are not intended to have many(any) public functions
class SecurityTargets(CBORArray):
    fields_desc = [
        CBORArray._major_type,
        BitFieldLenField("add", 0, 5, count_of="targets"),
        FieldListField(
            "targets", [0], CBORInteger("tgt", 0), count_from=lambda pkt: pkt.add
        ),
    ]

    def count_additional_fields(self):
        return len(self.getfieldval("targets"))


class CBORTuple(CBORArray):
    """
    A pair of CBOR integers consisting of [id, value].
    """

    fields_desc = CBORArray.fields_desc + [
        CBORInteger("id", 0),
        CBORAny("value", b"\x00"),
    ]


class CBORTupleArray(CBORArray):
    fields_desc = [
        CBORArray._major_type,
        BitFieldLenField("add", None, 5, count_of="tuples"),
        PacketListField(
            "tuples", [CBORTuple()], CBORTuple, count_from=lambda pkt: pkt.add
        ),
    ]

    def find_value_with_id(self, target_id: int):
        """Find the tuple with the specified id and return the value."""
        try:
            tup = next(x for x in self.tuples if x.id == target_id)
        except StopIteration:
            return None

        return tup.value

    def count_additional_fields(self) -> int:
        return len(self.getfieldval("tuples"))


class SecurityResults(CBORArray):
    """A CBOR array of CBORTupleArrays."""

    fields_desc = [
        CBORArray._major_type,
        BitFieldLenField("add", None, 5, count_of="results"),
        PacketListField(
            "results",
            [CBORTupleArray()],
            CBORTupleArray,
            count_from=lambda pkt: pkt.add,
        ),
    ]

    def count_additional_fields(self):
        return len(self.getfieldval("results"))


class AbstractSecurityBlock(Packet):
    """
    The structure of the security-specific parts of the BIB and BCB are identical
    and are defined here. This structure will reside in the block-specific data
    field of a BPv7 canonical block.
    """

    fields_desc = [
        PacketField("security_targets", SecurityTargets(), SecurityTargets),
        CBORInteger("security_context_id", 0),
        CBORInteger("security_context_flags", 1),
        PacketField("security_source", EndpointID(), EndpointID),
        ConditionalField(
            PacketField(
                "security_context_parameters", CBORTupleArray(), CBORTupleArray
            ),
            lambda p: (p.security_context_flags & 1),
        ),
        PacketField("security_results", SecurityResults(), SecurityResults),
    ]

    def dissect(self, s: bytes):
        """This dissect doesn't process the payload, because there is none."""
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)


class CanonicalBlock(CBORArray):
    class CtrlFlags(IntFlag):
        """
        Block Processing Control Flags
        """

        BLOCK_MUST_BE_REPLICATED = 0x01
        REPORT_IF_UNPROCESSABLE = 0x02
        DELETE_BUNDLE_IF_UNPROCESSED = 0x04
        DISCARD_IF_NOT_PROCESSED = 0x010

    TypeCodes = {
        BlockTypes.PAYLOAD: "payload",
        BlockTypes.AUTHENTICATION: "authentication",
        BlockTypes.INTEGRITY: "integrity",
        BlockTypes.CONFIDENTIALITY: "confidentiality",
        BlockTypes.PREV_HOP: "prev_hop",
        BlockTypes.PREV_NODE: "prev_node",
        BlockTypes.AGE: "age",
        BlockTypes.HOP_COUNT: "hop_count",
        BlockTypes.BLOCK_INTEGRITY: "block_integrity",
        BlockTypes.BLOCK_CONFIDENTIALITY: "block_confidentiality",
    }

    fields_template: Common.FieldsTemplate = {
        "type_code": BitEnumField("type_code", BlockTypes.PAYLOAD, 8, TypeCodes),
        "block_number": CBORInteger("block_number", 1),
        "flags": CBORInteger("flags", 0),
        "crc_type": CBORInteger("crc_type", CrcTypes.CRC32C),
        "data": CBORByteString("data", b"\xde\xad\xbe\xef"),
        "crc": ConditionalField(
            MultipleTypeField(
                [
                    (
                        CBORByteString("crc", b"\x00\x00"),
                        lambda pkt: pkt.crc_type == CrcTypes.CRC16,
                    ),
                    (
                        CBORByteString("crc", b"\x00\x00\x00\x00"),
                        lambda pkt: pkt.crc_type == CrcTypes.CRC32C,
                    ),
                ],
                CBORNull("crc", None),
            ),
            lambda pkt: pkt.crc_type != CrcTypes.NONE,
        ),
    }

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)
    encrypted = False
    encrypted_by = []

    def get_header(self) -> bytes:
        return raw(self)[1:4]

    def post_dissect(self, s):
        """
        Because some block elements--such as CRCs and CBOR array headers--are added to
        the raw representation via overriding the post_build method (and correspondingly
        removed during pre_dissect), the raw packet cache must be cleared. Otherwise,
        some important methods will be broken for Blocks built from sniffed packets;
        for example, `raw(Bundle(raw_bytes_received_from_socket))` will not produce
        valid bundle bytes. See the comment linked below and the subsequent comment
        with a solution copied here.

        https://github.com/secdev/scapy/issues/1021#issuecomment-704472941
        """
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def post_build(self, pkt, pay):
        pkt = self.set_additional_fields(pkt)

        if self.crc_type != CrcTypes.NONE:
            crc, index = compute_crc(self.crc_type, pkt)
            pkt = pkt[:index] + crc

        return pkt + pay

    def get_block_bytes(self) -> bytes:
        return raw(self)

    def count_additional_fields(self):
        return 5 if self.crc_type == CrcTypes.NONE else 6


class PayloadBlock(CanonicalBlock):
    """
    Contains the bundle payload.
    """

    fields_template = Common.template_replace(
        CanonicalBlock.fields_template,
        {
            "type_code": BitEnumField(
                "type_code", BlockTypes.PAYLOAD, 8, CanonicalBlock.TypeCodes
            )
        },
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)


# pylint: disable=R0901
class EncryptedPayloadBlock(PayloadBlock):
    """
    Contains the bundle payload. The data field is encrypted.
    """

    encrypted = True


class PreviousNodeBlock(CanonicalBlock):
    """
    Contains the ID of the node that forwarded this bundle.
    """

    fields_template = Common.template_replace(
        CanonicalBlock.fields_template,
        {
            "type_code": BitEnumField(
                "type_code", BlockTypes.PREV_NODE, 8, CanonicalBlock.TypeCodes
            ),
            "data": CBORPacketField("data", EndpointID(), EndpointID),
        },
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)


# pylint: disable=R0901
class EncryptedPreviousNodeBlock(PreviousNodeBlock):
    """
    Contains the ID of the node that forwarded this bundle. The data field is encrypted.
    """

    fields_template = Common.template_replace(
        PreviousNodeBlock.fields_template,
        {
            # The data field definition from the parent class cannot be used here.
            # That data is now encrypted and cannot be decrypted to its original bytes
            # (within the scope of this module), so the Packet that it represents
            # cannot be dissected.
            # Instead, the data field definition from CanonicalBlock is used.
            "data": CBORByteString("data", b"\xde\xad\xbe\xef")
        },
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)
    encrypted = True


class BundleAge(Packet):
    fields_desc = [CBORInteger("age", 0)]

    def __eq__(self, other):
        if isinstance(other, BundleAge):
            return self.age == other.age
        return False

    def dissect(self, s: bytes):
        """This dissect doesn't process the payload, because there is none."""
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)


class BundleAgeBlock(CanonicalBlock):
    """
    Contains the number of milliseconds that have elapsed between the time the
    bundle was created and the time at which it was most recently forwarded.
    """

    fields_template = Common.template_replace(
        CanonicalBlock.fields_template,
        {
            "type_code": BitEnumField(
                "type_code", BlockTypes.AGE, 8, CanonicalBlock.TypeCodes
            ),
            "data": CBORPacketFieldWithRemain("data", BundleAge(), BundleAge),
        },
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)


# pylint: disable=R0901
class EncryptedBundleAgeBlock(BundleAgeBlock):
    """
    Contains the number of milliseconds that have elapsed between the time the
    bundle was created and the time at which it was most recently forwarded.
    The data field is encrypted.
    """

    fields_template = Common.template_replace(
        BundleAgeBlock.fields_template,
        {"data": CBORByteString("data", b"\xde\xad\xbe\xef")},
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)
    encrypted = True


class HopCount(CBORArray):
    fields_desc = CBORArray.fields_desc + [
        CBORInteger("limit", 0),
        CBORInteger("count", 0),
    ]

    def __eq__(self, other):
        if isinstance(other, HopCount):
            return (self.limit == other.limit) and (self.count == other.count)
        return False


class HopCountBlock(CanonicalBlock):
    """
    Contains information on the Bundle's allowed number of hops and the hops that
    have already happened.
    """

    fields_template = Common.template_replace(
        CanonicalBlock.fields_template,
        {
            "type_code": BitEnumField(
                "type_code", BlockTypes.HOP_COUNT, 8, CanonicalBlock.TypeCodes
            ),
            "data": CBORPacketField("data", HopCount(), HopCount),
        },
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)


# pylint: disable=R0901
class EncryptedHopCountBlock(HopCountBlock):
    """
    Contains information on the Bundle's allowed number of hops and the hops that
    have already happened. The data field is encrypted.
    """

    fields_template = Common.template_replace(
        HopCountBlock.fields_template,
        {"data": CBORByteString("data", b"\xde\xad\xbe\xef")},
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)
    encrypted = True


class BlockIntegrityBlock(CanonicalBlock):
    """
    This defines a CanonicalBlock with its type code as 11 and an
    AbstractSecurityBlock as its data field.
    """

    fields_template = Common.template_replace(
        CanonicalBlock.fields_template,
        {
            "type_code": BitEnumField(
                "type_code", BlockTypes.BLOCK_INTEGRITY, 8, CanonicalBlock.TypeCodes
            ),
            "data": CBORPacketFieldWithRemain(
                "data", AbstractSecurityBlock(), AbstractSecurityBlock
            ),
        },
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)


# pylint: disable=R0901
class EncryptedBlockIntegrityBlock(BlockIntegrityBlock):
    """
    This defines a CanonicalBlock with its type code as 11 and an encrypted
    AbstractSecurityBlock as its data field.
    """

    fields_template = Common.template_replace(
        BlockIntegrityBlock.fields_template,
        {"data": CBORByteString("data", b"\xde\xad\xbe\xef")},
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)
    encrypted = True


class BlockConfidentialityBlock(CanonicalBlock):
    """
    This defines a CanonicalBlock with its type code as 12 and an
    AbstractSecurityBlock as its data field.
    """

    fields_template = Common.template_replace(
        CanonicalBlock.fields_template,
        {
            "type_code": BitEnumField(
                "type_code",
                BlockTypes.BLOCK_CONFIDENTIALITY,
                8,
                CanonicalBlock.TypeCodes,
            ),
            "data": CBORPacketFieldWithRemain(
                "data", AbstractSecurityBlock(), AbstractSecurityBlock
            ),
        },
    )

    fields_desc = CBORArray.fields_desc + Common.make_fields_desc(fields_template)


class UnassignedExtensionBlock(CanonicalBlock):
    """An extension block with an unassigned type code < 192."""


class EncryptedUnassignedExtensionBlock(CanonicalBlock):
    """An extension block with an unassigned type code < 192.
    The data field is encrypted."""

    encrypted = True


class ReservedExtensionBlock(CanonicalBlock):
    """An extension block with a type code 192-255."""


class EncryptedReservedExtensionBlock(CanonicalBlock):
    """An extension block with a type code 192-255. The data field is encrypted."""

    encrypted = True


class PrimaryBlock(CBORArray):
    class CtrlFlags(IntFlag):
        """
        Bundle Processing Control Flags
        """

        BUNDLE_IS_FRAGMENT = 0x01
        ADMIN_RECORD = 0x02
        MUST_NOT_BE_FRAGMENTED = 0x04
        ACKNOWLEDGEMENT_REQUESTED = 0x20
        STATUS_TIME_REQUESTED = 0x40

        REQUEST_REPORTING_OF_BUNDLE_RECEPTION = 0x4000
        REQUEST_REPORTING_OF_BUNDLE_FORWARDING = 0x10000
        REQUEST_REPORTING_OF_BUNDLE_DELIVERY = 0x20000
        REQUEST_REPORTING_OF_BUNDLE_DELETION = 0x40000

    fields_desc = CBORArray.fields_desc + [
        CBORInteger("version", 7),
        CBORInteger("flags", 0),
        CBORInteger("crc_type", CrcTypes.CRC32C),
        PacketField("dest", EndpointID(), EndpointID),
        PacketField("src", EndpointID(), EndpointID),
        PacketField("report", EndpointID(scheme_code=1), EndpointID),
        PacketField("creation_timestamp", Timestamp(t=int(time.time())), Timestamp),
        CBORInteger("lifetime", 0),
        ConditionalField(
            CBORInteger("fragment_offset", 0),
            lambda pkt: pkt.flags & PrimaryBlock.CtrlFlags.BUNDLE_IS_FRAGMENT,
        ),
        ConditionalField(
            CBORInteger("total_adu_length", 0),
            lambda pkt: pkt.flags & PrimaryBlock.CtrlFlags.BUNDLE_IS_FRAGMENT,
        ),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        CBORByteString("crc", b"\x00\x00"),
                        lambda pkt: pkt.crc_type == CrcTypes.CRC16,
                    ),
                    (
                        CBORByteString("crc", b"\x00\x00\x00\x00"),
                        lambda pkt: pkt.crc_type == CrcTypes.CRC32C,
                    ),
                ],
                CBORNull("crc", None),
            ),
            lambda pkt: pkt.crc_type != CrcTypes.NONE,
        ),
    ]

    def dissect(self, s: bytes):
        """This dissect doesn't process the payload, because there is none."""
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)

    def post_dissect(self, s):
        # see docstring for equivalent Canonical Block method
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def post_build(self, pkt, pay):
        pkt = self.set_additional_fields(pkt)

        if self.crc_type != CrcTypes.NONE:
            # insert crc
            crc, index = compute_crc(self.crc_type, pkt)
            pkt = pkt[:index] + crc

        return pkt + pay

    def count_additional_fields(self):
        count = 8
        if self.crc_type != CrcTypes.NONE:
            count += 1
        if self.flags & PrimaryBlock.CtrlFlags.BUNDLE_IS_FRAGMENT:
            count += 2
        return count


TYPE_CODE_TO_BLOCK_TYPE_MAP = {
    # (type_code, is_encrypted): block_type
    (BlockTypes.PRIMARY, False): PrimaryBlock,
    (BlockTypes.PRIMARY, True): None,  # should not happen
    (BlockTypes.PAYLOAD, False): PayloadBlock,
    (BlockTypes.PAYLOAD, True): EncryptedPayloadBlock,
    (BlockTypes.PREV_NODE, False): PreviousNodeBlock,
    (BlockTypes.PREV_NODE, True): EncryptedPreviousNodeBlock,
    (BlockTypes.AGE, False): BundleAgeBlock,
    (BlockTypes.AGE, True): EncryptedBundleAgeBlock,
    (BlockTypes.HOP_COUNT, False): HopCountBlock,
    (BlockTypes.HOP_COUNT, True): EncryptedHopCountBlock,
    (BlockTypes.BLOCK_INTEGRITY, False): BlockIntegrityBlock,
    (BlockTypes.BLOCK_INTEGRITY, True): EncryptedBlockIntegrityBlock,
    (BlockTypes.BLOCK_CONFIDENTIALITY, False): BlockConfidentialityBlock,
    (BlockTypes.BLOCK_CONFIDENTIALITY, True): None,  # should not happen
}

UNENCRYPTED_TO_ENCRYPTED_TYPE_MAP = {
    PayloadBlock: EncryptedPayloadBlock,
    PreviousNodeBlock: EncryptedPreviousNodeBlock,
    BundleAgeBlock: EncryptedBundleAgeBlock,
    HopCountBlock: EncryptedHopCountBlock,
    BlockIntegrityBlock: EncryptedBlockIntegrityBlock,
    UnassignedExtensionBlock: EncryptedUnassignedExtensionBlock,
    ReservedExtensionBlock: EncryptedReservedExtensionBlock,
}

ENCRYPTED_TO_UNENCRYPTED_TYPE_MAP = {
    EncryptedPayloadBlock: PayloadBlock,
    EncryptedPreviousNodeBlock: PreviousNodeBlock,
    EncryptedBundleAgeBlock: BundleAgeBlock,
    EncryptedHopCountBlock: HopCountBlock,
    EncryptedBlockIntegrityBlock: BlockIntegrityBlock,
    EncryptedUnassignedExtensionBlock: UnassignedExtensionBlock,
    EncryptedReservedExtensionBlock: ReservedExtensionBlock,
}


def next_block_type(pkt, lst, cur, remain):
    del pkt, lst, cur  # Not used
    if remain is None or remain == b"\xff":
        return None
    return Bundle.identify_block(remain)


def guess_block_class(block_bytes, pkt):
    del pkt  # Not used
    if block_bytes is None or block_bytes == b"\xff":
        return None
    return Bundle.identify_block(block_bytes)


class Bundle(CBORArray):
    def count_additional_fields(self) -> int:
        return 31

    fields_desc = [
        CBORArray._major_type,
        BitField("add", 31, 5),
        PacketFieldWithRemain("primary_block", PrimaryBlock(), PrimaryBlock),
        PacketListField(
            "canonical_blocks", [CanonicalBlock()], next_cls_cb=next_block_type
        ),
        CBORStopCode("stop_code", 31),
    ]

    @staticmethod
    def type_code_to_block_type(type_code: int, encrypted: bool = False):
        map_key = (type_code, encrypted)
        if map_key not in TYPE_CODE_TO_BLOCK_TYPE_MAP:
            if type_code < 192:
                if encrypted:
                    return EncryptedUnassignedExtensionBlock
                return UnassignedExtensionBlock
            if type_code >= 192:
                if encrypted:
                    return EncryptedReservedExtensionBlock
                return ReservedExtensionBlock
            return CanonicalBlock

        return TYPE_CODE_TO_BLOCK_TYPE_MAP[map_key]

    def find_block_by_type(
        self, block_type, excluded_block_nums: List[int] = None
    ) -> CanonicalBlock:
        """
        Find the first canonical block matching the specified type,
        with a block number not in the excluded list.
        """
        if excluded_block_nums is None:
            excluded_block_nums = []
        try:
            block = next(
                x
                for x in self.canonical_blocks
                if isinstance(x, block_type)
                and x.block_number not in excluded_block_nums
            )
        except StopIteration:
            block = None

        return block

    def find_block_by_type_code(
        self, type_code: int, excluded_block_nums: List[int] = None
    ) -> CanonicalBlock:
        """
        Find the first block matching the specified type code, with a block number not
        in the excluded list.
        """
        if excluded_block_nums is None:
            excluded_block_nums = []
        try:
            block = next(
                x
                for x in self.canonical_blocks
                if (x.type_code == type_code)
                and (x.block_number not in excluded_block_nums)
            )
        except StopIteration:
            block = None

        return block

    def find_block_by_number(self, block_num: int) -> CanonicalBlock:
        """Find the canonical block with the specified block number."""
        try:
            block = next(
                x for x in self.canonical_blocks if x.block_number == block_num
            )
        except StopIteration:
            block = None

        return block

    def get_new_block_number(self) -> int:
        """Return a new canonical block number one higher than the highest in use."""
        new_num = 2

        for block in self.canonical_blocks:
            if block.block_number >= new_num:
                new_num = block.block_number + 1

        return new_num

    def add_block(
        self,
        block: CanonicalBlock,
        block_num_to_insert_above=1,
        select_block_number=False,
    ) -> CanonicalBlock:
        """Insert an extension block before the block with specified block number."""
        if select_block_number:
            block.block_number = self.get_new_block_number()

        insert_pos = -1
        for idx, test_block in enumerate(self.canonical_blocks):
            if test_block.block_number == block_num_to_insert_above:
                insert_pos = idx

        if insert_pos == -1:
            raise ValueError(
                "Could not find block number to insert above", block_num_to_insert_above
            )

        self.canonical_blocks.insert(insert_pos, block)

        return block

    def replace_block_by_block_num(self, block_num: int, new_block: CanonicalBlock):
        for idx, block in enumerate(self.canonical_blocks):
            if block.block_number == block_num:
                self.canonical_blocks[idx] = new_block
                return

    @staticmethod
    def identify_block(block_bytes: bytes):
        """Determine the type of the canonical block."""
        type_code = block_bytes[1]

        block_type = Bundle.type_code_to_block_type(type_code)
        encrypted_block_type = Bundle.type_code_to_block_type(type_code, True)

        if encrypted_block_type is not block_type:
            # Try to construct the block as the unencrypted type. If it
            # doesn't work, specify the encrypted version. If it works due to
            # chance arrangement of bytes but is actually encrypted, it will
            # be corrected by post_dissect()
            try:
                _ = block_type(block_bytes)
            # pylint: disable=W0702, W0718
            # Scapy just raises a generic Exception if it fails
            except Exception:
                block_type = encrypted_block_type

        return block_type

    def post_dissect(self, s):
        """
        Find the BCBs and check their security targets to definitively determine
        which blocks are encrypted.
        """
        for bcb_block in self.canonical_blocks:
            if isinstance(bcb_block, BlockConfidentialityBlock):
                for idx, block in enumerate(self.canonical_blocks):
                    if block.block_number in bcb_block.data.security_targets.targets:
                        block_type = type(block)
                        new_block = block

                        # Found a block originally detected as unencrypted, but the
                        # BCB specifies is encrypted. Replace with an encrypted type.
                        if not block_type.encrypted:
                            encrypted_type = UNENCRYPTED_TO_ENCRYPTED_TYPE_MAP[
                                block_type
                            ]
                            new_block = encrypted_type(raw(block))
                            self.canonical_blocks[idx] = new_block

                        new_block.encrypted_by.append(bcb_block.block_number)
        return s
