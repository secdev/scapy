
import crcmod
import datetime
import enum
import logging
import struct
from typing import Any, Optional
from scapy import volatile
from scapy.config import conf
from scapy.fields import I, ConditionalField, PacketField, PacketListField
from scapy.packet import Packet, NoPayload, Raw, bind_layers
from scapy.cbor import (
    CborMajorType, cbor_chunk_int, cbor_chunk_tstr, cbor_chunk_array
)
from scapy.cborfields import (
    CborAnyField, CborUintField, CborIntField, CborEnumField,
    CborFlagsField, CborBstrField, CborFieldArrayField
)
from scapy.cborpacket import (
    CborArrayPacket, CborSequencePacket,
    cbor_array_item_cb
)

LOG_RUNTIME = logging.getLogger("scapy.runtime")


class DtnTimeField(CborUintField):
    ''' A DTN time value representing number of milliseconds from the
    DTN epoch 2000-01-01T00:00:00Z.

    This value is automatically converted from a
    :py:cls:`datetime.datetime` object and human friendly text in ISO8601
    format.
    The special human value "zero" represents the zero value time.
    '''

    # Epoch reference for DTN Time
    DTN_EPOCH = datetime.datetime(2000, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

    @staticmethod
    def datetime_to_dtntime(val):
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
            return 'zero'
        return dtval.isoformat(timespec='milliseconds')

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
            return DtnTimeField.datetime_to_dtntime(
                datetime.datetime.fromisoformat(x)
            )

        return int(x)

    def randval(self):
        return volatile.RandNum(0, int(2 ** 16))


class BundleTimestamp(CborArrayPacket):
    ''' A structured representation of an DTN Timestamp.
    The timestamp is a two-tuple of (time, sequence number)
    The creation time portion is automatically converted from a
    :py:cls:`datetime.datetime` object and text.
    '''
    fields_desc = (
        DtnTimeField('dtntime', default=0),
        CborUintField('seqno', default=0),
    )


class BundleEidPacket(CborArrayPacket):
    ''' A structured representation of a BP Endpoint ID (EID) as a packet.
    The EID is a two-item array of (scheme ID, scheme-specific part).
    '''
    fields_desc = (
        CborUintField('scheme', default=None),
        CborAnyField('ssp', default=None),
    )


class BundleEidField(CborAnyField):
    ''' Provide a human-friendly representation of a BP Endpoint ID (EID) as
    a single field.
    The EID is a two-item array of (scheme ID, scheme-specific part).
    '''

    def i2h(self, _pkt, x):
        # Translate to text form for known schemes
        if x is None:
            return None
        if x.head.major != CborMajorType.ARRAY:
            raise ValueError(f'EID must be enclosed in an array, got {x.head.major}')

        scheme_id = x.content[0].head.argument
        ssp_items = x.content[1].content
        match scheme_id:
            case 1:
                # DTN scheme
                return 'dtn:' + ssp_items
            case 2:
                # IPN scheme, 2 or 3 element forms
                parts = [chunk.head.argument for chunk in ssp_items]
                return 'ipn:' + '.'.join(['{:d}'.format(part) for part in parts])
            case _:
                raise ValueError(f'BP EID scheme {scheme_id} not understood')

    def h2i(self, _pkt, x):
        # type: (Optional[Packet], Any) -> I
        if x is None:
            return None

        scheme, ssp = x.split(':', 1)
        scheme = scheme.lower()
        scheme_id = None
        ssp_item = None
        match scheme:
            case 'dtn':
                scheme_id = 1
                ssp_item = cbor_chunk_tstr(ssp)
            case 'ipn':
                # force handling as decimal
                parts = [int(part, 10) for part in ssp.split('.')]

                scheme_id = 2
                ssp_item = cbor_chunk_array([
                    cbor_chunk_int(part)
                    for part in parts
                ])
            case _:
                raise ValueError(f'BP EID scheme {scheme} not understood')

        return cbor_chunk_array([
            cbor_chunk_int(scheme_id),
            ssp_item
        ])

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)


class AbstractBlock(CborArrayPacket):
    ''' Represent an abstract block with CRC fields.

    .. py:attribute:: crc_type_name
        The name of the CRC-type field.
    .. py:attribute:: crc_value_name
        The name of the CRC-value field.
    '''

    @enum.unique
    class CrcType(enum.IntEnum):
        ''' CRC type values.
        '''
        NONE = 0
        CRC16 = 1
        CRC32 = 2

    # Map from CRC type to algorithm
    CRC_DEFN = {
        CrcType.CRC16: {  # BPv7 CRC-16 X.25
            'func': crcmod.predefined.mkPredefinedCrcFun('x-25'),
            'encode': lambda val: struct.pack('>H', val)
        },
        CrcType.CRC32: {  # BPv7 CRC-32 Castagnoli
            'func': crcmod.predefined.mkPredefinedCrcFun('crc-32c'),
            'encode': lambda val: struct.pack('>L', val)
        },
    }

    crc_type_name = 'crc_type'
    crc_value_name = 'crc_value'

    def fill_fields(self):
        ''' Fill all fields so that the block is the full size it needs
        to be for encoding encoding with build().
        Derived classes should populate their block-type-specific-data also.
        '''
        crc_type = self.getfieldval(self.crc_type_name)
        crc_value = self.fields.get(self.crc_value_name)
        if crc_type and not crc_value:
            defn = AbstractBlock.CRC_DEFN[crc_type]
            # Encode with a zero-valued CRC field
            self.fields[self.crc_value_name] = defn['encode'](0)

    def update_crc(self, keep_existing=False):
        ''' Update this block's CRC field from the current field data
        only if the current CRC (field not default) value is None.
        '''
        if self.crc_type_name is None or self.crc_value_name is None:
            return

        crc_type = self.getfieldval(self.crc_type_name)
        if crc_type == 0:
            crc_value = None
        else:
            crc_value = self.fields.get(self.crc_value_name)
            if not keep_existing or crc_value is None:
                defn = AbstractBlock.CRC_DEFN[crc_type]
                # Encode with a zero-valued CRC field
                self.fields[self.crc_value_name] = defn['encode'](0)
                pre_crc = self.build()
                crc_int = defn['func'](pre_crc)
                crc_value = defn['encode'](crc_int)

        self.fields[self.crc_value_name] = crc_value

    def check_crc(self):
        ''' Check the current CRC value, if enabled.
        :return: True if the CRC is disabled or it is valid.
        '''
        if self.crc_type_name is None or self.crc_value_name is None:
            return True

        crc_type = self.getfieldval(self.crc_type_name)
        crc_value = self.fields.get(self.crc_value_name)
        if crc_type == 0:
            valid = crc_value is None
        else:
            defn = AbstractBlock.CRC_DEFN[crc_type]
            # Encode with a zero-valued CRC field
            self.fields[self.crc_value_name] = defn['encode'](0)
            pre_crc = self.build()
            crc_int = defn['func'](pre_crc)
            valid = crc_value == defn['encode'](crc_int)
            # Restore old value
            self.fields[self.crc_value_name] = crc_value

        return valid


class PrimaryBlock(AbstractBlock):
    ''' The primary block definition '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Bundle processing control flags.
        '''
        REQ_DELETION_REPORT = 0x040000
        ''' bundle deletion status reports are requested. '''
        REQ_DELIVERY_REPORT = 0x020000
        ''' bundle delivery status reports are requested. '''
        REQ_FORWARDING_REPORT = 0x010000
        ''' bundle forwarding status reports are requested. '''
        REQ_RECEPTION_REPORT = 0x004000
        ''' bundle reception status reports are requested. '''
        REQ_STATUS_TIME = 0x000040
        ''' status time is requested in all status reports. '''
        USER_APP_ACK = 0x000020
        ''' user application acknowledgement is requested. '''
        NO_FRAGMENT = 0x000004
        ''' bundle must not be fragmented. '''
        PAYLOAD_ADMIN = 0x000002
        ''' payload is an administrative record. '''
        IS_FRAGMENT = 0x000001
        ''' bundle is a fragment. '''

    fields_desc = (
        CborUintField('bp_version', default=7),
        CborFlagsField('bundle_flags', default=0, flags=Flag),
        CborEnumField('crc_type', default=AbstractBlock.CrcType.NONE,
                      enum=AbstractBlock.CrcType),
        BundleEidField('destination', default=None),
        BundleEidField('source', default=None),
        BundleEidField('report_to', default=None),
        PacketField('create_ts', default=BundleTimestamp(),
                    pkt_cls=BundleTimestamp),
        CborUintField('lifetime', default=0),
        ConditionalField(
            CborUintField('fragment_offset', default=0),
            lambda block: (block.getfieldval('bundle_flags')
                           & PrimaryBlock.Flag.IS_FRAGMENT)
        ),
        ConditionalField(
            CborUintField('total_app_data_len', default=0),
            lambda block: (block.getfieldval('bundle_flags')
                           & PrimaryBlock.Flag.IS_FRAGMENT)
        ),
        ConditionalField(
            CborBstrField('crc_value'),
            lambda block: block.getfieldval('crc_type') != 0
        ),
    )


class CanonicalBlock(AbstractBlock):
    ''' The canonical block definition with a type-specific payload.

    Any payload of this block is encoded as the "data" field when building
    and decoded from the "data" field when dissecting.
    '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Block processing control flags '''
        REMOVE_IF_NO_PROCESS = 0x10
        ''' block must be removed from bundle if it can't be processed. '''
        DELETE_IF_NO_PROCESS = 0x04
        ''' bundle must be deleted if block can't be processed. '''
        STATUS_IF_NO_PROCESS = 0x02
        ''' transmission of a status report is requested if block can't be
        processed. '''
        REPLICATE_IN_FRAGMENT = 0x01
        ''' block must be replicated in every fragment. '''

    fields_desc = (
        CborUintField('type_code', default=None),
        CborUintField('block_num', default=None),
        CborFlagsField('block_flags', default=0, flags=Flag),
        CborEnumField('crc_type', default=AbstractBlock.CrcType.NONE,
                      enum=AbstractBlock.CrcType),
        CborBstrField('btsd', default=None),  # block-type-specific data here
        ConditionalField(
            CborBstrField('crc_value'),
            lambda block: block.crc_type != 0
        ),
    )

    def ensure_block_type_specific_data(self):
        ''' Embed payload as BTSD if not already present.
        '''
        if isinstance(self.payload, NoPayload):
            return
        if self.fields.get('btsd') is not None:
            # already present
            return

        pay_data = self.payload.do_build()
        self.fields['btsd'] = pay_data

    def fill_fields(self):
        self.ensure_block_type_specific_data()
        super().fill_fields()

    def self_build(self, *args, **kwargs):
        self.ensure_block_type_specific_data()
        return super().self_build(*args, **kwargs)

    def do_build_payload(self):
        # Payload is handled by self_build()
        return b''

    def post_dissect(self, s):
        # Extract payload from fields
        blk_type = self.fields.get('type_code')
        blk_data = self.fields.get('btsd')

        cls = None
        if blk_data is not None and blk_type is not None:
            try:
                cls = self.guess_payload_class(None)
            except KeyError:
                pass

        if cls is not None and cls is not Raw:
            try:
                pay = cls(blk_data)
                self.add_payload(pay)
            except Exception as err:
                if conf.debug_dissector:
                    raise
                LOG_RUNTIME.warning('Failed to decode BPv7 BTSD: %s', err)

        return super().post_dissect(s)


class PreviousNodeBlock(CborSequencePacket):
    ''' Block data content from Section 4.4.1 of RFC 9171.
    '''
    fields_desc = (
        BundleEidField('node'),
    )


class BundleAgeBlock(CborSequencePacket):
    ''' Block data content from Section 4.4.2 of RFC 9171.
    '''
    fields_desc = (
        CborUintField('age'),
    )


class HopCountBlock(CborArrayPacket):
    ''' Block data content from Section 4.4.3 of RFC 9171.
    '''
    fields_desc = (
        CborUintField('limit'),
        CborUintField('count'),
    )


bind_layers(CanonicalBlock, PreviousNodeBlock, type_code=6)
bind_layers(CanonicalBlock, BundleAgeBlock, type_code=7)
bind_layers(CanonicalBlock, HopCountBlock, type_code=10)


class BpsecKeyValPair(CborArrayPacket):
    fields_desc = (
        CborUintField('key'),
        CborAnyField('val'),
    )


class BpsecKeyValList(CborArrayPacket):
    fields_desc = (
        PacketListField('pairs', [], pkt_cls=BpsecKeyValPair,
                        count_from=lambda pkt: pkt.array_head_arg),
    )


class BpsecKeyValListList(CborArrayPacket):
    fields_desc = (
        PacketListField('items', [], pkt_cls=BpsecKeyValList,
                        count_from=lambda pkt: pkt.array_head_arg),
    )


class AbstractSecurityBock(CborSequencePacket):
    ''' Block data content from Section 3.6 of RFC 9172.
    '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' ASB flags.
        Defined in Section 3.6 of RFC 9172.
        '''
        PARAMETERS = 0x01
        ''' Security context parameters present. '''

    fields_desc = (
        CborFieldArrayField('targets', [], field=CborIntField('blk_num')),
        CborIntField('context_id'),
        CborFlagsField('flags', 0, flags=Flag),
        BundleEidField('source', default=None),
        ConditionalField(
            PacketField('parameters', [], pkt_cls=BpsecKeyValList),
            cond=lambda pkt: pkt.flags & AbstractSecurityBock.Flag.PARAMETERS
        ),
        # one packet in this list per target
        PacketField('tgt_results', [], pkt_cls=BpsecKeyValListList),
    )


bind_layers(CanonicalBlock, AbstractSecurityBock, type_code=11)
bind_layers(CanonicalBlock, AbstractSecurityBock, type_code=12)


class BundleV7(CborArrayPacket):
    ''' An entire decoded bundle contents.

    Bundles with administrative records are handled specially in that the
    AdminRecord object will be made a (scapy) payload of the "payload block"
    which is block type code 1.
    '''

    BLOCK_TYPE_PAYLOAD = 1
    BLOCK_NUM_PAYLOAD = 1

    cbor_use_indefinite = True
    ''' The bundle PDU used indefinite length. '''
    fields_desc = (
        PacketField('primary', default=None, pkt_cls=PrimaryBlock),
        PacketListField('blocks', default=[],
                        next_cls_cb=cbor_array_item_cb(CanonicalBlock)),
    )
