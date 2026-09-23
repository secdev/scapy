# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright 2023 (C) nnayo

"""
CFDP protocol scapy layer

based on CCSDS file delivery protocol blue book (CCSDS 727.0-B-5)

this code has only being used to decode frames
some parts are still WIP
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitField, BitEnumField, BitFieldLenField, ByteEnumField,
    BitFixedLenField, XBitField,
    StrLenField, StrFixedLenField,
    XStrLenField, XStrFixedLenField, XStrField,
    ConditionalField, PacketListField
)

class PduHeader(Packet):
    """PDU header"""
    name = 'PDU header'
    fields_desc = [
        BitField('version', 1, 3),
        BitEnumField('PDU_type', 0, 1,
            {0: 'file directive', 1: 'file data'}),
        BitEnumField('direction', 0, 1,
            {0: 'to file receiver', 1: 'to file sender'}),
        BitEnumField('transmission_mode', 0, 1,
            {0: 'acknowledged', 1: 'unacknowledged'}),
        BitEnumField('CRC_flag', 0, 1,
            {0: 'not present', 1: 'present'}),
        BitEnumField('large_file_flag', 0, 1,
            {0: 'small file', 1: 'large file'}),
        BitFieldLenField('data_field_length', 0, 16),
        BitEnumField('segmentation_control', 0, 1,
            {0: 'record boundaries not preserved', 1: 'record boundaries preserved'}),
        BitFieldLenField('entity_ID_length', 0, 3, length_of='source_entity_ID'),
        BitField('segment_metadata_flag', 0, 1),
        BitFieldLenField('transaction_sequence_number_length', 0, 3,
             length_of='transaction_sequence_number'),
        XStrLenField('source_entity_ID', 0,
             length_from=lambda pkt: pkt.entity_ID_length + 1),
        XStrLenField('transaction_sequence_number', 0,
             length_from=lambda pkt: pkt.transaction_sequence_number_length + 1),
        XStrLenField('destination_entity_ID', 0,
             length_from=lambda pkt: pkt.entity_ID_length + 1),
    ]

    def mysummary(self):
        """
        display the triplet source/destination/transaction
        to help distinguish each exchange
        """
        return self.sprintf('PduHeader %source_entity_ID% -> '\
                '%destination_entity_ID% [%transaction_sequence_number%]')


# common to all file directives
DIRECTIVE_CODE = {
    0x4: 'EOF PDU',
    0x5: 'finished PDU',
    0x6:'ACK PDU',
    0x7: 'metadata PDU',
    0x8: 'NAK PDU',
    0x9: 'prompt PDU',
    0xc: 'keep alive PDU'
}

condition_code = BitEnumField('condition_code', 0, 4,
            {
                0b0000: 'no error',
                0b0001: 'positive ACK limit reached',
                0b0010: 'keep alive limit reached',
                0b0011: 'invalid transmission mode',
                0b0100: 'filestore rejection',
                0b0101: 'file checksum failure',
                0b0110: 'file size error',
                0b0111: 'NAK limit reached',
                0b1000: 'inactivity detected',
                0b1001: 'invalid file structure',
                0b1010: 'check limit reached',
                0b1011: 'unsupported checksum reached',
                # reserved
                0b1110: 'suspend.request received',
                0b1111: 'cancel.request received',
            })


class PduFileDirective(Packet):
    """file directive PDU"""
    name = 'file directive'
    fields_desc = [
        ByteEnumField('directive_code', 0, DIRECTIVE_CODE),
    ]


# file size sensistive @ CCSDS 727.0-B-5 / 5.1.10
# File-Size Sensitive (FSS) data items are integer values whose size in bits
# shall depend on the value of the Large File flag in the PDU header.
# When the value of the Large File flag is zero,
# the size of each FSS data item in the PDU shall be 32 bits.
# When the value of the Large File flag is 1,
# the size of each FSS data item in the PDU shall be 64 bits.
def _fss(pkt):
    """return the size in bytes not in bits"""
    # due to the protocol layering,
    # several steps could be needed to get to PDU header
    try:
        while not isinstance(pkt, PduHeader):
            pkt = pkt.underlayer
    except AttributeError:
        return 4

    pdu_header = pkt
    return 4 if not pdu_header.large_file_flag else 8


def _has_segment_metadata_flag(pkt):
    """return True if segment_metadata_flag in PDU header is set"""
    # due to the protocol layering,
    # several steps could be needed to get to PDU header
    try:
        while not isinstance(pkt, PduHeader):
            pkt = pkt.underlayer
    except AttributeError:
        return False

    pdu_header = pkt
    return pdu_header.segment_metadata_flag


#-------------------------------------------------------------------------------
# 'filestore request' packet

class TLVFilestoreRequest(Packet):
    """filestore request"""
    name = 'filestore request'
    fields_desc = [
        BitEnumField('action_code', 0, 4,
            {
                0b0000: 'create file',
                0b0001: 'delete file',
                0b0010: 'rename file',
                0b0011: 'append file',
                0b0100: 'replace file',
                0b0101: 'create directory',
                0b0110: 'remove directory',
                0b0111: 'deny file',
                0b1000: 'deny directory',
            }),
        BitField('spare', 0, 4),
        BitFieldLenField('first_filename_length', 0, 8, length_of='first_filename'),
        StrLenField('first_filename', 0, length_from=lambda pkt: pkt.first_filename_length),
        ConditionalField(
            BitFieldLenField('second_filename_length', 0, 8, length_of='second_filename'),
            cond=lambda pkt: pkt.action_code in (0b0010, 0b0100)
        ),
        ConditionalField(
            StrLenField('second_filename', 0, length_from=lambda pkt: pkt.second_filename_length),
            cond=lambda pkt: pkt.action_code in (0b0010, 0b0100)
        ),
    ]


#-------------------------------------------------------------------------------
# 'filestrore response' packet

class TLVFilestoreResponse(Packet):
    """filestore response"""
    name = 'filestore response'
    # TODO 5.4.2


#-------------------------------------------------------------------------------
# 'message to user' packet

class ProxyPutRequest(Packet):
    """proxy put request"""
    name = 'proxy put request'
    fields_desc = [
        BitFieldLenField('destination_entity_id_length', 0, 8,
             length_of='destination_entity_id'),
        XStrLenField('destination_entity_id', 0,
             length_from=lambda pkt: pkt.destination_entity_id_length),

        BitFieldLenField('source_filename_length', 0, 8, length_of='source_filename'),
        StrLenField('source_filename', 0, length_from=lambda pkt: pkt.source_filename_length),

        BitFieldLenField('destination_filename_length', 0, 8, length_of='destination_filename'),
        StrLenField('destination_filename', 0,
            length_from=lambda pkt: pkt.destination_filename_length),
    ]


class ProxyPutCancel(Packet):
    """proxy put cancel"""
    name = 'proxy put cancel'
    fields_desc = [
        # no content 6.2.6.2
    ]


class OriginatingTransactionId(Packet):
    """originating transaction id"""
    name = 'originating transaction id'
    fields_desc = [
        BitField('reserved0', 0, 1),
        BitFieldLenField('entity_id_length', 0, 3, length_of='entity_id'),
        BitField('reserved1', 0, 1),
        BitFieldLenField('transaction_seq_num_length', 0, 3, length_of='transaction_seq_num'),

        XStrLenField('entity_id', 0, length_from=lambda pkt: pkt.entity_id_length + 1),
        XStrLenField('transaction_seq_num', 0,
             length_from=lambda pkt: pkt.transaction_seq_num_length + 1),
    ]


class TLVMessageToUser(Packet):
    """message to user is TLV encoded"""
    name = 'message to user'
    fields_desc = [
        StrFixedLenField('message_identifier', 'cfdp', 4),
        BitEnumField('message_type', 0, 8,
            {
                0x00: 'proxy put request',
                0x01: 'proxy message to user',
                0x02: 'proxy filestore request',
                0x03: 'proxy fault handler override',
                0x04: 'proxy transmission mode',
                0x05: 'proxy flow label',
                0x06: 'proxy segmentation control',
                0x07: 'proxy put response',
                0x08: 'proxy filestore response',
                0x09: 'proxy put cancel',
                0x0a: 'originating transaction id',
                0x0b: 'proxy closure request',
            },
        ),
        ConditionalField(
            PacketListField('proxy_put_request', default=None, pkt_cls=ProxyPutRequest),
            cond=lambda pkt: pkt.message_type == 0x00),
        ConditionalField(
            PacketListField('proxy_put_cancel', default=None, pkt_cls=ProxyPutCancel),
            cond=lambda pkt: pkt.message_type == 0x09),
        ConditionalField(
            PacketListField('originating_transaction_id', default=None,
                pkt_cls=OriginatingTransactionId),
            cond=lambda pkt: pkt.message_type == 0x0a),
    ]


TLV_TYPES = {
    0x00: 'filestore request',
    0x01: 'filestore response',
    0x02: 'message to user',
    0x04: 'fault handler override',
    0x05: 'flow label',
    0x06: 'entity id',
}


class TLV(Packet):
    """TLV (Type / Length / Value) is meanly a field"""
    name = 'TLV'
    fields_desc = [
        ByteEnumField('type', 0, TLV_TYPES),
        BitFieldLenField('length', 0, 8),

        ConditionalField(
            PacketListField('filestore_request', default=None, pkt_cls=TLVFilestoreRequest),
            cond=lambda pkt: pkt.type == 0x00),
        ConditionalField(
            PacketListField('filestore_response', default=None, pkt_cls=TLVFilestoreResponse),
            cond=lambda pkt: pkt.type == 0x01),
        ConditionalField(
            PacketListField('message_to_user', default=None, pkt_cls=TLVMessageToUser),
            cond=lambda pkt: pkt.type == 0x02),
    ]


#-------------------------------------------------------------------------------
# sub PDU packets

class PduEof(Packet):
    """End Of File PDU"""
    name = 'End Of File PDU'
    fields_desc = [
        condition_code,
        BitField('spare', 0, 4),

        XBitField('file_checksum', 0, 32),

        BitFixedLenField('file_size', 0, length_from=lambda pkt: 8 * _fss(pkt)),
        # TODO fault locations TLV
    ]

    def mysummary(self):
        # force PDU header expansion
        return (self.sprintf('PduEof [%condition_code%]'), (PduHeader, ))


class PduFinished(Packet):
    """finished PDU"""
    name = 'finished PDU'
    fields_desc = [
        condition_code,
        BitField('spare', 0, 1),
        BitEnumField('delivery_code', 0, 1,
            {0: 'data complete', 1: 'data incomplete'}),
        BitEnumField('file_status', 0, 2,
            {
                0b00: 'delivered file discarded deliberately',
                0b01: 'delivered file discarded due to filestore rejection',
                0b10: 'delivered file retained in filestore successfully',
                0b11: 'delivered file status unreported',
            }),
    ]

    def mysummary(self):
        # force PDU header expansion
        return (self.sprintf('PduFinished [%file_status%]'), (PduHeader, ))


class PduAck(Packet):
    """ACK PDU"""
    name = 'ACK PDU'
    fields_desc = [
        BitEnumField('directive_code_of_ack', 0, 4, DIRECTIVE_CODE),
        BitField('directive_subtype_code', 0, 4),

        condition_code,
        BitField('spare', 0, 2),
        BitEnumField('transaction_status', 0, 2,
            {
                0b00: 'undefined',
                0b01: 'active',
                0b10: 'terminated',
                0b11: 'unrecognized'
            }),
    ]

    def mysummary(self):
        # force PDU header expansion
        return (self.sprintf('PduAck [%directive_code_of_ack%]'), (PduHeader, ))


class PduMetadata(Packet):
    """metadata PDU"""
    name = 'metadata PDU'
    fields_desc = [
        BitField('reserved0', 0, 1),
        BitEnumField('closure_requested', 0, 1,
            {0: 'no', 1: 'yes'}),
        BitField('reserved1', 0, 2),
        BitField('checksum_type', 0, 4),

        XStrFixedLenField('file_size', 0, length_from=lambda pkt: _fss(pkt)),

        BitFieldLenField('source_filename_length', 0, 8, length_of='source_filename'),
        StrLenField('source_filename', 0, length_from=lambda pkt: pkt.source_filename_length),

        BitFieldLenField('destination_filename_length', 0, 8, length_of='destination_filename'),
        StrLenField('destination_filename', 0,
            length_from=lambda pkt: pkt.destination_filename_length),

        PacketListField('options', default=None, pkt_cls=TLV),
    ]

    def mysummary(self):
        # force PDU header expansion
        return (self.sprintf('PduMetadata [%source_filename%]'), (PduHeader, ))


class PduNack(Packet):
    """NACK PDU"""
    name = 'NACK PDU'
    fields_desc = [
        BitField('start_of_scope', 0, 4),
        BitField('end_of_scope', 0, 4),

        # TODO segment_requests 5.2.6.1
    ]


class PduPrompt(Packet):
    """prompt PDU"""
    name = 'prompt PDU'
    fields_desc = [
        BitEnumField('closure_requested', 0, 1,
            {0: 'nak', 1: 'keep alive'}),
        BitField('spare', 0, 7),
    ]


class PduKeepAlive(Packet):
    """keep alive PDU"""
    name = 'keep alive PDU'
    fields_desc = [
        XStrFixedLenField('progress', 0, length_from=lambda pkt: _fss(pkt)),
    ]


class PduFileData(Packet):
    """file data PDU"""
    name = 'file data PDU'
    fields_desc = [
        ConditionalField(
            BitEnumField('record_continuation_state', 0, 2,
                {
                    0b00: 'not start nor end',
                    0b01: 'first octet of record',
                    0b10: 'last octet of record',
                    0b11: 'first and last',
                }),
            cond=lambda pkt: _has_segment_metadata_flag(pkt)
        ),
        ConditionalField(
            BitFieldLenField('segment_metadata_length', 0, 6, length_of='segment_metadata'),
            cond=lambda pkt: _has_segment_metadata_flag(pkt)
        ),

        ConditionalField(
            XStrLenField('segment_metadata', 0,
                 length_from=lambda pkt: pkt.segment_metadata_length),
            cond=lambda pkt: _has_segment_metadata_flag(pkt)
        ),

        ConditionalField(
            BitFieldLenField('offset_32bit', 0, 32, length_of='file_data'),
            cond=lambda pkt: _fss(pkt) == 4
        ),
        ConditionalField(
            BitFieldLenField('offset_64bit', 0, 64, length_of='file_data'),
            cond=lambda pkt: _fss(pkt) == 8
        ),
        XStrField('file_data', 0),
    ]


#-------------------------------------------------------------------------------
# bind the layers

# from header
bind_layers(PduHeader, PduFileDirective, PDU_type=0)
bind_layers(PduHeader, PduFileData, PDU_type=1)

# from file directive
# associate each packet with its directive code
pkts = (PduEof, PduFinished, PduAck, PduMetadata, PduNack, PduPrompt, PduKeepAlive,)
association = zip(pkts, DIRECTIVE_CODE.keys())

for func, code in association:
    bind_layers(PduFileDirective, func, directive_code=code)
