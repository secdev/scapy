#! /usr/bin/env python
#
# scapy.contrib.description = EtherCat
# scapy.contrib.status = loads

"""
    EtherCat automation protocol
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Thomas Tannhaeuser, hecke@naberius.de
    :license:   GPLv2

        This module is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.

        This module is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

    :description:

        This module provides Scapy layers for the EtherCat protocol.

        normative references:
            - IEC 61158-3-12 - data link service and topology description
            - IEC 61158-4-12 - protocol specification

        Currently only read/write services as defined in IEC 61158-4-12,
        sec. 5.4 are supported.

    :TODO:

        - Mailbox service (sec. 5.5)
        - Network variable service (sec. 5.6)

    :NOTES:

        - EtherCat frame type defaults to TYPE-12-PDU (0x01) using xxx bytes
          of padding
        - padding for minimum frame size is added automatically

"""


import struct


from scapy.compat import raw
from scapy.error import log_runtime, Scapy_Exception
from scapy.fields import BitField, ByteField, LEShortField, FieldListField, \
    LEIntField, FieldLenField, _EnumField, EnumField
from scapy.layers.l2 import Ether, Dot1Q
from scapy.modules import six
from scapy.packet import bind_layers, Packet, Padding

'''
EtherCat uses some little endian bitfields without alignment to any common boundaries.  # noqa: E501
See https://github.com/secdev/scapy/pull/569#issuecomment-295419176 for a short explanation  # noqa: E501
why the following field definitions are necessary.
'''


class LEBitFieldSequenceException(Scapy_Exception):
    """
    thrown by EtherCat structure tests
    """
    pass


class LEBitField(BitField):
    """
    a little endian version of the BitField
    """

    def _check_field_type(self, pkt, index):
        """
        check if the field addressed by given index relative to this field
        shares type of this field so we can catch a mix of LEBitField
        and BitField/other types
        """
        my_idx = pkt.fields_desc.index(self)
        try:
            next_field = pkt.fields_desc[my_idx + index]
            if type(next_field) is not LEBitField and \
               next_field.__class__.__base__ is not LEBitField:
                raise LEBitFieldSequenceException('field after field {} must '
                                                  'be of type LEBitField or '
                                                  'derived classes'.format(self.name))  # noqa: E501
        except IndexError:
            # no more fields -> error
            raise LEBitFieldSequenceException('Missing further LEBitField '
                                              'based fields after field '
                                              '{} '.format(self.name))

    def addfield(self, pkt, s, val):
        """

        :param pkt: packet instance the raw string s and field belongs to
        :param s:   raw string representing the frame
        :param val: value
        :return: final raw string, tuple (s, bitsdone, data) if in between bit field  # noqa: E501

        as we don't know the final size of the full bitfield we need to accumulate the data.  # noqa: E501
        if we reach a field that ends at a octet boundary, we build the whole string  # noqa: E501

        """
        if type(s) is tuple and len(s) == 4:
            s, bitsdone, data, _ = s
            self._check_field_type(pkt, -1)
        else:
            # this is the first bit field in the set
            bitsdone = 0
            data = []

        bitsdone += self.size
        data.append((self.size, self.i2m(pkt, val)))

        if bitsdone % 8:
            # somewhere in between bit 0 .. 7 - next field should add more bits...  # noqa: E501
            self._check_field_type(pkt, 1)
            return s, bitsdone, data, type(LEBitField)
        else:
            data.reverse()
            octet = 0
            remaining_len = 8
            octets = bytearray()
            for size, val in data:

                while True:
                    if size < remaining_len:
                        remaining_len = remaining_len - size
                        octet |= val << remaining_len
                        break

                    elif size > remaining_len:
                        # take the leading bits and add them to octet
                        size -= remaining_len
                        octet |= val >> size
                        octets = struct.pack('!B', octet) + octets

                        octet = 0
                        remaining_len = 8
                        # delete all consumed bits
                        # TODO: do we need to add a check for bitfields > 64 bits to catch overruns here?  # noqa: E501
                        val &= ((2 ** size) - 1)
                        continue
                    else:
                        # size == remaining len
                        octet |= val
                        octets = struct.pack('!B', octet) + octets
                        octet = 0
                        remaining_len = 8
                        break

        return s + octets

    def getfield(self, pkt, s):

        """
        extract data from raw str

        collect all instances belonging to the bit field set.
        if we reach a field that ends at a octet boundary, dissect the whole bit field at once  # noqa: E501

        :param pkt: packet instance the field belongs to
        :param s: raw string representing the frame -or- tuple containing raw str, number of bits and array of fields  # noqa: E501
        :return: tuple containing raw str, number of bits and array of fields -or- remaining raw str and value of this  # noqa: E501
        """

        if type(s) is tuple and len(s) == 3:
            s, bits_in_set, fields = s
        else:
            bits_in_set = 0
            fields = []

        bits_in_set += self.size

        fields.append(self)

        if bits_in_set % 8:
            # we are in between the bitfield
            return (s, bits_in_set, fields), None

        else:
            cur_val = 0
            cur_val_bit_idx = 0
            this_val = 0

            field_idx = 0
            field = fields[field_idx]
            field_required_bits = field.size
            idx = 0

            s = bytearray(s)
            bf_total_byte_length = bits_in_set // 8

            for octet in s[0:bf_total_byte_length]:
                idx += 1

                octet_bits_left = 8

                while octet_bits_left:

                    if field_required_bits == octet_bits_left:
                        # whole field fits into remaining bits
                        # as this also signals byte-alignment this should exit the inner and outer loop  # noqa: E501
                        cur_val |= octet << cur_val_bit_idx
                        pkt.fields[field.name] = cur_val

                        '''
                        TODO: check if do_dessect() needs a non-None check for assignment to raw_packet_cache_fields  # noqa: E501

                        setfieldval() is evil as it sets raw_packet_cache_fields to None - but this attribute  # noqa: E501
                        is accessed in do_dissect() without checking for None... exception is caught and the  # noqa: E501
                        user ends up with a layer decoded as raw...

                        pkt.setfieldval(field.name, int(bit_str[:field.size], 2))  # noqa: E501
                        '''

                        octet_bits_left = 0

                        this_val = cur_val

                    elif field_required_bits < octet_bits_left:
                        # pick required bits
                        cur_val |= (octet & ((2 ** field_required_bits) - 1)) << cur_val_bit_idx  # noqa: E501
                        pkt.fields[field.name] = cur_val

                        # remove consumed bits
                        octet >>= field_required_bits
                        octet_bits_left -= field_required_bits

                        # and move to the next field
                        field_idx += 1
                        field = fields[field_idx]
                        field_required_bits = field.size
                        cur_val_bit_idx = 0
                        cur_val = 0

                    elif field_required_bits > octet_bits_left:
                        # take remaining bits
                        cur_val |= octet << cur_val_bit_idx

                        cur_val_bit_idx += octet_bits_left
                        field_required_bits -= octet_bits_left
                        octet_bits_left = 0

            return s[bf_total_byte_length:], this_val


class LEBitFieldLenField(LEBitField):
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt, x: x):  # noqa: E501
        LEBitField.__init__(self, name, default, size)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust

    def i2m(self, pkt, x):
        return (FieldLenField.i2m.__func__ if six.PY2 else FieldLenField.i2m)(self, pkt, x)  # noqa: E501


class LEBitEnumField(LEBitField, _EnumField):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, size, enum):
        _EnumField.__init__(self, name, default, enum)
        self.rev = size < 0
        self.size = abs(size)


################################################
# DLPDU structure definitions (read/write PDUs)
################################################

ETHERCAT_TYPE_12_CIRCULATING_FRAME = {
    0x00: 'FRAME-NOT-CIRCULATING',
    0x01: 'FRAME-CIRCULATED-ONCE'
}

ETHERCAT_TYPE_12_NEXT_FRAME = {
    0x00: 'LAST-TYPE12-PDU',
    0x01: 'TYPE12-PDU-FOLLOWS'
}


class EtherCatType12DLPDU(Packet):
    """
    Type12 message base class
    """
    def post_build(self, pkt, pay):
        """

        set next attr automatically if not set explicitly by user

        :param pkt: raw string containing the current layer
        :param pay: raw string containing the payload
        :return: <new current layer> + payload
        """

        data_len = len(self.data)
        if data_len > 2047:
            raise ValueError('payload size {} exceeds maximum length {} '
                             'of data size.'.format(data_len, 2047))

        if self.next is not None:
            has_next = True if self.next else False
        else:
            if pay:
                has_next = True
            else:
                has_next = False

        if has_next:
            next_flag = bytearray([pkt[7] | 0b10000000])
        else:
            next_flag = bytearray([pkt[7] & 0b01111111])

        return pkt[:7] + next_flag + pkt[8:] + pay

    def guess_payload_class(self, payload):

        try:
            dlpdu_type = payload[0]
            return EtherCat.ETHERCAT_TYPE12_DLPDU_TYPES[dlpdu_type]

        except KeyError:
            log_runtime.error(
                '{}.guess_payload_class() - unknown or invalid '
                'DLPDU type'.format(self.__class__.__name__))
            return Packet.guess_payload_class(self, payload)

    # structure templates lacking leading cmd-attribute
    PHYSICAL_ADDRESSING_DESC = [
        ByteField('idx', 0),
        LEShortField('adp', 0),
        LEShortField('ado', 0),
        LEBitFieldLenField('len', None, 11, count_of='data'),
        LEBitField('_reserved', 0, 3),
        LEBitEnumField('c', 0, 1, ETHERCAT_TYPE_12_CIRCULATING_FRAME),
        LEBitEnumField('next', None, 1, ETHERCAT_TYPE_12_NEXT_FRAME),
        LEShortField('irq', 0),
        FieldListField('data', [], ByteField('', 0x00),
                       count_from=lambda pkt: pkt.len),
        LEShortField('wkc', 0)
    ]

    BROADCAST_ADDRESSING_DESC = PHYSICAL_ADDRESSING_DESC

    LOGICAL_ADDRESSING_DESC = [
        ByteField('idx', 0),
        LEIntField('adr', 0),
        LEBitFieldLenField('len', None, 11, count_of='data'),
        LEBitField('_reserved', 0, 3),
        LEBitEnumField('c', 0, 1, ETHERCAT_TYPE_12_CIRCULATING_FRAME),
        LEBitEnumField('next', None, 1, ETHERCAT_TYPE_12_NEXT_FRAME),
        LEShortField('irq', 0),
        FieldListField('data', [], ByteField('', 0x00),
                       count_from=lambda pkt: pkt.len),
        LEShortField('wkc', 0)
    ]


################
# read messages
################

class EtherCatAPRD(EtherCatType12DLPDU):
    """
    APRD - Auto Increment Physical Read
    (IEC 61158-5-12, sec. 5.4.1.2 tab. 14 / p. 32)
    """

    fields_desc = [ByteField('_cmd', 0x01)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFPRD(EtherCatType12DLPDU):
    """
    FPRD - Configured address physical read
    (IEC 61158-5-12, sec. 5.4.1.3 tab. 15 / p. 33)
    """

    fields_desc = [ByteField('_cmd', 0x04)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatBRD(EtherCatType12DLPDU):
    """
    BRD - Broadcast read
    (IEC 61158-5-12, sec. 5.4.1.4 tab. 16 / p. 34)
    """

    fields_desc = [ByteField('_cmd', 0x07)] + \
        EtherCatType12DLPDU.BROADCAST_ADDRESSING_DESC


class EtherCatLRD(EtherCatType12DLPDU):
    """
    LRD - Logical read
    (IEC 61158-5-12, sec. 5.4.1.5 tab. 17 / p. 36)
    """

    fields_desc = [ByteField('_cmd', 0x0a)] + \
        EtherCatType12DLPDU.LOGICAL_ADDRESSING_DESC


#################
# write messages
#################


class EtherCatAPWR(EtherCatType12DLPDU):
    """
    APWR - Auto Increment Physical Write
    (IEC 61158-5-12, sec. 5.4.2.2 tab. 18 / p. 37)
    """

    fields_desc = [ByteField('_cmd', 0x02)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFPWR(EtherCatType12DLPDU):
    """
    FPWR - Configured address physical write
    (IEC 61158-5-12, sec. 5.4.2.3 tab. 19 / p. 38)
    """

    fields_desc = [ByteField('_cmd', 0x05)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatBWR(EtherCatType12DLPDU):
    """
    BWR - Broadcast read (IEC 61158-5-12, sec. 5.4.2.4 tab. 20 / p. 39)
    """

    fields_desc = [ByteField('_cmd', 0x08)] + \
        EtherCatType12DLPDU.BROADCAST_ADDRESSING_DESC


class EtherCatLWR(EtherCatType12DLPDU):
    """
    LWR - Logical write
    (IEC 61158-5-12, sec. 5.4.2.5 tab. 21 / p. 40)
    """

    fields_desc = [ByteField('_cmd', 0x0b)] + \
        EtherCatType12DLPDU.LOGICAL_ADDRESSING_DESC


######################
# read/write messages
######################


class EtherCatAPRW(EtherCatType12DLPDU):
    """
    APRW - Auto Increment Physical Read Write
    (IEC 61158-5-12, sec. 5.4.3.1 tab. 22 / p. 41)
    """

    fields_desc = [ByteField('_cmd', 0x03)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFPRW(EtherCatType12DLPDU):
    """
    FPRW - Configured address physical read write
    (IEC 61158-5-12, sec. 5.4.3.2 tab. 23 / p. 43)
    """

    fields_desc = [ByteField('_cmd', 0x06)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatBRW(EtherCatType12DLPDU):
    """
    BRW - Broadcast read write
    (IEC 61158-5-12, sec. 5.4.3.3 tab. 24 / p. 39)
    """

    fields_desc = [ByteField('_cmd', 0x09)] + \
        EtherCatType12DLPDU.BROADCAST_ADDRESSING_DESC


class EtherCatLRW(EtherCatType12DLPDU):
    """
    LRW - Logical read write
    (IEC 61158-5-12, sec. 5.4.3.4 tab. 25 / p. 45)
    """

    fields_desc = [ByteField('_cmd', 0x0c)] + \
        EtherCatType12DLPDU.LOGICAL_ADDRESSING_DESC


class EtherCatARMW(EtherCatType12DLPDU):
    """
    ARMW - Auto increment physical read multiple write
    (IEC 61158-5-12, sec. 5.4.3.5 tab. 26 / p. 46)
    """

    fields_desc = [ByteField('_cmd', 0x0d)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFRMW(EtherCatType12DLPDU):
    """
    FRMW - Configured address physical read multiple write
    (IEC 61158-5-12, sec. 5.4.3.6 tab. 27 / p. 47)
    """

    fields_desc = [ByteField('_cmd', 0x0e)] + \
        EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCat(Packet):
    """
    Common EtherCat header layer
    """
    ETHER_HEADER_LEN = 14
    ETHER_FSC_LEN = 4
    ETHER_FRAME_MIN_LEN = 64
    ETHERCAT_HEADER_LEN = 2

    FRAME_TYPES = {
        0x01: 'TYPE-12-PDU',
        0x04: 'NETWORK-VARIABLES',
        0x05: 'MAILBOX'
    }

    fields_desc = [
        LEBitField('length', 0, 11),
        LEBitField('_reserved', 0, 1),
        LEBitField('type', 0, 4),
    ]

    ETHERCAT_TYPE12_DLPDU_TYPES = {
        0x01: EtherCatAPRD,
        0x04: EtherCatFPRD,
        0x07: EtherCatBRD,
        0x0a: EtherCatLRD,
        0x02: EtherCatAPWR,
        0x05: EtherCatFPWR,
        0x08: EtherCatBWR,
        0x0b: EtherCatLWR,
        0x03: EtherCatAPRW,
        0x06: EtherCatFPRW,
        0x09: EtherCatBRW,
        0x0c: EtherCatLRW,
        0x0d: EtherCatARMW,
        0x0e: EtherCatFRMW
    }

    def post_build(self, pkt, pay):
        """
        need to set the length of the whole PDU manually
        to avoid any bit fiddling use a dummy class to build the layer content

        also add padding if frame is < 64 bytes

        Note: padding only handles Ether/n*Dot1Q/EtherCat
              (no special mumbo jumbo)

        :param pkt: raw string containing the current layer
        :param pay: raw string containing the payload
        :return: <new current layer> + payload
        """

        class _EtherCatLengthCalc(Packet):
            """
            dummy class used to generate str representation easily
            """
            fields_desc = [
                LEBitField('length', None, 11),
                LEBitField('_reserved', 0, 1),
                LEBitField('type', 0, 4),
            ]

        payload_len = len(pay)

        # length field is 11 bit
        if payload_len > 2047:
            raise ValueError('payload size {} exceeds maximum length {} '
                             'of EtherCat message.'.format(payload_len, 2047))

        self.length = payload_len

        vlan_headers_total_size = 0
        upper_layer = self.underlayer

        # add size occupied by VLAN tags
        while upper_layer and isinstance(upper_layer, Dot1Q):
            vlan_headers_total_size += 4
            upper_layer = upper_layer.underlayer

        if not isinstance(upper_layer, Ether):
            raise Exception('missing Ether layer')

        pad_len = EtherCat.ETHER_FRAME_MIN_LEN - (EtherCat.ETHER_HEADER_LEN +
                                                  vlan_headers_total_size +
                                                  EtherCat.ETHERCAT_HEADER_LEN +  # noqa: E501
                                                  payload_len +
                                                  EtherCat.ETHER_FSC_LEN)

        if pad_len > 0:
            pad = Padding()
            pad.load = b'\x00' * pad_len

            return raw(_EtherCatLengthCalc(length=self.length,
                                           type=self.type)) + pay + raw(pad)
        return raw(_EtherCatLengthCalc(length=self.length,
                                       type=self.type)) + pay

    def guess_payload_class(self, payload):
        try:
            dlpdu_type = payload[0]
            return EtherCat.ETHERCAT_TYPE12_DLPDU_TYPES[dlpdu_type]
        except KeyError:
            log_runtime.error(
                '{}.guess_payload_class() - unknown or invalid '
                'DLPDU type'.format(self.__class__.__name__))
            return Packet.guess_payload_class(self, payload)


bind_layers(Ether, EtherCat, type=0x88a4)
bind_layers(Dot1Q, EtherCat, type=0x88a4)

# bindings for DLPDUs

bind_layers(EtherCat, EtherCatAPRD, type=0x01)
bind_layers(EtherCat, EtherCatFPRD, type=0x01)
bind_layers(EtherCat, EtherCatBRD, type=0x01)
bind_layers(EtherCat, EtherCatLRD, type=0x01)
bind_layers(EtherCat, EtherCatAPWR, type=0x01)
bind_layers(EtherCat, EtherCatFPWR, type=0x01)
bind_layers(EtherCat, EtherCatBWR, type=0x01)
bind_layers(EtherCat, EtherCatLWR, type=0x01)
bind_layers(EtherCat, EtherCatAPRW, type=0x01)
bind_layers(EtherCat, EtherCatFPRW, type=0x01)
bind_layers(EtherCat, EtherCatBRW, type=0x01)
bind_layers(EtherCat, EtherCatLRW, type=0x01)
bind_layers(EtherCat, EtherCatARMW, type=0x01)
bind_layers(EtherCat, EtherCatFRMW, type=0x01)
