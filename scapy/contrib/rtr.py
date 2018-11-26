# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2018 Francois Contat <francois.contat@ssi.gouv.fr>

# Based on RTR RFC 6810 https://tools.ietf.org/html/rfc6810 for version 0
# Based on RTR RFC 8210 https://tools.ietf.org/html/rfc8210 for version 1

# scapy.contrib.description = The RPKI to Router Protocol
# scapy.contrib.status = loads

# Start dev

import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IntField, ShortField
from scapy.fields import IPField, IP6Field, StrLenField
from scapy.fields import FieldLenField
from scapy.fields import StrFixedLenField, ShortEnumField
from scapy.layers.inet import TCP

STATIC_SERIAL_NOTIFY_LENGTH = 12
STATIC_SERIAL_QUERY_LENGTH = 12
STATIC_RESET_QUERY_LENGTH = 8
STATIC_CACHE_RESET_LENGTH = 8
STATIC_CACHE_RESPONSE_LENGTH = 8
STATIC_IPV4_PREFIX_LENGTH = 20
STATIC_IPV6_PREFIX_LENGTH = 32
STATIC_END_OF_DATA_V0_LENGTH = 12
STATIC_END_OF_DATA_V1_LENGTH = 24

RTR_VERSION = {0: '0',
               1: '1'}

PDU_TYPE = {0: 'Serial Notify',
            1: 'Serial Query',
            2: 'Reset Query',
            3: 'Cache Response',
            4: 'IPv4 Prefix',
            6: 'IPv6 Prefix',
            7: 'End of Data',
            8: 'Cache Reset',
            9: 'Router Key',
            10: 'Error Report',
            255: 'Reserved'}

ERROR_LIST = {0: 'Corrupt Data',
              1: 'Internal Error',
              2: 'No data Available',
              3: 'Invalid Request',
              4: 'Unsupported Protocol Version',
              5: 'Unsupported PDU Type',
              6: 'Withdrawal of Unknown Record',
              7: 'Duplicate Announcement Received',
              8: 'Unexpected Protocol Version'}


class RTRSerialNotify(Packet):

    '''

    Serial Notify packet from section 5.2
    https://tools.ietf.org/html/rfc6810#section-5.2

    '''

    name = 'Serial Notify'
    fields_desc = [ShortField('session_id', 0),
                   IntField('length', STATIC_SERIAL_NOTIFY_LENGTH),
                   IntField('serial_number', 0)]


class RTRSerialQuery(Packet):

    '''

    Serial Query packet from section 5.3
    https://tools.ietf.org/html/rfc6810#section-5.3

    '''
    name = 'Serial Query'
    fields_desc = [ShortField('session_id', 0),
                   IntField('length', STATIC_SERIAL_QUERY_LENGTH),
                   IntField('serial_number', 0)]


class RTRResetQuery(Packet):

    '''

    Reset Query packet from section 5.4
    https://tools.ietf.org/html/rfc6810#section-5.4

    '''
    name = 'Reset Query'
    fields_desc = [ShortField('reserved', 0),
                   IntField('length', STATIC_RESET_QUERY_LENGTH)]


class RTRCacheResponse(Packet):

    '''

    Cache Response packet from section 5.5
    https://tools.ietf.org/html/rfc6810#section-5.5

    '''
    name = 'Cache Response'
    fields_desc = [ShortField('session_id', 0),
                   IntField('length', STATIC_CACHE_RESPONSE_LENGTH)]

    def guess_payload_class(self, payload):
        return RTRHeader


class RTRIPv4Prefix(Packet):

    '''

    IPv4 Prefix packet from section 5.6
    https://tools.ietf.org/html/rfc6810#section-5.6

    '''
    name = 'IPv4 Prefix'
    fields_desc = [ShortField('reserved', 0),
                   IntField('length', STATIC_IPV4_PREFIX_LENGTH),
                   ByteField('flags', 0),
                   ByteField('shortest_length', 0),
                   ByteField('longest_length', 0),
                   ByteField('zeros', 0),
                   IPField('prefix', '0.0.0.0'),
                   IntField('asn', 0)]

    def guess_payload_class(self, payload):
        return RTRHeader


class RTRIPv6Prefix(Packet):

    '''

    IPv6 Prefix packet from section 5.7
    https://tools.ietf.org/html/rfc6810#section-5.7

    '''
    name = 'IPv6 Prefix'
    fields_desc = [ShortField('reserved', 0),
                   IntField('length', STATIC_IPV6_PREFIX_LENGTH),
                   ByteField('flags', 0),
                   ByteField('shortest_length', 0),
                   ByteField('longest_length', 0),
                   ByteField('zeros', 0),
                   IP6Field("prefix", "::"),
                   IntField('asn', 0)]

    def guess_payload_class(self, payload):
        return RTRHeader


class RTREndofDatav0(Packet):

    '''

    End of Data packet from version 0 standard section 5.8
    https://tools.ietf.org/html/rfc6810#section-5.8

    '''
    name = 'End of Data - version 0'
    fields_desc = [ShortField('session_id', 0),
                   IntField('length', STATIC_END_OF_DATA_V0_LENGTH),
                   IntField('serial_number', 0)]


class RTREndofDatav1(Packet):

    '''

    End of Data packet from version 1 standard section 5.8
    https://tools.ietf.org/html/rfc8210#section-5.8

    '''
    name = 'End of Data - version 1'
    fields_desc = [ShortField('session_id', 0),
                   IntField('length', STATIC_END_OF_DATA_V1_LENGTH),
                   IntField('serial_number', 0),
                   IntField('refresh_interval', 0),
                   IntField('retry_interval', 0),
                   IntField('expire_interval', 0)]


class RTRCacheReset(Packet):

    '''

    Cache Reset packet from section 5.9
    https://tools.ietf.org/html/rfc6810#section-5.9

    '''
    name = 'Reset Query'
    fields_desc = [ShortField('reserved', 0),
                   IntField('length', STATIC_CACHE_RESET_LENGTH)]


class RTRRouterKey(Packet):

    '''

    Router Key packet from version 1 standard section 5.10
    https://tools.ietf.org/html/rfc8210#section-5.10

    '''
    name = 'Router Key'
    fields_desc = [ByteField('flags', 0),
                   ByteField('zeros', 0),
                   IntField('length', None),
                   StrFixedLenField('subject_key_identifier', '', 20),
                   IntField('asn', 0),
                   StrLenField('subject_PKI', '',
                               length_from=lambda x: x.length - 32)]

    def post_build(self, pkt, pay):
        temp_len = len(pkt) + 2
        if not self.length:
            pkt = pkt[:2] + struct.pack('!I', temp_len) + pkt[6:]
        return pkt + pay


class RTRErrorReport(Packet):

    '''

    Error Report packet from section 5.10
    https://tools.ietf.org/html/rfc6810#section-5.10

    '''
    name = 'Error Report'
    fields_desc = [ShortEnumField('error_code', 0, ERROR_LIST),
                   IntField('length', None),
                   FieldLenField('length_of_encaps_PDU',
                                 None, fmt='!I', length_of='erroneous_PDU'),
                   StrLenField('erroneous_PDU', '',
                               length_from=lambda x: x.length_of_encaps_PDU),
                   FieldLenField('length_of_error_text', None, fmt='!I',
                                 length_of='error_text'),
                   StrLenField('error_text', '',
                               length_from=lambda x: x.length_of_error_text)]

    def post_build(self, pkt, pay):
        temp_len = len(pkt) + 2
        if not self.length:
            pkt = pkt[:2] + struct.pack('!I', temp_len) + pkt[6:]
        return pkt + pay


class RTRHeader(Packet):

    '''

    RPKI to Router Header from every RTR packet
    eg. https://tools.ietf.org/html/rfc6810#section-5.2
    '''
    name = 'RTR Header'
    fields_desc = [ByteEnumField('rtr_version', 0, RTR_VERSION),
                   ByteEnumField('pdu_type', 0, PDU_TYPE)]

    def guess_payload_class(self, payload):
        if self.pdu_type == 0:
            return RTRSerialNotify
        elif self.pdu_type == 1:
            return RTRSerialQuery
        elif self.pdu_type == 2:
            return RTRResetQuery
        elif self.pdu_type == 3:
            return RTRCacheResponse
        elif self.pdu_type == 4:
            return RTRIPv4Prefix
        elif self.pdu_type == 6:
            return RTRIPv6Prefix
        elif self.pdu_type == 7:
            if self.rtr_version == 0:
                return RTREndofDatav0
            elif self.rtr_version == 1:
                return RTREndofDatav1
        elif self.pdu_type == 8:
            return RTRCacheReset
        elif self.pdu_type == 9:
            if self.rtr_version == 1:
                return RTRRouterKey
        elif self.pdu_type == 10:
            return RTRErrorReport


bind_layers(TCP, RTRHeader, dport=323)  # real reserved port
bind_layers(TCP, RTRHeader, sport=323)  # real reserved port
bind_layers(TCP, RTRHeader, dport=8282)  # RIPE implementation default port
bind_layers(TCP, RTRHeader, sport=8282)  # RIPE implementation default port
bind_layers(RTRHeader, RTRCacheResponse, pdu_type=3, dport=8282)

if __name__ == '__main__':
    from scapy.main import interact
    interact(mydict=globals(), mybanner='RPKI to Router')
