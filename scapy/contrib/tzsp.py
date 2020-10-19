# scapy.contrib.description = TaZmen Sniffer Protocol (TZSP)
# scapy.contrib.status = loads

"""
    TZSP - TaZmen Sniffer Protocol
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

        This module provides Scapy layers for the TZSP protocol.

        references:
            - https://en.wikipedia.org/wiki/TZSP
            - https://web.archive.org/web/20050404125022/http://www.networkchemistry.com/support/appnotes/an001_tzsp.html  # noqa: E501

    :NOTES:
        - to allow Scapy to dissect this layer automatically, you need to bind the TZSP layer to UDP using  # noqa: E501
          the default TZSP port (0x9090), e.g.

            bind_layers(UDP, TZSP, sport=TZSP_PORT_DEFAULT)
            bind_layers(UDP, TZSP, dport=TZSP_PORT_DEFAULT)

        - packet format definition from www.networkchemistry.com is different from the one given by wikipedia  # noqa: E501
        - seems Wireshark implements the wikipedia protocol version (didn't dive into their code)  # noqa: E501
        - observed (miss)behavior of Wireshark (2.2.6)
          - fails to decode RSSI & SNR using short values - only one byte taken
          - SNR is labeled as silence
          - WlanRadioHdrSerial is labeled as Sensor MAC
          - doesn't know the packet count tag (40 / 0x28)

"""
from scapy.compat import orb
from scapy.contrib.avs import AVSWLANHeader
from scapy.error import warning, Scapy_Exception
from scapy.fields import ByteField, ShortEnumField, IntField, FieldLenField, YesNoByteField  # noqa: E501
from scapy.layers.dot11 import Packet, Dot11, PrismHeader
from scapy.layers.l2 import Ether
from scapy.fields import StrLenField, ByteEnumField, ShortField, XStrLenField
from scapy.packet import Raw


TZSP_PORT_DEFAULT = 0x9090


class TZSP(Packet):
    TYPE_RX_PACKET = 0x00
    TYPE_TX_PACKET = 0x01
    TYPE_CONFIG = 0x03
    TYPE_KEEPALIVE = TYPE_NULL = 0x04
    TYPE_PORT = 0x05

    TYPES = {
        TYPE_RX_PACKET: 'RX_PACKET',
        TYPE_TX_PACKET: 'TX_PACKET',
        TYPE_CONFIG: 'CONFIG',
        TYPE_NULL: 'KEEPALIVE/NULL',
        TYPE_PORT: 'PORT',
    }

    ENCAPSULATED_ETHERNET = 0x01
    ENCAPSULATED_IEEE_802_11 = 0x12
    ENCAPSULATED_PRISM_HEADER = 0x77
    ENCAPSULATED_WLAN_AVS = 0x7f

    ENCAPSULATED_PROTOCOLS = {
        ENCAPSULATED_ETHERNET: 'ETHERNET',
        ENCAPSULATED_IEEE_802_11: 'IEEE 802.11',
        ENCAPSULATED_PRISM_HEADER: 'PRISM HEADER',
        ENCAPSULATED_WLAN_AVS: 'WLAN AVS'
    }

    ENCAPSULATED_PROTOCOL_CLASSES = {
        ENCAPSULATED_ETHERNET: Ether,
        ENCAPSULATED_IEEE_802_11: Dot11,
        ENCAPSULATED_PRISM_HEADER: PrismHeader,
        ENCAPSULATED_WLAN_AVS: AVSWLANHeader
    }

    fields_desc = [
        ByteField('version', 0x01),
        ByteEnumField('type', TYPE_RX_PACKET, TYPES),
        ShortEnumField('encapsulated_protocol', ENCAPSULATED_ETHERNET, ENCAPSULATED_PROTOCOLS)  # noqa: E501
    ]

    def get_encapsulated_payload_class(self):
        """
        get the class that holds the encapsulated payload of the TZSP packet
        :return: class representing the payload, Raw() on error
        """

        try:
            return TZSP.ENCAPSULATED_PROTOCOL_CLASSES[self.encapsulated_protocol]  # noqa: E501
        except KeyError:
            warning(
                'unknown or invalid encapsulation type (%i) - returning payload as raw()' % self.encapsulated_protocol)  # noqa: E501
            return Raw

    def guess_payload_class(self, payload):
        if self.type == TZSP.TYPE_KEEPALIVE:
            if len(payload):
                warning('payload (%i bytes) in KEEPALIVE/NULL packet',
                        len(payload))
            return Raw
        else:
            return _tzsp_guess_next_tag(payload)

    def get_encapsulated_payload(self):

        has_encapsulated_data = self.type == TZSP.TYPE_RX_PACKET or self.type == TZSP.TYPE_TX_PACKET  # noqa: E501

        if has_encapsulated_data:
            end_tag_lyr = self.payload.getlayer(TZSPTagEnd)
            if end_tag_lyr:
                return end_tag_lyr.payload
            else:
                return None


def _tzsp_handle_unknown_tag(payload, tag_type):

    payload_len = len(payload)

    if payload_len < 2:
        warning('invalid or unknown tag type (%i) and too short packet - '
                'treat remaining data as Raw', tag_type)
        return Raw

    tag_data_length = orb(payload[1])

    tag_data_fits_in_payload = (tag_data_length + 2) <= payload_len
    if not tag_data_fits_in_payload:
        warning('invalid or unknown tag type (%i) and too short packet - '
                'treat remaining data as Raw', tag_type)
        return Raw

    warning('invalid or unknown tag type (%i)', tag_type)

    return TZSPTagUnknown


def _tzsp_guess_next_tag(payload):
    """
    :return: class representing the next tag, Raw on error, None on missing payload  # noqa: E501
    """

    if not payload:
        warning('missing payload')
        return None

    tag_type = orb(payload[0])

    try:
        tag_class_definition = _TZSP_TAG_CLASSES[tag_type]

    except KeyError:

        return _tzsp_handle_unknown_tag(payload, tag_type)

    if type(tag_class_definition) is not dict:
        return tag_class_definition

    try:
        length = orb(payload[1])
    except IndexError:
        length = None

    if not length:
        warning('no tag length given - packet too short')
        return Raw

    try:
        return tag_class_definition[length]
    except KeyError:
        warning('invalid tag length %s for tag type %s', length, tag_type)
        return Raw


class _TZSPTag(Packet):
    TAG_TYPE_PADDING = 0x00
    TAG_TYPE_END = 0x01
    TAG_TYPE_RAW_RSSI = 0x0a
    TAG_TYPE_SNR = 0x0b
    TAG_TYPE_DATA_RATE = 0x0c
    TAG_TYPE_TIMESTAMP = 0x0d
    TAG_TYPE_CONTENTION_FREE = 0x0f
    TAG_TYPE_DECRYPTED = 0x10
    TAG_TYPE_FCS_ERROR = 0x11
    TAG_TYPE_RX_CHANNEL = 0x12
    TAG_TYPE_PACKET_COUNT = 0x28
    TAG_TYPE_RX_FRAME_LENGTH = 0x29
    TAG_TYPE_WLAN_RADIO_HDR_SERIAL = 0x3c

    TAG_TYPES = {
        TAG_TYPE_PADDING: 'PADDING',
        TAG_TYPE_END: 'END',
        TAG_TYPE_RAW_RSSI: 'RAW_RSSI',
        TAG_TYPE_SNR: 'SNR',
        TAG_TYPE_DATA_RATE: 'DATA_RATE',
        TAG_TYPE_TIMESTAMP: 'TIMESTAMP',
        TAG_TYPE_CONTENTION_FREE: 'CONTENTION_FREE',
        TAG_TYPE_DECRYPTED: 'DECRYPTED',
        TAG_TYPE_FCS_ERROR: 'FCS_ERROR',
        TAG_TYPE_RX_CHANNEL: 'RX_CHANNEL',
        TAG_TYPE_PACKET_COUNT: 'PACKET_COUNT',
        TAG_TYPE_RX_FRAME_LENGTH: 'RX_FRAME_LENGTH',
        TAG_TYPE_WLAN_RADIO_HDR_SERIAL: 'WLAN_RADIO_HDR_SERIAL'
    }

    def guess_payload_class(self, payload):
        return _tzsp_guess_next_tag(payload)


class TZSPStructureException(Scapy_Exception):
    pass


class TZSPTagPadding(_TZSPTag):
    """
    padding tag (should be ignored)
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_PADDING, _TZSPTag.TAG_TYPES),
    ]


class TZSPTagEnd(Packet):
    """
    last tag
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_END, _TZSPTag.TAG_TYPES),
    ]

    def guess_payload_class(self, payload):
        """
        the type of the payload encapsulation is given be the outer TZSP layers attribute encapsulation_protocol  # noqa: E501
        """

        under_layer = self.underlayer
        tzsp_header = None

        while under_layer:
            if isinstance(under_layer, TZSP):
                tzsp_header = under_layer
                break
            under_layer = under_layer.underlayer

        if tzsp_header:

            return tzsp_header.get_encapsulated_payload_class()
        else:
            raise TZSPStructureException('missing parent TZSP header')


class TZSPTagRawRSSIByte(_TZSPTag):
    """
    relative received signal strength - signed byte value
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_RAW_RSSI, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        ByteField('raw_rssi', 0)
    ]


class TZSPTagRawRSSIShort(_TZSPTag):
    """
    relative received signal strength - signed short value
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_RAW_RSSI, _TZSPTag.TAG_TYPES),
        ByteField('len', 2),
        ShortField('raw_rssi', 0)
    ]


class TZSPTagSNRByte(_TZSPTag):
    """
    signal noise ratio - signed byte value
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_SNR, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        ByteField('snr', 0)
    ]


class TZSPTagSNRShort(_TZSPTag):
    """
    signal noise ratio - signed short value
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_SNR, _TZSPTag.TAG_TYPES),
        ByteField('len', 2),
        ShortField('snr', 0)
    ]


class TZSPTagDataRate(_TZSPTag):
    """
    wireless link data rate
    """
    DATA_RATE_UNKNOWN = 0x00
    DATA_RATE_1 = 0x02
    DATA_RATE_2 = 0x04
    DATA_RATE_5_5 = 0x0B
    DATA_RATE_6 = 0x0C
    DATA_RATE_9 = 0x12
    DATA_RATE_11 = 0x16
    DATA_RATE_12 = 0x18
    DATA_RATE_18 = 0x24
    DATA_RATE_22 = 0x2C
    DATA_RATE_24 = 0x30
    DATA_RATE_33 = 0x42
    DATA_RATE_36 = 0x48
    DATA_RATE_48 = 0x60
    DATA_RATE_54 = 0x6C
    DATA_RATE_LEGACY_1 = 0x0A
    DATA_RATE_LEGACY_2 = 0x14
    DATA_RATE_LEGACY_5_5 = 0x37
    DATA_RATE_LEGACY_11 = 0x6E

    DATA_RATES = {
        DATA_RATE_UNKNOWN: 'unknown',
        DATA_RATE_1: '1 MB/s',
        DATA_RATE_2: '2 MB/s',
        DATA_RATE_5_5: '5.5 MB/s',
        DATA_RATE_6: '6 MB/s',
        DATA_RATE_9: '9 MB/s',
        DATA_RATE_11: '11 MB/s',
        DATA_RATE_12: '12 MB/s',
        DATA_RATE_18: '18 MB/s',
        DATA_RATE_22: '22 MB/s',
        DATA_RATE_24: '24 MB/s',
        DATA_RATE_33: '33 MB/s',
        DATA_RATE_36: '36 MB/s',
        DATA_RATE_48: '48 MB/s',
        DATA_RATE_54: '54 MB/s',
        DATA_RATE_LEGACY_1: '1 MB/s (legacy)',
        DATA_RATE_LEGACY_2: '2 MB/s (legacy)',
        DATA_RATE_LEGACY_5_5: '5.5 MB/s (legacy)',
        DATA_RATE_LEGACY_11: '11 MB/s (legacy)',
    }

    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_DATA_RATE, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        ByteEnumField('data_rate', DATA_RATE_UNKNOWN, DATA_RATES)
    ]


class TZSPTagTimestamp(_TZSPTag):
    """
    MAC receive timestamp
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_TIMESTAMP, _TZSPTag.TAG_TYPES),
        ByteField('len', 4),
        IntField('timestamp', 0)
    ]


class TZSPTagContentionFree(_TZSPTag):
    """
    packet received in contention free period
    """
    NO = 0x00
    YES = 0x01

    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_CONTENTION_FREE, _TZSPTag.TAG_TYPES),  # noqa: E501
        ByteField('len', 1),
        YesNoByteField('contention_free', NO)
    ]


class TZSPTagDecrypted(_TZSPTag):
    """
    packet was decrypted
    """
    YES = 0x00
    NO = 0x01

    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_DECRYPTED, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        YesNoByteField('decrypted', NO, config={'yes': YES, 'no': (NO, 0xff)})
    ]


class TZSPTagError(_TZSPTag):
    """
    frame checksum error
    """
    NO = 0x00
    YES = 0x01

    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_FCS_ERROR, _TZSPTag.TAG_TYPES),
        ByteField('len', 1),
        YesNoByteField('fcs_error', NO, config={'no': NO, 'yes': YES, 'reserved': (YES + 1, 0xff)})  # noqa: E501
    ]


class TZSPTagRXChannel(_TZSPTag):
    """
    channel the sensor was on while receiving the frame
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_RX_CHANNEL, _TZSPTag.TAG_TYPES),  # noqa: E501
        ByteField('len', 1),
        ByteField('rx_channel', 0)
    ]


class TZSPTagPacketCount(_TZSPTag):
    """
    packet counter
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_PACKET_COUNT, _TZSPTag.TAG_TYPES),  # noqa: E501
        ByteField('len', 4),
        IntField('packet_count', 0)
    ]


class TZSPTagRXFrameLength(_TZSPTag):
    """
    received packet length
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_RX_FRAME_LENGTH, _TZSPTag.TAG_TYPES),  # noqa: E501
        ByteField('len', 2),
        ShortField('rx_frame_length', 0)
    ]


class TZSPTagWlanRadioHdrSerial(_TZSPTag):
    """
    (vendor specific) unique capture device (sensor/AP) identifier
    """
    fields_desc = [
        ByteEnumField('type', _TZSPTag.TAG_TYPE_WLAN_RADIO_HDR_SERIAL, _TZSPTag.TAG_TYPES),  # noqa: E501
        FieldLenField('len', None, length_of='sensor_id', fmt='b'),
        StrLenField('sensor_id', '', length_from=lambda pkt:pkt.len)
    ]


class TZSPTagUnknown(_TZSPTag):
    """
    unknown tag type dummy
    """
    fields_desc = [
        ByteField('type', 0xff),
        FieldLenField('len', None, length_of='data', fmt='b'),
        XStrLenField('data', '', length_from=lambda pkt: pkt.len)
    ]


_TZSP_TAG_CLASSES = {
    _TZSPTag.TAG_TYPE_PADDING: TZSPTagPadding,
    _TZSPTag.TAG_TYPE_END: TZSPTagEnd,
    _TZSPTag.TAG_TYPE_RAW_RSSI: {1: TZSPTagRawRSSIByte, 2: TZSPTagRawRSSIShort},  # noqa: E501
    _TZSPTag.TAG_TYPE_SNR: {1: TZSPTagSNRByte, 2: TZSPTagSNRShort},
    _TZSPTag.TAG_TYPE_DATA_RATE: TZSPTagDataRate,
    _TZSPTag.TAG_TYPE_TIMESTAMP: TZSPTagTimestamp,
    _TZSPTag.TAG_TYPE_CONTENTION_FREE: TZSPTagContentionFree,
    _TZSPTag.TAG_TYPE_DECRYPTED: TZSPTagDecrypted,
    _TZSPTag.TAG_TYPE_FCS_ERROR: TZSPTagError,
    _TZSPTag.TAG_TYPE_RX_CHANNEL: TZSPTagRXChannel,
    _TZSPTag.TAG_TYPE_PACKET_COUNT: TZSPTagPacketCount,
    _TZSPTag.TAG_TYPE_RX_FRAME_LENGTH: TZSPTagRXFrameLength,
    _TZSPTag.TAG_TYPE_WLAN_RADIO_HDR_SERIAL: TZSPTagWlanRadioHdrSerial
}
