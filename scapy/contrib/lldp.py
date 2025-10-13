# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Link Layer Discovery Protocol (LLDP)
# scapy.contrib.status = loads

"""
    LLDP - Link Layer Discovery Protocol
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Thomas Tannhaeuser, hecke@naberius.de

    :description:

        This module provides Scapy layers for the LLDP protocol.

        normative references:
            - IEEE 802.1AB 2016 - LLDP protocol, topology and MIB description

    :TODO:
        - | organization specific TLV e.g. ProfiNet
          | (see LLDPDUGenericOrganisationSpecific for a starting point)
        - Ignore everything after EndofLLDPDUTLV

    :NOTES:
        - you can find the layer configuration options at the end of this file
        - default configuration enforces standard conform:

          * | frame structure
            | (ChassisIDTLV/PortIDTLV/TimeToLiveTLV/...)
          * multiplicity of TLVs (if given by the standard)
          * min sizes of strings used by the TLVs

        - conf.contribs['LLDP'].strict_mode_disable() -> disable strict mode

"""
from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.layers.l2 import Ether, Dot1Q
from scapy.fields import MACField, IPField, IP6Field, BitField, \
    StrLenField, ByteEnumField, BitEnumField, \
    EnumField, ThreeBytesField, BitFieldLenField, \
    ShortField, XStrLenField, ByteField, ConditionalField, \
    MultipleTypeField, FlagsField, ShortEnumField, ScalingField, \
    BitScalingField
from scapy.packet import Packet, bind_layers
from scapy.data import ETHER_TYPES
from scapy.compat import orb, bytes_int

LLDP_NEAREST_BRIDGE_MAC = '01:80:c2:00:00:0e'
LLDP_NEAREST_NON_TPMR_BRIDGE_MAC = '01:80:c2:00:00:03'
LLDP_NEAREST_CUSTOMER_BRIDGE_MAC = '01:80:c2:00:00:00'

LLDP_ETHER_TYPE = 0x88cc
ETHER_TYPES[LLDP_ETHER_TYPE] = 'LLDP'


class LLDPInvalidFieldValue(Scapy_Exception):
    """
    field value is out of allowed range
    """
    pass


class LLDPInvalidFrameStructure(Scapy_Exception):
    """
    basic frame structure not standard conform
    (missing TLV, invalid order or multiplicity)
    """
    pass


class LLDPMissingLowerLayer(Scapy_Exception):
    """
    first layer below first LLDPDU must be Ethernet or Dot1q
    """
    pass


class LLDPInvalidTLVCount(Scapy_Exception):
    """
    invalid number of entries for a specific TLV type
    """
    pass


class LLDPInvalidLengthField(Scapy_Exception):
    """
    invalid value of length field
    """
    pass


class LLDPDU(Packet):
    """
    base class for all LLDP data units
    """
    TYPES = {
        0x00: 'end of LLDPDU',
        0x01: 'chassis id',
        0x02: 'port id',
        0x03: 'time to live',
        0x04: 'port description',
        0x05: 'system name',
        0x06: 'system description',
        0x07: 'system capabilities',
        0x08: 'management address',
        127: 'organisation specific TLV'
    }

    IANA_ADDRESS_FAMILY_NUMBERS = {
        0x00: 'other',
        0x01: 'IPv4',
        0x02: 'IPv6',
        0x03: 'NSAP',
        0x04: 'HDLC',
        0x05: 'BBN',
        0x06: '802',
        0x07: 'E.163',
        0x08: 'E.164',
        0x09: 'F.69',
        0x0a: 'X.121',
        0x0b: 'IPX',
        0x0c: 'Appletalk',
        0x0d: 'Decnet IV',
        0x0e: 'Banyan Vines',
        0x0f: 'E.164 with NSAP',
        0x10: 'DNS',
        0x11: 'Distinguished Name',
        0x12: 'AS Number',
        0x13: 'XTP over IPv4',
        0x14: 'XTP over IPv6',
        0x15: 'XTP native mode XTP',
        0x16: 'Fiber Channel World-Wide Port Name',
        0x17: 'Fiber Channel World-Wide Node Name',
        0x18: 'GWID',
        0x19: 'AFI for L2VPN',
        0x1a: 'MPLS-TP Section Endpoint ID',
        0x1b: 'MPLS-TP LSP Endpoint ID',
        0x1c: 'MPLS-TP Pseudowire Endpoint ID',
        0x1d: 'MT IP Multi-Topology IPv4',
        0x1e: 'MT IP Multi-Topology IPv6'
    }

    DOT1Q_HEADER_LEN = 4
    ETHER_HEADER_LEN = 14
    ETHER_FSC_LEN = 4
    ETHER_FRAME_MIN_LEN = 64

    LAYER_STACK = []
    LAYER_MULTIPLICITIES = {}

    def guess_payload_class(self, payload):
        # type is a 7-bit bitfield spanning bits 1..7 -> div 2
        try:
            lldpdu_tlv_type = orb(payload[0]) // 2
            class_type = LLDPDU_CLASS_TYPES.get(lldpdu_tlv_type, conf.raw_layer)
            if isinstance(class_type, list):
                for cls in class_type:
                    if cls._match_organization_specific(payload):
                        return cls
            else:
                return class_type
        except IndexError:
            return conf.raw_layer

    @staticmethod
    def _dot1q_headers_size(layer):
        """
        calculate size of lower dot1q layers (if present)
        :param layer: the layer to start at
        :return: size of vlan headers, layer below lowest vlan header
        """

        vlan_headers_size = 0
        under_layer = layer

        while under_layer and isinstance(under_layer, Dot1Q):
            vlan_headers_size += LLDPDU.DOT1Q_HEADER_LEN
            under_layer = under_layer.underlayer

        return vlan_headers_size, under_layer

    def post_build(self, pkt, pay):

        under_layer = self.underlayer

        if under_layer is None:
            if conf.contribs['LLDP'].strict_mode():
                raise LLDPMissingLowerLayer('No lower layer (Ethernet '
                                            'or Dot1Q) provided.')
            else:
                return pkt + pay

        if isinstance(under_layer, LLDPDU):
            return pkt + pay

        frame_size, under_layer = LLDPDU._dot1q_headers_size(under_layer)

        if not under_layer or not isinstance(under_layer, Ether):
            if conf.contribs['LLDP'].strict_mode():
                raise LLDPMissingLowerLayer('No Ethernet layer provided.')
            else:
                return pkt + pay

        frame_size += LLDPDU.ETHER_HEADER_LEN
        frame_size += len(pkt) + len(pay) + LLDPDU.ETHER_FSC_LEN
        if frame_size < LLDPDU.ETHER_FRAME_MIN_LEN:
            return pkt + pay + b'\x00' * (LLDPDU.ETHER_FRAME_MIN_LEN - frame_size)  # noqa: E501
        return pkt + pay

    @staticmethod
    def _frame_structure_check(structure_description):
        """
        check if the structure of the frame is conform to the basic
        frame structure defined by the standard
        :param structure_description: string-list reflecting LLDP-msg structure
        """

        standard_frame_structure = [LLDPDUChassisID.__name__,
                                    LLDPDUPortID.__name__,
                                    LLDPDUTimeToLive.__name__,
                                    '<...>']

        if len(structure_description) < 3:
            raise LLDPInvalidFrameStructure(
                'Invalid frame structure.\ngot: {}\nexpected: '
                '{}'.format(' '.join(structure_description),
                            ' '.join(standard_frame_structure)))

        for idx, layer_name in enumerate(standard_frame_structure):

            if layer_name == '<...>':
                break
            if layer_name != structure_description[idx]:
                raise LLDPInvalidFrameStructure(
                    'Invalid frame structure.\ngot: {}\nexpected: '
                    '{}'.format(' '.join(structure_description),
                                ' '.join(standard_frame_structure)))

    @staticmethod
    def _tlv_multiplicities_check(tlv_type_count):
        """
        check if multiplicity of present TLVs conforms to the standard
        :param tlv_type_count: dict containing counte-per-TLV
        """

        # * : 0..n, 1 : one and only one.
        standard_multiplicities = {
            LLDPDUEndOfLLDPDU.__name__: '*',
            LLDPDUChassisID.__name__: 1,
            LLDPDUPortID.__name__: 1,
            LLDPDUTimeToLive.__name__: 1,
            LLDPDUPortDescription: '*',
            LLDPDUSystemName: '*',
            LLDPDUSystemDescription: '*',
            LLDPDUSystemCapabilities: '*',
            LLDPDUManagementAddress: '*'
        }

        for tlv_type_name in standard_multiplicities:

            standard_tlv_multiplicity = \
                standard_multiplicities[tlv_type_name]
            if standard_tlv_multiplicity == '*':
                continue

            try:
                if tlv_type_count[tlv_type_name] != standard_tlv_multiplicity:
                    raise LLDPInvalidTLVCount(
                        'Invalid number of entries for TLV type '
                        '{} - expected {} entries, got '
                        '{}'.format(tlv_type_name,
                                    standard_tlv_multiplicity,
                                    tlv_type_count[tlv_type_name]))

            except KeyError:
                raise LLDPInvalidTLVCount('Missing TLV layer of type '
                                          '{}.'.format(tlv_type_name))

    def pre_dissect(self, s):

        if conf.contribs['LLDP'].strict_mode():
            if self.__class__.__name__ == 'LLDPDU':
                LLDPDU.LAYER_STACK = []
                LLDPDU.LAYER_MULTIPLICITIES = {}
            else:
                LLDPDU.LAYER_STACK.append(self.__class__.__name__)
                try:
                    LLDPDU.LAYER_MULTIPLICITIES[self.__class__.__name__] += 1
                except KeyError:
                    LLDPDU.LAYER_MULTIPLICITIES[self.__class__.__name__] = 1

        return s

    def dissection_done(self, pkt):

        if self.__class__.__name__ == 'LLDPDU' and \
                conf.contribs['LLDP'].strict_mode():
            LLDPDU._frame_structure_check(LLDPDU.LAYER_STACK)
            LLDPDU._tlv_multiplicities_check(LLDPDU.LAYER_MULTIPLICITIES)

        super(LLDPDU, self).dissection_done(pkt)

    def _check(self):
        """Overwritten by LLDPU objects"""
        pass

    def post_dissect(self, s):
        self._check()
        return super(LLDPDU, self).post_dissect(s)

    def do_build(self):
        self._check()
        return super(LLDPDU, self).do_build()


def _ldp_id_adjustlen(pkt, x):
    """Return the length of the `id` field,
    according to its real encoded type"""
    f, v = pkt.getfield_and_val('id')
    length = f.i2len(pkt, v) + 1
    if (isinstance(pkt, LLDPDUPortID) and pkt.subtype == 0x4) or \
            (isinstance(pkt, LLDPDUChassisID) and pkt.subtype == 0x5):
        # Take the ConditionalField into account
        length += 1
    return length


def _ldp_id_lengthfrom(pkt):
    length = pkt._length
    if length is None:
        return 0
    # Subtract the subtype field
    length -= 1
    if (isinstance(pkt, LLDPDUPortID) and pkt.subtype == 0x4) or \
            (isinstance(pkt, LLDPDUChassisID) and pkt.subtype == 0x5):
        # Take the ConditionalField into account
        length -= 1
    return length


class LLDPDUChassisID(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.2 / p. 26
    """
    LLDP_CHASSIS_ID_TLV_SUBTYPES = {
        0x00: 'reserved',
        0x01: 'chassis component',
        0x02: 'interface alias',
        0x03: 'port component',
        0x04: 'MAC address',
        0x05: 'network address',
        0x06: 'interface name',
        0x07: 'locally assigned',
    }

    SUBTYPE_RESERVED = 0x00
    SUBTYPE_CHASSIS_COMPONENT = 0x01
    SUBTYPE_INTERFACE_ALIAS = 0x02
    SUBTYPE_PORT_COMPONENT = 0x03
    SUBTYPE_MAC_ADDRESS = 0x04
    SUBTYPE_NETWORK_ADDRESS = 0x05
    SUBTYPE_INTERFACE_NAME = 0x06
    SUBTYPE_LOCALLY_ASSIGNED = 0x07

    fields_desc = [
        BitEnumField('_type', 0x01, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='id',
                         adjust=lambda pkt, x: _ldp_id_adjustlen(pkt, x)),
        ByteEnumField('subtype', 0x00, LLDP_CHASSIS_ID_TLV_SUBTYPES),
        ConditionalField(
            ByteEnumField('family', 0, LLDPDU.IANA_ADDRESS_FAMILY_NUMBERS),
            lambda pkt: pkt.subtype == 0x05
        ),
        MultipleTypeField([
            (
                MACField('id', None),
                lambda pkt: pkt.subtype == 0x04
            ),
            (
                IPField('id', None),
                lambda pkt: pkt.subtype == 0x05 and pkt.family == 0x01
            ),
            (
                IP6Field('id', None),
                lambda pkt: pkt.subtype == 0x05 and pkt.family == 0x02
            ),
        ], StrLenField('id', '', length_from=_ldp_id_lengthfrom)
        )
    ]

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and not self.id:
            raise LLDPInvalidLengthField('id must be >= 1 characters long')


class LLDPDUPortID(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.3 / p. 26
    """
    LLDP_PORT_ID_TLV_SUBTYPES = {
        0x00: 'reserved',
        0x01: 'interface alias',
        0x02: 'port component',
        0x03: 'MAC address',
        0x04: 'network address',
        0x05: 'interface name',
        0x06: 'agent circuit ID',
        0x07: 'locally assigned',
    }

    SUBTYPE_RESERVED = 0x00
    SUBTYPE_INTERFACE_ALIAS = 0x01
    SUBTYPE_PORT_COMPONENT = 0x02
    SUBTYPE_MAC_ADDRESS = 0x03
    SUBTYPE_NETWORK_ADDRESS = 0x04
    SUBTYPE_INTERFACE_NAME = 0x05
    SUBTYPE_AGENT_CIRCUIT_ID = 0x06
    SUBTYPE_LOCALLY_ASSIGNED = 0x07

    fields_desc = [
        BitEnumField('_type', 0x02, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='id',
                         adjust=lambda pkt, x: _ldp_id_adjustlen(pkt, x)),
        ByteEnumField('subtype', 0x00, LLDP_PORT_ID_TLV_SUBTYPES),
        ConditionalField(
            ByteEnumField('family', 0, LLDPDU.IANA_ADDRESS_FAMILY_NUMBERS),
            lambda pkt: pkt.subtype == 0x04
        ),
        MultipleTypeField([
            (
                MACField('id', None),
                lambda pkt: pkt.subtype == 0x03
            ),
            (
                IPField('id', None),
                lambda pkt: pkt.subtype == 0x04 and pkt.family == 0x01
            ),
            (
                IP6Field('id', None),
                lambda pkt: pkt.subtype == 0x04 and pkt.family == 0x02
            ),
        ], StrLenField('id', '', length_from=_ldp_id_lengthfrom)
        )
    ]

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and not self.id:
            raise LLDPInvalidLengthField('id must be >= 1 characters long')


class LLDPDUTimeToLive(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.4 / p. 29
    """
    fields_desc = [
        BitEnumField('_type', 0x03, 7, LLDPDU.TYPES),
        BitField('_length', 0x02, 9),
        ShortField('ttl', 20)
    ]

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and self._length != 2:
            raise LLDPInvalidLengthField('length must be 2 - got '
                                         '{}'.format(self._length))


class LLDPDUEndOfLLDPDU(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.1 / p. 26
    """
    fields_desc = [
        BitEnumField('_type', 0x00, 7, LLDPDU.TYPES),
        BitField('_length', 0x00, 9),
    ]

    def extract_padding(self, s):
        return '', s

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and self._length != 0:
            raise LLDPInvalidLengthField('length must be 0 - got '
                                         '{}'.format(self._length))


class LLDPDUPortDescription(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.5 / p. 29
    """
    fields_desc = [
        BitEnumField('_type', 0x04, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='description'),
        StrLenField('description', '', length_from=lambda pkt: pkt._length)
    ]


class LLDPDUSystemName(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.6 / p. 30
    """
    fields_desc = [
        BitEnumField('_type', 0x05, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='system_name'),
        StrLenField('system_name', '', length_from=lambda pkt: pkt._length)
    ]


class LLDPDUSystemDescription(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.7 / p. 31
    """
    fields_desc = [
        BitEnumField('_type', 0x06, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='description'),
        StrLenField('description', '', length_from=lambda pkt: pkt._length)
    ]


class LLDPDUSystemCapabilities(LLDPDU):
    """
        ieee 802.1ab-2016 - sec. 8.5.8 / p. 31
    """
    fields_desc = [
        BitEnumField('_type', 0x07, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', 4, 9),
        BitField('reserved_5_available', 0, 1),
        BitField('reserved_4_available', 0, 1),
        BitField('reserved_3_available', 0, 1),
        BitField('reserved_2_available', 0, 1),
        BitField('reserved_1_available', 0, 1),
        BitField('two_port_mac_relay_available', 0, 1),
        BitField('s_vlan_component_available', 0, 1),
        BitField('c_vlan_component_available', 0, 1),
        BitField('station_only_available', 0, 1),
        BitField('docsis_cable_device_available', 0, 1),
        BitField('telephone_available', 0, 1),
        BitField('router_available', 0, 1),
        BitField('wlan_access_point_available', 0, 1),
        BitField('mac_bridge_available', 0, 1),
        BitField('repeater_available', 0, 1),
        BitField('other_available', 0, 1),
        BitField('reserved_5_enabled', 0, 1),
        BitField('reserved_4_enabled', 0, 1),
        BitField('reserved_3_enabled', 0, 1),
        BitField('reserved_2_enabled', 0, 1),
        BitField('reserved_1_enabled', 0, 1),
        BitField('two_port_mac_relay_enabled', 0, 1),
        BitField('s_vlan_component_enabled', 0, 1),
        BitField('c_vlan_component_enabled', 0, 1),
        BitField('station_only_enabled', 0, 1),
        BitField('docsis_cable_device_enabled', 0, 1),
        BitField('telephone_enabled', 0, 1),
        BitField('router_enabled', 0, 1),
        BitField('wlan_access_point_enabled', 0, 1),
        BitField('mac_bridge_enabled', 0, 1),
        BitField('repeater_enabled', 0, 1),
        BitField('other_enabled', 0, 1),
    ]

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and self._length != 4:
            raise LLDPInvalidLengthField('length must be 4 - got '
                                         '{}'.format(self._length))


class LLDPDUManagementAddress(LLDPDU):
    """
    ieee 802.1ab-2016 - sec. 8.5.9 / p. 32

    currently only 0x00..0x1e are used by standards, no way to
    use anything > 0xff as management address subtype is only
    one octet wide

    see https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml  # noqa: E501
    """

    SUBTYPE_MANAGEMENT_ADDRESS_OTHER = 0x00
    SUBTYPE_MANAGEMENT_ADDRESS_IPV4 = 0x01
    SUBTYPE_MANAGEMENT_ADDRESS_IPV6 = 0x02
    SUBTYPE_MANAGEMENT_ADDRESS_NSAP = 0x03
    SUBTYPE_MANAGEMENT_ADDRESS_HDLC = 0x04
    SUBTYPE_MANAGEMENT_ADDRESS_BBN = 0x05
    SUBTYPE_MANAGEMENT_ADDRESS_802 = 0x06
    SUBTYPE_MANAGEMENT_ADDRESS_E_163 = 0x07
    SUBTYPE_MANAGEMENT_ADDRESS_E_164 = 0x08
    SUBTYPE_MANAGEMENT_ADDRESS_F_69 = 0x09
    SUBTYPE_MANAGEMENT_ADDRESS_X_121 = 0x0A
    SUBTYPE_MANAGEMENT_ADDRESS_IPX = 0x0B
    SUBTYPE_MANAGEMENT_ADDRESS_APPLETALK = 0x0C
    SUBTYPE_MANAGEMENT_ADDRESS_DECNET_IV = 0x0D
    SUBTYPE_MANAGEMENT_ADDRESS_BANYAN_VINES = 0x0E
    SUBTYPE_MANAGEMENT_ADDRESS_E_164_WITH_NSAP = 0x0F
    SUBTYPE_MANAGEMENT_ADDRESS_DNS = 0x10
    SUBTYPE_MANAGEMENT_ADDRESS_DISTINGUISHED_NAME = 0x11
    SUBTYPE_MANAGEMENT_ADDRESS_AS_NUMBER = 0x12
    SUBTYPE_MANAGEMENT_ADDRESS_XTP_OVER_IPV4 = 0x13
    SUBTYPE_MANAGEMENT_ADDRESS_XTP_OVER_IPV6 = 0x14
    SUBTYPE_MANAGEMENT_ADDRESS_XTP_NATIVE_MODE_XTP = 0x15
    SUBTYPE_MANAGEMENT_ADDRESS_FIBER_CHANNEL_WORLD_WIDE_PORT_NAME = 0x16
    SUBTYPE_MANAGEMENT_ADDRESS_FIBER_CHANNEL_WORLD_WIDE_NODE_NAME = 0x17
    SUBTYPE_MANAGEMENT_ADDRESS_GWID = 0x18
    SUBTYPE_MANAGEMENT_ADDRESS_AFI_FOR_L2VPN = 0x19
    SUBTYPE_MANAGEMENT_ADDRESS_MPLS_TP_SECTION_ENDPOINT_ID = 0x1A
    SUBTYPE_MANAGEMENT_ADDRESS_MPLS_TP_LSP_ENDPOINT_ID = 0x1B
    SUBTYPE_MANAGEMENT_ADDRESS_MPLS_TP_PSEUDOWIRE_ENDPOINT_ID = 0x1C
    SUBTYPE_MANAGEMENT_ADDRESS_MT_IP_MULTI_TOPOLOGY_IPV4 = 0x1D
    SUBTYPE_MANAGEMENT_ADDRESS_MT_IP_MULTI_TOPOLOGY_IPV6 = 0x1E

    INTERFACE_NUMBERING_SUBTYPES = {
        0x01: 'unknown',
        0x02: 'ifIndex',
        0x03: 'system port number'
    }

    SUBTYPE_INTERFACE_NUMBER_UNKNOWN = 0x01
    SUBTYPE_INTERFACE_NUMBER_IF_INDEX = 0x02
    SUBTYPE_INTERFACE_NUMBER_SYSTEM_PORT_NUMBER = 0x03

    '''
    Note - calculation of _length field::

        _length = 1@_management_address_string_length +
                  1@management_address_subtype +
                  management_address.len +
                  1@interface_numbering_subtype +
                  4@interface_number +
                  1@_oid_string_length +
                  object_id.len
    '''

    fields_desc = [
        BitEnumField('_type', 0x08, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='management_address',
                         adjust=lambda pkt, x:
                         8 + len(pkt.management_address) + len(pkt.object_id)),
        BitFieldLenField('_management_address_string_length', None, 8,
                         length_of='management_address',
                         adjust=lambda pkt, x: len(pkt.management_address) + 1),  # noqa: E501
        ByteEnumField('management_address_subtype', 0x00,
                      LLDPDU.IANA_ADDRESS_FAMILY_NUMBERS),
        XStrLenField('management_address', '',
                     length_from=lambda pkt: 0
                     if pkt._management_address_string_length is None else
                     pkt._management_address_string_length - 1),
        ByteEnumField('interface_numbering_subtype',
                      SUBTYPE_INTERFACE_NUMBER_UNKNOWN,
                      INTERFACE_NUMBERING_SUBTYPES),
        BitField('interface_number', 0, 32),
        BitFieldLenField('_oid_string_length', None, 8, length_of='object_id'),
        XStrLenField('object_id', '',
                     length_from=lambda pkt: pkt._oid_string_length),
    ]

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode():
            management_address_len = len(self.management_address)
            if management_address_len == 0 or management_address_len > 31:
                raise LLDPInvalidLengthField(
                    'management address must be  1..31 characters long - '
                    'got string of size {}'.format(management_address_len))


class ThreeBytesEnumField(EnumField, ThreeBytesField):

    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "!I")


class LLDPDUGenericOrganisationSpecific(LLDPDU):

    ORG_UNIQUE_CODE_PNO = 0x000ecf
    ORG_UNIQUE_CODE_IEEE_802_1 = 0x0080c2
    ORG_UNIQUE_CODE_IEEE_802_3 = 0x00120f
    ORG_UNIQUE_CODE_TIA_TR_41_MED = 0x0012bb
    ORG_UNIQUE_CODE_HYTEC = 0x30b216

    ORG_UNIQUE_CODES = {
        ORG_UNIQUE_CODE_PNO: "PROFIBUS International (PNO)",
        ORG_UNIQUE_CODE_IEEE_802_1: "IEEE 802.1",
        ORG_UNIQUE_CODE_IEEE_802_3: "IEEE 802.3",
        ORG_UNIQUE_CODE_TIA_TR_41_MED: "TIA TR-41 Committee . Media Endpoint Discovery",  # noqa: E501
        ORG_UNIQUE_CODE_HYTEC: "Hytec Geraetebau GmbH"
    }

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='data', adjust=lambda pkt, x: len(pkt.data) + 4),  # noqa: E501
        ThreeBytesEnumField('org_code', 0, ORG_UNIQUE_CODES),
        ByteField('subtype', 0x00),
        XStrLenField('data', '',
                     length_from=lambda pkt: 0 if pkt._length is None else
                     pkt._length - 4)
    ]

    @staticmethod
    def _match_organization_specific(payload):
        return True


class LLDPDUPowerViaMDI(LLDPDUGenericOrganisationSpecific):
    """
    Legacy PoE TLV originally defined in IEEE Std 802.1AB-2005 Annex G.3.

    IEEE802.3bt-2018 - sec. 79.3.2.
    """

    # IEEE802.3bt-2018 - sec. 79.3.2.1
    MDI_POWER_SUPPORT = {
        (1 << 3): 'PSE pairs controlled',
        (1 << 2): 'PSE MDI power enabled',
        (1 << 1): 'PSE MDI power supported',
        (1 << 0): 'port class PSE',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.2
    PSE_POWER_PAIR = {
        1: 'alt A',
        2: 'alt B',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.3
    POWER_CLASS = {
        1: 'class 0',
        2: 'class 1',
        3: 'class 2',
        4: 'class 3',
        5: 'class 4 and above',
    }

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 7, 9),
        ThreeBytesField('org_code', LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3),  # noqa: E501
        ByteField('subtype', 2),
        FlagsField('MDI_power_support', 0, 8, MDI_POWER_SUPPORT),
        ByteEnumField('PSE_power_pair', 1, PSE_POWER_PAIR),
        ByteEnumField('power_class', 1, POWER_CLASS),
    ]

    @staticmethod
    def _match_organization_specific(payload):
        """
        match organization specific TLV
        """
        return (orb(payload[5]) == 2 and orb(payload[1]) == 7
                and bytes_int(payload[2:5]) ==
                LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3)

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and self._length != 7:
            raise LLDPInvalidLengthField('length must be 7 - got '
                                         '{}'.format(self._length))


class LLDPDUPowerViaMDIDDL(LLDPDUPowerViaMDI):
    """
    PoE TLV with DLL classification extension specified in IEEE802.3at-2009

    Note: power values are expressed in units of Watts,
    converted to tenth of Watts internally

    IEEE802.3bt-2018 - sec. 79.3.2
    """

    # IEEE802.3bt-2018 - sec. 79.3.2.4
    POWER_TYPE_NO = {
        1: 'type 1',
        0: 'type 2',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.4
    POWER_TYPE_DIR = {
        1: 'PD',
        0: 'PSE',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.4
    POWER_SOURCE_PD = {
        0b11: 'PSE and local',
        0b10: 'reserved',
        0b01: 'PSE',
        0b00: 'unknown',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.4
    POWER_SOURCE_PSE = {
        0b11: 'reserved',
        0b10: 'backup source',
        0b01: 'primary source',
        0b00: 'unknown',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.4
    PD_4PID_SUP = {
        0: 'not supported',
        1: 'supported',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.4
    POWER_PRIO = {
        0b11: 'low',
        0b10: 'high',
        0b01: 'critical',
        0b00: 'unknown',
    }

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 12, 9),
        ThreeBytesField('org_code', LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3),  # noqa: E501
        ByteField('subtype', 2),
        FlagsField('MDI_power_support', 0, 8, LLDPDUPowerViaMDI.MDI_POWER_SUPPORT),
        ByteEnumField('PSE_power_pair', 1, LLDPDUPowerViaMDI.PSE_POWER_PAIR),
        ByteEnumField('power_class', 1, LLDPDUPowerViaMDI.POWER_CLASS),
        BitEnumField('power_type_no', 1, 1, POWER_TYPE_NO),
        BitEnumField('power_type_dir', 1, 1, POWER_TYPE_DIR),
        MultipleTypeField([
            (
                BitEnumField('power_source', 0b01, 2, POWER_SOURCE_PD),
                lambda pkt: pkt.power_type_dir == 1
            ),
        ], BitEnumField('power_source', 0b01, 2, POWER_SOURCE_PSE)),
        MultipleTypeField([
            (
                BitEnumField('PD_4PID', 0, 2, PD_4PID_SUP),
                lambda pkt: pkt.power_type_dir == 1
            ),
        ], BitField('PD_4PID', 0, 2)),
        BitEnumField('power_prio', 0, 2, POWER_PRIO),
        ScalingField('PD_requested_power', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        ScalingField('PSE_allocated_power', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
    ]

    @staticmethod
    def _match_organization_specific(payload):
        """
        match organization specific TLV
        """
        return (orb(payload[5]) == 2 and orb(payload[1]) == 12
                and bytes_int(payload[2:5]) ==
                LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3)

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and self._length != 12:
            raise LLDPInvalidLengthField('length must be 12 - got '
                                         '{}'.format(self._length))
        # IEEE802.3bt-2018 - sec. 79.3.2.{5,6}
        for field, description, max_value in [('PD_requested_power',
                                               'PSE requested power',
                                               99.9),
                                              ('PSE_allocated_power',
                                               'PSE allocated power',
                                               99.9)]:
            val = getattr(self, field)
            if (conf.contribs['LLDP'].strict_mode() and val > max_value):
                raise LLDPInvalidFieldValue(
                    'exceeded maximum {} of {} - got '
                    '{}'.format(description, max_value, val))


class LLDPDUPowerViaMDIType34(LLDPDUPowerViaMDIDDL):
    """
    PoE TLV with DLL classification and type 3 and 4 extensions
    specified in IEEE802.3bt-2018

    Note: power values are expressed in units of Watts,
    converted to tenth of Watts internally

    IEEE802.3bt-2018 - sec. 79.3.2
    """

    # IEEE802.3bt-2018 - sec. 79.3.2.6e
    PSE_POWERING_STATUS = {
        0b11: '4-pair powering dual-signature PD',
        0b10: '4-pair powering single-signature PD',
        0b01: '2-pair powering',
        0b00: 'ignore',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6e
    PD_POWERED_STATUS = {
        0b11: '4-pair powered dual-signature PD',
        0b10: '2-pair powered dual-signature PD',
        0b01: 'powered single-signature PD',
        0b00: 'ignore',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6e
    PSE_POWER_PAIRS_EXT = {
        0b11: 'both alts',
        0b10: 'alt A',
        0b01: 'alt B',
        0b00: 'ignore',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6e
    DUAL_SIGNATURE_POWER_CLASS = {
        0b111: 'single-signature PD or 2-pair only PSE',
        0b110: 'ignore',
        0b101: 'class 5',
        0b100: 'class 4',
        0b011: 'class 3',
        0b010: 'class 2',
        0b001: 'class 1',
        0b000: 'ignore',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6e
    POWER_CLASS_EXT = {
        0b1111: 'dual-signature pd',
        0b1110: 'ignore',
        0b1101: 'ignore',
        0b1100: 'ignore',
        0b1011: 'ignore',
        0b1010: 'ignore',
        0b1001: 'ignore',
        0b1000: 'class 8',
        0b0111: 'class 7',
        0b0110: 'class 6',
        0b0101: 'class 5',
        0b0100: 'class 4',
        0b0011: 'class 3',
        0b0010: 'class 2',
        0b0001: 'class 1',
        0b0000: 'ignore',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6d
    POWER_TYPE_EXT = {
        0b111: 'ignore',
        0b110: 'ignore',
        0b101: 'type 4 dual-signature PD',
        0b100: 'type 4 single-signature PD',
        0b011: 'type 3 dual-signature PD',
        0b010: 'type 3 single-signature PD',
        0b001: 'type 4 PSE',
        0b000: 'type 3 PSE',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6d
    PD_LOAD = {
        1: 'dual-signature and electrically isolated',
        0: 'single-signature or not electrically isolated',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6h
    AUTOCLASS = {
        (1 << 2): 'PSE autoclass support',
        (1 << 1): 'autoclass completed',
        (1 << 0): 'autoclass request',
    }

    # IEEE802.3bt-2018 - sec. 79.3.2.6i
    POWER_DOWN_REQ = {
        0x1d: 'power down',
        0: 'ignore',
    }

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 29, 9),
        ThreeBytesField('org_code', LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3),  # noqa: E501
        ByteField('subtype', 2),
        FlagsField('MDI_power_support', 0, 8, LLDPDUPowerViaMDI.MDI_POWER_SUPPORT),
        ByteEnumField('PSE_power_pair', 1, LLDPDUPowerViaMDI.PSE_POWER_PAIR),
        ByteEnumField('power_class', 1, LLDPDUPowerViaMDI.POWER_CLASS),
        BitEnumField('power_type_no', 1, 1, LLDPDUPowerViaMDIDDL.POWER_TYPE_NO),
        BitEnumField('power_type_dir', 1, 1, LLDPDUPowerViaMDIDDL.POWER_TYPE_DIR),
        MultipleTypeField([
            (
                BitEnumField('power_source', 0b01, 2, LLDPDUPowerViaMDIDDL.POWER_SOURCE_PD),  # noqa: E501
                lambda pkt: pkt.power_type_dir == 1
            ),
        ], BitEnumField('power_source', 0b01, 2, LLDPDUPowerViaMDIDDL.POWER_SOURCE_PSE)),  # noqa: E501
        MultipleTypeField([
            (
                BitEnumField('PD_4PID', 0, 2, LLDPDUPowerViaMDIDDL.PD_4PID_SUP),
                lambda pkt: pkt.power_type_dir == 1
            ),
        ], BitField('PD_4PID', 0, 2)),
        BitEnumField('power_prio', 0, 2, LLDPDUPowerViaMDIDDL.POWER_PRIO),
        ScalingField('PD_requested_power', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        ScalingField('PSE_allocated_power', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        ScalingField('PD_requested_power_mode_A', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        ScalingField('PD_requested_power_mode_B', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        ScalingField('PD_allocated_power_alt_A', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        ScalingField('PD_allocated_power_alt_B', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        BitEnumField('PSE_powering_status', 0, 2, PSE_POWERING_STATUS),
        BitEnumField('PD_powered_status', 0, 2, PD_POWERED_STATUS),
        BitEnumField('PD_power_pair_ext', 0, 2, PSE_POWER_PAIRS_EXT),
        BitEnumField('dual_signature_class_mode_A',
                     0b111, 3, DUAL_SIGNATURE_POWER_CLASS),
        BitEnumField('dual_signature_class_mode_B',
                     0b111, 3, DUAL_SIGNATURE_POWER_CLASS),
        BitEnumField('power_class_ext', 0, 4, POWER_CLASS_EXT),
        BitEnumField('power_type_ext', 0, 7, POWER_TYPE_EXT),
        BitEnumField('PD_load', 0, 1, PD_LOAD),
        ScalingField('PSE_max_available_power', 0, scaling=0.1,
                     unit='W', ndigits=1, fmt='H'),
        FlagsField('autoclass', 0, 8, AUTOCLASS),
        BitEnumField('power_down_req', 0, 6, POWER_DOWN_REQ),
        BitScalingField('power_down_time', 0, 18, unit='s'),
    ]

    @staticmethod
    def _match_organization_specific(payload):
        '''
        match organization specific TLV
        '''
        return (orb(payload[5]) == 2 and orb(payload[1]) == 29
                and bytes_int(payload[2:5]) ==
                LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3)

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and self._length != 29:
            raise LLDPInvalidLengthField('length must be 29 - got '
                                         '{}'.format(self._length))
        # IEEE802.3bt-2018 - sec. 79.3.2.6{a..b,e,g}
        for field, description, max_value in [('PD_requested_power',
                                               'PSE requested power',
                                               99.9),
                                              ('PSE_allocated_power',
                                               'PSE allocated power',
                                               99.9),
                                              ('PD_requested_power_mode_A',
                                               'PD requested power mode A',
                                               49.9),
                                              ('PD_requested_power_mode_B',
                                               'PD requested power mode B',
                                               49.9),
                                              ('PD_allocated_power_alt_A',
                                               'PD allocated power alt A',
                                               49.9),
                                              ('PD_allocated_power_alt_B',
                                               'PD allocated power alt B',
                                               49.9),
                                              ('PSE_max_available_power',
                                               'PSE maximum available power',
                                               99.9),
                                              ('power_down_time',
                                               'power down time',
                                               262143)]:
            val = getattr(self, field) or 0
            if (conf.contribs['LLDP'].strict_mode() and val > max_value):
                raise LLDPInvalidFieldValue(
                    'exceeded maximum {} of {} - got '
                    '{}'.format(description, max_value, val))


class LLDPDUPowerViaMDIMeasure(LLDPDUGenericOrganisationSpecific):
    """
    PoE TLV measurements in IEEE802.3bt-2018

    Note: power values are expressed in units of Watts,
    converted to hundredths of Watts internally;
    energy values are expressed in units of Joules,
    converted to tenths of kilo-Joules internally;
    voltage values are expressed in units of Volts,
    converted to milli-Volts internally;
    current values are expressed in units of Amperes,
    converted to tenths of milli-Amperes internally.
    PSE price index is converted internally.

    IEEE802.3bt-2018 - sec. 79.3.8
    """

    MEASURE_TYPE = {
        (1 << 3): 'voltage',
        (1 << 2): 'current',
        (1 << 1): 'power',
        (1 << 0): 'energy',
    }

    MEASURE_SOURCE = {
        0b00: 'no request',
        0b01: 'mode A',
        0b10: 'mode B',
        0b11: 'port total',
    }

    POWER_PRICE_INDEX = {
        0xffff: 'not available',
    }

    @staticmethod
    def _encode_ppi(val):
        # IEEE802.3bt-2018 - sec. 79.3.8
        return int(75046 / 2.512 * (val ** (1 / 5)) - 10046)

    @staticmethod
    def _decode_ppi(val):
        # IEEE802.3bt-2018 - sec. 79.3.8
        return ((val + 10046) * 2.512 / 75046) ** 5

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 26, 9),
        ThreeBytesField('org_code', LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3),  # noqa: E501
        ByteField('subtype', 8),
        FlagsField('support', 0, 4, MEASURE_TYPE),
        BitEnumField('source', 0, 4, MEASURE_SOURCE),
        FlagsField('request', 0, 4, MEASURE_TYPE),
        FlagsField('valid', 0, 4, MEASURE_TYPE),
        ScalingField('voltage_uncertainty', 0, scaling=0.001,
                     unit='V', ndigits=3, fmt='H'),
        ScalingField('current_uncertainty', 0, scaling=0.0001,
                     unit='A', ndigits=4, fmt='H'),
        ScalingField('power_uncertainty', 0, scaling=0.01,
                     unit='W', ndigits=2, fmt='H'),
        ScalingField('energy_uncertainty', 0, scaling=100,
                     unit='J', ndigits=0, fmt='H'),
        ScalingField('voltage_measurement', 0, scaling=0.001,
                     unit='V', ndigits=3, fmt='H'),
        ScalingField('current_measurement', 0, scaling=0.0001,
                     unit='A', ndigits=4, fmt='H'),
        ScalingField('power_measurement', 0, scaling=0.01,
                     unit='W', ndigits=2, fmt='H'),
        ScalingField('energy_measurement', 0, scaling=100,
                     unit='J', ndigits=0, fmt='I'),
        ShortEnumField('power_price_index', 0xffff, POWER_PRICE_INDEX),
    ]

    def do_build(self):
        backup_ppi = self.power_price_index
        self.power_price_index = 0xffff if self.power_price_index == 0xffff \
            else LLDPDUPowerViaMDIMeasure._encode_ppi(self.power_price_index)
        s = super(LLDPDUPowerViaMDIMeasure, self).do_build()
        self.power_price_index = backup_ppi
        return s

    def post_dissect(self, s):
        s = super(LLDPDUPowerViaMDIMeasure, self).post_dissect(s)
        self.power_price_index = 0xffff if self.power_price_index == 0xffff \
            else LLDPDUPowerViaMDIMeasure._decode_ppi(self.power_price_index)
        return s

    @staticmethod
    def _match_organization_specific(payload):
        '''
        match organization specific TLV
        '''
        return (orb(payload[5]) == 8 and orb(payload[1]) == 26
                and bytes_int(payload[2:5]) ==
                LLDPDUGenericOrganisationSpecific.ORG_UNIQUE_CODE_IEEE_802_3)

    def _check(self):
        """
        run layer specific checks
        """
        if conf.contribs['LLDP'].strict_mode() and self._length != 26:
            raise LLDPInvalidLengthField('length must be 26 - got '
                                         '{}'.format(self._length))
        # IEEE802.3bt-2018 - sec. 79.3.8
        for field, description, max_value in [('voltage_uncertainty',
                                               'voltage uncertainty',
                                               65),
                                              ('voltage_measurement',
                                               'voltage measurement',
                                               65),
                                              ('current_uncertainty',
                                               'current uncertainty',
                                               6.5),
                                              ('current_measurement',
                                               'current measurement',
                                               6.5),
                                              ('energy_uncertainty',
                                               'energy uncertainty',
                                               6500000),
                                              ('power_uncertainty',
                                               'power uncertainty',
                                               650),
                                              ('power_measurement',
                                               'power measurement',
                                               650)]:
            val = getattr(self, field) or 0
            if (conf.contribs['LLDP'].strict_mode() and val > max_value):
                raise LLDPInvalidFieldValue(
                    'exceeded maximum {} of {} - got '
                    '{}'.format(description, max_value, val))
            val = self.power_price_index or 0xffff
            if val > 65000 and val != 0xffff:
                raise LLDPInvalidFieldValue(
                    'exceeded maximum power price index of {} - got '
                    '{}'.format(LLDPDUPowerViaMDIMeasure._decode_ppi(65000),
                                LLDPDUPowerViaMDIMeasure._decode_ppi(val)))


# 0x09 .. 0x7e is reserved for future standardization and for now treated as Raw() data  # noqa: E501
LLDPDU_CLASS_TYPES = {
    0x00: LLDPDUEndOfLLDPDU,
    0x01: LLDPDUChassisID,
    0x02: LLDPDUPortID,
    0x03: LLDPDUTimeToLive,
    0x04: LLDPDUPortDescription,
    0x05: LLDPDUSystemName,
    0x06: LLDPDUSystemDescription,
    0x07: LLDPDUSystemCapabilities,
    0x08: LLDPDUManagementAddress,
    127: [
        LLDPDUPowerViaMDI,
        LLDPDUPowerViaMDIDDL,
        LLDPDUPowerViaMDIType34,
        LLDPDUPowerViaMDIMeasure,
        LLDPDUGenericOrganisationSpecific,
    ]
}


class LLDPConfiguration(object):
    """
    basic configuration for LLDP layer
    """

    def __init__(self):
        self._strict_mode = True
        self.strict_mode_enable()

    def strict_mode_enable(self):
        """
        enable strict mode and dissector debugging
        """
        self._strict_mode = True

    def strict_mode_disable(self):
        """
        disable strict mode and dissector debugging
        """
        self._strict_mode = False

    def strict_mode(self):
        """
        get current strict mode state
        """
        return self._strict_mode


conf.contribs['LLDP'] = LLDPConfiguration()

bind_layers(Ether, LLDPDU, type=LLDP_ETHER_TYPE)
bind_layers(Dot1Q, LLDPDU, type=LLDP_ETHER_TYPE)
