# scapy.contrib.description = Link Layer Discovery Protocol (LLDP)
# scapy.contrib.status = loads

"""
    LLDP - Link Layer Discovery Protocol
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
from scapy.fields import MACField, IPField, BitField, \
    StrLenField, ByteEnumField, BitEnumField, \
    EnumField, ThreeBytesField, BitFieldLenField, \
    ShortField, XStrLenField, ByteField, ConditionalField, \
    MultipleTypeField
from scapy.packet import Packet, bind_layers
from scapy.modules.six.moves import range
from scapy.data import ETHER_TYPES
from scapy.compat import orb

LLDP_NEAREST_BRIDGE_MAC = '01:80:c2:00:00:0e'
LLDP_NEAREST_NON_TPMR_BRIDGE_MAC = '01:80:c2:00:00:03'
LLDP_NEAREST_CUSTOMER_BRIDGE_MAC = '01:80:c2:00:00:00'

LLDP_ETHER_TYPE = 0x88cc
ETHER_TYPES['LLDP'] = LLDP_ETHER_TYPE


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
        range(0x09, 0x7e): 'reserved - future standardization',
        127: 'organisation specific TLV'
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
            return LLDPDU_CLASS_TYPES.get(lldpdu_tlv_type, conf.raw_layer)
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
        """Overwrited by LLDPU objects"""
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
        range(0x08, 0xff): 'reserved'
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
            ByteField('family', 0),
            lambda pkt: pkt.subtype == 0x05
        ),
        MultipleTypeField([
            (
                MACField('id', None),
                lambda pkt: pkt.subtype == 0x04
            ),
            (
                IPField('id', None),
                lambda pkt: pkt.subtype == 0x05
            ),
        ], StrLenField('id', '', length_from=lambda pkt: pkt._length - 1)
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
        range(0x08, 0xff): 'reserved'
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
            ByteField('family', 0),
            lambda pkt: pkt.subtype == 0x04
        ),
        MultipleTypeField([
            (
                MACField('id', None),
                lambda pkt: pkt.subtype == 0x03
            ),
            (
                IPField('id', None),
                lambda pkt: pkt.subtype == 0x04
            ),
        ], StrLenField('id', '', length_from=lambda pkt: pkt._length - 1)
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
                      IANA_ADDRESS_FAMILY_NUMBERS),
        XStrLenField('management_address', '',
                     length_from=lambda pkt:
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
        XStrLenField('data', '', length_from=lambda pkt: pkt._length - 4)
    ]


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
    127: LLDPDUGenericOrganisationSpecific
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
