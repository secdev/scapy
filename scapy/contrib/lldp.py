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
          | (see LLDPDUGenericOrganisationSpecific for a starting point;
          |  IEEE 802.1Q and IEEE 802.1AX org-specific TLVs are implemented)
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
    BitFieldLenField, \
    ShortField, XStrLenField, ByteField, ConditionalField, \
    MultipleTypeField, FlagsField, ShortEnumField, ScalingField, \
    BitScalingField, FieldLenField, IntField, XIntField, PacketListField, OUIField
from scapy.packet import NoPayload, Packet, bind_layers
from scapy.data import ETHER_TYPES

LLDP_NEAREST_BRIDGE_MAC = '01:80:c2:00:00:0e'
LLDP_NEAREST_NON_TPMR_BRIDGE_MAC = '01:80:c2:00:00:03'
LLDP_NEAREST_CUSTOMER_BRIDGE_MAC = '01:80:c2:00:00:00'

LLDP_ETHER_TYPE = 0x88cc
ETHER_TYPES[LLDP_ETHER_TYPE] = 'LLDP'

_LLDP_ETS_TSA_ALGORITHMS = {
    0: 'Strict Priority',
    1: 'Credit-Based Shaper',
    2: 'Enhanced Transmission Selection',
    3: 'ATS Transmission Selection',
    # 4-254: Reserved for future standardization
    255: 'Vendor Specific',  # used with DCBX
}

ORG_UNIQUE_CODES = {
    0x000ecf: "PROFIBUS International (PNO)",
    0x0080c2: "IEEE 802.1",
    0x00120f: "IEEE 802.3",
    0x0012bb: "TIA TR-41 Committee - Media Endpoint Discovery",
    0x30b216: "Hytec Geraetebau GmbH",
}

ORG_UNIQUE_CODE_PNO = 0x000ecf
ORG_UNIQUE_CODE_IEEE_802_1 = 0x0080c2
ORG_UNIQUE_CODE_IEEE_802_3 = 0x00120f
ORG_UNIQUE_CODE_TIA_TR_41_MED = 0x0012bb
ORG_UNIQUE_CODE_HYTEC = 0x30b216

_LLDP_SEL_FIELD_VALUES = {
    0: 'Reserved',
    1: 'Default or Ethertype',
    2: 'TCP/SCTP port',
    3: 'UDP/DCCP port',
    4: 'TCP/SCTP/UDP/DCCP port',
    5: 'DSCP',
    6: 'Reserved',
    7: 'Reserved',
}


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
            lldpdu_tlv_type = payload[0] // 2
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
        BitFieldLenField(
            '_management_address_string_length',
            None,
            8,
            length_of='management_address',
            adjust=lambda pkt, x: len(pkt.management_address) + 1
        ),
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


class LLDPDUGenericOrganisationSpecific(LLDPDU):
    SUBTYPE = None          # type: int | None
    ORG_CODE = None         # type: int | None
    EXPECTED_LENGTH = None  # type: int | None

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitFieldLenField(
            '_length',
            None,
            9,
            length_of='data',
            adjust=lambda pkt, x: len(pkt.data) + 4
        ),
        OUIField('org_code', 0),
        ByteField('subtype', 0x00),
        XStrLenField(
            'data',
            '',
            length_from=lambda pkt: 0 if pkt._length is None else
            pkt._length - 4
        )
    ]

    @classmethod
    def _match_organization_specific(cls, payload):
        if cls.SUBTYPE is None or cls.ORG_CODE is None:
            return True  # base class: accept anything
        if payload[5] != cls.SUBTYPE:
            return False
        if int.from_bytes(payload[2:5], 'big') != cls.ORG_CODE:
            return False
        if cls.EXPECTED_LENGTH is not None:
            return _lldp_tlv_length(payload) == cls.EXPECTED_LENGTH
        return True

    def _check(self):
        if (self.EXPECTED_LENGTH is not None
                and conf.contribs['LLDP'].strict_mode()
                and self._length is not None
                and self._length != self.EXPECTED_LENGTH):
            raise LLDPInvalidLengthField(
                '{} TLV length must be {}, got {}'.format(
                    type(self).__name__, self.EXPECTED_LENGTH, self._length))


def _lldp_tlv_length(payload):
    """Extract the 9-bit TLV length from the two-byte LLDP TLV header.

    The LLDP TLV header is 16 bits: bits 15-9 carry the 7-bit type and
    bits 8-0 carry the 9-bit length (IEEE 802.1AB-2016 section 9.2).
    In wire bytes: bit 8 of the length sits in the LSB of payload[0],
    and bits 7-0 sit in payload[1].
    """
    return ((payload[0] & 0x01) << 8) | payload[1]


class LLDPDUOrgSpecific_IEEE8021_Port_VLAN_ID(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: Port VLAN ID (PVID).

    Carries the native (untagged) VLAN ID of the port (the VLAN ID that
    802.1Q Dot1Q sniffing cannot observe, because frames on the native VLAN
    carry no 802.1Q header).

    IEEE 802.1Q D.2.1.

    Payload layout (6 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x01
        bytes 4-5   PVID (big-endian)
    """

    SUBTYPE = 0x01
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 6

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 6, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x01),
        ShortField('pvid', 0),
    ]


class LLDPDUOrgSpecific_IEEE8021_Port_And_Protocol_VLAN_ID(
        LLDPDUGenericOrganisationSpecific
):
    """
    IEEE 802.1 organizationally specific TLV: Port and Protocol VLAN ID.

    Advertises the Port and Protocol VLAN ID (PPVID) together with flags
    indicating whether the port supports and has enabled the protocol VLAN.
    Multiple instances may appear in one LLDPDU, one per protocol VLAN.

    IEEE 802.1Q D.2.2.

    Payload layout (7 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x02
        byte  4     flags: bits 7-3: reserved, bit 2: ppvid_enabled,
                           bit 1: ppvid_supported, bit 0: reserved
        bytes 5-6   PPVID (big-endian, 0 if unknown)
    """

    SUBTYPE = 0x02
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 7

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 7, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x02),
        BitField('reserved', 0, 5),
        BitField('ppvid_enabled', 0, 1),
        BitField('ppvid_supported', 0, 1),
        BitField('reserved0', 0, 1),
        ShortField('ppvid', 0),
    ]


class LLDPDUOrgSpecific_IEEE8021_VLAN_Name(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: VLAN Name.

    Carries a VLAN ID together with its human-readable name.  One TLV is
    emitted per VLAN, so a single LLDP frame from a trunk port can enumerate
    the switch's complete VLAN table.

    IEEE 802.1Q D.2.3.

    Payload layout (7 + len(vlan_name) bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x03
        bytes 4-5   VLAN ID (big-endian)
        byte  6     vlan_name_length (0-32)
        bytes 7..N  vlan_name
    """

    SUBTYPE = 0x03
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='vlan_name',
                         adjust=lambda pkt, x: x + 7),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x03),
        ShortField('vlan_id', 0),
        FieldLenField('vlan_name_length', None, length_of='vlan_name', fmt='B'),
        StrLenField('vlan_name', b'', length_from=lambda pkt: pkt.vlan_name_length),
    ]

    def _check(self):
        if not conf.contribs['LLDP'].strict_mode():
            return
        if self._length is not None:
            if self._length < 7:
                raise LLDPInvalidLengthField(
                    'IEEE 802.1 VLAN Name TLV length must be >= 7, '
                    'got {}'.format(self._length))
            if self._length > 39:
                raise LLDPInvalidLengthField(
                    'IEEE 802.1 VLAN Name TLV length must be <= 39 '
                    '(vlan_name max 32 bytes), got {}'.format(self._length))
        # D.2.3.5: each VID+name combination must be unique in the frame
        root = self
        while root.underlayer is not None:
            root = root.underlayer
        layer = root
        while layer is not None and not isinstance(layer, NoPayload):
            if (layer is not self
                    and isinstance(layer,
                                   LLDPDUOrgSpecific_IEEE8021_VLAN_Name)
                    and layer.vlan_id == self.vlan_id
                    and layer.vlan_name == self.vlan_name):
                raise LLDPInvalidFrameStructure(
                    'Duplicate VLAN Name TLV: VID={} name={!r}'.format(
                        self.vlan_id, self.vlan_name))
            layer = layer.payload


class LLDPDUOrgSpecific_IEEE8021_Protocol_Identity(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: Protocol Identity.

    Identifies a protocol accessible through the port by carrying its raw
    protocol-identity octets (e.g. the first few bytes of a PDU header).
    Multiple instances may appear in one LLDPDU, one per protocol.

    IEEE 802.1Q D.2.4.

    Payload layout (5 to 260 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x04
        byte  4     protocol_identity_length
        bytes 5..N  protocol_identity (0-255 bytes)
    """

    SUBTYPE = 0x04
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='protocol_identity',
                         adjust=lambda pkt, x: x + 5),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x04),
        FieldLenField('protocol_identity_length', None,
                      length_of='protocol_identity', fmt='B'),
        XStrLenField('protocol_identity', b'',
                     length_from=lambda pkt: pkt.protocol_identity_length),
    ]

    @classmethod
    def _match_organization_specific(cls, payload):
        length = _lldp_tlv_length(payload)
        return (payload[5] == cls.SUBTYPE
                and 5 <= length <= 260
                and int.from_bytes(payload[2:5], 'big') == cls.ORG_CODE)

    def _check(self):
        if conf.contribs['LLDP'].strict_mode():
            if (self._length is not None
                    and not (5 <= self._length <= 260)):
                raise LLDPInvalidLengthField(
                    'IEEE 802.1 Protocol Identity TLV length must be between 5 and 260,'
                    ' got {}'.format(self._length))
            if len(self.protocol_identity) > 255:
                raise LLDPInvalidLengthField(
                    'protocol_identity max 255 bytes (got {})'.format(
                        len(self.protocol_identity)))


class LLDPDUOrgSpecific_IEEE8021_VID_Usage_Digest(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: VID Usage Digest.

    Advertises the VID Usage Digest associated with the port. The digest is
    the CRC32 of the 512-octet VID Usage Table (128 entries x 4 bytes).

    IEEE 802.1Q D.2.5.

    Payload layout (8 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x05
        bytes 4-7   vid_usage_digest (CRC32, big-endian)
    """

    SUBTYPE = 0x05
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 8

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 8, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x05),
        XIntField('vid_usage_digest', 0),
    ]


class LLDPDUOrgSpecific_IEEE8021_Management_VID(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: Management VID.

    Advertises the VLAN ID associated with the management address of the
    device.  A value of 0 means the device has no management VID.

    IEEE 802.1Q D.2.6.

    Payload layout (6 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x06
        bytes 4-5   management_vid (big-endian, 0 if none)
    """

    SUBTYPE = 0x06
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 6

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 6, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x06),
        ShortField('management_vid', 0),
    ]


class LLDPDUOrgSpecific_IEEE8021_Link_Aggregation(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: Link Aggregation.

    Advertises whether the port supports link aggregation, whether it is
    currently aggregated, and the ID of the aggregated port (0 if not
    aggregated).

    IEEE 802.1AX.

    Payload layout (9 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x07
        byte  4     aggregation status (bit 0: capable, bit 1: enabled)
        bytes 5-8   aggregated_port_id (big-endian, 0 if not aggregated)
    """

    AGG_STATUS = {
        (1 << 0): 'capable',
        (1 << 1): 'enabled',
    }

    SUBTYPE = 0x07
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 9

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 9, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x07),
        FlagsField('aggregation_status', 0, 8, AGG_STATUS),
        IntField('aggregated_port_id', 0),
    ]


class LLDPDUOrgSpecific_IEEE8021_Congestion_Notification(
        LLDPDUGenericOrganisationSpecific
):
    """
    IEEE 802.1 organizationally specific TLV: Congestion Notification.

    Advertises per-priority Congestion Notification Point Variable (CNPV)
    and Ready indicators for all 8 802.1p priorities on the port.

    IEEE 802.1Q D.2.7.

    Payload layout (6 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x08
        byte  4     CNPV indicators (bit 0: prio 0, ..., bit 7: prio 7)
        byte  5     ready indicators (bit 0: prio 0, ..., bit 7: prio 7)
    """

    PRIORITY_BITS = {
        (1 << 0): 'prio0', (1 << 1): 'prio1',
        (1 << 2): 'prio2', (1 << 3): 'prio3',
        (1 << 4): 'prio4', (1 << 5): 'prio5',
        (1 << 6): 'prio6', (1 << 7): 'prio7',
    }

    SUBTYPE = 0x08
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 6

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 6, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x08),
        FlagsField('cnpv_indicators', 0, 8, PRIORITY_BITS),
        FlagsField('ready_indicators', 0, 8, PRIORITY_BITS),
    ]


class LLDPDUOrgSpecific_IEEE8021_ETS_Configuration(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: ETS Configuration.

    Advertises the Enhanced Transmission Selection configuration for the port:
    the priority-to-traffic-class mapping, per-TC bandwidth allocation, and
    the Transmission Selection Algorithm (TSA) for each TC.

    IEEE 802.1Q D.2.8.

    Payload layout (25 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x09
        byte  4     flags: bit 7: willing, bit 6: CBS, bits 5-3: reserved,
                           bits 2-0: max_tcs
        bytes 5-8   priority assignment table (4 bits per priority, prio 0-7)
        bytes 9-16  TC bandwidth table (1 byte per TC, TC 0-7)
        bytes 17-24 TSA assignment table (1 byte per TC, TC 0-7)
    """

    SUBTYPE = 0x09
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 25

    TSA_ALGORITHMS = _LLDP_ETS_TSA_ALGORITHMS

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 25, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x09),
        # flags byte: bit7=willing, bit6=CBS, bits5-3=reserved, bits2-0=maxTCs
        BitField('willing', 0, 1),
        BitField('cbs', 0, 1),
        BitField('reserved', 0, 3),
        BitField('max_tcs', 0, 3),
        # priority assignment table: 4 bits per priority, MSB=prio0
        BitField('prio0_tc', 0, 4),
        BitField('prio1_tc', 0, 4),
        BitField('prio2_tc', 0, 4),
        BitField('prio3_tc', 0, 4),
        BitField('prio4_tc', 0, 4),
        BitField('prio5_tc', 0, 4),
        BitField('prio6_tc', 0, 4),
        BitField('prio7_tc', 0, 4),
        # TC bandwidth table: percentage per TC
        ByteField('tc0_bw', 0),
        ByteField('tc1_bw', 0),
        ByteField('tc2_bw', 0),
        ByteField('tc3_bw', 0),
        ByteField('tc4_bw', 0),
        ByteField('tc5_bw', 0),
        ByteField('tc6_bw', 0),
        ByteField('tc7_bw', 0),
        # TSA assignment table: algorithm per TC
        ByteEnumField('tc0_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc1_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc2_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc3_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc4_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc5_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc6_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc7_tsa', 0, TSA_ALGORITHMS),
    ]


class LLDPDUOrgSpecific_IEEE8021_ETS_Recommendation(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: ETS Recommendation.

    Carries the recommended ETS configuration (priority-to-TC mapping, per-TC
    bandwidth, and TSA per TC) that the sender would prefer the remote bridge
    to apply.  Unlike the ETS Configuration TLV this TLV has no flags byte.

    IEEE 802.1Q D.2.9.

    Payload layout (25 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x0A
        byte  4     reserved
        bytes 5-8   priority assignment table (4 bits per priority, prio 0-7)
        bytes 9-16  TC bandwidth table (1 byte per TC, TC 0-7)
        bytes 17-24 TSA assignment table (1 byte per TC, TC 0-7)
    """

    SUBTYPE = 0x0A
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 25

    TSA_ALGORITHMS = _LLDP_ETS_TSA_ALGORITHMS

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 25, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x0A),
        ByteField('reserved', 0),
        # priority assignment table: 4 bits per priority, MSB=prio0
        BitField('prio0_tc', 0, 4),
        BitField('prio1_tc', 0, 4),
        BitField('prio2_tc', 0, 4),
        BitField('prio3_tc', 0, 4),
        BitField('prio4_tc', 0, 4),
        BitField('prio5_tc', 0, 4),
        BitField('prio6_tc', 0, 4),
        BitField('prio7_tc', 0, 4),
        # TC bandwidth table: percentage per TC
        ByteField('tc0_bw', 0),
        ByteField('tc1_bw', 0),
        ByteField('tc2_bw', 0),
        ByteField('tc3_bw', 0),
        ByteField('tc4_bw', 0),
        ByteField('tc5_bw', 0),
        ByteField('tc6_bw', 0),
        ByteField('tc7_bw', 0),
        # TSA assignment table: algorithm per TC
        ByteEnumField('tc0_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc1_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc2_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc3_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc4_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc5_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc6_tsa', 0, TSA_ALGORITHMS),
        ByteEnumField('tc7_tsa', 0, TSA_ALGORITHMS),
    ]


class LLDPDUOrgSpecific_IEEE8021_PFC_Configuration(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: PFC Configuration.

    Advertises the Priority-based Flow Control (PFC) configuration for the port:
    willingness to negotiate, MACsec bypass capability, PFC cap (number of TCs
    that can simultaneously have PFC enabled), and the per-priority PFC enable bitmap.

    IEEE 802.1Q D.2.10.

    Payload layout (6 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x0B
        byte  4     flags: bit 7: willing, bit 6: MBC,
                           bits 5-4: reserved, bits 3-0: PFC cap
        byte  5     PFC enable bitmap (bit 0: prio 0, ..., bit 7: prio 7)
    """

    PFC_ENABLE_BITS = {
        (1 << 0): 'prio0', (1 << 1): 'prio1',
        (1 << 2): 'prio2', (1 << 3): 'prio3',
        (1 << 4): 'prio4', (1 << 5): 'prio5',
        (1 << 6): 'prio6', (1 << 7): 'prio7',
    }

    SUBTYPE = 0x0B
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 6

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 6, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x0B),
        # flags byte: bit7=willing, bit6=MBC, bits5-4=reserved, bits3-0=PFC cap
        BitField('willing', 0, 1),
        BitField('mbc', 0, 1),
        BitField('reserved', 0, 2),
        BitField('pfc_cap', 0, 4),
        FlagsField('pfc_enable', 0, 8, PFC_ENABLE_BITS),
    ]


class LLDPDUOrgSpecific_IEEE8021_AppPriority_Entry(Packet):
    """
    Single application priority entry in an Application Priority TLV.

    IEEE 802.1Q D.2.11.

    Payload layout (3 bytes):
        byte 0    bits 7-5: priority (3 bits)
                  bits 4-3: reserved (2 bits)
                  bits 2-0: sel (3 bits)
        bytes 1-2 protocol (big-endian)
    """

    fields_desc = [
        BitField('priority', 0, 3),
        BitField('reserved', 0, 2),
        BitEnumField('sel', 0, 3, _LLDP_SEL_FIELD_VALUES),
        ShortField('protocol', 0),
    ]

    def extract_padding(self, s):
        return b'', s


class LLDPDUOrgSpecific_IEEE8021_Application_Priority(
        LLDPDUGenericOrganisationSpecific
):
    """
    IEEE 802.1 organizationally specific TLV: Application Priority.

    Maps application protocols (identified by Ethertype, TCP/UDP port, etc.)
    to 802.1p priority values. Zero or more 3-byte application entries may
    appear in a single TLV.

    IEEE 802.1Q D.2.11.

    Payload layout (5 + 3N bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x0C
        byte  4     reserved
        N x 3 bytes application entries, each:
            byte 0    bits 7-5: priority (3 bits)
                      bits 4-3: reserved (2 bits)
                      bits 2-0: sel (3 bits)
            bytes 1-2 protocol (big-endian)
    """

    SUBTYPE = 0x0C
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='app_priority_table',
                         adjust=lambda pkt, x: x + 5),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x0C),
        ByteField('reserved', 0),
        PacketListField('app_priority_table', [],
                        LLDPDUOrgSpecific_IEEE8021_AppPriority_Entry,
                        length_from=lambda pkt: 0 if pkt._length is None
                        else pkt._length - 5),
    ]

    def _check(self):
        if conf.contribs['LLDP'].strict_mode() and self._length is not None:
            if self._length < 5 or (self._length - 5) % 3 != 0:
                raise LLDPInvalidLengthField(
                    'IEEE 802.1 Application Priority TLV length must be '
                    '5 + 3N (got {})'.format(self._length))


class LLDPDUOrgSpecific_IEEE8021_EVB(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: EVB (Edge Virtual Bridging).

    Negotiates EVB capabilities between a station (hypervisor) and bridge.

    IEEE 802.1Q D.2.12.

    Payload layout (9 bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x0D
        byte  4     EVB bridge status
                      bits 7-3: reserved
                      bit 2: BGID
                      bit 1: RRCAP
                      bit 0: RRCTR
        byte  5     EVB station status
                      bits 7-4: reserved
                      bit 3: SGID
                      bit 2: RRREQ
                      bits 1-0: RRSTAT
        byte  6     bits 7-5: R (ECP max retries)
                    bits 4-0: RTE
        byte  7     bits 7-6: EVB mode
                    bit 5: rwd_rol (ROL for resource wait delay)
                    bits 4-0: RWD
        byte  8     bits 7-6: rka_reserved
                    bit 5: rka_rol (ROL for reinit keep alive)
                    bits 4-0: RKA
    """

    SUBTYPE = 0x0D
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1
    EXPECTED_LENGTH = 9

    EVB_MODES = {
        0: 'Not Supported',
        1: 'EVB Bridge',
        2: 'EVB station',
        3: 'NVO3',
    }

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitField('_length', 9, 9),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x0D),
        # EVB bridge status (byte 4)
        BitField('bridge_reserved', 0, 5),
        BitField('bgid', 0, 1),
        BitField('rrcap', 0, 1),
        BitField('rrctr', 0, 1),
        # EVB station status (byte 5)
        BitField('station_reserved', 0, 4),
        BitField('sgid', 0, 1),
        BitField('rrreq', 0, 1),
        BitField('rrstat', 0, 2),
        # R (ECP max retries) and RTE (retransmit timer exponent)
        BitField('r', 0, 3),
        BitField('rte', 0, 5),
        # Byte 7: EVB mode, ROL for RWD, resource wait delay
        BitEnumField('evb_mode', 0, 2, EVB_MODES),
        BitField('rwd_rol', 0, 1),
        BitField('rwd', 0, 5),
        # Byte 8: reserved, ROL for RKA, reinit keep alive
        BitField('rka_reserved', 0, 2),
        BitField('rka_rol', 0, 1),
        BitField('rka', 0, 5),
    ]


class LLDPDUOrgSpecific_IEEE8021_SCID_SVID_Pair(Packet):
    """
    Single S-channel entry in a CDCP TLV.

    IEEE 802.1Q D.2.13.

    Payload layout (3 bytes):
        bits 23-12: scid (S-channel identifier, 12 bits)
        bits 11-0:  svid (S-channel VLAN identifier, 12 bits)
    """

    fields_desc = [
        BitField('scid', 0, 12),
        BitField('svid', 0, 12),
    ]

    def extract_padding(self, s):
        return b'', s


class LLDPDUOrgSpecific_IEEE8021_CDCP(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: CDCP
    (Channel Discovery and Configuration Protocol).

    Advertises S-channel assignments between EVB stations and bridges.

    IEEE 802.1Q D.2.13.

    Payload layout (8 + 3N bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x0E
        byte  4     bit 7: role (0=EVB station, 1=EVB bridge)
                    bits 6-4: res1
                    bit 3: scomp (short channel compression)
                    bits 2-0: res2[14:12]
        byte  5     bits 7-0: res2[11:4]
        byte  6     bits 7-4: res2[3:0]
                    bits 3-0: chncap[11:8]
        byte  7     bits 7-0: chncap[7:0]
        bytes 8..N  N x 3-octet SCID/SVID entries
    """

    ROLE_VALUES = {
        0: 'EVB station',
        1: 'EVB bridge',
    }

    SUBTYPE = 0x0E
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='scid_svid_list',
                         adjust=lambda pkt, x: x + 8),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x0E),
        # Byte 4
        BitEnumField('role', 0, 1, ROLE_VALUES),
        BitField('res1', 0, 3),
        BitField('scomp', 0, 1),
        # res2: 15 bits spanning bytes 4-6
        BitField('res2', 0, 15),
        # chncap: 12 bits spanning bytes 6-7
        BitField('chncap', 0, 12),
        # N x 3-octet S-channel entries
        PacketListField('scid_svid_list', [],
                        LLDPDUOrgSpecific_IEEE8021_SCID_SVID_Pair,
                        length_from=lambda pkt: 0 if pkt._length is None
                        else pkt._length - 8),
    ]

    def _check(self):
        if (conf.contribs['LLDP'].strict_mode()
                and self._length is not None
                and self._length < 8):
            raise LLDPInvalidLengthField(
                'IEEE 802.1 CDCP TLV length must be >= 8, '
                'got {}'.format(self._length))


class LLDPDUOrgSpecific_IEEE8021_AppVLANEntry(Packet):
    """
    Single entry in an Application VLAN TLV.

    IEEE 802.1Q D.2.14, Table D-12.

    Payload layout (4 bytes):
        bytes 0-1   bits 15-4: vid (VLAN ID, 12 bits)
                    bit 3: reserved
                    bits 2-0: sel (protocol ID type, 3 bits)
        bytes 2-3   protocol (meaning determined by sel, big-endian)
    """

    fields_desc = [
        BitField('vid', 0, 12),
        BitField('reserved', 0, 1),
        BitEnumField('sel', 0, 3, _LLDP_SEL_FIELD_VALUES),
        ShortField('protocol', 0),
    ]

    def extract_padding(self, s):
        return b'', s


class LLDPDUOrgSpecific_IEEE8021_Application_VLAN(LLDPDUGenericOrganisationSpecific):
    """
    IEEE 802.1 organizationally specific TLV: Application VLAN.

    Advertises the local Application VLAN Table, mapping protocols to VLAN IDs,
    to indicate local configuration to peer stations.

    IEEE 802.1Q D.2.14.

    Payload layout (4 + 4N bytes):
        bytes 0-2   OUI  0x0080c2
        byte  3     subtype 0x10
        N x 4 bytes Application VLAN Table entries:
            bytes 0-1   bits 15-4: vid (12 bits)
                        bit 3: reserved
                        bits 2-0: sel (3 bits)
            bytes 2-3   protocol (big-endian)
    """

    SUBTYPE = 0x10
    ORG_CODE = ORG_UNIQUE_CODE_IEEE_802_1

    fields_desc = [
        BitEnumField('_type', 127, 7, LLDPDU.TYPES),
        BitFieldLenField('_length', None, 9, length_of='app_vlan_table',
                         adjust=lambda pkt, x: x + 4),
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_1),
        ByteField('subtype', 0x10),
        PacketListField('app_vlan_table', [],
                        LLDPDUOrgSpecific_IEEE8021_AppVLANEntry,
                        length_from=lambda pkt: 0 if pkt._length is None
                        else pkt._length - 4),
    ]

    def _check(self):
        if conf.contribs['LLDP'].strict_mode() and self._length is not None:
            if self._length < 4 or (self._length - 4) % 4 != 0:
                raise LLDPInvalidLengthField(
                    'IEEE 802.1 Application VLAN TLV length must be 4 + 4N, '
                    'got {}'.format(self._length))


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
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_3),
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
        return (payload[5] == 2 and _lldp_tlv_length(payload) == 7
                and int.from_bytes(payload[2:5], 'big') ==
                ORG_UNIQUE_CODE_IEEE_802_3)

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
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_3),
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
        return (payload[5] == 2 and _lldp_tlv_length(payload) == 12
                and int.from_bytes(payload[2:5], 'big') ==
                ORG_UNIQUE_CODE_IEEE_802_3)

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
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_3),
        ByteField('subtype', 2),
        FlagsField('MDI_power_support', 0, 8, LLDPDUPowerViaMDI.MDI_POWER_SUPPORT),
        ByteEnumField('PSE_power_pair', 1, LLDPDUPowerViaMDI.PSE_POWER_PAIR),
        ByteEnumField('power_class', 1, LLDPDUPowerViaMDI.POWER_CLASS),
        BitEnumField('power_type_no', 1, 1, LLDPDUPowerViaMDIDDL.POWER_TYPE_NO),
        BitEnumField('power_type_dir', 1, 1, LLDPDUPowerViaMDIDDL.POWER_TYPE_DIR),
        MultipleTypeField(
            [
                (
                    BitEnumField(
                        'power_source',
                        0b01,
                        2,
                        LLDPDUPowerViaMDIDDL.POWER_SOURCE_PD
                    ),
                    lambda pkt: pkt.power_type_dir == 1
                )
            ],
            BitEnumField(
                'power_source',
                0b01,
                2,
                LLDPDUPowerViaMDIDDL.POWER_SOURCE_PSE
            )
        ),
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
        return (payload[5] == 2 and _lldp_tlv_length(payload) == 29
                and int.from_bytes(payload[2:5], 'big') ==
                ORG_UNIQUE_CODE_IEEE_802_3)

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
        OUIField('org_code', ORG_UNIQUE_CODE_IEEE_802_3),
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
        return (payload[5] == 8 and _lldp_tlv_length(payload) == 26
                and int.from_bytes(payload[2:5], 'big') ==
                ORG_UNIQUE_CODE_IEEE_802_3)

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
        LLDPDUOrgSpecific_IEEE8021_Port_VLAN_ID,
        LLDPDUOrgSpecific_IEEE8021_Port_And_Protocol_VLAN_ID,
        LLDPDUOrgSpecific_IEEE8021_VLAN_Name,
        LLDPDUOrgSpecific_IEEE8021_Protocol_Identity,
        LLDPDUOrgSpecific_IEEE8021_VID_Usage_Digest,
        LLDPDUOrgSpecific_IEEE8021_Management_VID,
        LLDPDUOrgSpecific_IEEE8021_Link_Aggregation,
        LLDPDUOrgSpecific_IEEE8021_Congestion_Notification,
        LLDPDUOrgSpecific_IEEE8021_ETS_Configuration,
        LLDPDUOrgSpecific_IEEE8021_ETS_Recommendation,
        LLDPDUOrgSpecific_IEEE8021_PFC_Configuration,
        LLDPDUOrgSpecific_IEEE8021_Application_Priority,
        LLDPDUOrgSpecific_IEEE8021_EVB,
        LLDPDUOrgSpecific_IEEE8021_CDCP,
        LLDPDUOrgSpecific_IEEE8021_Application_VLAN,
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
