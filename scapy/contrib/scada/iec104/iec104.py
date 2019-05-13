# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Thomas Tannhaeuser <hecke@naberius.de>
# This program is published under a GPLv2 license
#
# scapy.contrib.description = IEC-60870-5-104 APCI / APDU layer definitions
# scapy.contrib.status = loads

"""
    IEC 60870-5-104
    ~~~~~~~~~~~~~~~

    :description:

        This module provides the IEC 60870-5-104 (common short name: iec104)
        layer, the information objects and related information element
        definitions.

        normative references:
            - IEC 60870-5-4:1994 (atomic base types / data format)
            - IEC 60870-5-101:2003 (information elements (sec. 7.2.6) and
              ASDU definition (sec. 7.3))
            - IEC 60870-5-104:2006 (information element TSC (sec. 8.8, p. 44))

    :TODO:
        - add allowed direction to IO attributes
          (but this could be derived from the name easily <--> )
        - information elements / objects need more testing
          (e.g. on live traffic w comparison against tshark)

    :NOTES:
        - bit and octet numbering is used as in the related standards
          (they usually start with index one instead of zero)
        - some of the information objects are only valid for IEC 60870-5-101 -
          so usually they should never appear on the network as iec101 uses
          serial connections. I added them if decoding of those messages is
          needed cause one goes to implement a iec101<-->iec104 gateway or
          hits such a gateway that acts not standard conform (e.g. by
          forwarding 101 messages to a 104 network)
"""

from scapy.compat import orb

from scapy.contrib.scada.iec104.iec104_fields import LEThreeBytesField, \
    IEC104SequenceNumber
from scapy.contrib.scada.iec104.iec104_information_objects import \
    IEC104_IO_NAMES, IEC104_IO_WITH_IOA_CLASSES, \
    IEC104_IO_CLASSES, IEC104_IO_ID_C_RD_NA_1, IEC104_IO_C_RD_NA_1

from scapy.config import conf
from scapy.contrib.scada.iec104.iec104_information_objects import \
    IEC104_IO_Packet
from scapy.error import warning, Scapy_Exception
from scapy.fields import ByteField, BitField, ByteEnumField, PacketListField, \
    BitEnumField, XByteField, FieldLenField, LEShortField, BitFieldLenField

from scapy.layers.inet import TCP
from scapy.packet import Raw
from scapy.packet import Packet, bind_layers

IEC_104_IANA_PORT = 2404

# direction - from the central station to the substation
IEC104_CONTROL_DIRECTION = 0
IEC104_CENTRAL_2_SUB_DIR = IEC104_CONTROL_DIRECTION

# direction - from the substation to the central station
IEC104_MONITOR_DIRECTION = 1
IEC104_SUB_2_CENTRAL_DIR = IEC104_MONITOR_DIRECTION

IEC104_DIRECTIONS = {
    IEC104_MONITOR_DIRECTION: 'monitor direction (sub -> central)',
    IEC104_CONTROL_DIRECTION: 'control direction (central -> sub)',
}

# COT - cause of transmission
IEC104_COT_UNDEFINED = 0
IEC104_COT_CYC = 1
IEC104_COT_BACK = 2
IEC104_COT_SPONT = 3
IEC104_COT_INIT = 4
IEC104_COT_REQ = 5
IEC104_COT_ACT = 6
IEC104_COT_ACTCON = 7
IEC104_COT_DEACT = 8
IEC104_COT_DEACTCON = 9
IEC104_COT_ACTTERM = 10
IEC104_COT_RETREM = 11
IEC104_COT_RETLOC = 12
IEC104_COT_FILE = 13
IEC104_COT_RESERVED_14 = 14
IEC104_COT_RESERVED_15 = 15
IEC104_COT_RESERVED_16 = 16
IEC104_COT_RESERVED_17 = 17
IEC104_COT_RESERVED_18 = 18
IEC104_COT_RESERVED_19 = 19
IEC104_COT_INROGEN = 20
IEC104_COT_INRO1 = 21
IEC104_COT_INRO2 = 22
IEC104_COT_INRO3 = 23
IEC104_COT_INRO4 = 24
IEC104_COT_INRO5 = 25
IEC104_COT_INRO6 = 26
IEC104_COT_INRO7 = 27
IEC104_COT_INRO8 = 28
IEC104_COT_INRO9 = 29
IEC104_COT_INRO10 = 30
IEC104_COT_INRO11 = 31
IEC104_COT_INRO12 = 32
IEC104_COT_INRO13 = 33
IEC104_COT_INRO14 = 34
IEC104_COT_INRO15 = 35
IEC104_COT_INRO16 = 36
IEC104_COT_REQCOGEN = 37
IEC104_COT_REQCO1 = 38
IEC104_COT_REQCO2 = 39
IEC104_COT_REQCO3 = 40
IEC104_COT_REQCO4 = 41
IEC104_COT_RESERVED_42 = 42
IEC104_COT_RESERVED_43 = 43
IEC104_COT_UNKNOWN_TYPE_CODE = 44
IEC104_COT_UNKNOWN_TRANSMIT_REASON = 45
IEC104_COT_UNKNOWN_COMMON_ADDRESS_OF_ASDU = 46
IEC104_COT_UNKNOWN_ADDRESS_OF_INFORMATION_OBJECT = 47
IEC104_COT_PRIVATE_48 = 48
IEC104_COT_PRIVATE_49 = 49
IEC104_COT_PRIVATE_50 = 50
IEC104_COT_PRIVATE_51 = 51
IEC104_COT_PRIVATE_52 = 52
IEC104_COT_PRIVATE_53 = 53
IEC104_COT_PRIVATE_54 = 54
IEC104_COT_PRIVATE_55 = 55
IEC104_COT_PRIVATE_56 = 56
IEC104_COT_PRIVATE_57 = 57
IEC104_COT_PRIVATE_58 = 58
IEC104_COT_PRIVATE_59 = 59
IEC104_COT_PRIVATE_60 = 60
IEC104_COT_PRIVATE_61 = 61
IEC104_COT_PRIVATE_62 = 62
IEC104_COT_PRIVATE_63 = 63

CAUSE_OF_TRANSMISSIONS = {
    IEC104_COT_UNDEFINED: 'undefined',
    IEC104_COT_CYC: 'cyclic (per/cyc)',
    IEC104_COT_BACK: 'background (back)',
    IEC104_COT_SPONT: 'spontaneous (spont)',
    IEC104_COT_INIT: 'initialized (init)',
    IEC104_COT_REQ: 'request (req)',
    IEC104_COT_ACT: 'activation (act)',
    IEC104_COT_ACTCON: 'activation confirmed (actcon)',
    IEC104_COT_DEACT: 'activation canceled (deact)',
    IEC104_COT_DEACTCON: 'activation cancellation confirmed (deactcon)',
    IEC104_COT_ACTTERM: 'activation finished (actterm)',
    IEC104_COT_RETREM: 'feedback caused by remote command (retrem)',
    IEC104_COT_RETLOC: 'feedback caused by local command (retloc)',
    IEC104_COT_FILE: 'file transfer (file)',
    IEC104_COT_RESERVED_14: 'reserved_14',
    IEC104_COT_RESERVED_15: 'reserved_15',
    IEC104_COT_RESERVED_16: 'reserved_16',
    IEC104_COT_RESERVED_17: 'reserved_17',
    IEC104_COT_RESERVED_18: 'reserved_18',
    IEC104_COT_RESERVED_19: 'reserved_19',
    IEC104_COT_INROGEN: 'queried by station (inrogen)',
    IEC104_COT_INRO1: 'queried by query to group 1 (inro1)',
    IEC104_COT_INRO2: 'queried by query to group 2 (inro2)',
    IEC104_COT_INRO3: 'queried by query to group 3 (inro3)',
    IEC104_COT_INRO4: 'queried by query to group 4 (inro4)',
    IEC104_COT_INRO5: 'queried by query to group 5 (inro5)',
    IEC104_COT_INRO6: 'queried by query to group 6 (inro6)',
    IEC104_COT_INRO7: 'queried by query to group 7 (inro7)',
    IEC104_COT_INRO8: 'queried by query to group 8 (inro8)',
    IEC104_COT_INRO9: 'queried by query to group 9 (inro9)',
    IEC104_COT_INRO10: 'queried by query to group 10 (inro10)',
    IEC104_COT_INRO11: 'queried by query to group 11 (inro11)',
    IEC104_COT_INRO12: 'queried by query to group 12 (inro12)',
    IEC104_COT_INRO13: 'queried by query to group 13 (inro13)',
    IEC104_COT_INRO14: 'queried by query to group 14 (inro14)',
    IEC104_COT_INRO15: 'queried by query to group 15 (inro15)',
    IEC104_COT_INRO16: 'queried by query to group 16 (inro16)',
    IEC104_COT_REQCOGEN: 'queried by counter general interrogation (reqcogen)',
    IEC104_COT_REQCO1: 'queried by query to counter group 1 (reqco1)',
    IEC104_COT_REQCO2: 'queried by query to counter group 2 (reqco2)',
    IEC104_COT_REQCO3: 'queried by query to counter group 3 (reqco3)',
    IEC104_COT_REQCO4: 'queried by query to counter group 4 (reqco4)',
    IEC104_COT_RESERVED_42: 'reserved_42',
    IEC104_COT_RESERVED_43: 'reserved_43',
    IEC104_COT_UNKNOWN_TYPE_CODE: 'unknown type code',
    IEC104_COT_UNKNOWN_TRANSMIT_REASON: 'unknown transmit reason',
    IEC104_COT_UNKNOWN_COMMON_ADDRESS_OF_ASDU:
        'unknown common address of ASDU',
    IEC104_COT_UNKNOWN_ADDRESS_OF_INFORMATION_OBJECT:
        'unknown address of information object',
    IEC104_COT_PRIVATE_48: 'private_48',
    IEC104_COT_PRIVATE_49: 'private_49',
    IEC104_COT_PRIVATE_50: 'private_50',
    IEC104_COT_PRIVATE_51: 'private_51',
    IEC104_COT_PRIVATE_52: 'private_52',
    IEC104_COT_PRIVATE_53: 'private_53',
    IEC104_COT_PRIVATE_54: 'private_54',
    IEC104_COT_PRIVATE_55: 'private_55',
    IEC104_COT_PRIVATE_56: 'private_56',
    IEC104_COT_PRIVATE_57: 'private_57',
    IEC104_COT_PRIVATE_58: 'private_58',
    IEC104_COT_PRIVATE_59: 'private_59',
    IEC104_COT_PRIVATE_60: 'private_60',
    IEC104_COT_PRIVATE_61: 'private_61',
    IEC104_COT_PRIVATE_62: 'private_62',
    IEC104_COT_PRIVATE_63: 'private_63'
}

IEC104_APDU_TYPE_UNKNOWN = 0x00
IEC104_APDU_TYPE_I_SEQ_IOA = 0x01
IEC104_APDU_TYPE_I_SINGLE_IOA = 0x02
IEC104_APDU_TYPE_U = 0x03
IEC104_APDU_TYPE_S = 0x04


def _iec104_apci_type_from_packet(data):
    """
    the type of the message is encoded in octet 1..4

                 oct 1, bit 1   2       oct 3, bit 1
    I Message               0  1|0                 0
    S Message               1   0                  0
    U Message               1   1                  0


    see EN 60870-5-104:2006, sec. 5 (p. 13, fig. 6,7,8)
    """

    oct_1 = orb(data[2])
    oct_3 = orb(data[4])

    oct_1_bit_1 = bool(oct_1 & 1)
    oct_1_bit_2 = bool(oct_1 & 2)
    oct_3_bit_1 = bool(oct_3 & 1)

    if oct_1_bit_1 is False and oct_3_bit_1 is False:
        if len(data) < 8:
            return IEC104_APDU_TYPE_UNKNOWN

        is_seq_ioa = ((orb(data[7]) & 0x80) == 0x80)

        if is_seq_ioa:
            return IEC104_APDU_TYPE_I_SEQ_IOA
        else:
            return IEC104_APDU_TYPE_I_SINGLE_IOA

    if oct_1_bit_1 and oct_1_bit_2 is False and oct_3_bit_1 is False:
        return IEC104_APDU_TYPE_S

    if oct_1_bit_1 and oct_1_bit_2 and oct_3_bit_1 is False:
        return IEC104_APDU_TYPE_U

    return IEC104_APDU_TYPE_UNKNOWN


class IEC104_APDU(Packet):
    """
    basic Application Protocol Data Unit definition used by S/U/I messages
    """

    def guess_payload_class(self, payload):

        payload_len = len(payload)

        if payload_len < 6:
            return self.default_payload_class(payload)

        if orb(payload[0]) != 0x68:
            self.default_payload_class(payload)

        # the length field contains the number of bytes starting from the
        # first control octet
        apdu_length = 2 + orb(payload[1])

        if payload_len < apdu_length:
            warning(
                'invalid len of APDU. given len: {} available len: {}'.format(
                    apdu_length, payload_len))
            return self.default_payload_class(payload)

        apdu_type = _iec104_apci_type_from_packet(payload)

        return IEC104_APDU_CLASSES.get(apdu_type,
                                       self.default_payload_class(payload))

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        detect type of the message by checking packet data
        :param _pkt: raw bytes of the packet layer data to be checked
        :param args: unused
        :param kargs: unused
        :return: class of the detected message type
        """

        if _iec104_is_i_apdu_seq_ioa(_pkt):
            return IEC104_I_Message_SeqIOA

        if _iec104_is_i_apdu_single_ioa(_pkt):
            return IEC104_I_Message_SingleIOA

        if _iec104_is_u_apdu(_pkt):
            return IEC104_U_Message

        if _iec104_is_s_apdu(_pkt):
            return IEC104_S_Message

        return Raw


class IEC104_S_Message(IEC104_APDU):
    """
    message used for ack of received I-messages
    """
    name = 'IEC-104 S APDU'

    fields_desc = [

        XByteField('start', 0x68),
        ByteField("apdu_length", 4),

        ByteField('octet_1', 0x01),
        ByteField('octet_2', 0),
        IEC104SequenceNumber('rx_seq_num', 0),
    ]


class IEC104_U_Message(IEC104_APDU):
    """
    message used for connection tx control (start/stop)  and monitoring (test)
    """
    name = 'IEC-104 U APDU'

    fields_desc = [

        XByteField('start', 0x68),
        ByteField("apdu_length", 4),

        BitField('testfr_con', 0, 1),
        BitField('testfr_act', 0, 1),
        BitField('stopdt_con', 0, 1),
        BitField('stopdt_act', 0, 1),
        BitField('startdt_con', 0, 1),
        BitField('startdt_act', 0, 1),
        BitField('octet_1_1_2', 3, 2),

        ByteField('octet_2', 0),
        ByteField('octet_3', 0),
        ByteField('octet_4', 0)
    ]


def _i_msg_io_dispatcher_sequence(pkt, next_layer_data):
    """
    get the type id and return the matching ASDU instance
    """
    next_layer_class_type = IEC104_IO_CLASSES.get(pkt.type_id, conf.raw_layer)

    return next_layer_class_type(next_layer_data)


def _i_msg_io_dispatcher_single(pkt, next_layer_data):
    """
    get the type id and return the matching ASDU instance
    (information object address + regular ASDU information object fields)
    """
    next_layer_class_type = IEC104_IO_WITH_IOA_CLASSES.get(pkt.type_id,
                                                           conf.raw_layer)

    return next_layer_class_type(next_layer_data)


class IEC104ASDUPacketListField(PacketListField):
    """
    used to add a list of information objects to an I-message
    """
    def m2i(self, pkt, m):
        """
        add calling layer instance to the cls()-signature
        :param pkt: calling layer instance
        :param m: raw data forming the next layer
        :return: instance of the class representing the next layer
        """
        return self.cls(pkt, m)


class IEC104_I_Message_StructureException(Scapy_Exception):
    """
    Exception raised if payload is not of type Information Object
    """
    pass


class IEC104_I_Message(IEC104_APDU):
    """
    message used for transmitting data (APDU - Application Protocol Data Unit)

    APDU: MAGIC + APCI + ASDU
    MAGIC: 0x68
    APCI : Control Information (rx/tx seq/ack numbers)
    ASDU : Application Service Data Unit - information object related data

    see EN 60870-5-104:2006, sec. 5 (p. 12)
    """
    name = 'IEC-104 I APDU'

    IEC_104_MAGIC = 0x68  # dec -> 104

    SQ_FLAG_SINGLE = 0
    SQ_FLAG_SEQUENCE = 1

    SQ_FLAGS = {
        SQ_FLAG_SINGLE: 'single',
        SQ_FLAG_SEQUENCE: 'sequence'
    }

    TEST_DISABLED = 0
    TEST_ENABLED = 1

    TEST_FLAGS = {
        TEST_DISABLED: 'disabled',
        TEST_ENABLED: 'enabled'
    }

    ACK_POSITIVE = 0
    ACK_NEGATIVE = 1

    ACK_FLAGS = {
        ACK_POSITIVE: 'positive',
        ACK_NEGATIVE: 'negative'
    }

    fields_desc = []

    def __init__(self, _pkt=b"", post_transform=None, _internal=0,
                 _underlayer=None, **fields):

        super(IEC104_I_Message, self).__init__(_pkt=_pkt,
                                               post_transform=post_transform,
                                               _internal=_internal,
                                               _underlayer=_underlayer,
                                               **fields)

        if 'io' in fields and fields['io']:
            self._information_object_update(fields['io'])

    def _information_object_update(self, io_instances):
        """
        set the type_id in the ASDU header based on the given information
        object (io) and check for valid structure
        :param io_instances: information object
        """

        if not isinstance(io_instances, list):
            io_instances = [io_instances]

        first_io = io_instances[0]
        first_io_class = first_io.__class__

        if not issubclass(first_io_class, IEC104_IO_Packet):
            raise IEC104_I_Message_StructureException(
                'information object payload must be a subclass of '
                'IEC104_IO_Packet')

        self.type_id = first_io.iec104_io_type_id()

        # ensure all io elements within the ASDU share the same class type
        for io_inst in io_instances[1:]:
            if io_inst.__class__ != first_io_class:
                raise IEC104_I_Message_StructureException(
                    'each information object within the ASDU must be of '
                    'the same class type (first io: {}, '
                    'current io: {})'.format(first_io_class._name,
                                             io_inst._name))


class IEC104_I_Message_SeqIOA(IEC104_I_Message):
    """
    all information objects share a base information object address field

    sq = 1, see EN 60870-5-101:2003, sec. 7.2.2.1 (p. 33)
    """
    name = 'IEC-104 I APDU (Seq IOA)'

    fields_desc = [
        # APCI
        XByteField('start', IEC104_I_Message.IEC_104_MAGIC),
        FieldLenField("apdu_length", None, fmt="!B", length_of='io',
                      adjust=lambda pkt, x: x + 13),

        IEC104SequenceNumber('tx_seq_num', 0),
        IEC104SequenceNumber('rx_seq_num', 0),

        # ASDU
        ByteEnumField('type_id', 0, IEC104_IO_NAMES),

        BitEnumField('sq', IEC104_I_Message.SQ_FLAG_SEQUENCE, 1,
                     IEC104_I_Message.SQ_FLAGS),
        BitFieldLenField('num_io', None, 7, count_of='io'),

        BitEnumField('test', 0, 1, IEC104_I_Message.TEST_FLAGS),
        BitEnumField('ack', 0, 1, IEC104_I_Message.ACK_FLAGS),
        BitEnumField('cot', 0, 6, CAUSE_OF_TRANSMISSIONS),

        ByteField('origin_address', 0),

        LEShortField('common_asdu_address', 0),

        LEThreeBytesField('information_object_address', 0),

        IEC104ASDUPacketListField('io',
                                  conf.raw_layer(),
                                  _i_msg_io_dispatcher_sequence,
                                  length_from=lambda pkt: pkt.apdu_length - 13)
    ]

    def post_dissect(self, s):
        if self.type_id == IEC104_IO_ID_C_RD_NA_1:

            # IEC104_IO_ID_C_RD_NA_1 has no payload. we will add the layer
            # manually to the stack right now. we do this num_io times
            # as - even if it makes no sense - someone could decide
            # to add more than one read commands in a sequence...
            setattr(self, 'io', [IEC104_IO_C_RD_NA_1()] * self.num_io)

        return s


class IEC104_I_Message_SingleIOA(IEC104_I_Message):
    """
    every information object contains an individual information object
    address field

    sq = 0, see EN 60870-5-101:2003, sec. 7.2.2.1 (p. 33)
    """
    name = 'IEC-104 I APDU (single IOA)'

    fields_desc = [
        # APCI
        XByteField('start', IEC104_I_Message.IEC_104_MAGIC),
        FieldLenField("apdu_length", None, fmt="!B", length_of='io',
                      adjust=lambda pkt, x: x + 10),

        IEC104SequenceNumber('tx_seq_num', 0),
        IEC104SequenceNumber('rx_seq_num', 0),

        # ASDU
        ByteEnumField('type_id', 0, IEC104_IO_NAMES),

        BitEnumField('sq', IEC104_I_Message.SQ_FLAG_SINGLE, 1,
                     IEC104_I_Message.SQ_FLAGS),
        BitFieldLenField('num_io', None, 7, count_of='io'),

        BitEnumField('test', 0, 1, IEC104_I_Message.TEST_FLAGS),
        BitEnumField('ack', 0, 1, IEC104_I_Message.ACK_FLAGS),
        BitEnumField('cot', 0, 6, CAUSE_OF_TRANSMISSIONS),

        ByteField('origin_address', 0),

        LEShortField('common_asdu_address', 0),

        IEC104ASDUPacketListField('io',
                                  conf.raw_layer(),
                                  _i_msg_io_dispatcher_single,
                                  length_from=lambda pkt: pkt.apdu_length - 10)
    ]


IEC104_APDU_CLASSES = {
    IEC104_APDU_TYPE_UNKNOWN: conf.raw_layer,
    IEC104_APDU_TYPE_I_SEQ_IOA: IEC104_I_Message_SeqIOA,
    IEC104_APDU_TYPE_I_SINGLE_IOA: IEC104_I_Message_SingleIOA,
    IEC104_APDU_TYPE_U: IEC104_U_Message,
    IEC104_APDU_TYPE_S: IEC104_S_Message
}


def _iec104_is_i_apdu_seq_ioa(payload):
    len_payload = len(payload)
    if len_payload < 6:
        return False

    if orb(payload[0]) != 0x68 or (
            orb(payload[1]) + 2) > len_payload or len_payload < 8:
        return False

    return IEC104_APDU_TYPE_I_SEQ_IOA == _iec104_apci_type_from_packet(payload)


def _iec104_is_i_apdu_single_ioa(payload):
    len_payload = len(payload)
    if len_payload < 6:
        return False

    if orb(payload[0]) != 0x68 or (
            orb(payload[1]) + 2) > len_payload or len_payload < 8:
        return False

    return IEC104_APDU_TYPE_I_SINGLE_IOA == _iec104_apci_type_from_packet(
        payload)


def _iec104_is_u_apdu(payload):
    if len(payload) < 6:
        return False

    if orb(payload[0]) != 0x68 or orb(payload[1]) != 4:
        return False

    return IEC104_APDU_TYPE_U == _iec104_apci_type_from_packet(payload)


def _iec104_is_s_apdu(payload):
    if len(payload) < 6:
        return False

    if orb(payload[0]) != 0x68 or orb(payload[1]) != 4:
        return False

    return IEC104_APDU_TYPE_S == _iec104_apci_type_from_packet(payload)


def iec104_decode(payload):
    """
    can be used to dissect payload of a TCP connection
    :param payload: the application layer data (IEC104-APDU(s))
    :return: iec104 (I/U/S) message instance, conf.raw_layer() if unknown
    """

    if _iec104_is_i_apdu_seq_ioa(payload):
        return IEC104_I_Message_SeqIOA(payload)
    elif _iec104_is_i_apdu_single_ioa(payload):
        return IEC104_I_Message_SingleIOA(payload)
    elif _iec104_is_s_apdu(payload):
        return IEC104_S_Message(payload)
    elif _iec104_is_u_apdu(payload):
        return IEC104_U_Message(payload)
    else:
        return conf.raw_layer(payload)


bind_layers(TCP, IEC104_APDU, sport=IEC_104_IANA_PORT)
bind_layers(TCP, IEC104_APDU, dport=IEC_104_IANA_PORT)
