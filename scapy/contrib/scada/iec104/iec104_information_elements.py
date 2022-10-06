# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Thomas Tannhaeuser <hecke@naberius.de>

# scapy.contrib.status = skip

"""
    information element definitions used by IEC 60870-5-101/104
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :description:

        This module provides the information element (IE) definitions used to
        compose the ASDUs (Application Service Data Units) used within the
        IEC 60870-5-101 and IEC 60870-5-104 protocol.

        normative references:
            - IEC 60870-5-4:1993 (atomic base types / data format)
            - IEC 60870-5-101:2003 (information elements (sec. 7.2.6) and
              ASDU definition (sec. 7.3))
            - IEC 60870-5-104:2006 (information element TSC (sec. 8.8, p. 44))

    :TODO:
        - some definitions should use signed types as outlined in the standard
        - normed value element should use a float type

"""
from scapy.contrib.scada.iec104.iec104_fields import \
    IEC60870_5_4_NormalizedFixPoint, IEC104SignedSevenBitValue, \
    LESignedShortField, LEIEEEFloatField
from scapy.fields import BitEnumField, ByteEnumField, ByteField, \
    ThreeBytesField, \
    BitField, LEShortField, LESignedIntField


def _generate_attributes_and_dicts(cls):
    """
    create class attributes and dict entries for range-based attributes

    class attributes will take the form: cls.<attribute_name_prefix>_<index>

    dictionary entries will be generated as:

      the_dict[index] = "<dict_entry_prefix> (<index>)"

    expects a GENERATED_ATTRIBUTES attribute within the class that contains a
    list of the specification for the attributes and dictionary entries to be
    generated. each list entry must have this format:

        (attribute_name_prefix, dict_entry_prefix, dictionary, first_index,
         last_index)

    with
        <attribute_name_prefix> - the prefix of the attribute name
        first_index - index of the first attribute to be generated
        last_index - index of the last attribute to be generated
    :param cls: the class the attributes should be added to
    :return: cls extended by generated attributes
    """

    for attribute_name_prefix, dict_entry_prefix, the_dict, first_index, \
        last_index \
            in cls.GENERATED_ATTRIBUTES:

        for index in range(first_index, last_index + 1):
            the_dict[index] = '{} ({})'.format(dict_entry_prefix, index)

            setattr(cls, '{}_{}'.format(attribute_name_prefix, index), index)

    return cls


class IEC104_IE_CommonQualityFlags:
    """
    common / shared information element quality flags
    """
    IV_FLAG_VALID = 0
    IV_FLAG_INVALID = 1
    IV_FLAGS = {
        IV_FLAG_VALID: 'valid',
        IV_FLAG_INVALID: 'invalid'
    }

    NT_FLAG_CURRENT_VALUE = 0
    NT_FLAG_OLD_VALUE = 1
    NT_FLAGS = {
        NT_FLAG_CURRENT_VALUE: 'current value',
        NT_FLAG_OLD_VALUE: 'old value'
    }

    SB_FLAG_NOT_SUBSTITUTED = 0
    SB_FLAG_SUBSTITUTED = 1
    SB_FLAGS = {
        SB_FLAG_NOT_SUBSTITUTED: 'not substituted',
        SB_FLAG_SUBSTITUTED: 'substituted'
    }

    BL_FLAG_NOT_BLOCKED = 0
    BL_FLAG_BLOCKED = 1
    BL_FLAGS = {
        BL_FLAG_NOT_BLOCKED: 'not blocked',
        BL_FLAG_BLOCKED: 'blocked'
    }

    EI_FLAG_ELAPSED_TIME_VALID = 0
    EI_FLAG_ELAPSED_TIME_INVALID = 1
    EI_FLAGS = {
        EI_FLAG_ELAPSED_TIME_VALID: 'elapsed time valid',
        EI_FLAG_ELAPSED_TIME_INVALID: 'elapsed time invalid'
    }


class IEC104_IE_SIQ(IEC104_IE_CommonQualityFlags):
    """
    SIQ - single point information with quality descriptor

    EN 60870-5-101:2003, sec. 7.2.6.1 (p. 44)
    """

    SPI_FLAG_STATE_OFF = 0
    SPI_FLAG_STATE_ON = 1

    SPI_FLAGS = {
        SPI_FLAG_STATE_OFF: 'off',
        SPI_FLAG_STATE_ON: 'on'
    }

    informantion_element_fields = [
        BitEnumField('iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        # invalid
        BitEnumField('nt', 0, 1, IEC104_IE_CommonQualityFlags.NT_FLAGS),
        # live or cached old value
        BitEnumField('sb', 0, 1, IEC104_IE_CommonQualityFlags.SB_FLAGS),
        # value substituted
        BitEnumField('bl', 0, 1, IEC104_IE_CommonQualityFlags.BL_FLAGS),
        # blocked
        BitField('reserved', 0, 3),
        BitEnumField('spi_value', 0, 1, SPI_FLAGS)
    ]


class IEC104_IE_DIQ(IEC104_IE_CommonQualityFlags):
    """
    DIQ - double-point information with quality descriptor

    EN 60870-5-101:2003, sec. 7.2.6.2 (p. 44)
    """

    DPI_FLAG_STATE_UNDEFINED_OR_TRANSIENT = 0
    DPI_FLAG_STATE_OFF = 1
    DPI_FLAG_STATE_ON = 2
    DPI_FLAG_STATE_UNDEFINED = 3

    DPI_FLAGS = {
        DPI_FLAG_STATE_UNDEFINED_OR_TRANSIENT: 'undefined/transient',
        DPI_FLAG_STATE_OFF: 'off',
        DPI_FLAG_STATE_ON: 'on',
        DPI_FLAG_STATE_UNDEFINED: 'undefined'
    }

    informantion_element_fields = [
        BitEnumField('iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        # invalid
        BitEnumField('nt', 0, 1, IEC104_IE_CommonQualityFlags.NT_FLAGS),
        # live or cached old value
        BitEnumField('sb', 0, 1, IEC104_IE_CommonQualityFlags.SB_FLAGS),
        # value substituted
        BitEnumField('bl', 0, 1, IEC104_IE_CommonQualityFlags.BL_FLAGS),
        # blocked
        BitField('reserved', 0, 2),
        BitEnumField('dpi_value', 0, 2, DPI_FLAGS)
    ]


class IEC104_IE_QDS(IEC104_IE_CommonQualityFlags):
    """
    QDS - quality descriptor separate object

    EN 60870-5-101:2003, sec. 7.2.6.3 (p. 45)
    """

    OV_FLAG_NO_OVERFLOW = 0
    OV_FLAG_OVERFLOW = 1
    OV_FLAGS = {
        OV_FLAG_NO_OVERFLOW: 'no overflow',
        OV_FLAG_OVERFLOW: 'overflow'
    }

    informantion_element_fields = [
        BitEnumField('iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        # invalid
        BitEnumField('nt', 0, 1, IEC104_IE_CommonQualityFlags.NT_FLAGS),
        # live or cached old value
        BitEnumField('sb', 0, 1, IEC104_IE_CommonQualityFlags.SB_FLAGS),
        # value substituted
        BitEnumField('bl', 0, 1, IEC104_IE_CommonQualityFlags.BL_FLAGS),
        # blocked
        BitField('reserved', 0, 3),
        BitEnumField('ov', 0, 1, OV_FLAGS),  # overflow
    ]


class IEC104_IE_QDP(IEC104_IE_CommonQualityFlags):
    """
    QDP - quality descriptor protection equipment separate object

    EN 60870-5-101:2003, sec. 7.2.6.4 (p. 46)
    """

    informantion_element_fields = [
        BitEnumField('iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        # invalid
        BitEnumField('nt', 0, 1, IEC104_IE_CommonQualityFlags.NT_FLAGS),
        # live or cached old value
        BitEnumField('sb', 0, 1, IEC104_IE_CommonQualityFlags.SB_FLAGS),
        # value substituted
        BitEnumField('bl', 0, 1, IEC104_IE_CommonQualityFlags.BL_FLAGS),
        # blocked
        BitEnumField('ei', 0, 1, IEC104_IE_CommonQualityFlags.EI_FLAGS),
        # blocked
        BitField('reserved_qdp', 0, 3)
    ]


class IEC104_IE_VTI:
    """
    VTI - value with transient state indication

    EN 60870-5-101:2003, sec. 7.2.6.5 (p. 47)
    """

    TRANSIENT_STATE_DISABLED = 0
    TRANSIENT_STATE_ENABLED = 1

    TRANSIENT_STATE_FLAGS = {
        TRANSIENT_STATE_DISABLED: 'device not in transient state',
        TRANSIENT_STATE_ENABLED: 'device in transient state'
    }

    informantion_element_fields = [
        BitEnumField('transient_state', 0, 1, TRANSIENT_STATE_FLAGS),
        IEC104SignedSevenBitValue('value', 0)
    ]


class IEC104_IE_NVA:
    """
    NVA - normed value

    EN 60870-5-101:2003, sec. 7.2.6.6 (p. 47)
    """

    informantion_element_fields = [
        IEC60870_5_4_NormalizedFixPoint('normed_value', 0)
    ]


class IEC104_IE_SVA:
    """
    SVA - scaled value

    EN 60870-5-101:2003, sec. 7.2.6.7 (p. 47)
    """

    informantion_element_fields = [
        LESignedShortField('scaled_value', 0)
    ]


class IEC104_IE_R32_IEEE_STD_754:
    """
    R32-IEEE STD 754 - short floating point value

    EN 60870-5-101:2003, sec. 7.2.6.8 (p. 47)
    """

    informantion_element_fields = [
        LEIEEEFloatField('scaled_value', 0)
    ]


class IEC104_IE_BCR:
    """
    BCR - binary counter reading

    EN 60870-5-101:2003, sec. 7.2.6.9 (p. 47)
    """
    CA_FLAG_COUNTER_NOT_ADJUSTED = 0
    CA_FLAG_COUNTER_ADJUSTED = 1
    CA_FLAGS = {
        CA_FLAG_COUNTER_NOT_ADJUSTED: 'counter not adjusted',
        CA_FLAG_COUNTER_ADJUSTED: 'counter adjusted'
    }

    CY_FLAG_NO_OVERFLOW = 0
    CY_FLAG_OVERFLOW = 1
    CY_FLAGS = {
        CY_FLAG_NO_OVERFLOW: 'no overflow',
        CY_FLAG_OVERFLOW: 'overflow'
    }

    informantion_element_fields = [
        LESignedIntField('counter_value', 0),
        BitEnumField('iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        # invalid
        BitEnumField('ca', 0, 1, CA_FLAGS),  # counter adjusted
        BitEnumField('cy', 0, 1, CY_FLAGS),  # carry flag / overflow
        BitField('sq', 0, 5)  # sequence
    ]


class IEC104_IE_SEP(IEC104_IE_CommonQualityFlags):
    """
    SEP - single event of protection equipment

    EN 60870-5-101:2003, sec. 7.2.6.10 (p. 48)
    """

    ES_FLAG_STATE_UNDEFINED_0 = 0
    ES_FLAG_STATE_OFF = 1
    ES_FLAG_STATE_ON = 2
    ES_FLAG_STATE_UNDEFINED_3 = 3
    ES_FLAGS = {
        ES_FLAG_STATE_UNDEFINED_0: 'undefined (0)',
        ES_FLAG_STATE_OFF: 'off',
        ES_FLAG_STATE_ON: 'on',
        ES_FLAG_STATE_UNDEFINED_3: 'undefined (3)',
    }

    informantion_element_fields = [
        BitEnumField('iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        # invalid
        BitEnumField('nt', 0, 1, IEC104_IE_CommonQualityFlags.NT_FLAGS),
        # live or cached old value
        BitEnumField('sb', 0, 1, IEC104_IE_CommonQualityFlags.SB_FLAGS),
        # value substituted
        BitEnumField('bl', 0, 1, IEC104_IE_CommonQualityFlags.BL_FLAGS),
        # blocked
        BitEnumField('ei', 0, 1, IEC104_IE_CommonQualityFlags.EI_FLAGS),
        # time valid
        BitField('reserved', 0, 1),
        BitEnumField('es', 0, 2, ES_FLAGS),  # event state
    ]


class IEC104_IE_SPE:
    """
    SPE - start events of protection equipment

    EN 60870-5-101:2003, sec. 7.2.6.11 (p. 48)
    """
    GS_FLAG_NO_GENERAL_TRIGGER = 0
    GS_FLAG_GENERAL_TRIGGER = 1
    GS_FLAGS = {
        GS_FLAG_NO_GENERAL_TRIGGER: 'general trigger',
        GS_FLAG_GENERAL_TRIGGER: 'no general trigger'
    }

    # protection relays - start of operation - fault detection per phase
    SL_FLAG_START_OPR_PHASE_L1_NO_TRIGGER = 0
    SL_FLAG_START_OPR_PHASE_L1_TRIGGER = 1
    SL_FLAG_START_OPR_PHASE_L2_NO_TRIGGER = 0
    SL_FLAG_START_OPR_PHASE_L2_TRIGGER = 1
    SL_FLAG_START_OPR_PHASE_L3_NO_TRIGGER = 0
    SL_FLAG_START_OPR_PHASE_L3_TRIGGER = 1
    SL_FLAGS = {
        SL_FLAG_START_OPR_PHASE_L1_NO_TRIGGER: 'no start of operation',
        SL_FLAG_START_OPR_PHASE_L1_TRIGGER: 'start of operation'
    }

    # protection event start caused by earth current
    SIE_FLAG_START_OPR_PHASE_IE_NO_TRIGGER = 0
    SIE_FLAG_START_OPR_PHASE_IE_TRIGGER = 1
    SIE_FLAGS = {
        SIE_FLAG_START_OPR_PHASE_IE_NO_TRIGGER: 'no start of operation',
        SIE_FLAG_START_OPR_PHASE_IE_TRIGGER: 'start of operation'
    }

    # direction of the started protection event
    SRD_FLAG_DIRECTION_FORWARD = 0
    SRD_FLAG_DIRECTION_BACKWARD = 1
    SRD_FLAGS = {
        SRD_FLAG_DIRECTION_FORWARD: 'forward',
        SRD_FLAG_DIRECTION_BACKWARD: 'backward'
    }

    informantion_element_fields = [
        BitField('reserved', 0, 2),
        BitEnumField('srd', 0, 1, SRD_FLAGS),
        BitEnumField('sie', 0, 1, SIE_FLAGS),
        BitEnumField('sl3', 0, 1, SL_FLAGS),
        BitEnumField('sl2', 0, 1, SL_FLAGS),
        BitEnumField('sl1', 0, 1, SL_FLAGS),
        BitEnumField('gs', 0, 1, GS_FLAGS)
    ]


class IEC104_IE_OCI:
    """
    OCI - output circuit information of protection equipment

    EN 60870-5-101:2003, sec. 7.2.6.12 (p. 49)
    """
    # all 3 phases off command
    GC_FLAG_NO_GENERAL_COMMAND_OFF = 0
    GC_FLAG_GENERAL_COMMAND_OFF = 1
    GC_FLAGS = {
        GC_FLAG_NO_GENERAL_COMMAND_OFF: 'no general off',
        GC_FLAG_GENERAL_COMMAND_OFF: 'general off'
    }
    # phase based off command
    # protection relays - start of operation - fault detection per phase
    CL_FLAG_NO_COMMAND_L1_OFF = 0
    CL_FLAG_COMMAND_L1_OFF = 1
    CL_FLAG_NO_COMMAND_L2_OFF = 0
    CL_FLAG_COMMAND_L2_OFF = 1
    CL_FLAG_NO_COMMAND_L3_OFF = 0
    CL_FLAG_COMMAND_L3_OFF = 1
    CL_FLAGS = {
        CL_FLAG_NO_COMMAND_L1_OFF: 'no command off',
        CL_FLAG_COMMAND_L1_OFF: 'no command off'
    }

    informantion_element_fields = [
        BitField('reserved', 0, 4),
        BitEnumField('cl3', 0, 1, CL_FLAGS),  # command Lx
        BitEnumField('cl2', 0, 1, CL_FLAGS),
        BitEnumField('cl1', 0, 1, CL_FLAGS),
        BitEnumField('gc', 0, 1, GC_FLAGS),  # general off
    ]


class IEC104_IE_BSI:
    """
    BSI - binary state information

    EN 60870-5-101:2003, sec. 7.2.6.13 (p. 49)
    """
    informantion_element_fields = [
        BitField('bsi', 0, 32)
    ]


class IEC104_IE_FBP:
    """
    FBP - fixed test bit pattern

    EN 60870-5-101:2003, sec. 7.2.6.14 (p. 49)
    """
    informantion_element_fields = [
        LEShortField('fbp', 0)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_QOC:
    """
    QOC - qualifier of command

    EN 60870-5-101:2003, sec. 7.2.6.26 (p. 54)
    """

    QU_FLAG_NO_ADDITIONAL_PARAMETERS = 0
    QU_FLAG_SHORT_COMMAND_EXEC_TIME = 1  # e.g. controlling a power switch
    QU_FLAG_LONG_COMMAND_EXEC_TIME = 2
    QU_FLAG_PERMANENT_COMMAND = 3

    QU_FLAGS = {
        QU_FLAG_NO_ADDITIONAL_PARAMETERS: 'no additional parameter',
        QU_FLAG_SHORT_COMMAND_EXEC_TIME: 'short execution time',
        QU_FLAG_LONG_COMMAND_EXEC_TIME: 'long execution time',
        QU_FLAG_PERMANENT_COMMAND: 'permanent command',
    }

    GENERATED_ATTRIBUTES = [
        ('QU_FLAG_RESERVED_COMPATIBLE', 'reserved - compatible', QU_FLAGS, 4,
         8),
        ('QU_FLAG_RESERVED_PREDEFINED_FUNCTION',
         'reserved - predefined function', QU_FLAGS, 9, 15),
        ('QU_FLAG_RESERVED_PRIVATE', 'reserved - private', QU_FLAGS, 16, 31)
    ]

    SE_FLAG_EXECUTE = 0
    SE_FLAG_SELECT = 1
    SE_FLAGS = {
        SE_FLAG_EXECUTE: 'execute',
        SE_FLAG_SELECT: 'select'
    }

    informantion_element_fields = [
        BitEnumField('s_or_e', 0, 1, SE_FLAGS),
        BitEnumField('qu', 0, 5, QU_FLAGS)
    ]


class IEC104_IE_SCO(IEC104_IE_QOC):
    """
    SCO - single command

    EN 60870-5-101:2003, sec. 7.2.6.15 (p. 50)
    """
    SCS_FLAG_STATE_OFF = 0
    SCS_FLAG_STATE_ON = 1
    SCS_FLAGS = {
        SCS_FLAG_STATE_OFF: 'off',
        SCS_FLAG_STATE_ON: 'on'
    }

    informantion_element_fields = IEC104_IE_QOC.informantion_element_fields + [
        BitField('reserved', 0, 1),
        BitEnumField('scs', 0, 1, SCS_FLAGS)
    ]


class IEC104_IE_DCO(IEC104_IE_QOC):
    """
    DCO - double command

    EN 60870-5-101:2003, sec. 7.2.6.16 (p. 50)
    """
    DCS_FLAG_STATE_INVALID_0 = 0
    DCS_FLAG_STATE_OFF = 1
    DCS_FLAG_STATE_ON = 2
    DCS_FLAG_STATE_INVALID_3 = 3
    DCS_FLAGS = {
        DCS_FLAG_STATE_INVALID_0: 'invalid (0)',
        DCS_FLAG_STATE_OFF: 'off',
        DCS_FLAG_STATE_ON: 'on',
        DCS_FLAG_STATE_INVALID_3: 'invalid (3)',
    }

    informantion_element_fields = IEC104_IE_QOC.informantion_element_fields + [
        BitEnumField('dcs', 0, 2, DCS_FLAGS)
    ]


class IEC104_IE_RCO(IEC104_IE_QOC):
    """
    RCO - regulating step command

    EN 60870-5-101:2003, sec. 7.2.6.17 (p. 50)
    """
    RCO_FLAG_STATE_INVALID_0 = 0
    RCO_FLAG_STATE_STEP_DOWN = 1
    RCO_FLAG_STATE_STEP_UP = 2
    RCO_FLAG_STATE_INVALID_3 = 3
    RCO_FLAGS = {
        RCO_FLAG_STATE_INVALID_0: 'invalid (0)',
        RCO_FLAG_STATE_STEP_DOWN: 'step down',
        RCO_FLAG_STATE_STEP_UP: 'step up',
        RCO_FLAG_STATE_INVALID_3: 'invalid (3)',
    }

    informantion_element_fields = IEC104_IE_QOC.informantion_element_fields + [
        BitEnumField('rcs', 0, 2, RCO_FLAGS)
    ]


class IEC104_IE_CP56TIME2A(IEC104_IE_CommonQualityFlags):
    """
    CP56Time2a - dual time, 7 octets
                 (milliseconds, valid flag, minutes, hours,
                  summer-time-indicator, day of month, weekday, years)

    well, someone should have talked to them about the idea of the
    unix timestamp...

    EN 60870-5-101:2003, sec. 7.2.6.18 (p. 50)

    time representation format according IEC 60870-5-4:1993, sec. 6.8, p. 23
    """
    WEEK_DAY_FLAG_UNUSED = 0
    WEEK_DAY_FLAG_MONDAY = 1
    WEEK_DAY_FLAG_TUESDAY = 2
    WEEK_DAY_FLAG_WEDNESDAY = 3
    WEEK_DAY_FLAG_THURSDAY = 4
    WEEK_DAY_FLAG_FRIDAY = 5
    WEEK_DAY_FLAG_SATURDAY = 6
    WEEK_DAY_FLAG_SUNDAY = 7
    WEEK_DAY_FLAGS = {
        WEEK_DAY_FLAG_UNUSED: 'unused',
        WEEK_DAY_FLAG_MONDAY: 'Monday',
        WEEK_DAY_FLAG_TUESDAY: 'Tuesday',
        WEEK_DAY_FLAG_WEDNESDAY: 'Wednesday',
        WEEK_DAY_FLAG_THURSDAY: 'Thursday',
        WEEK_DAY_FLAG_FRIDAY: 'Friday',
        WEEK_DAY_FLAG_SATURDAY: 'Saturday',
        WEEK_DAY_FLAG_SUNDAY: 'Sunday'
    }

    GEN_FLAG_REALTIME = 0
    GEN_FLAG_SUBSTITUTED_TIME = 1
    GEN_FLAGS = {
        GEN_FLAG_REALTIME: 'real time',
        GEN_FLAG_SUBSTITUTED_TIME: 'substituted time'
    }

    SU_FLAG_NORMAL_TIME = 0
    SU_FLAG_SUMMER_TIME = 1
    SU_FLAGS = {
        SU_FLAG_NORMAL_TIME: 'normal time',
        SU_FLAG_SUMMER_TIME: 'summer time'
    }

    informantion_element_fields = [
        LEShortField('sec_milli', 0),
        BitEnumField('iv_time', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        BitEnumField('gen', 0, 1, GEN_FLAGS),
        # only valid in monitor direction ToDo: special treatment needed?
        BitField('minutes', 0, 6),
        BitEnumField('su', 0, 1, SU_FLAGS),
        BitField('reserved_2', 0, 2),
        BitField('hours', 0, 5),
        BitEnumField('weekday', 0, 3, WEEK_DAY_FLAGS),
        BitField('day_of_month', 0, 5),
        BitField('reserved_3', 0, 4),
        BitField('month', 0, 4),
        BitField('reserved_4', 0, 1),
        BitField('year', 0, 7),
    ]


class IEC104_IE_CP56TIME2A_START_TIME(IEC104_IE_CP56TIME2A):
    """
    derived IE, used for ASDU that requires two CP56TIME2A timestamps for
    defining a range
    """
    _DERIVED_IE = True
    informantion_element_fields = [
        LEShortField('start_sec_milli', 0),
        BitEnumField('start_iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        BitEnumField('start_gen', 0, 1, IEC104_IE_CP56TIME2A.GEN_FLAGS),
        # only valid in monitor direction ToDo: special treatment needed?
        BitField('start_minutes', 0, 6),
        BitEnumField('start_su', 0, 1, IEC104_IE_CP56TIME2A.SU_FLAGS),
        BitField('start_reserved_2', 0, 2),
        BitField('start_hours', 0, 5),
        BitEnumField('start_weekday', 0, 3,
                     IEC104_IE_CP56TIME2A.WEEK_DAY_FLAGS),
        BitField('start_day_of_month', 0, 5),
        BitField('start_reserved_3', 0, 4),
        BitField('start_month', 0, 4),
        BitField('start_reserved_4', 0, 1),
        BitField('start_year', 0, 7),
    ]


class IEC104_IE_CP56TIME2A_STOP_TIME(IEC104_IE_CP56TIME2A):
    """
    derived IE, used for ASDU that requires two CP56TIME2A timestamps for
    defining a range
    """
    _DERIVED_IE = True
    informantion_element_fields = [
        LEShortField('stop_sec_milli', 0),
        BitEnumField('stop_iv', 0, 1, IEC104_IE_CommonQualityFlags.IV_FLAGS),
        BitEnumField('stop_gen', 0, 1, IEC104_IE_CP56TIME2A.GEN_FLAGS),
        # only valid in monitor direction ToDo: special treatment needed?
        BitField('stop_minutes', 0, 6),
        BitEnumField('stop_su', 0, 1, IEC104_IE_CP56TIME2A.SU_FLAGS),
        BitField('stop_reserved_2', 0, 2),
        BitField('stop_hours', 0, 5),
        BitEnumField('stop_weekday', 0, 3,
                     IEC104_IE_CP56TIME2A.WEEK_DAY_FLAGS),
        BitField('stop_day_of_month', 0, 5),
        BitField('stop_reserved_3', 0, 4),
        BitField('stop_month', 0, 4),
        BitField('stop_reserved_4', 0, 1),
        BitField('stop_year', 0, 7),
    ]


class IEC104_IE_CP24TIME2A(IEC104_IE_CP56TIME2A):
    """
    CP24Time2a - dual time, 3 octets
                 (milliseconds, valid flag, minutes)

    EN 60870-5-101:2003, sec. 7.2.6.19 (p. 51)

    time representation format according IEC 60870-5-4:1993, sec. 6.8, p. 23,
    octet 4..7 discarded
    """

    informantion_element_fields = \
        IEC104_IE_CP56TIME2A.informantion_element_fields[:4]


class IEC104_IE_CP16TIME2A:
    """
    CP16Time2a - dual time, 2 octets
                (milliseconds)

    EN 60870-5-101:2003, sec. 7.2.6.20 (p. 51)
    """
    informantion_element_fields = [
        LEShortField('sec_milli', 0)
    ]


class IEC104_IE_CP16TIME2A_ELAPSED:
    """
    derived IE, used in ASDU using more than one CP* field and this one is
    used to show an elapsed time
    """
    _DERIVED_IE = True

    informantion_element_fields = [
        LEShortField('elapsed_sec_milli', 0)
    ]


class IEC104_IE_CP16TIME2A_PROTECTION_ACTIVE:
    """
    derived IE, used in ASDU using more than one CP* field and this one is
    used to show an protection activation time
    """
    _DERIVED_IE = True

    informantion_element_fields = [
        LEShortField('prot_act_sec_milli', 0)
    ]


class IEC104_IE_CP16TIME2A_PROTECTION_COMMAND:
    """
    derived IE, used in ASDU using more than one CP* field and this one is
    used to show an protection command time
    """
    _DERIVED_IE = True

    informantion_element_fields = [
        LEShortField('prot_cmd_sec_milli', 0)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_COI:
    """
    COI - cause of initialization

    EN 60870-5-101:2003, sec. 7.2.6.21 (p. 51)
    """
    LPC_FLAG_LOCAL_PARAMETER_UNCHANGED = 0
    LPC_FLAG_LOCAL_PARAMETER_CHANGED = 1
    LPC_FLAGS = {
        LPC_FLAG_LOCAL_PARAMETER_UNCHANGED: 'unchanged',
        LPC_FLAG_LOCAL_PARAMETER_CHANGED: 'changed'
    }

    COI_FLAG_LOCAL_POWER_ON = 0
    COI_FLAG_LOCAL_MANUAL_RESET = 1
    COI_FLAG_REMOTE_RESET = 2

    COI_FLAGS = {
        COI_FLAG_LOCAL_POWER_ON: 'local power on',
        COI_FLAG_LOCAL_MANUAL_RESET: 'manual reset',
        COI_FLAG_REMOTE_RESET: 'remote reset'
    }

    GENERATED_ATTRIBUTES = [
        ('COI_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', COI_FLAGS, 3,
         31),
        ('COI_FLAG_PRIVATE_RESERVED', 'private reserved', COI_FLAGS, 32, 127)
    ]

    informantion_element_fields = [
        BitEnumField('local_param_state', 0, 1, LPC_FLAGS),
        BitEnumField('coi', 0, 7, COI_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_QOI:
    """
    QOI - qualifier of interrogation

    EN 60870-5-101:2003, sec. 7.2.6.22 (p. 52)
    """
    QOI_FLAG_UNUSED = 0
    QOI_FLAG_STATION_INTERROGATION = 20
    QOI_FLAG_GROUP_1_INTERROGATION = 21
    QOI_FLAG_GROUP_2_INTERROGATION = 22
    QOI_FLAG_GROUP_3_INTERROGATION = 23
    QOI_FLAG_GROUP_4_INTERROGATION = 24
    QOI_FLAG_GROUP_5_INTERROGATION = 25
    QOI_FLAG_GROUP_6_INTERROGATION = 26
    QOI_FLAG_GROUP_7_INTERROGATION = 27
    QOI_FLAG_GROUP_8_INTERROGATION = 28
    QOI_FLAG_GROUP_9_INTERROGATION = 29
    QOI_FLAG_GROUP_10_INTERROGATION = 30
    QOI_FLAG_GROUP_11_INTERROGATION = 31
    QOI_FLAG_GROUP_12_INTERROGATION = 32
    QOI_FLAG_GROUP_13_INTERROGATION = 33
    QOI_FLAG_GROUP_14_INTERROGATION = 34
    QOI_FLAG_GROUP_15_INTERROGATION = 35
    QOI_FLAG_GROUP_16_INTERROGATION = 36

    QOI_FLAGS = {
        QOI_FLAG_UNUSED: 'unused',
        QOI_FLAG_STATION_INTERROGATION: 'station interrogation',
        QOI_FLAG_GROUP_1_INTERROGATION: 'group 1 interrogation',
        QOI_FLAG_GROUP_2_INTERROGATION: 'group 2 interrogation',
        QOI_FLAG_GROUP_3_INTERROGATION: 'group 3 interrogation',
        QOI_FLAG_GROUP_4_INTERROGATION: 'group 4 interrogation',
        QOI_FLAG_GROUP_5_INTERROGATION: 'group 5 interrogation',
        QOI_FLAG_GROUP_6_INTERROGATION: 'group 6 interrogation',
        QOI_FLAG_GROUP_7_INTERROGATION: 'group 7 interrogation',
        QOI_FLAG_GROUP_8_INTERROGATION: 'group 8 interrogation',
        QOI_FLAG_GROUP_9_INTERROGATION: 'group 9 interrogation',
        QOI_FLAG_GROUP_10_INTERROGATION: 'group 10 interrogation',
        QOI_FLAG_GROUP_11_INTERROGATION: 'group 11 interrogation',
        QOI_FLAG_GROUP_12_INTERROGATION: 'group 12 interrogation',
        QOI_FLAG_GROUP_13_INTERROGATION: 'group 13 interrogation',
        QOI_FLAG_GROUP_14_INTERROGATION: 'group 14 interrogation',
        QOI_FLAG_GROUP_15_INTERROGATION: 'group 15 interrogation',
        QOI_FLAG_GROUP_16_INTERROGATION: 'group 16 interrogation'
    }

    GENERATED_ATTRIBUTES = [
        ('QOI_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', QOI_FLAGS, 1,
         19),
        ('QOI_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', QOI_FLAGS, 37,
         63),
        ('QOI_FLAG_PRIVATE_RESERVED', 'private reserved', QOI_FLAGS, 64, 255)
    ]

    informantion_element_fields = [
        ByteEnumField('qoi', 0, QOI_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_QCC:
    """
    QCC - qualifier of counter interrogation command

    EN 60870-5-101:2003, sec. 7.2.6.23 (p. 52)
    """

    # request flags
    RQT_FLAG_UNUSED = 0
    RQT_FLAG_GROUP_1_COUNTER_INTERROGATION = 1
    RQT_FLAG_GROUP_2_COUNTER_INTERROGATION = 2
    RQT_FLAG_GROUP_3_COUNTER_INTERROGATION = 3
    RQT_FLAG_GROUP_4_COUNTER_INTERROGATION = 4
    RQT_FLAG_GENERAL_COUNTER_INTERROGATION = 5

    RQT_FLAGS = {
        RQT_FLAG_UNUSED: 'unused',
        RQT_FLAG_GROUP_1_COUNTER_INTERROGATION: 'counter group 1 '
                                                'interrogation',
        RQT_FLAG_GROUP_2_COUNTER_INTERROGATION: 'counter group 2 '
                                                'interrogation',
        RQT_FLAG_GROUP_3_COUNTER_INTERROGATION: 'counter group 3 '
                                                'interrogation',
        RQT_FLAG_GROUP_4_COUNTER_INTERROGATION: 'counter group 4 '
                                                'interrogation',
        RQT_FLAG_GENERAL_COUNTER_INTERROGATION: 'general counter '
                                                'interrogation',
    }

    GENERATED_ATTRIBUTES = [
        ('RQT_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', RQT_FLAGS, 6,
         31),
        ('RQT_FLAG_PRIVATE_RESERVED', 'private reserved', RQT_FLAGS, 32, 63),
    ]

    FRZ_FLAG_QUERY = 0
    FRZ_FLAG_SAVE_COUNTER_WITHOUT_RESET = 1
    FRZ_FLAG_SAVE_COUNTER_AND_RESET = 2
    FRZ_FLAG_COUNTER_RESET = 3

    FRZ_FLAGS = {
        FRZ_FLAG_QUERY: 'query',
        FRZ_FLAG_SAVE_COUNTER_WITHOUT_RESET: 'save counter, no counter reset',
        FRZ_FLAG_SAVE_COUNTER_AND_RESET: 'save counter and reset counter',
        FRZ_FLAG_COUNTER_RESET: 'reset counter'
    }

    informantion_element_fields = [
        BitEnumField('frz', 0, 2, FRZ_FLAGS),
        BitEnumField('rqt', 0, 6, RQT_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_QPM:
    """
    QPM - qualifier of parameter of measured values

    EN 60870-5-101:2003, sec. 7.2.6.24 (p. 53)
    """

    KPA_FLAG_UNUSED = 0
    KPA_FLAG_THRESHOLD = 1
    KPA_FLAG_SMOOTHING_FACTOR = 2
    KPA_FLAG_LOWER_LIMIT_FOR_MEAS_TX = 3
    KPA_FLAG_UPPER_LIMIT_FOR_MEAS_TX = 4

    KPA_FLAGS = {
        KPA_FLAG_UNUSED: 'unused',
        KPA_FLAG_THRESHOLD: 'threshold',
        KPA_FLAG_SMOOTHING_FACTOR: 'smoothing factor',
        KPA_FLAG_LOWER_LIMIT_FOR_MEAS_TX: 'lower limit meas transmit',
        KPA_FLAG_UPPER_LIMIT_FOR_MEAS_TX: 'upper limit meas transmit'
    }

    GENERATED_ATTRIBUTES = [
        ('KPA_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', KPA_FLAGS, 5,
         31),
        ('KPA_FLAG_PRIVATE_RESERVED', 'private reserved', KPA_FLAGS, 32, 63)
    ]

    LPC_FLAG_LOCAL_PARAMETER_MOT_CHANGED = 0
    LPC_FLAG_LOCAL_PARAMETER_CHANGED = 1
    LPC_FLAGS = {
        LPC_FLAG_LOCAL_PARAMETER_MOT_CHANGED: 'local parameter not changed',
        LPC_FLAG_LOCAL_PARAMETER_CHANGED: 'local parameter changed'
    }

    POP_FLAG_PARAM_EFFECTIVE = 0
    POP_FLAG_PARAM_INEFFECTIVE = 1
    POP_FLAGS = {
        POP_FLAG_PARAM_EFFECTIVE: 'parameter effective',
        POP_FLAG_PARAM_INEFFECTIVE: 'parameter ineffective',
    }

    informantion_element_fields = [
        BitEnumField('pop', 0, 1, POP_FLAGS),  # usually unused, should be zero
        BitEnumField('lpc', 0, 1, LPC_FLAGS),  # usually unused, should be zero
        BitEnumField('kpa', 0, 6, KPA_FLAGS),
    ]


@_generate_attributes_and_dicts
class IEC104_IE_QPA:
    """
    QPA - qualifier of parameter activation

    EN 60870-5-101:2003, sec. 7.2.6.25 (p. 53)
    """
    QPA_FLAG_UNUSED = 0
    QPA_FLAG_ACT_DEACT_LOADED_PARAM_OA_0 = 1
    QPA_FLAG_ACT_DEACT_LOADED_PARAM = 2
    QPA_FLAG_ACT_DEACT_CYCLIC_TX = 3

    QPA_FLAGS = {
        QPA_FLAG_UNUSED: 'unused',
        QPA_FLAG_ACT_DEACT_LOADED_PARAM_OA_0: 'act/deact loaded parameters '
                                              'for object addr 0',
        QPA_FLAG_ACT_DEACT_LOADED_PARAM: 'act/deact loaded parameters for '
                                         'given object addr',
        QPA_FLAG_ACT_DEACT_CYCLIC_TX: 'act/deact cyclic transfer of object '
                                      'given by object addr',
    }

    GENERATED_ATTRIBUTES = [
        ('QPA_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', QPA_FLAGS, 4,
         127),
        ('QPA_FLAG_PRIVATE_RESERVED', 'private reserved', QPA_FLAGS, 128, 255)
    ]

    informantion_element_fields = [
        ByteEnumField('qpa', 0, QPA_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_QRP:
    """
    QRP - Qualifier of reset process command

    EN 60870-5-101:2003, sec. 7.2.6.27 (p. 54)
    """
    QRP_FLAG_UNUSED = 0
    QRP_FLAG_GENERAL_PROCESS_RESET = 1
    QRP_FLAG_RESET_EVENT_BUFFER = 2

    QRP_FLAGS = {
        QRP_FLAG_UNUSED: 'unsued',
        QRP_FLAG_GENERAL_PROCESS_RESET: 'general process reset',
        QRP_FLAG_RESET_EVENT_BUFFER: 'reset event buffer'
    }

    GENERATED_ATTRIBUTES = [
        ('QRP_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', QRP_FLAGS, 3,
         127),
        ('QRP_FLAG_PRIVATE_RESERVED', 'private reserved', QRP_FLAGS, 128, 255),
    ]

    informantion_element_fields = [
        ByteEnumField('qrp', 0, QRP_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_FRQ:
    """
    FRQ - file ready qualifier

    EN 60870-5-101:2003, sec. 7.2.6.28 (p. 54)
    """
    FR_FLAG_UNUSED = 0

    FR_FLAGS = {
        FR_FLAG_UNUSED: 'unused'
    }

    GENERATED_ATTRIBUTES = [
        ('FR_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         FR_FLAGS, 1, 63),
        ('FR_FLAG_PRIVATE_RESERVED', 'private reserved', FR_FLAGS, 64, 127),
    ]

    FRACK_FLAG_POSITIVE_ACK = 0
    FRACK_FLAG_NEGATIVE_ACK = 1
    FRACK_FLAGS = {
        FRACK_FLAG_POSITIVE_ACK: 'positive ack',
        FRACK_FLAG_NEGATIVE_ACK: 'negative ack'
    }

    informantion_element_fields = [
        BitEnumField('fr_ack', 0, 1, FRACK_FLAGS),
        BitEnumField('fr', 0, 7, FR_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_SRQ:
    """
    SRQ - sequence ready qualifier

    EN 60870-5-101:2003, sec. 7.2.6.29 (p. 54)
    """
    SR_FLAG_UNUSED = 0

    SR_FLAGS = {
        SR_FLAG_UNUSED: 'unused'
    }

    GENERATED_ATTRIBUTES = [
        ('SR_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         SR_FLAGS, 1, 63),
        ('SR_FLAG_PRIVATE_RESERVED', 'private reserved', SR_FLAGS, 64, 127),
    ]

    SLOAD_FLAG_SECTION_READY = 0
    SLOAD_FLAG_SECTION_NOT_READY = 1
    SLAOD_FLAGS = {
        SLOAD_FLAG_SECTION_READY: 'section ready',
        SLOAD_FLAG_SECTION_NOT_READY: 'section not ready'
    }

    informantion_element_fields = [
        BitEnumField('section_load_state', 0, 1, SLAOD_FLAGS),
        BitEnumField('sr', 0, 7, SR_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_SCQ:
    """
    SCQ - select and call qualifier

    EN 60870-5-101:2003, sec. 7.2.6.30 (p. 55)
    """
    SEL_CALL_FLAG_UNUSED = 0
    SEL_CALL_FLAG_FILE_SELECT = 1
    SEL_CALL_FLAG_FILE_REQUEST = 2
    SEL_CALL_FLAG_FILE_ABORT = 3
    SEL_CALL_FLAG_FILE_DELETE = 4
    SEL_CALL_FLAG_SECTION_SELECTION = 5
    SEL_CALL_FLAG_SECTION_REQUEST = 6
    SEL_CALL_FLAG_SECTION_ABORT = 7

    SEL_CALL_FLAGS = {
        SEL_CALL_FLAG_UNUSED: 'unused',
        SEL_CALL_FLAG_FILE_SELECT: 'file select',
        SEL_CALL_FLAG_FILE_REQUEST: 'file request',
        SEL_CALL_FLAG_FILE_ABORT: 'file abort',
        SEL_CALL_FLAG_FILE_DELETE: 'file delete',
        SEL_CALL_FLAG_SECTION_SELECTION: 'section selection',
        SEL_CALL_FLAG_SECTION_REQUEST: 'section request',
        SEL_CALL_FLAG_SECTION_ABORT: 'section abort'
    }

    SEL_CALL_ERR_FLAG_UNUSED = 0
    SEL_CALL_ERR_FLAG_REQ_MEM_AREA_NO_AVAIL = 1
    SEL_CALL_ERR_FLAG_INVALID_CHECKSUM = 2
    SEL_CALL_ERR_FLAG_UNEXPECTED_COMMUNICATION_SERVICE = 3
    SEL_CALL_ERR_FLAG_UNEXPECTED_FILENAME = 4
    SEL_CALL_ERR_FLAG_UNEXPECTED_SECTION_NAME = 5
    SEL_CALL_ERR_FLAG_COMPATIBLE_RESERVED_6 = 6
    SEL_CALL_ERR_FLAG_COMPATIBLE_RESERVED_7 = 7
    SEL_CALL_ERR_FLAG_COMPATIBLE_RESERVED_8 = 8
    SEL_CALL_ERR_FLAG_COMPATIBLE_RESERVED_9 = 9
    SEL_CALL_ERR_FLAG_COMPATIBLE_RESERVED_10 = 10
    SEL_CALL_ERR_FLAG_PRIVATE_RESERVED_11 = 11
    SEL_CALL_ERR_FLAG_PRIVATE_RESERVED_12 = 12
    SEL_CALL_ERR_FLAG_PRIVATE_RESERVED_13 = 13
    SEL_CALL_ERR_FLAG_PRIVATE_RESERVED_14 = 14
    SEL_CALL_ERR_FLAG_PRIVATE_RESERVED_15 = 15

    SEL_CALL_ERR_FLAGS = {
        SEL_CALL_ERR_FLAG_UNUSED: 'unused',
        SEL_CALL_ERR_FLAG_REQ_MEM_AREA_NO_AVAIL: 'requested memory area '
                                                 'not available',
        SEL_CALL_ERR_FLAG_INVALID_CHECKSUM: 'invalid checksum',
        SEL_CALL_ERR_FLAG_UNEXPECTED_COMMUNICATION_SERVICE: 'unexpected '
                                                            'communication '
                                                            'service',
        SEL_CALL_ERR_FLAG_UNEXPECTED_FILENAME: 'unexpected file name',
        SEL_CALL_ERR_FLAG_UNEXPECTED_SECTION_NAME: 'unexpected section name'
    }

    GENERATED_ATTRIBUTES = [
        ('SEL_CALL_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         SEL_CALL_FLAGS, 8, 10),
        ('SEL_CALL_FLAG_PRIVATE_RESERVED', 'private reserved', SEL_CALL_FLAGS,
         11, 15),
        ('SEL_CALL_ERR_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         SEL_CALL_ERR_FLAGS, 6, 10),
        ('SEL_CALL_ERR_FLAG_PRIVATE_RESERVED', 'private reserved',
         SEL_CALL_ERR_FLAGS, 11, 15)
    ]

    informantion_element_fields = [
        BitEnumField('errors', 0, 4, SEL_CALL_ERR_FLAGS),
        BitEnumField('select_call', 0, 4, SEL_CALL_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_LSQ:
    """
    LSQ - last section or segment qualifier

    EN 60870-5-101:2003, sec. 7.2.6.31 (p. 55)
    """
    LSQ_FLAG_UNUSED = 0
    LSQ_FLAG_FILE_TRANSFER_NO_ABORT = 1
    LSQ_FLAG_FILE_TRANSFER_ABORT = 2
    LSQ_FLAG_SECTION_TRANSFER_NO_ABORT = 3
    LSQ_FLAG_SECTION_TRANSFER_ABORT = 4

    LSQ_FLAGS = {
        LSQ_FLAG_UNUSED: 'unused',
        LSQ_FLAG_FILE_TRANSFER_NO_ABORT: 'file transfer - no abort',
        LSQ_FLAG_FILE_TRANSFER_ABORT: 'file transfer - aborted',
        LSQ_FLAG_SECTION_TRANSFER_NO_ABORT: 'section transfer - no abort',
        LSQ_FLAG_SECTION_TRANSFER_ABORT: 'section transfer - aborted',
    }

    GENERATED_ATTRIBUTES = [
        ('LSQ_FLAG_COMPATIBLE_RESERVED', 'compatible reserved', LSQ_FLAGS, 5,
         127),
        ('LSQ_FLAG_PRIVATE_RESERVED', 'private reserved', LSQ_FLAGS, 128, 255),
    ]

    informantion_element_fields = [
        ByteEnumField('lsq', 0, LSQ_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_AFQ:
    """
    AFQ - acknowledge file or section qualifier

    EN 60870-5-101:2003, sec. 7.2.6.32 (p. 55)
    """
    ACK_FILE_OR_SEC_FLAG_UNUSED = 0
    ACK_FILE_OR_SEC_FLAG_POSITIVE_ACK_FILE_TRANSFER = 1
    ACK_FILE_OR_SEC_FLAG_NEGATIVE_ACK_FILE_TRANSFER = 2
    ACK_FILE_OR_SEC_FLAG_POSITIVE_ACK_SECTION_TRANSFER = 3
    ACK_FILE_OR_SEC_FLAG_NEGATIVE_ACK_SECTION_TRANSFER = 4

    ACK_FILE_OR_SEC_FLAGS = {
        ACK_FILE_OR_SEC_FLAG_UNUSED: 'unused',
        ACK_FILE_OR_SEC_FLAG_POSITIVE_ACK_FILE_TRANSFER: 'positive acknowledge'
                                                         ' file transfer',
        ACK_FILE_OR_SEC_FLAG_NEGATIVE_ACK_FILE_TRANSFER: 'negative acknowledge'
                                                         ' file transfer',
        ACK_FILE_OR_SEC_FLAG_POSITIVE_ACK_SECTION_TRANSFER: 'positive '
                                                            'acknowledge '
                                                            'section transfer',
        ACK_FILE_OR_SEC_FLAG_NEGATIVE_ACK_SECTION_TRANSFER: 'negative '
                                                            'acknowledge '
                                                            'section transfer'
    }

    ACK_FILE_OR_SEC_ERR_FLAG_UNUSED = 0
    ACK_FILE_OR_SEC_ERR_FLAG_REQ_MEM_AREA_NO_AVAIL = 1
    ACK_FILE_OR_SEC_ERR_FLAG_INVALID_CHECKSUM = 2
    ACK_FILE_OR_SEC_ERR_FLAG_UNEXPECTED_COMMUNICATION_SERVICE = 3
    ACK_FILE_OR_SEC_ERR_FLAG_UNEXPECTED_FILENAME = 4
    ACK_FILE_OR_SEC_ERR_FLAG_UNEXPECTED_SECTION_NAME = 5

    ACK_FILE_OR_SEC_ERR_FLAGS = {
        ACK_FILE_OR_SEC_ERR_FLAG_UNUSED: 'unused',
        ACK_FILE_OR_SEC_ERR_FLAG_REQ_MEM_AREA_NO_AVAIL: 'requested memory '
                                                        'area not available',
        ACK_FILE_OR_SEC_ERR_FLAG_INVALID_CHECKSUM: 'invalid checksum',
        ACK_FILE_OR_SEC_ERR_FLAG_UNEXPECTED_COMMUNICATION_SERVICE: 'unexpected'
                                                                   ' communica'
                                                                   'tion '
                                                                   'service',
        ACK_FILE_OR_SEC_ERR_FLAG_UNEXPECTED_FILENAME: 'unexpected file name',
        ACK_FILE_OR_SEC_ERR_FLAG_UNEXPECTED_SECTION_NAME: 'unexpected '
                                                          'section name'
    }

    GENERATED_ATTRIBUTES = [
        ('ACK_FILE_OR_SEC_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         ACK_FILE_OR_SEC_FLAGS, 5, 10),
        ('ACK_FILE_OR_SEC_FLAG_PRIVATE_RESERVED', 'private reserved',
         ACK_FILE_OR_SEC_FLAGS, 11, 15),

        ('ACK_FILE_OR_SEC_ERR_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         ACK_FILE_OR_SEC_ERR_FLAGS, 6, 10),
        ('ACK_FILE_OR_SEC_ERR_FLAG_PRIVATE_RESERVED', 'private reserved',
         ACK_FILE_OR_SEC_ERR_FLAGS, 11, 15)
    ]

    informantion_element_fields = [
        BitEnumField('errors', 0, 4, ACK_FILE_OR_SEC_ERR_FLAGS),
        BitEnumField('ack_file_or_sec', 0, 4, ACK_FILE_OR_SEC_FLAGS)
    ]


class IEC104_IE_NOF:
    """
    NOF - name of file

    EN 60870-5-101:2003, sec. 7.2.6.33 (p. 56)
    """
    informantion_element_fields = [
        LEShortField('file_name', 0)
    ]


class IEC104_IE_NOS:
    """
    NOS - name of section

    EN 60870-5-101:2003, sec. 7.2.6.34 (p. 56)
    """
    informantion_element_fields = [
        ByteField('section_name', 0)
    ]


class IEC104_IE_LOF:
    """
    LOF - length of file or section

    EN 60870-5-101:2003, sec. 7.2.6.35 (p. 55)
    """
    informantion_element_fields = [
        ThreeBytesField('file_length', 0)
    ]


class IEC104_IE_LOS:
    """
    LOS - length of segment

    EN 60870-5-101:2003, sec. 7.2.6.36 (p. 56)
    """
    informantion_element_fields = [
        ByteField('segment_length', 0)
    ]


class IEC104_IE_CHS:
    """
    CHS - checksum

    EN 60870-5-101:2003, sec. 7.2.6.37 (p. 56)
    """
    informantion_element_fields = [
        ByteField('checksum', 0)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_SOF:
    """
    SOF - status of file

    EN 60870-5-101:2003, sec. 7.2.6.38 (p. 56)
    """
    STATUS_FLAG_UNUSED = 0

    STATUS_FLAGS = {
        STATUS_FLAG_UNUSED: 'unused'
    }

    GENERATED_ATTRIBUTES = [
        ('STATUS_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         STATUS_FLAGS, 1, 15),
        ('STATUS_FLAG_PRIVATE_RESERVED', 'private reserved',
         STATUS_FLAGS, 16, 32)
    ]

    LFD_FLAG_NEXT_FILE_OF_DIR_FOLLOWS = 0
    LFD_FLAG_LAST_FILE_OF_DIR = 1
    LFD_FLAGS = {
        LFD_FLAG_NEXT_FILE_OF_DIR_FOLLOWS: 'next file of dir follows',
        LFD_FLAG_LAST_FILE_OF_DIR: 'last file of dir'
    }

    FOR_FLAG_NAME_DEFINES_FILE = 0
    FOR_FLAG_NAME_DEFINES_SUBDIR = 1
    FOR_FLAGS = {
        FOR_FLAG_NAME_DEFINES_FILE: 'name defines file',
        FOR_FLAG_NAME_DEFINES_SUBDIR: 'name defines subdirectory'
    }

    FA_FLAG_FILE_WAITS_FOR_TRANSFER = 0
    FA_FLAG_FILE_TRANSFER_IS_ACTIVE = 1
    FA_FLAGS = {
        FA_FLAG_FILE_WAITS_FOR_TRANSFER: 'file waits for transfer',
        FA_FLAG_FILE_TRANSFER_IS_ACTIVE: 'transfer of file active'
    }

    informantion_element_fields = [
        BitEnumField('fa', 0, 1, FA_FLAGS),
        BitEnumField('for_', 0, 1, FOR_FLAGS),
        BitEnumField('lfd', 0, 1, LFD_FLAGS),
        BitEnumField('status', 0, 5, STATUS_FLAGS)
    ]


@_generate_attributes_and_dicts
class IEC104_IE_QOS:
    """
    QOS - qualifier of set-point command

    EN 60870-5-101:2003, sec. 7.2.6.39 (p. 57)
    """
    QL_FLAG_UNUSED = 0

    QL_FLAGS = {
        QL_FLAG_UNUSED: 'unused'
    }

    GENERATED_ATTRIBUTES = [
        ('QL_FLAG_COMPATIBLE_RESERVED', 'compatible reserved',
         QL_FLAGS, 1, 63),
        ('QL_FLAG_PRIVATE_RESERVED', 'private reserved',
         QL_FLAGS, 64, 127)
    ]

    SE_FLAG_EXECUTE = 0
    SE_FLAG_SELECT = 1
    SE_FLAGS = {
        SE_FLAG_EXECUTE: 'execute',
        SE_FLAG_SELECT: 'select'
    }

    informantion_element_fields = [
        BitEnumField('action', 0, 1, SE_FLAGS),
        BitEnumField('ql', 0, 7, QL_FLAGS)
    ]


class IEC104_IE_SCD:
    """
    SCD - status and status change detection

    EN 60870-5-101:2003, sec. 7.2.6.40 (p. 57)
    """
    ST_FLAG_STATE_OFF = 0
    ST_FLAG_STATE_ON = 1
    ST_FLAGS = {
        ST_FLAG_STATE_OFF: 'off',
        ST_FLAG_STATE_ON: 'on'
    }

    CD_FLAG_STATE_NOT_CHANGED = 0
    CD_FLAG_STATE_CHANGED = 1
    CD_FLAGS = {
        CD_FLAG_STATE_NOT_CHANGED: 'state not changed',
        CD_FLAG_STATE_CHANGED: 'state changed'
    }

    informantion_element_fields = [
        BitEnumField('cd_16', 0, 1, CD_FLAGS),
        BitEnumField('cd_15', 0, 1, CD_FLAGS),
        BitEnumField('cd_14', 0, 1, CD_FLAGS),
        BitEnumField('cd_13', 0, 1, CD_FLAGS),
        BitEnumField('cd_12', 0, 1, CD_FLAGS),
        BitEnumField('cd_11', 0, 1, CD_FLAGS),
        BitEnumField('cd_10', 0, 1, CD_FLAGS),
        BitEnumField('cd_9', 0, 1, CD_FLAGS),
        BitEnumField('cd_8', 0, 1, CD_FLAGS),
        BitEnumField('cd_7', 0, 1, CD_FLAGS),
        BitEnumField('cd_6', 0, 1, CD_FLAGS),
        BitEnumField('cd_5', 0, 1, CD_FLAGS),
        BitEnumField('cd_4', 0, 1, CD_FLAGS),
        BitEnumField('cd_3', 0, 1, CD_FLAGS),
        BitEnumField('cd_2', 0, 1, CD_FLAGS),
        BitEnumField('cd_1', 0, 1, CD_FLAGS),
        BitEnumField('st_16', 0, 1, ST_FLAGS),
        BitEnumField('st_15', 0, 1, ST_FLAGS),
        BitEnumField('st_14', 0, 1, ST_FLAGS),
        BitEnumField('st_13', 0, 1, ST_FLAGS),
        BitEnumField('st_12', 0, 1, ST_FLAGS),
        BitEnumField('st_11', 0, 1, ST_FLAGS),
        BitEnumField('st_10', 0, 1, ST_FLAGS),
        BitEnumField('st_9', 0, 1, ST_FLAGS),
        BitEnumField('st_8', 0, 1, ST_FLAGS),
        BitEnumField('st_7', 0, 1, ST_FLAGS),
        BitEnumField('st_6', 0, 1, ST_FLAGS),
        BitEnumField('st_5', 0, 1, ST_FLAGS),
        BitEnumField('st_4', 0, 1, ST_FLAGS),
        BitEnumField('st_3', 0, 1, ST_FLAGS),
        BitEnumField('st_2', 0, 1, ST_FLAGS),
        BitEnumField('st_1', 0, 1, ST_FLAGS),
    ]


class IEC104_IE_TSC:
    """
    TSC - test sequence counter

    EN 60870-5-104:2006, sec. 8.8 (p. 44)
    """
    informantion_element_fields = [
        LEShortField('tsc', 0)
    ]
