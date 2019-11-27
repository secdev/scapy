# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Thomas Tannhaeuser <hecke@naberius.de>
# This program is published under a GPLv2 license
#
# scapy.contrib.description = IEC-60870-5-104 ASDU layers / IO definitions
# scapy.contrib.status = loads

"""
    application service data units used by  IEC 60870-5-101/104
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :description:

        This module provides the information object (IO) definitions used
        within the IEC 60870-5-101 and IEC 60870-5-104 protocol.

        normative references:
            - IEC 60870-5-101:2003 (sec. 7.3)
            - IEC 60870-5-104:2006 (sec. 8))


    :NOTES:
        - this file contains all IO definitions from 101 and 104 - even if an
          IO is not used within 104
"""
from scapy.config import conf
from scapy.contrib.scada.iec104.iec104_fields import LEThreeBytesField
from scapy.contrib.scada.iec104.iec104_information_elements import \
    IEC104_IE_SIQ, IEC104_IE_CP24TIME2A, IEC104_IE_DIQ, IEC104_IE_VTI, \
    IEC104_IE_QDS, IEC104_IE_BSI, IEC104_IE_NVA, IEC104_IE_SVA, \
    IEC104_IE_R32_IEEE_STD_754, IEC104_IE_BCR, IEC104_IE_CP16TIME2A_ELAPSED, \
    IEC104_IE_SEP, IEC104_IE_SPE, IEC104_IE_CP16TIME2A_PROTECTION_ACTIVE, \
    IEC104_IE_QDP, IEC104_IE_CP16TIME2A_PROTECTION_COMMAND, IEC104_IE_OCI, \
    IEC104_IE_SCD, IEC104_IE_CP56TIME2A, IEC104_IE_SCO, IEC104_IE_DCO, \
    IEC104_IE_RCO, IEC104_IE_QOS, IEC104_IE_QOI, IEC104_IE_QCC, \
    IEC104_IE_FBP, IEC104_IE_QRP, IEC104_IE_CP16TIME2A, IEC104_IE_QPM, \
    IEC104_IE_QPA, IEC104_IE_NOF, IEC104_IE_LOF, IEC104_IE_FRQ, \
    IEC104_IE_NOS, IEC104_IE_SRQ, IEC104_IE_SCQ, IEC104_IE_CHS, \
    IEC104_IE_LSQ, IEC104_IE_AFQ, IEC104_IE_SOF, IEC104_IE_COI, \
    IEC104_IE_CP56TIME2A_START_TIME, IEC104_IE_CP56TIME2A_STOP_TIME, \
    IEC104_IE_TSC

from scapy.fields import XStrLenField, BitFieldLenField
from scapy.packet import Packet

IEC104_IO_ID_UNDEFINED = 0x00
IEC104_IO_ID_M_SP_NA_1 = 0x01
IEC104_IO_ID_M_SP_TA_1 = 0x02
IEC104_IO_ID_M_DP_NA_1 = 0x03
IEC104_IO_ID_M_DP_TA_1 = 0x04
IEC104_IO_ID_M_ST_NA_1 = 0x05
IEC104_IO_ID_M_ST_TA_1 = 0x06
IEC104_IO_ID_M_BO_NA_1 = 0x07
IEC104_IO_ID_M_BO_TA_1 = 0x08
IEC104_IO_ID_M_ME_NA_1 = 0x09
IEC104_IO_ID_M_ME_TA_1 = 0x0a
IEC104_IO_ID_M_ME_NB_1 = 0x0b
IEC104_IO_ID_M_ME_TB_1 = 0x0c
IEC104_IO_ID_M_ME_NC_1 = 0x0d
IEC104_IO_ID_M_ME_TC_1 = 0x0e
IEC104_IO_ID_M_IT_NA_1 = 0x0f
IEC104_IO_ID_M_IT_TA_1 = 0x10
IEC104_IO_ID_M_EP_TA_1 = 0x11
IEC104_IO_ID_M_EP_TB_1 = 0x12
IEC104_IO_ID_M_EP_TC_1 = 0x13
IEC104_IO_ID_M_PS_NA_1 = 0x14
IEC104_IO_ID_M_ME_ND_1 = 0x15
IEC104_IO_ID_M_SP_TB_1 = 0x1e
IEC104_IO_ID_M_DP_TB_1 = 0x1f
IEC104_IO_ID_M_ST_TB_1 = 0x20
IEC104_IO_ID_M_BO_TB_1 = 0x21
IEC104_IO_ID_M_ME_TD_1 = 0x22
IEC104_IO_ID_M_ME_TE_1 = 0x23
IEC104_IO_ID_M_ME_TF_1 = 0x24
IEC104_IO_ID_M_IT_TB_1 = 0x25
IEC104_IO_ID_M_EP_TD_1 = 0x26
IEC104_IO_ID_M_EP_TE_1 = 0x27
IEC104_IO_ID_M_EP_TF_1 = 0x28
IEC104_IO_ID_C_SC_NA_1 = 0x2d
IEC104_IO_ID_C_DC_NA_1 = 0x2e
IEC104_IO_ID_C_RC_NA_1 = 0x2f
IEC104_IO_ID_C_SE_NA_1 = 0x30
IEC104_IO_ID_C_SE_NB_1 = 0x31
IEC104_IO_ID_C_SE_NC_1 = 0x32
IEC104_IO_ID_C_BO_NA_1 = 0x33
IEC104_IO_ID_M_EI_NA_1 = 0x46
IEC104_IO_ID_C_IC_NA_1 = 0x64
IEC104_IO_ID_C_CI_NA_1 = 0x65
IEC104_IO_ID_C_RD_NA_1 = 0x66
IEC104_IO_ID_C_CS_NA_1 = 0x67
IEC104_IO_ID_C_TS_NA_1 = 0x68
IEC104_IO_ID_C_RP_NA_1 = 0x69
IEC104_IO_ID_C_CD_NA_1 = 0x6a
IEC104_IO_ID_P_ME_NA_1 = 0x6e
IEC104_IO_ID_P_ME_NB_1 = 0x6f
IEC104_IO_ID_P_ME_NC_1 = 0x70
IEC104_IO_ID_P_AC_NA_1 = 0x71
IEC104_IO_ID_F_FR_NA_1 = 0x78
IEC104_IO_ID_F_SR_NA_1 = 0x79
IEC104_IO_ID_F_SC_NA_1 = 0x7a
IEC104_IO_ID_F_LS_NA_1 = 0x7b
IEC104_IO_ID_F_AF_NA_1 = 0x7c
IEC104_IO_ID_F_SG_NA_1 = 0x7d
IEC104_IO_ID_F_DR_TA_1 = 0x7e
# specific IOs from 60870-5-104:2006, sec. 8 (p. 37 ff)
IEC104_IO_ID_C_SC_TA_1 = 0x3a
IEC104_IO_ID_C_DC_TA_1 = 0x3b
IEC104_IO_ID_C_RC_TA_1 = 0x3c
IEC104_IO_ID_C_SE_TA_1 = 0x3d
IEC104_IO_ID_C_SE_TB_1 = 0x3e
IEC104_IO_ID_C_SE_TC_1 = 0x3f
IEC104_IO_ID_C_BO_TA_1 = 0x40
IEC104_IO_ID_C_TS_TA_1 = 0x6b
IEC104_IO_ID_F_SC_NB_1 = 0x7f


def _dict_add_reserved_range(d, start, end):
    for idx in range(start, end + 1):
        d[idx] = 'reserved_{}'.format(idx)


IEC104_IO_DESCRIPTIONS = {
    0: 'undefined',
    IEC104_IO_ID_M_SP_NA_1: 'M_SP_NA_1 (single point report)',
    IEC104_IO_ID_M_SP_TA_1: 'M_SP_TA_1 (single point report with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_DP_NA_1: 'M_DP_NA_1 (double point report)',
    IEC104_IO_ID_M_DP_TA_1: 'M_DP_TA_1 (double point report with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_ST_NA_1: 'M_ST_NA_1 (step control report)',
    IEC104_IO_ID_M_ST_TA_1: 'M_ST_TA_1 (step control report with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_BO_NA_1: 'M_BO_NA_1 (bitmask 32 bit)',
    IEC104_IO_ID_M_BO_TA_1: 'M_BO_TA_1 (bitmask 32 bit with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_ME_NA_1: 'M_ME_NA_1 (meas, normed value)',
    IEC104_IO_ID_M_ME_TA_1: 'M_ME_TA_1 (meas, normed value with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_ME_NB_1: 'M_ME_NB_1 (meas, scaled value)',
    IEC104_IO_ID_M_ME_TB_1: 'M_ME_TB_1 (meas, scaled value with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_ME_NC_1: 'M_ME_NC_1 (meas, shortened floating point value)',
    IEC104_IO_ID_M_ME_TC_1: 'M_ME_TC_1 (meas, shortened floating point value '
                            'with timestamp) # 60870-4-101 only',
    IEC104_IO_ID_M_IT_NA_1: 'M_IT_NA_1 (counter value)',
    IEC104_IO_ID_M_IT_TA_1: 'M_IT_TA_1 (counter value with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_EP_TA_1: 'M_EP_TA_1 (protection event  with timestamp) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_M_EP_TB_1: 'M_EP_TB_1 (blocked protection trigger with '
                            'timestamp) # 60870-4-101 only',
    IEC104_IO_ID_M_EP_TC_1: 'M_EP_TC_1 (blocked protection action with '
                            'timestamp) # 60870-4-101 only',
    IEC104_IO_ID_M_PS_NA_1: 'M_PS_NA_1 (blocked single report with '
                            'change indication)',
    IEC104_IO_ID_M_ME_ND_1: 'M_ME_ND_1 (meas, normed value, no quality '
                            'indication)',
    IEC104_IO_ID_M_SP_TB_1: 'M_SP_TB_1 (single point report with CP56Time2a '
                            'time field)',
    IEC104_IO_ID_M_DP_TB_1: 'M_DP_TB_1 (double point report with CP56Time2a '
                            'time field)',
    IEC104_IO_ID_M_ST_TB_1: 'M_ST_TB_1 (step control report with CP56Time2a '
                            'time field)',
    IEC104_IO_ID_M_BO_TB_1: 'M_BO_TB_1 (bitmask 32 bit with CP56Time2a time '
                            'field)',
    IEC104_IO_ID_M_ME_TD_1: 'M_ME_TD_1 (meas, normed value with CP56Time2a '
                            'time field)',
    IEC104_IO_ID_M_ME_TE_1: 'M_ME_TE_1 (meas, scaled value with CP56Time2a '
                            'time field)',
    IEC104_IO_ID_M_ME_TF_1: 'M_ME_TF_1 (meas, shortened floating point value '
                            'with CP56Time2a time field)',
    IEC104_IO_ID_M_IT_TB_1: 'M_IT_TB_1 (counter with CP56Time2a time field)',
    IEC104_IO_ID_M_EP_TD_1: 'M_EP_TD_1 (protection event with CP56Time2a '
                            'time field)',
    IEC104_IO_ID_M_EP_TE_1: 'M_EP_TE_1 (blocked protection trigger with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_M_EP_TF_1: 'M_EP_TF_1 (blocked protection action with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_C_SC_NA_1: 'C_SC_NA_1 (single command)',
    IEC104_IO_ID_C_DC_NA_1: 'C_DC_NA_1 (double command)',
    IEC104_IO_ID_C_RC_NA_1: 'C_RC_NA_1 (step control command)',
    IEC104_IO_ID_C_SE_NA_1: 'C_SE_NA_1 (setpoint control command, '
                            'normed value)',
    IEC104_IO_ID_C_SE_NB_1: 'C_SE_NB_1 (setpoint control command, '
                            'scaled value)',
    IEC104_IO_ID_C_SE_NC_1: 'C_SE_NC_1 (setpoint control command, '
                            'shortened floating point value)',
    IEC104_IO_ID_C_BO_NA_1: 'C_BO_NA_1 (bitmask 32 bit)',
    IEC104_IO_ID_C_SC_TA_1: 'C_SC_TA_1 (single point command with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_C_DC_TA_1: 'C_DC_TA_1 (double point command with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_C_RC_TA_1: 'C_RC_TA_1 (step control command with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_C_SE_TA_1: 'C_SE_TA_1 (setpoint command, normed value with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_C_SE_TB_1: 'C_SE_TB_1 (setpoint command, scaled value with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_C_SE_TC_1: 'C_SE_TC_1 (setpoint command, shortened floating '
                            'point value with CP56Time2a time field)',
    IEC104_IO_ID_C_BO_TA_1: 'C_BO_TA_1 (bitmask 32 command bit with '
                            'CP56Time2a time field)',
    IEC104_IO_ID_M_EI_NA_1: 'M_EI_NA_1 (init done)',
    IEC104_IO_ID_C_IC_NA_1: 'C_IC_NA_1 (general interrogation command)',
    IEC104_IO_ID_C_CI_NA_1: 'C_CI_NA_1 (counter interrogation command)',
    IEC104_IO_ID_C_RD_NA_1: 'C_RD_NA_1 (interrogation)',
    IEC104_IO_ID_C_CS_NA_1: 'C_CS_NA_1 (time synchronisation command)',
    IEC104_IO_ID_C_TS_NA_1: 'C_TS_NA_1 (test command) # 60870-4-101 only',
    IEC104_IO_ID_C_RP_NA_1: 'C_RP_NA_1 (process reset command)',
    IEC104_IO_ID_C_CD_NA_1: 'C_CD_NA_1 (meas telegram transit time command) '
                            '# 60870-4-101 only',
    IEC104_IO_ID_C_TS_TA_1: 'C_TS_TA_1 (test command with CP56Time2a '
                            'time field)',
    IEC104_IO_ID_P_ME_NA_1: 'P_ME_NA_1 (meas parameter, normed value)',
    IEC104_IO_ID_P_ME_NB_1: 'P_ME_NB_1 (meas parameter, scaled value)',
    IEC104_IO_ID_P_ME_NC_1: 'P_ME_NC_1 (meas parameter, shortened floating '
                            'point value)',
    IEC104_IO_ID_P_AC_NA_1: 'P_AC_NA_1 (parameter for activation)',
    IEC104_IO_ID_F_FR_NA_1: 'F_FR_NA_1 (file ready)',
    IEC104_IO_ID_F_SR_NA_1: 'F_SR_NA_1 (section ready)',
    IEC104_IO_ID_F_SC_NA_1: 'F_SC_NA_1 (query directory, selection, section)',
    IEC104_IO_ID_F_LS_NA_1: 'F_LS_NA_1 (last part/segment)',
    IEC104_IO_ID_F_AF_NA_1: 'F_AF_NA_1 (file/section acknowledgement)',
    IEC104_IO_ID_F_SG_NA_1: 'F_SG_NA_1 (segment)',
    IEC104_IO_ID_F_DR_TA_1: 'F_DR_TA_1 (directory)',
    IEC104_IO_ID_F_SC_NB_1: 'F_SC_NB_1 (query log - request archive file)'
}
_dict_add_reserved_range(IEC104_IO_DESCRIPTIONS, 22, 29)
_dict_add_reserved_range(IEC104_IO_DESCRIPTIONS, 41, 44)
_dict_add_reserved_range(IEC104_IO_DESCRIPTIONS, 52, 57)
_dict_add_reserved_range(IEC104_IO_DESCRIPTIONS, 65, 69)
_dict_add_reserved_range(IEC104_IO_DESCRIPTIONS, 71, 99)
_dict_add_reserved_range(IEC104_IO_DESCRIPTIONS, 108, 109)
_dict_add_reserved_range(IEC104_IO_DESCRIPTIONS, 114, 119)

IEC104_IO_NAMES = {
    0: 'undefined',
    IEC104_IO_ID_M_SP_NA_1: 'M_SP_NA_1',
    IEC104_IO_ID_M_SP_TA_1: 'M_SP_TA_1',
    IEC104_IO_ID_M_DP_NA_1: 'M_DP_NA_1',
    IEC104_IO_ID_M_DP_TA_1: 'M_DP_TA_1',
    IEC104_IO_ID_M_ST_NA_1: 'M_ST_NA_1',
    IEC104_IO_ID_M_ST_TA_1: 'M_ST_TA_1',
    IEC104_IO_ID_M_BO_NA_1: 'M_BO_NA_1',
    IEC104_IO_ID_M_BO_TA_1: 'M_BO_TA_1',
    IEC104_IO_ID_M_ME_NA_1: 'M_ME_NA_1',
    IEC104_IO_ID_M_ME_TA_1: 'M_ME_TA_1',
    IEC104_IO_ID_M_ME_NB_1: 'M_ME_NB_1',
    IEC104_IO_ID_M_ME_TB_1: 'M_ME_TB_1',
    IEC104_IO_ID_M_ME_NC_1: 'M_ME_NC_1',
    IEC104_IO_ID_M_ME_TC_1: 'M_ME_TC_1',
    IEC104_IO_ID_M_IT_NA_1: 'M_IT_NA_1',
    IEC104_IO_ID_M_IT_TA_1: 'M_IT_TA_1',
    IEC104_IO_ID_M_EP_TA_1: 'M_EP_TA_1',
    IEC104_IO_ID_M_EP_TB_1: 'M_EP_TB_1',
    IEC104_IO_ID_M_EP_TC_1: 'M_EP_TC_1',
    IEC104_IO_ID_M_PS_NA_1: 'M_PS_NA_1',
    IEC104_IO_ID_M_ME_ND_1: 'M_ME_ND_1',
    IEC104_IO_ID_M_SP_TB_1: 'M_SP_TB_1',
    IEC104_IO_ID_M_DP_TB_1: 'M_DP_TB_1',
    IEC104_IO_ID_M_ST_TB_1: 'M_ST_TB_1',
    IEC104_IO_ID_M_BO_TB_1: 'M_BO_TB_1',
    IEC104_IO_ID_M_ME_TD_1: 'M_ME_TD_1',
    IEC104_IO_ID_M_ME_TE_1: 'M_ME_TE_1',
    IEC104_IO_ID_M_ME_TF_1: 'M_ME_TF_1',
    IEC104_IO_ID_M_IT_TB_1: 'M_IT_TB_1',
    IEC104_IO_ID_M_EP_TD_1: 'M_EP_TD_1',
    IEC104_IO_ID_M_EP_TE_1: 'M_EP_TE_1',
    IEC104_IO_ID_M_EP_TF_1: 'M_EP_TF_1',
    IEC104_IO_ID_C_SC_NA_1: 'C_SC_NA_1',
    IEC104_IO_ID_C_DC_NA_1: 'C_DC_NA_1',
    IEC104_IO_ID_C_RC_NA_1: 'C_RC_NA_1',
    IEC104_IO_ID_C_SE_NA_1: 'C_SE_NA_1',
    IEC104_IO_ID_C_SE_NB_1: 'C_SE_NB_1',
    IEC104_IO_ID_C_SE_NC_1: 'C_SE_NC_1',
    IEC104_IO_ID_C_BO_NA_1: 'C_BO_NA_1',
    IEC104_IO_ID_C_SC_TA_1: 'C_SC_TA_1',
    IEC104_IO_ID_C_DC_TA_1: 'C_DC_TA_1',
    IEC104_IO_ID_C_RC_TA_1: 'C_RC_TA_1',
    IEC104_IO_ID_C_SE_TA_1: 'C_SE_TA_1',
    IEC104_IO_ID_C_SE_TB_1: 'C_SE_TB_1',
    IEC104_IO_ID_C_SE_TC_1: 'C_SE_TC_1',
    IEC104_IO_ID_C_BO_TA_1: 'C_BO_TA_1',
    IEC104_IO_ID_M_EI_NA_1: 'M_EI_NA_1',
    IEC104_IO_ID_C_IC_NA_1: 'C_IC_NA_1',
    IEC104_IO_ID_C_CI_NA_1: 'C_CI_NA_1',
    IEC104_IO_ID_C_RD_NA_1: 'C_RD_NA_1',
    IEC104_IO_ID_C_CS_NA_1: 'C_CS_NA_1',
    IEC104_IO_ID_C_TS_NA_1: 'C_TS_NA_1',
    IEC104_IO_ID_C_RP_NA_1: 'C_RP_NA_1',
    IEC104_IO_ID_C_CD_NA_1: 'C_CD_NA_1',
    IEC104_IO_ID_C_TS_TA_1: 'C_TS_TA_1',
    IEC104_IO_ID_P_ME_NA_1: 'P_ME_NA_1',
    IEC104_IO_ID_P_ME_NB_1: 'P_ME_NB_1',
    IEC104_IO_ID_P_ME_NC_1: 'P_ME_NC_1',
    IEC104_IO_ID_P_AC_NA_1: 'P_AC_NA_1',
    IEC104_IO_ID_F_FR_NA_1: 'F_FR_NA_1',
    IEC104_IO_ID_F_SR_NA_1: 'F_SR_NA_1',
    IEC104_IO_ID_F_SC_NA_1: 'F_SC_NA_1',
    IEC104_IO_ID_F_LS_NA_1: 'F_LS_NA_1',
    IEC104_IO_ID_F_AF_NA_1: 'F_AF_NA_1',
    IEC104_IO_ID_F_SG_NA_1: 'F_SG_NA_1',
    IEC104_IO_ID_F_DR_TA_1: 'F_DR_TA_1',
    IEC104_IO_ID_F_SC_NB_1: 'F_SC_NB_1'
}
_dict_add_reserved_range(IEC104_IO_NAMES, 22, 29)
_dict_add_reserved_range(IEC104_IO_NAMES, 41, 44)
_dict_add_reserved_range(IEC104_IO_NAMES, 52, 57)
_dict_add_reserved_range(IEC104_IO_NAMES, 65, 69)
_dict_add_reserved_range(IEC104_IO_NAMES, 71, 99)
_dict_add_reserved_range(IEC104_IO_NAMES, 108, 109)
_dict_add_reserved_range(IEC104_IO_NAMES, 114, 119)


class IEC104_IO_InvalidPayloadException(Exception):
    """
    raised if payload is not of the same type, raw() or a child of IEC104_APDU
    """
    pass


class IEC104_IO_Packet(Packet):
    """
    base class of all information object representations
    """
    DEFINED_IN_IEC_101 = 0x01
    DEFINED_IN_IEC_104 = 0x02

    _DEFINED_IN = []

    def guess_payload_class(self, payload):
        return conf.padding_layer

    _IEC104_IO_TYPE_ID = IEC104_IO_ID_UNDEFINED

    def iec104_io_type_id(self):
        """
        get individual type id of the information object instance

        :return: information object type id (IEC104_IO_ID_*)
        """
        return self._IEC104_IO_TYPE_ID

    def defined_for_iec_101(self):
        """
        information object ASDU allowed for IEC 60870-5-101

        :return: True if the information object is defined within
                 IEC 60870-5-101, else False
        """
        return IEC104_IO_Packet.DEFINED_IN_IEC_101 in self._DEFINED_IN

    def defined_for_iec_104(self):
        """
        information object ASDU allowed for IEC 60870-5-104

        :return: True if the information object is defined within
                 IEC 60870-5-104, else False
        """
        return IEC104_IO_Packet.DEFINED_IN_IEC_104 in self._DEFINED_IN


class IEC104_IO_M_SP_NA_1(IEC104_IO_Packet):
    """
    single-point information without time tag]

    EN 60870-5-101:2003, sec. 7.3.1.1 (p. 58)
    """
    name = 'M_SP_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_SP_NA_1

    fields_desc = IEC104_IE_SIQ.informantion_element_fields


class IEC104_IO_M_SP_TA_1(IEC104_IO_Packet):
    """
    single-point information with time tag

    EN 60870-5-101:2003, sec. 7.3.1.2 (p. 59)
    """
    name = 'M_SP_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_SP_TA_1

    fields_desc = IEC104_IE_SIQ.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_DP_NA_1(IEC104_IO_Packet):
    """
    double-point information without time tag

    EN 60870-5-101:2003, sec. 7.3.1.3 (p. 60)
    """
    name = 'M_DP_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_DP_NA_1

    fields_desc = IEC104_IE_DIQ.informantion_element_fields


class IEC104_IO_M_DP_TA_1(IEC104_IO_Packet):
    """
    double-point information with time tag

    EN 60870-5-101:2003, sec. 7.3.1.4 (p. 61)
    """
    name = 'M_DP_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_DP_TA_1

    fields_desc = IEC104_IE_DIQ.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_ST_NA_1(IEC104_IO_Packet):
    """
    step position information

    EN 60870-5-101:2003, sec. 7.3.1.5 (p. 62)
    """
    name = 'M_ST_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ST_NA_1

    fields_desc = IEC104_IE_VTI.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields


class IEC104_IO_M_ST_TA_1(IEC104_IO_Packet):
    """
    step position information with time tag

    EN 60870-5-101:2003, sec. 7.3.1.6 (p. 63)
    """
    name = 'M_ST_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ST_TA_1

    fields_desc = IEC104_IE_VTI.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_BO_NA_1(IEC104_IO_Packet):
    """
    bitstring of 32 bit

    EN 60870-5-101:2003, sec. 7.3.1.7 (p. 64)
    """
    name = 'M_BO_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_BO_NA_1

    fields_desc = IEC104_IE_BSI.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields


class IEC104_IO_M_BO_TA_1(IEC104_IO_Packet):
    """
    bitstring of 32 bit with time tag

    EN 60870-5-101:2003, sec. 7.3.1.8 (p. 66)
    """
    name = 'M_BO_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_BO_TA_1

    fields_desc = IEC104_IE_BSI.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_ME_NA_1(IEC104_IO_Packet):
    """
    measured value, normalized value

    EN 60870-5-101:2003, sec. 7.3.1.9 (p. 67)
    """
    name = 'M_ME_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_NA_1

    fields_desc = IEC104_IE_NVA.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields


class IEC104_IO_M_ME_TA_1(IEC104_IO_Packet):
    """
    measured value, normalized value with time tag

    EN 60870-5-101:2003, sec. 7.3.1.10 (p. 68)
    """
    name = 'M_ME_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_TA_1

    fields_desc = IEC104_IE_NVA.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_ME_NB_1(IEC104_IO_Packet):
    """
    measured value, scaled value

    EN 60870-5-101:2003, sec. 7.3.1.11 (p. 69)
    """
    name = 'M_ME_NB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_NB_1

    fields_desc = IEC104_IE_SVA.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields


class IEC104_IO_M_ME_TB_1(IEC104_IO_Packet):
    """
    measured value, scaled value with time tag

    EN 60870-5-101:2003, sec. 7.3.1.12 (p. 71)
    """
    name = 'M_ME_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_TB_1

    fields_desc = IEC104_IE_SVA.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_ME_NC_1(IEC104_IO_Packet):
    """
    measured value, short floating point number

    EN 60870-5-101:2003, sec. 7.3.1.13 (p. 72)
    """
    name = 'M_ME_NC_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_NC_1

    fields_desc = IEC104_IE_R32_IEEE_STD_754.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields


class IEC104_IO_M_ME_TC_1(IEC104_IO_Packet):
    """
    measured value, short floating point number with time tag

    EN 60870-5-101:2003, sec. 7.3.1.14 (p. 74)
    """
    name = 'M_ME_TC_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_TC_1

    fields_desc = IEC104_IE_R32_IEEE_STD_754.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_IT_NA_1(IEC104_IO_Packet):
    """
    integrated totals

    EN 60870-5-101:2003, sec. 7.3.1.15 (p. 75)
    """
    name = 'M_IT_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_IT_NA_1

    fields_desc = IEC104_IE_BCR.informantion_element_fields


class IEC104_IO_M_IT_TA_1(IEC104_IO_Packet):
    """
    integrated totals with time tag

    EN 60870-5-101:2003, sec. 7.3.1.16 (p. 77)
    """
    name = 'M_IT_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_IT_TA_1

    fields_desc = IEC104_IE_BCR.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_EP_TA_1(IEC104_IO_Packet):
    """
    event of protection equipment with time tag

    EN 60870-5-101:2003, sec. 7.3.1.17 (p. 78)
    """
    name = 'M_EP_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_EP_TA_1

    fields_desc = IEC104_IE_SEP.informantion_element_fields + \
        IEC104_IE_CP16TIME2A_ELAPSED.informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_EP_TB_1(IEC104_IO_Packet):
    """
    packed start events of protection equipment with time tag

    EN 60870-5-101:2003, sec. 7.3.1.18 (p. 79)
    """
    name = 'M_EP_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_EP_TB_1

    fields_desc = IEC104_IE_SPE.informantion_element_fields + \
        IEC104_IE_QDP.informantion_element_fields + \
        IEC104_IE_CP16TIME2A_PROTECTION_ACTIVE.\
        informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_EP_TC_1(IEC104_IO_Packet):
    """
    packed output circuit information of protection equipment with time tag

    EN 60870-5-101:2003, sec. 7.3.1.19 (p. 80)
    """
    name = 'M_EP_TC_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_EP_TC_1

    fields_desc = IEC104_IE_OCI.informantion_element_fields + \
        IEC104_IE_QDP.informantion_element_fields + \
        IEC104_IE_CP16TIME2A_PROTECTION_COMMAND.\
        informantion_element_fields + \
        IEC104_IE_CP24TIME2A.informantion_element_fields


class IEC104_IO_M_PS_NA_1(IEC104_IO_Packet):
    """
    packed single-point information with status change detection

    EN 60870-5-101:2003, sec. 7.3.1.20 (p. 81)
    """
    name = 'M_PS_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_PS_NA_1

    fields_desc = IEC104_IE_SCD.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields


class IEC104_IO_M_ME_ND_1(IEC104_IO_Packet):
    """
    measured value, normalized value without quality descriptor

    EN 60870-5-101:2003, sec. 7.3.1.21 (p. 83)
    """
    name = 'M_ME_ND_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_ND_1

    fields_desc = IEC104_IE_NVA.informantion_element_fields


class IEC104_IO_M_SP_TB_1(IEC104_IO_Packet):
    """
    single-point information with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.22 (p. 84)
    """
    name = 'M_SP_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_SP_TB_1

    fields_desc = IEC104_IE_SIQ.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_DP_TB_1(IEC104_IO_Packet):
    """
    double-point information with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.23 (p. 85)
    """
    name = 'M_DP_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_DP_TB_1

    fields_desc = IEC104_IE_DIQ.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_ST_TB_1(IEC104_IO_Packet):
    """
    step position information with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.24 (p. 87)
    """
    name = 'M_ST_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ST_TB_1

    fields_desc = IEC104_IE_VTI.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_BO_TB_1(IEC104_IO_Packet):
    """
    bitstring of 32 bits with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.25 (p. 89)
    """
    name = 'M_BO_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_BO_TB_1

    fields_desc = IEC104_IE_BSI.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_ME_TD_1(IEC104_IO_Packet):
    """
    measured value, normalized value with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.26 (p. 91)
    """
    name = 'M_ME_TD_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_TD_1

    fields_desc = IEC104_IE_NVA.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_ME_TE_1(IEC104_IO_Packet):
    """
    measured value, scaled value with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.27 (p. 93)
    """
    name = 'M_ME_TE_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_TE_1

    fields_desc = IEC104_IE_SVA.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_ME_TF_1(IEC104_IO_Packet):
    """
    measured value, short floating point number with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.28 (p. 95)
    """
    name = 'M_ME_TF_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_ME_TF_1

    fields_desc = IEC104_IE_R32_IEEE_STD_754.informantion_element_fields + \
        IEC104_IE_QDS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_IT_TB_1(IEC104_IO_Packet):
    """
    integrated totals with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.29 (p. 97)
    """
    name = 'M_IT_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_IT_TB_1

    fields_desc = IEC104_IE_BCR.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_EP_TD_1(IEC104_IO_Packet):
    """
    event of protection equipment with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.30 (p. 99)
    """
    name = 'M_EP_TD_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_EP_TD_1

    fields_desc = IEC104_IE_SEP.informantion_element_fields + \
        IEC104_IE_CP16TIME2A_ELAPSED.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_EP_TE_1(IEC104_IO_Packet):
    """
    packed start events of protection equipment with time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.31 (p. 100)
    """
    name = 'M_EP_TE_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_EP_TE_1

    fields_desc = IEC104_IE_SPE.informantion_element_fields + \
        IEC104_IE_QDP.informantion_element_fields + \
        IEC104_IE_CP16TIME2A_PROTECTION_ACTIVE.\
        informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_M_EP_TF_1(IEC104_IO_Packet):
    """
    packed output circuit information of protection equipment with
    time tag cp56time2a

    EN 60870-5-101:2003, sec. 7.3.1.32 (p. 101)
    """
    name = 'M_EP_TF_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_EP_TF_1

    fields_desc = IEC104_IE_OCI.informantion_element_fields + \
        IEC104_IE_QDP.informantion_element_fields + \
        IEC104_IE_CP16TIME2A_PROTECTION_COMMAND.\
        informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_SC_NA_1(IEC104_IO_Packet):
    """
    single command

    EN 60870-5-101:2003, sec. 7.3.2.1 (p. 102)
    """
    name = 'C_SC_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SC_NA_1

    fields_desc = IEC104_IE_SCO.informantion_element_fields


class IEC104_IO_C_DC_NA_1(IEC104_IO_Packet):
    """
    double command

    EN 60870-5-101:2003, sec. 7.3.2.2 (p. 102)
    """
    name = 'C_DC_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_DC_NA_1

    fields_desc = IEC104_IE_DCO.informantion_element_fields


class IEC104_IO_C_RC_NA_1(IEC104_IO_Packet):
    """
    regulating step command

    EN 60870-5-101:2003, sec. 7.3.2.3 (p. 103)
    """
    name = 'C_RC_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_RC_NA_1

    fields_desc = IEC104_IE_RCO.informantion_element_fields


class IEC104_IO_C_SE_NA_1(IEC104_IO_Packet):
    """
    set-point command, normalized value

    EN 60870-5-101:2003, sec. 7.3.2.4 (p. 104)
    """
    name = 'C_SE_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SE_NA_1

    fields_desc = IEC104_IE_NVA.informantion_element_fields + \
        IEC104_IE_QOS.informantion_element_fields


class IEC104_IO_C_SE_NB_1(IEC104_IO_Packet):
    """
    set-point command, scaled value

    EN 60870-5-101:2003, sec. 7.3.2.5 (p. 104)
    """
    name = 'C_SE_NB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SE_NB_1

    fields_desc = IEC104_IE_SVA.informantion_element_fields + \
        IEC104_IE_QOS.informantion_element_fields


class IEC104_IO_C_SE_NC_1(IEC104_IO_Packet):
    """
    set-point command, short floating point number

    EN 60870-5-101:2003, sec. 7.3.2.6 (p. 105)
    """
    name = 'C_SE_NC_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SE_NC_1

    fields_desc = IEC104_IE_R32_IEEE_STD_754.informantion_element_fields + \
        IEC104_IE_QOS.informantion_element_fields


class IEC104_IO_C_BO_NA_1(IEC104_IO_Packet):
    """
    bitstring of 32 bit

    EN 60870-5-101:2003, sec. 7.3.2.7 (p. 106)
    """
    name = 'C_BO_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_BO_NA_1

    fields_desc = IEC104_IE_BSI.informantion_element_fields


class IEC104_IO_M_EI_NA_1(IEC104_IO_Packet):
    """
    end of initialization

    EN 60870-5-101:2003, sec. 7.3.3.1 (p. 106)
    """
    name = 'M_EI_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_M_EI_NA_1

    fields_desc = IEC104_IE_COI.informantion_element_fields


class IEC104_IO_C_IC_NA_1(IEC104_IO_Packet):
    """
    interrogation command

    EN 60870-5-101:2003, sec. 7.3.4.1 (p. 107)
    """
    name = 'C_IC_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_IC_NA_1

    fields_desc = IEC104_IE_QOI.informantion_element_fields


class IEC104_IO_C_CI_NA_1(IEC104_IO_Packet):
    """
    counter interrogation command

    EN 60870-5-101:2003, sec. 7.3.4.2 (p. 108)
    """
    name = 'C_CI_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_CI_NA_1

    fields_desc = IEC104_IE_QCC.informantion_element_fields


class IEC104_IO_C_RD_NA_1(IEC104_IO_Packet):
    """
    read command

    EN 60870-5-101:2003, sec. 7.3.4.3 (p. 108)
    """
    name = 'C_RD_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_RD_NA_1

    # this information object contains no data
    fields_desc = []


class IEC104_IO_C_CS_NA_1(IEC104_IO_Packet):
    """
    clock synchronization command

    EN 60870-5-101:2003, sec. 7.3.4.4 (p. 109)
    """
    name = 'C_CS_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_CS_NA_1

    fields_desc = IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_TS_NA_1(IEC104_IO_Packet):
    """
    test command

    EN 60870-5-101:2003, sec. 7.3.4.5 (p. 110)
    """
    name = 'C_TS_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_TS_NA_1

    fields_desc = IEC104_IE_FBP.informantion_element_fields


class IEC104_IO_C_RP_NA_1(IEC104_IO_Packet):
    """
    reset process command

    EN 60870-5-101:2003, sec. 7.3.4.6 (p. 110)
    """
    name = 'C_RP_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_RP_NA_1

    fields_desc = IEC104_IE_QRP.informantion_element_fields


class IEC104_IO_C_CD_NA_1(IEC104_IO_Packet):
    """
    (telegram) delay acquisition command

    EN 60870-5-101:2003, sec. 7.3.4.7 (p. 111)
    """
    name = 'C_CD_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_CD_NA_1

    fields_desc = IEC104_IE_CP16TIME2A.informantion_element_fields


class IEC104_IO_P_ME_NA_1(IEC104_IO_Packet):
    """
    parameter of measured values, normalized value

    EN 60870-5-101:2003, sec. 7.3.5.1 (p. 112)
    """
    name = 'P_ME_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_P_ME_NA_1

    fields_desc = IEC104_IE_NVA.informantion_element_fields + \
        IEC104_IE_QPM.informantion_element_fields


class IEC104_IO_P_ME_NB_1(IEC104_IO_Packet):
    """
    parameter of measured values, scaled value

    EN 60870-5-101:2003, sec. 7.3.5.2 (p. 113)
    """
    name = 'P_ME_NB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_P_ME_NB_1

    fields_desc = IEC104_IE_SVA.informantion_element_fields + \
        IEC104_IE_QPM.informantion_element_fields


class IEC104_IO_P_ME_NC_1(IEC104_IO_Packet):
    """
    parameter of measured values, short floating point number

    EN 60870-5-101:2003, sec. 7.3.5.3 (p. 114)
    """
    name = 'P_ME_NC_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_P_ME_NC_1

    fields_desc = IEC104_IE_R32_IEEE_STD_754.informantion_element_fields + \
        IEC104_IE_QPM.informantion_element_fields


class IEC104_IO_P_AC_NA_1(IEC104_IO_Packet):
    """
    parameter activation

    EN 60870-5-101:2003, sec. 7.3.5.4 (p. 115)
    """
    name = 'P_AC_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_P_AC_NA_1

    fields_desc = IEC104_IE_QPA.informantion_element_fields


class IEC104_IO_F_FR_NA_1(IEC104_IO_Packet):
    """
    file ready

    EN 60870-5-101:2003, sec. 7.3.6.1 (p. 116)
    """
    name = 'F_FR_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_FR_NA_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_LOF.informantion_element_fields + \
        IEC104_IE_FRQ.informantion_element_fields


class IEC104_IO_F_SR_NA_1(IEC104_IO_Packet):
    """
    section ready

    EN 60870-5-101:2003, sec. 7.3.6.2 (p. 117)
    """
    name = 'F_SR_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_SR_NA_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_NOS.informantion_element_fields + \
        IEC104_IE_LOF.informantion_element_fields + \
        IEC104_IE_SRQ.informantion_element_fields


class IEC104_IO_F_SC_NA_1(IEC104_IO_Packet):
    """
    call directory, select file, call file, call section

    EN 60870-5-101:2003, sec. 7.3.6.3 (p. 118)
    """
    name = 'F_SC_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_SC_NA_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_NOS.informantion_element_fields + \
        IEC104_IE_SCQ.informantion_element_fields


class IEC104_IO_F_LS_NA_1(IEC104_IO_Packet):
    """
    last section, last segment

    EN 60870-5-101:2003, sec. 7.3.6.4 (p. 119)
    """
    name = 'F_LS_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_LS_NA_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_NOS.informantion_element_fields + \
        IEC104_IE_LSQ.informantion_element_fields + \
        IEC104_IE_CHS.informantion_element_fields


class IEC104_IO_F_AF_NA_1(IEC104_IO_Packet):
    """
    ack file, ack section

    EN 60870-5-101:2003, sec. 7.3.6.5 (p. 119)
    """
    name = 'F_AF_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_AF_NA_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_NOS.informantion_element_fields + \
        IEC104_IE_AFQ.informantion_element_fields


class IEC104_IO_F_SG_NA_1(IEC104_IO_Packet):
    """
    file / section data octets

    EN 60870-5-101:2003, sec. 7.3.6.6 (p. 120)
    """
    name = 'F_SG_NA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_SG_NA_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_NOS.informantion_element_fields + [
            BitFieldLenField('segment_length', None, 8,
                             length_of='data'),  # repr IEC104_IE_LOS
            XStrLenField('data', '',
                         length_from=lambda pkt: pkt.segment_length)
        ]


class IEC104_IO_F_DR_TA_1(IEC104_IO_Packet):
    """
    directory

    EN 60870-5-101:2003, sec. 7.3.6.7 (p. 121)
    """
    name = 'F_DR_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_101,
                   IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_DR_TA_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_LOF.informantion_element_fields + \
        IEC104_IE_SOF.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_SC_TA_1(IEC104_IO_Packet):
    """
    single command with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.1 (p. 37)
    """
    name = 'C_SC_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SC_TA_1

    fields_desc = IEC104_IE_SCO.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_DC_TA_1(IEC104_IO_Packet):
    """
    double command with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.2 (p. 38)
    """
    name = 'C_DC_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_DC_TA_1

    fields_desc = IEC104_IE_DCO.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_RC_TA_1(IEC104_IO_Packet):
    """
    step control command with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.3 (p. 39)
    """
    name = 'C_RC_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_RC_TA_1

    fields_desc = IEC104_IE_RCO.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_SE_TA_1(IEC104_IO_Packet):
    """
    set point command, normed value with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.4 (p. 40)
    """
    name = 'C_SE_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SE_TA_1

    fields_desc = IEC104_IE_NVA.informantion_element_fields + \
        IEC104_IE_QOS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_SE_TB_1(IEC104_IO_Packet):
    """
    set point command, scaled value with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.5 (p. 41)
    """
    name = 'C_SE_TB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SE_TB_1

    fields_desc = IEC104_IE_SVA.informantion_element_fields + \
        IEC104_IE_QOS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_SE_TC_1(IEC104_IO_Packet):
    """
    set point command, shortened floating point value with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.6 (p. 42)
    """
    name = 'C_SE_TC_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_SE_TC_1

    fields_desc = IEC104_IE_R32_IEEE_STD_754.informantion_element_fields + \
        IEC104_IE_QOS.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_BO_TA_1(IEC104_IO_Packet):
    """
    bitmask 32 bit with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.7 (p. 43)
    """
    name = 'C_BO_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_BO_TA_1

    fields_desc = IEC104_IE_BSI.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_C_TS_TA_1(IEC104_IO_Packet):
    """
    test command with timestamp CP56Time2a

    EN 60870-5-104:2006, sec. 8.8 (p. 44)
    """
    name = 'C_TS_TA_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_C_TS_TA_1

    fields_desc = IEC104_IE_TSC.informantion_element_fields + \
        IEC104_IE_CP56TIME2A.informantion_element_fields


class IEC104_IO_F_SC_NB_1(IEC104_IO_Packet):
    """
    request archive file

    EN 60870-5-104:2006, sec. 8.9 (p. 45)
    """
    name = 'F_SC_NB_1'

    _DEFINED_IN = [IEC104_IO_Packet.DEFINED_IN_IEC_104]
    _IEC104_IO_TYPE_ID = IEC104_IO_ID_F_SC_NB_1

    fields_desc = IEC104_IE_NOF.informantion_element_fields + \
        IEC104_IE_CP56TIME2A_START_TIME.\
        informantion_element_fields + \
        IEC104_IE_CP56TIME2A_STOP_TIME.informantion_element_fields


IEC104_IO_CLASSES = {
    IEC104_IO_ID_M_SP_NA_1: IEC104_IO_M_SP_NA_1,
    IEC104_IO_ID_M_SP_TA_1: IEC104_IO_M_SP_TA_1,
    IEC104_IO_ID_M_DP_NA_1: IEC104_IO_M_DP_NA_1,
    IEC104_IO_ID_M_DP_TA_1: IEC104_IO_M_DP_TA_1,
    IEC104_IO_ID_M_ST_NA_1: IEC104_IO_M_ST_NA_1,
    IEC104_IO_ID_M_ST_TA_1: IEC104_IO_M_ST_TA_1,
    IEC104_IO_ID_M_BO_NA_1: IEC104_IO_M_BO_NA_1,
    IEC104_IO_ID_M_BO_TA_1: IEC104_IO_M_BO_TA_1,
    IEC104_IO_ID_M_ME_NA_1: IEC104_IO_M_ME_NA_1,
    IEC104_IO_ID_M_ME_TA_1: IEC104_IO_M_ME_TA_1,
    IEC104_IO_ID_M_ME_NB_1: IEC104_IO_M_ME_NB_1,
    IEC104_IO_ID_M_ME_TB_1: IEC104_IO_M_ME_TB_1,
    IEC104_IO_ID_M_ME_NC_1: IEC104_IO_M_ME_NC_1,
    IEC104_IO_ID_M_ME_TC_1: IEC104_IO_M_ME_TC_1,
    IEC104_IO_ID_M_IT_NA_1: IEC104_IO_M_IT_NA_1,
    IEC104_IO_ID_M_IT_TA_1: IEC104_IO_M_IT_TA_1,
    IEC104_IO_ID_M_EP_TA_1: IEC104_IO_M_EP_TA_1,
    IEC104_IO_ID_M_EP_TB_1: IEC104_IO_M_EP_TB_1,
    IEC104_IO_ID_M_EP_TC_1: IEC104_IO_M_EP_TC_1,
    IEC104_IO_ID_M_PS_NA_1: IEC104_IO_M_PS_NA_1,
    IEC104_IO_ID_M_ME_ND_1: IEC104_IO_M_ME_ND_1,
    IEC104_IO_ID_M_SP_TB_1: IEC104_IO_M_SP_TB_1,
    IEC104_IO_ID_M_DP_TB_1: IEC104_IO_M_DP_TB_1,
    IEC104_IO_ID_M_ST_TB_1: IEC104_IO_M_ST_TB_1,
    IEC104_IO_ID_M_BO_TB_1: IEC104_IO_M_BO_TB_1,
    IEC104_IO_ID_M_ME_TD_1: IEC104_IO_M_ME_TD_1,
    IEC104_IO_ID_M_ME_TE_1: IEC104_IO_M_ME_TE_1,
    IEC104_IO_ID_M_ME_TF_1: IEC104_IO_M_ME_TF_1,
    IEC104_IO_ID_M_IT_TB_1: IEC104_IO_M_IT_TB_1,
    IEC104_IO_ID_M_EP_TD_1: IEC104_IO_M_EP_TD_1,
    IEC104_IO_ID_M_EP_TE_1: IEC104_IO_M_EP_TE_1,
    IEC104_IO_ID_M_EP_TF_1: IEC104_IO_M_EP_TF_1,
    IEC104_IO_ID_C_SC_NA_1: IEC104_IO_C_SC_NA_1,
    IEC104_IO_ID_C_DC_NA_1: IEC104_IO_C_DC_NA_1,
    IEC104_IO_ID_C_RC_NA_1: IEC104_IO_C_RC_NA_1,
    IEC104_IO_ID_C_SE_NA_1: IEC104_IO_C_SE_NA_1,
    IEC104_IO_ID_C_SE_NB_1: IEC104_IO_C_SE_NB_1,
    IEC104_IO_ID_C_SE_NC_1: IEC104_IO_C_SE_NC_1,
    IEC104_IO_ID_C_BO_NA_1: IEC104_IO_C_BO_NA_1,
    IEC104_IO_ID_C_SC_TA_1: IEC104_IO_C_SC_TA_1,
    IEC104_IO_ID_C_DC_TA_1: IEC104_IO_C_DC_TA_1,
    IEC104_IO_ID_C_RC_TA_1: IEC104_IO_C_RC_TA_1,
    IEC104_IO_ID_C_SE_TA_1: IEC104_IO_C_SE_TA_1,
    IEC104_IO_ID_C_SE_TB_1: IEC104_IO_C_SE_TB_1,
    IEC104_IO_ID_C_SE_TC_1: IEC104_IO_C_SE_TC_1,
    IEC104_IO_ID_C_BO_TA_1: IEC104_IO_C_BO_TA_1,
    IEC104_IO_ID_M_EI_NA_1: IEC104_IO_M_EI_NA_1,
    IEC104_IO_ID_C_IC_NA_1: IEC104_IO_C_IC_NA_1,
    IEC104_IO_ID_C_CI_NA_1: IEC104_IO_C_CI_NA_1,
    IEC104_IO_ID_C_RD_NA_1: IEC104_IO_C_RD_NA_1,
    IEC104_IO_ID_C_CS_NA_1: IEC104_IO_C_CS_NA_1,
    IEC104_IO_ID_C_TS_NA_1: IEC104_IO_C_TS_NA_1,
    IEC104_IO_ID_C_RP_NA_1: IEC104_IO_C_RP_NA_1,
    IEC104_IO_ID_C_CD_NA_1: IEC104_IO_C_CD_NA_1,
    IEC104_IO_ID_C_TS_TA_1: IEC104_IO_C_TS_TA_1,
    IEC104_IO_ID_P_ME_NA_1: IEC104_IO_P_ME_NA_1,
    IEC104_IO_ID_P_ME_NB_1: IEC104_IO_P_ME_NB_1,
    IEC104_IO_ID_P_ME_NC_1: IEC104_IO_P_ME_NC_1,
    IEC104_IO_ID_P_AC_NA_1: IEC104_IO_P_AC_NA_1,
    IEC104_IO_ID_F_FR_NA_1: IEC104_IO_F_FR_NA_1,
    IEC104_IO_ID_F_SR_NA_1: IEC104_IO_F_SR_NA_1,
    IEC104_IO_ID_F_SC_NA_1: IEC104_IO_F_SC_NA_1,
    IEC104_IO_ID_F_LS_NA_1: IEC104_IO_F_LS_NA_1,
    IEC104_IO_ID_F_AF_NA_1: IEC104_IO_F_AF_NA_1,
    IEC104_IO_ID_F_SG_NA_1: IEC104_IO_F_SG_NA_1,
    IEC104_IO_ID_F_DR_TA_1: IEC104_IO_F_DR_TA_1,
    IEC104_IO_ID_F_SC_NB_1: IEC104_IO_F_SC_NB_1
}


class IEC104_IO_M_SP_NA_1_IOA(IEC104_IO_M_SP_NA_1):
    """
    extended version of IEC104_IO_M_SP_NA_1 containing an individual
    information object address
    """
    name = 'M_SP_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_SP_NA_1.fields_desc


class IEC104_IO_M_SP_TA_1_IOA(IEC104_IO_M_SP_TA_1):
    """
    extended version of IEC104_IO_M_SP_TA_1 containing an individual
    information object address
    """
    name = 'M_SP_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_SP_TA_1.fields_desc


class IEC104_IO_M_DP_NA_1_IOA(IEC104_IO_M_DP_NA_1):
    """
    extended version of IEC104_IO_M_DP_NA_1 containing an individual
    information object address
    """
    name = 'M_DP_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_DP_NA_1.fields_desc


class IEC104_IO_M_DP_TA_1_IOA(IEC104_IO_M_DP_TA_1):
    """
    extended version of IEC104_IO_M_DP_TA_1 containing an individual
    information object address
    """
    name = 'M_DP_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_DP_TA_1.fields_desc


class IEC104_IO_M_ST_NA_1_IOA(IEC104_IO_M_ST_NA_1):
    """
    extended version of IEC104_IO_M_ST_NA_1 containing an individual
    information object address
    """
    name = 'M_ST_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ST_NA_1.fields_desc


class IEC104_IO_M_ST_TA_1_IOA(IEC104_IO_M_ST_TA_1):
    """
    extended version of IEC104_IO_M_ST_TA_1 containing an individual
    information object address
    """
    name = 'M_ST_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ST_TA_1.fields_desc


class IEC104_IO_M_BO_NA_1_IOA(IEC104_IO_M_BO_NA_1):
    """
    extended version of IEC104_IO_M_BO_NA_1 containing an individual
    information object address
    """
    name = 'M_BO_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_BO_NA_1.fields_desc


class IEC104_IO_M_BO_TA_1_IOA(IEC104_IO_M_BO_TA_1):
    """
    extended version of IEC104_IO_M_BO_TA_1 containing an individual
    information object address
    """
    name = 'M_BO_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_BO_TA_1.fields_desc


class IEC104_IO_M_ME_NA_1_IOA(IEC104_IO_M_ME_NA_1):
    """
    extended version of IEC104_IO_M_ME_NA_1 containing an individual
    information object address
    """
    name = 'M_ME_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_NA_1.fields_desc


class IEC104_IO_M_ME_TA_1_IOA(IEC104_IO_M_ME_TA_1):
    """
    extended version of IEC104_IO_M_ME_TA_1 containing an individual
    information object address
    """
    name = 'M_ME_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_TA_1.fields_desc


class IEC104_IO_M_ME_NB_1_IOA(IEC104_IO_M_ME_NB_1):
    """
    extended version of IEC104_IO_M_ME_NB_1 containing an individual
    information object address
    """
    name = 'M_ME_NB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_NB_1.fields_desc


class IEC104_IO_M_ME_TB_1_IOA(IEC104_IO_M_ME_TB_1):
    """
    extended version of IEC104_IO_M_ME_TB_1 containing an individual
    information object address
    """
    name = 'M_ME_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_TB_1.fields_desc


class IEC104_IO_M_ME_NC_1_IOA(IEC104_IO_M_ME_NC_1):
    """
    extended version of IEC104_IO_M_ME_NC_1 containing an individual
    information object address
    """
    name = 'M_ME_NC_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_NC_1.fields_desc


class IEC104_IO_M_ME_TC_1_IOA(IEC104_IO_M_ME_TC_1):
    """
    extended version of IEC104_IO_M_ME_TC_1 containing an individual
    information object address
    """
    name = 'M_ME_TC_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_TC_1.fields_desc


class IEC104_IO_M_IT_NA_1_IOA(IEC104_IO_M_IT_NA_1):
    """
    extended version of IEC104_IO_M_IT_NA_1 containing an individual
    information object address
    """
    name = 'M_IT_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_IT_NA_1.fields_desc


class IEC104_IO_M_IT_TA_1_IOA(IEC104_IO_M_IT_TA_1):
    """
    extended version of IEC104_IO_M_IT_TA_1 containing an individual
    information object address
    """
    name = 'M_IT_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_IT_TA_1.fields_desc


class IEC104_IO_M_EP_TA_1_IOA(IEC104_IO_M_EP_TA_1):
    """
    extended version of IEC104_IO_M_EP_TA_1 containing an individual
    information object address
    """
    name = 'M_EP_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_EP_TA_1.fields_desc


class IEC104_IO_M_EP_TB_1_IOA(IEC104_IO_M_EP_TB_1):
    """
    extended version of IEC104_IO_M_EP_TB_1 containing an individual
    information object address
    """
    name = 'M_EP_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_EP_TB_1.fields_desc


class IEC104_IO_M_EP_TC_1_IOA(IEC104_IO_M_EP_TC_1):
    """
    extended version of IEC104_IO_M_EP_TC_1 containing an individual
    information object address
    """
    name = 'M_EP_TC_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_EP_TC_1.fields_desc


class IEC104_IO_M_PS_NA_1_IOA(IEC104_IO_M_PS_NA_1):
    """
    extended version of IEC104_IO_M_PS_NA_1 containing an individual
    information object address
    """
    name = 'M_PS_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_PS_NA_1.fields_desc


class IEC104_IO_M_ME_ND_1_IOA(IEC104_IO_M_ME_ND_1):
    """
    extended version of IEC104_IO_M_ME_ND_1 containing an individual
    information object address
    """
    name = 'M_ME_ND_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_ND_1.fields_desc


class IEC104_IO_M_SP_TB_1_IOA(IEC104_IO_M_SP_TB_1):
    """
    extended version of IEC104_IO_M_SP_TB_1 containing an individual
    information object address
    """
    name = 'M_SP_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_SP_TB_1.fields_desc


class IEC104_IO_M_DP_TB_1_IOA(IEC104_IO_M_DP_TB_1):
    """
    extended version of IEC104_IO_M_DP_TB_1 containing an individual
    information object address
    """
    name = 'M_DP_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_DP_TB_1.fields_desc


class IEC104_IO_M_ST_TB_1_IOA(IEC104_IO_M_ST_TB_1):
    """
    extended version of IEC104_IO_M_ST_TB_1 containing an individual
    information object address
    """
    name = 'M_ST_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ST_TB_1.fields_desc


class IEC104_IO_M_BO_TB_1_IOA(IEC104_IO_M_BO_TB_1):
    """
    extended version of IEC104_IO_M_BO_TB_1 containing an individual
    information object address
    """
    name = 'M_BO_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_BO_TB_1.fields_desc


class IEC104_IO_M_ME_TD_1_IOA(IEC104_IO_M_ME_TD_1):
    """
    extended version of IEC104_IO_M_ME_TD_1 containing an individual
    information object address
    """
    name = 'M_ME_TD_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_TD_1.fields_desc


class IEC104_IO_M_ME_TE_1_IOA(IEC104_IO_M_ME_TE_1):
    """
    extended version of IEC104_IO_M_ME_TE_1 containing an individual
    information object address
    """
    name = 'M_ME_TE_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_TE_1.fields_desc


class IEC104_IO_M_ME_TF_1_IOA(IEC104_IO_M_ME_TF_1):
    """
    extended version of IEC104_IO_M_ME_TF_1 containing an individual
    information object address
    """
    name = 'M_ME_TF_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_ME_TF_1.fields_desc


class IEC104_IO_M_IT_TB_1_IOA(IEC104_IO_M_IT_TB_1):
    """
    extended version of IEC104_IO_M_IT_TB_1 containing an individual
    information object address
    """
    name = 'M_IT_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_IT_TB_1.fields_desc


class IEC104_IO_M_EP_TD_1_IOA(IEC104_IO_M_EP_TD_1):
    """
    extended version of IEC104_IO_M_EP_TD_1 containing an individual
    information object address
    """
    name = 'M_EP_TD_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_EP_TD_1.fields_desc


class IEC104_IO_M_EP_TE_1_IOA(IEC104_IO_M_EP_TE_1):
    """
    extended version of IEC104_IO_M_EP_TE_1 containing an individual
    information object address
    """
    name = 'M_EP_TE_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_EP_TE_1.fields_desc


class IEC104_IO_M_EP_TF_1_IOA(IEC104_IO_M_EP_TF_1):
    """
    extended version of IEC104_IO_M_EP_TF_1 containing an individual
    information object address
    """
    name = 'M_EP_TF_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_EP_TF_1.fields_desc


class IEC104_IO_C_SC_NA_1_IOA(IEC104_IO_C_SC_NA_1):
    """
    extended version of IEC104_IO_C_SC_NA_1 containing an individual
    information object address
    """
    name = 'C_SC_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SC_NA_1.fields_desc


class IEC104_IO_C_DC_NA_1_IOA(IEC104_IO_C_DC_NA_1):
    """
    extended version of IEC104_IO_C_DC_NA_1 containing an individual
    information object address
    """
    name = 'C_DC_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_DC_NA_1.fields_desc


class IEC104_IO_C_RC_NA_1_IOA(IEC104_IO_C_RC_NA_1):
    """
    extended version of IEC104_IO_C_RC_NA_1 containing an individual
    information object address
    """
    name = 'C_RC_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_RC_NA_1.fields_desc


class IEC104_IO_C_SE_NA_1_IOA(IEC104_IO_C_SE_NA_1):
    """
    extended version of IEC104_IO_C_SE_NA_1 containing an individual
    information object address
    """
    name = 'C_SE_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SE_NA_1.fields_desc


class IEC104_IO_C_SE_NB_1_IOA(IEC104_IO_C_SE_NB_1):
    """
    extended version of IEC104_IO_C_SE_NB_1 containing an individual
    information object address
    """
    name = 'C_SE_NB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SE_NB_1.fields_desc


class IEC104_IO_C_SE_NC_1_IOA(IEC104_IO_C_SE_NC_1):
    """
    extended version of IEC104_IO_C_SE_NC_1 containing an individual
    information object address
    """
    name = 'C_SE_NC_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SE_NC_1.fields_desc


class IEC104_IO_C_BO_NA_1_IOA(IEC104_IO_C_BO_NA_1):
    """
    extended version of IEC104_IO_C_BO_NA_1 containing an individual
    information object address
    """
    name = 'C_BO_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_BO_NA_1.fields_desc


class IEC104_IO_C_SC_TA_1_IOA(IEC104_IO_C_SC_TA_1):
    """
    extended version of IEC104_IO_C_SC_TA_1 containing an individual
    information object address
    """
    name = 'C_SC_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SC_TA_1.fields_desc


class IEC104_IO_C_DC_TA_1_IOA(IEC104_IO_C_DC_TA_1):
    """
    extended version of IEC104_IO_C_DC_TA_1 containing an individual
    information object address
    """
    name = 'C_DC_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_DC_TA_1.fields_desc


class IEC104_IO_C_RC_TA_1_IOA(IEC104_IO_C_RC_TA_1):
    """
    extended version of IEC104_IO_C_RC_TA_1 containing an individual
    information object address
    """
    name = 'C_RC_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_RC_TA_1.fields_desc


class IEC104_IO_C_SE_TA_1_IOA(IEC104_IO_C_SE_TA_1):
    """
    extended version of IEC104_IO_C_SE_TA_1 containing an individual
    information object address
    """
    name = 'C_SE_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SE_TA_1.fields_desc


class IEC104_IO_C_SE_TB_1_IOA(IEC104_IO_C_SE_TB_1):
    """
    extended version of IEC104_IO_C_SE_TB_1 containing an individual
    information object address
    """
    name = 'C_SE_TB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SE_TB_1.fields_desc


class IEC104_IO_C_SE_TC_1_IOA(IEC104_IO_C_SE_TC_1):
    """
    extended version of IEC104_IO_C_SE_TC_1 containing an individual
    information object address
    """
    name = 'C_SE_TC_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_SE_TC_1.fields_desc


class IEC104_IO_C_BO_TA_1_IOA(IEC104_IO_C_BO_TA_1):
    """
    extended version of IEC104_IO_C_BO_TA_1 containing an individual
    information object address
    """
    name = 'C_BO_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_BO_TA_1.fields_desc


class IEC104_IO_M_EI_NA_1_IOA(IEC104_IO_M_EI_NA_1):
    """
    extended version of IEC104_IO_M_EI_NA_1 containing an individual
    information object address
    """
    name = 'M_EI_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_M_EI_NA_1.fields_desc


class IEC104_IO_C_IC_NA_1_IOA(IEC104_IO_C_IC_NA_1):
    """
    extended version of IEC104_IO_C_IC_NA_1 containing an individual
    information object address
    """
    name = 'C_IC_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_IC_NA_1.fields_desc


class IEC104_IO_C_CI_NA_1_IOA(IEC104_IO_C_CI_NA_1):
    """
    extended version of IEC104_IO_C_CI_NA_1 containing an individual
    information object address
    """
    name = 'C_CI_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_CI_NA_1.fields_desc


class IEC104_IO_C_RD_NA_1_IOA(IEC104_IO_C_RD_NA_1):
    """
    extended version of IEC104_IO_C_RD_NA_1 containing an individual
    information object address
    """
    name = 'C_RD_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_RD_NA_1.fields_desc


class IEC104_IO_C_CS_NA_1_IOA(IEC104_IO_C_CS_NA_1):
    """
    extended version of IEC104_IO_C_CS_NA_1 containing an individual
    information object address
    """
    name = 'C_CS_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_CS_NA_1.fields_desc


class IEC104_IO_C_TS_NA_1_IOA(IEC104_IO_C_TS_NA_1):
    """
    extended version of IEC104_IO_C_TS_NA_1 containing an individual
    information object address
    """
    name = 'C_TS_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_TS_NA_1.fields_desc


class IEC104_IO_C_RP_NA_1_IOA(IEC104_IO_C_RP_NA_1):
    """
    extended version of IEC104_IO_C_RP_NA_1 containing an individual
    information object address
    """
    name = 'C_RP_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_RP_NA_1.fields_desc


class IEC104_IO_C_CD_NA_1_IOA(IEC104_IO_C_CD_NA_1):
    """
    extended version of IEC104_IO_C_CD_NA_1 containing an individual
    information object address
    """
    name = 'C_CD_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_CD_NA_1.fields_desc


class IEC104_IO_C_TS_TA_1_IOA(IEC104_IO_C_TS_TA_1):
    """
    extended version of IEC104_IO_C_TS_TA_1 containing an individual
    information object address
    """
    name = 'C_TS_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_C_TS_TA_1.fields_desc


class IEC104_IO_P_ME_NA_1_IOA(IEC104_IO_P_ME_NA_1):
    """
    extended version of IEC104_IO_P_ME_NA_1 containing an individual
    information object address
    """
    name = 'P_ME_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_P_ME_NA_1.fields_desc


class IEC104_IO_P_ME_NB_1_IOA(IEC104_IO_P_ME_NB_1):
    """
    extended version of IEC104_IO_P_ME_NB_1 containing an individual
    information object address
    """
    name = 'P_ME_NB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_P_ME_NB_1.fields_desc


class IEC104_IO_P_ME_NC_1_IOA(IEC104_IO_P_ME_NC_1):
    """
    extended version of IEC104_IO_P_ME_NC_1 containing an individual
    information object address
    """
    name = 'P_ME_NC_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_P_ME_NC_1.fields_desc


class IEC104_IO_P_AC_NA_1_IOA(IEC104_IO_P_AC_NA_1):
    """
    extended version of IEC104_IO_P_AC_NA_1 containing an individual
    information object address
    """
    name = 'P_AC_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_P_AC_NA_1.fields_desc


class IEC104_IO_F_FR_NA_1_IOA(IEC104_IO_F_FR_NA_1):
    """
    extended version of IEC104_IO_F_FR_NA_1 containing an individual
    information object address
    """
    name = 'F_FR_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_FR_NA_1.fields_desc


class IEC104_IO_F_SR_NA_1_IOA(IEC104_IO_F_SR_NA_1):
    """
    extended version of IEC104_IO_F_SR_NA_1 containing an individual
    information object address
    """
    name = 'F_SR_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_SR_NA_1.fields_desc


class IEC104_IO_F_SC_NA_1_IOA(IEC104_IO_F_SC_NA_1):
    """
    extended version of IEC104_IO_F_SC_NA_1 containing an individual
    information object address
    """
    name = 'F_SC_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_SC_NA_1.fields_desc


class IEC104_IO_F_LS_NA_1_IOA(IEC104_IO_F_LS_NA_1):
    """
    extended version of IEC104_IO_F_LS_NA_1 containing an individual
    information object address
    """
    name = 'F_LS_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_LS_NA_1.fields_desc


class IEC104_IO_F_AF_NA_1_IOA(IEC104_IO_F_AF_NA_1):
    """
    extended version of IEC104_IO_F_AF_NA_1 containing an individual
    information object address
    """
    name = 'F_AF_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_AF_NA_1.fields_desc


class IEC104_IO_F_SG_NA_1_IOA(IEC104_IO_F_SG_NA_1):
    """
    extended version of IEC104_IO_F_SG_NA_1 containing an individual
    information object address
    """
    name = 'F_SG_NA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_SG_NA_1.fields_desc


class IEC104_IO_F_DR_TA_1_IOA(IEC104_IO_F_DR_TA_1):
    """
    extended version of IEC104_IO_F_DR_TA_1 containing an individual
    information object address
    """
    name = 'F_DR_TA_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_DR_TA_1.fields_desc


class IEC104_IO_F_SC_NB_1_IOA(IEC104_IO_F_SC_NB_1):
    """
    extended version of IEC104_IO_F_SC_NB_1 containing an individual
    information object address
    """
    name = 'F_SC_NB_1 (+ioa)'
    fields_desc = [LEThreeBytesField('information_object_address', 0)] + \
        IEC104_IO_F_SC_NB_1.fields_desc


IEC104_IO_WITH_IOA_CLASSES = {
    IEC104_IO_ID_M_SP_NA_1: IEC104_IO_M_SP_NA_1_IOA,
    IEC104_IO_ID_M_SP_TA_1: IEC104_IO_M_SP_TA_1_IOA,
    IEC104_IO_ID_M_DP_NA_1: IEC104_IO_M_DP_NA_1_IOA,
    IEC104_IO_ID_M_DP_TA_1: IEC104_IO_M_DP_TA_1_IOA,
    IEC104_IO_ID_M_ST_NA_1: IEC104_IO_M_ST_NA_1_IOA,
    IEC104_IO_ID_M_ST_TA_1: IEC104_IO_M_ST_TA_1_IOA,
    IEC104_IO_ID_M_BO_NA_1: IEC104_IO_M_BO_NA_1_IOA,
    IEC104_IO_ID_M_BO_TA_1: IEC104_IO_M_BO_TA_1_IOA,
    IEC104_IO_ID_M_ME_NA_1: IEC104_IO_M_ME_NA_1_IOA,
    IEC104_IO_ID_M_ME_TA_1: IEC104_IO_M_ME_TA_1_IOA,
    IEC104_IO_ID_M_ME_NB_1: IEC104_IO_M_ME_NB_1_IOA,
    IEC104_IO_ID_M_ME_TB_1: IEC104_IO_M_ME_TB_1_IOA,
    IEC104_IO_ID_M_ME_NC_1: IEC104_IO_M_ME_NC_1_IOA,
    IEC104_IO_ID_M_ME_TC_1: IEC104_IO_M_ME_TC_1_IOA,
    IEC104_IO_ID_M_IT_NA_1: IEC104_IO_M_IT_NA_1_IOA,
    IEC104_IO_ID_M_IT_TA_1: IEC104_IO_M_IT_TA_1_IOA,
    IEC104_IO_ID_M_EP_TA_1: IEC104_IO_M_EP_TA_1_IOA,
    IEC104_IO_ID_M_EP_TB_1: IEC104_IO_M_EP_TB_1_IOA,
    IEC104_IO_ID_M_EP_TC_1: IEC104_IO_M_EP_TC_1_IOA,
    IEC104_IO_ID_M_PS_NA_1: IEC104_IO_M_PS_NA_1_IOA,
    IEC104_IO_ID_M_ME_ND_1: IEC104_IO_M_ME_ND_1_IOA,
    IEC104_IO_ID_M_SP_TB_1: IEC104_IO_M_SP_TB_1_IOA,
    IEC104_IO_ID_M_DP_TB_1: IEC104_IO_M_DP_TB_1_IOA,
    IEC104_IO_ID_M_ST_TB_1: IEC104_IO_M_ST_TB_1_IOA,
    IEC104_IO_ID_M_BO_TB_1: IEC104_IO_M_BO_TB_1_IOA,
    IEC104_IO_ID_M_ME_TD_1: IEC104_IO_M_ME_TD_1_IOA,
    IEC104_IO_ID_M_ME_TE_1: IEC104_IO_M_ME_TE_1_IOA,
    IEC104_IO_ID_M_ME_TF_1: IEC104_IO_M_ME_TF_1_IOA,
    IEC104_IO_ID_M_IT_TB_1: IEC104_IO_M_IT_TB_1_IOA,
    IEC104_IO_ID_M_EP_TD_1: IEC104_IO_M_EP_TD_1_IOA,
    IEC104_IO_ID_M_EP_TE_1: IEC104_IO_M_EP_TE_1_IOA,
    IEC104_IO_ID_M_EP_TF_1: IEC104_IO_M_EP_TF_1_IOA,
    IEC104_IO_ID_C_SC_NA_1: IEC104_IO_C_SC_NA_1_IOA,
    IEC104_IO_ID_C_DC_NA_1: IEC104_IO_C_DC_NA_1_IOA,
    IEC104_IO_ID_C_RC_NA_1: IEC104_IO_C_RC_NA_1_IOA,
    IEC104_IO_ID_C_SE_NA_1: IEC104_IO_C_SE_NA_1_IOA,
    IEC104_IO_ID_C_SE_NB_1: IEC104_IO_C_SE_NB_1_IOA,
    IEC104_IO_ID_C_SE_NC_1: IEC104_IO_C_SE_NC_1_IOA,
    IEC104_IO_ID_C_BO_NA_1: IEC104_IO_C_BO_NA_1_IOA,
    IEC104_IO_ID_C_SC_TA_1: IEC104_IO_C_SC_TA_1_IOA,
    IEC104_IO_ID_C_DC_TA_1: IEC104_IO_C_DC_TA_1_IOA,
    IEC104_IO_ID_C_RC_TA_1: IEC104_IO_C_RC_TA_1_IOA,
    IEC104_IO_ID_C_SE_TA_1: IEC104_IO_C_SE_TA_1_IOA,
    IEC104_IO_ID_C_SE_TB_1: IEC104_IO_C_SE_TB_1_IOA,
    IEC104_IO_ID_C_SE_TC_1: IEC104_IO_C_SE_TC_1_IOA,
    IEC104_IO_ID_C_BO_TA_1: IEC104_IO_C_BO_TA_1_IOA,
    IEC104_IO_ID_M_EI_NA_1: IEC104_IO_M_EI_NA_1_IOA,
    IEC104_IO_ID_C_IC_NA_1: IEC104_IO_C_IC_NA_1_IOA,
    IEC104_IO_ID_C_CI_NA_1: IEC104_IO_C_CI_NA_1_IOA,
    IEC104_IO_ID_C_RD_NA_1: IEC104_IO_C_RD_NA_1_IOA,
    IEC104_IO_ID_C_CS_NA_1: IEC104_IO_C_CS_NA_1_IOA,
    IEC104_IO_ID_C_TS_NA_1: IEC104_IO_C_TS_NA_1_IOA,
    IEC104_IO_ID_C_RP_NA_1: IEC104_IO_C_RP_NA_1_IOA,
    IEC104_IO_ID_C_CD_NA_1: IEC104_IO_C_CD_NA_1_IOA,
    IEC104_IO_ID_C_TS_TA_1: IEC104_IO_C_TS_TA_1_IOA,
    IEC104_IO_ID_P_ME_NA_1: IEC104_IO_P_ME_NA_1_IOA,
    IEC104_IO_ID_P_ME_NB_1: IEC104_IO_P_ME_NB_1_IOA,
    IEC104_IO_ID_P_ME_NC_1: IEC104_IO_P_ME_NC_1_IOA,
    IEC104_IO_ID_P_AC_NA_1: IEC104_IO_P_AC_NA_1_IOA,
    IEC104_IO_ID_F_FR_NA_1: IEC104_IO_F_FR_NA_1_IOA,
    IEC104_IO_ID_F_SR_NA_1: IEC104_IO_F_SR_NA_1_IOA,
    IEC104_IO_ID_F_SC_NA_1: IEC104_IO_F_SC_NA_1_IOA,
    IEC104_IO_ID_F_LS_NA_1: IEC104_IO_F_LS_NA_1_IOA,
    IEC104_IO_ID_F_AF_NA_1: IEC104_IO_F_AF_NA_1_IOA,
    IEC104_IO_ID_F_SG_NA_1: IEC104_IO_F_SG_NA_1_IOA,
    IEC104_IO_ID_F_DR_TA_1: IEC104_IO_F_DR_TA_1_IOA,
    IEC104_IO_ID_F_SC_NB_1: IEC104_IO_F_SC_NB_1_IOA
}
