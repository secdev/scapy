# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = UDS Ecu logging additions
# scapy.contrib.status = library

from scapy.contrib.automotive.uds import UDS_DSCPR, UDS_ERPR, UDS_SAPR, \
    UDS_CCPR, UDS_TPPR, UDS_DSC, UDS_ER, UDS_RDPR, UDS_TDPR, UDS_RD, UDS_TD, \
    UDS_CC, UDS_NR, UDS_SA, UDS_RDBIPR, UDS_LC, UDS_RC, UDS_TP, UDS_RU, \
    UDS_IOCBIPR, UDS_WDBIPR, UDS_CDTCIPR, UDS_CDTCI, UDS_RDTCIPR, \
    UDS_RDTCI, UDS_RMBAPR, UDS_WMBAPR, UDS_WMBA, UDS_LCPR, UDS_RCPR, UDS_RFT, \
    UDS_RTE, UDS_RTEPR, UDS_RFTPR, UDS_IOCBI, UDS_RDBI, UDS_RMBA, UDS_WDBI, \
    UDS_CDTCS, UDS_CDTCSPR, UDS_SDT, UDS_SDTPR, UDS_RUPR
from scapy.packet import Packet
from scapy.contrib.automotive.ecu import Ecu

from typing import (
    Any,
    Tuple,
)


@Ecu.extend_pkt_with_logging(UDS_DSC)
def UDS_DSC_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_DSC.diagnosticSessionType%")


@Ecu.extend_pkt_with_logging(UDS_DSCPR)
def UDS_DSCPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_DSCPR.diagnosticSessionType%")


@Ecu.extend_pkt_with_logging(UDS_ER)
def UDS_ER_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_ER.resetType%")


@Ecu.extend_pkt_with_logging(UDS_ERPR)
def UDS_ERPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_ER.resetType%")


@Ecu.extend_pkt_with_logging(UDS_SA)
def UDS_SA_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    if self.securityAccessType % 2 == 1:
        return self.sprintf("%UDS.service%"),\
            (self.securityAccessType, None)
    else:
        return self.sprintf("%UDS.service%"),\
            (self.securityAccessType, self.securityKey)


@Ecu.extend_pkt_with_logging(UDS_SAPR)
def UDS_SAPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    if self.securityAccessType % 2 == 0:
        return self.sprintf("%UDS.service%"),\
            (self.securityAccessType, None)
    else:
        return self.sprintf("%UDS.service%"),\
            (self.securityAccessType, self.securitySeed)


@Ecu.extend_pkt_with_logging(UDS_CC)
def UDS_CC_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_CC.controlType%")


@Ecu.extend_pkt_with_logging(UDS_CCPR)
def UDS_CCPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_CCPR.controlType%")


@Ecu.extend_pkt_with_logging(UDS_TP)
def UDS_TP_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.subFunction


@Ecu.extend_pkt_with_logging(UDS_TPPR)
def UDS_TPPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.zeroSubFunction


@Ecu.extend_pkt_with_logging(UDS_SDT)
def UDS_SDT_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.securityDataRequestRecord


@Ecu.extend_pkt_with_logging(UDS_SDTPR)
def UDS_SDTPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.securityDataResponseRecord


@Ecu.extend_pkt_with_logging(UDS_CDTCS)
def UDS_CDTCS_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_CDTCS.DTCSettingType%")


@Ecu.extend_pkt_with_logging(UDS_CDTCSPR)
def UDS_CDTCSPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_CDTCSPR.DTCSettingType%")


@Ecu.extend_pkt_with_logging(UDS_LC)
def UDS_LC_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS.linkControlType%")


@Ecu.extend_pkt_with_logging(UDS_LCPR)
def UDS_LCPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS.linkControlType%")


@Ecu.extend_pkt_with_logging(UDS_RDBI)
def UDS_RDBI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_RDBI.identifiers%")


@Ecu.extend_pkt_with_logging(UDS_RDBIPR)
def UDS_RDBIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_RDBIPR.dataIdentifier%")


@Ecu.extend_pkt_with_logging(UDS_RMBA)
def UDS_RMBA_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        (getattr(self, "memoryAddress%d" % self.memoryAddressLen),
         getattr(self, "memorySize%d" % self.memorySizeLen))


@Ecu.extend_pkt_with_logging(UDS_RMBAPR)
def UDS_RMBAPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.dataRecord


@Ecu.extend_pkt_with_logging(UDS_WDBI)
def UDS_WDBI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_WDBI.dataIdentifier%")


@Ecu.extend_pkt_with_logging(UDS_WDBIPR)
def UDS_WDBIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        self.sprintf("%UDS_WDBIPR.dataIdentifier%")


@Ecu.extend_pkt_with_logging(UDS_WMBA)
def UDS_WMBA_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    addr = getattr(self, "memoryAddress%d" % self.memoryAddressLen)
    size = getattr(self, "memorySize%d" % self.memorySizeLen)
    return self.sprintf("%UDS.service%"), (addr, size, self.dataRecord)


@Ecu.extend_pkt_with_logging(UDS_WMBAPR)
def UDS_WMBAPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    addr = getattr(self, "memoryAddress%d" % self.memoryAddressLen)
    size = getattr(self, "memorySize%d" % self.memorySizeLen)
    return self.sprintf("%UDS.service%"), (addr, size)


@Ecu.extend_pkt_with_logging(UDS_CDTCI)
def UDS_CDTCI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        (self.groupOfDTCHighByte, self.groupOfDTCMiddleByte,
         self.groupOfDTCLowByte)


@Ecu.extend_pkt_with_logging(UDS_CDTCIPR)
def UDS_CDTCIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), None


@Ecu.extend_pkt_with_logging(UDS_RDTCI)
def UDS_RDTCI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), repr(self)


@Ecu.extend_pkt_with_logging(UDS_RDTCIPR)
def UDS_RDTCIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), repr(self)


@Ecu.extend_pkt_with_logging(UDS_RC)
def UDS_RC_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"),\
        (self.routineControlType,
         self.routineIdentifier)


@Ecu.extend_pkt_with_logging(UDS_RCPR)
def UDS_RCPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"),\
        (self.routineControlType,
         self.routineIdentifier)


@Ecu.extend_pkt_with_logging(UDS_RD)
def UDS_RD_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    addr = getattr(self, "memoryAddress%d" % self.memoryAddressLen)
    size = getattr(self, "memorySize%d" % self.memorySizeLen)
    return self.sprintf("%UDS.service%"), (addr, size)


@Ecu.extend_pkt_with_logging(UDS_RDPR)
def UDS_RDPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.memorySizeLen


@Ecu.extend_pkt_with_logging(UDS_RU)
def UDS_RU_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    addr = getattr(self, "memoryAddress%d" % self.memoryAddressLen)
    size = getattr(self, "memorySize%d" % self.memorySizeLen)
    return self.sprintf("%UDS.service%"), (addr, size)


@Ecu.extend_pkt_with_logging(UDS_RUPR)
def UDS_RUPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.memorySizeLen


@Ecu.extend_pkt_with_logging(UDS_TD)
def UDS_TD_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"),\
        (self.blockSequenceCounter, self.transferRequestParameterRecord)


@Ecu.extend_pkt_with_logging(UDS_TDPR)
def UDS_TDPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.blockSequenceCounter


@Ecu.extend_pkt_with_logging(UDS_RTE)
def UDS_RTE_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"),\
        self.transferRequestParameterRecord


@Ecu.extend_pkt_with_logging(UDS_RTEPR)
def UDS_RTEPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"),\
        self.transferResponseParameterRecord


@Ecu.extend_pkt_with_logging(UDS_RFT)
def UDS_RFT_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"),\
        self.modeOfOperation


@Ecu.extend_pkt_with_logging(UDS_RFTPR)
def UDS_RFTPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"),\
        self.modeOfOperation


@Ecu.extend_pkt_with_logging(UDS_IOCBI)
def UDS_IOCBI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.dataIdentifier


@Ecu.extend_pkt_with_logging(UDS_IOCBIPR)
def UDS_IOCBIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), self.dataIdentifier


@Ecu.extend_pkt_with_logging(UDS_NR)
def UDS_NR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%UDS.service%"), \
        (self.sprintf("%UDS_NR.requestServiceId%"),
         self.sprintf("%UDS_NR.negativeResponseCode%"))
