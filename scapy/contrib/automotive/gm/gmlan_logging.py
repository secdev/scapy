# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = GMLAN Ecu logging additions
# scapy.contrib.status = library


from scapy.contrib.automotive.gm.gmlan import GMLAN_SA, GMLAN_IDO, GMLAN_DC, \
    GMLAN_NR, GMLAN_RD, GMLAN_TD, GMLAN_DCPR, GMLAN_DPBA, GMLAN_DPBAPR, \
    GMLAN_RPSPR, GMLAN_RDI, GMLAN_WDBI, GMLAN_WDBIPR, GMLAN_PM, GMLAN_SAPR, \
    GMLAN_RDBI, GMLAN_RDBIPR, GMLAN_RDBPI, GMLAN_RDBPIPR, GMLAN_RDBPKTI, \
    GMLAN_RFRD, GMLAN_RFRDPR, GMLAN_RMBA, GMLAN_RMBAPR, GMLAN_DDM, GMLAN_DDMPR
from scapy.packet import Packet
from scapy.compat import Tuple, Any
from scapy.contrib.automotive.ecu import Ecu


@Ecu.extend_pkt_with_logging(GMLAN_IDO)
def GMLAN_IDO_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_IDO.subfunction%")


@Ecu.extend_pkt_with_logging(GMLAN_RFRD)
def GMLAN_RFRD_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RFRD.subfunction%")


@Ecu.extend_pkt_with_logging(GMLAN_RFRDPR)
def GMLAN_RFRDPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RFRDPR.subfunction%")


@Ecu.extend_pkt_with_logging(GMLAN_RDBI)
def GMLAN_RDBI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RDBI.dataIdentifier%")


@Ecu.extend_pkt_with_logging(GMLAN_RDBIPR)
def GMLAN_RDBIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.sprintf("%GMLAN_RDBIPR.dataIdentifier%"),
         bytes(self.load))


@Ecu.extend_pkt_with_logging(GMLAN_RDBPI)
def GMLAN_RDBPI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RDBPI.identifiers%")


@Ecu.extend_pkt_with_logging(GMLAN_RDBPIPR)
def GMLAN_RDBPIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RDBPIPR.parameterIdentifier%")


@Ecu.extend_pkt_with_logging(GMLAN_RDBPKTI)
def GMLAN_RDBPKTI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RDBPKTI.subfunction%")


@Ecu.extend_pkt_with_logging(GMLAN_RMBA)
def GMLAN_RMBA_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RMBA.memoryAddress%")


@Ecu.extend_pkt_with_logging(GMLAN_RMBAPR)
def GMLAN_RMBAPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.sprintf("%GMLAN_RMBAPR.memoryAddress%"), self.dataRecord)


@Ecu.extend_pkt_with_logging(GMLAN_SA)
def GMLAN_SA_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    if self.subfunction % 2 == 1:
        return self.sprintf("%GMLAN.service%"), \
            (self.subfunction, None)
    else:
        return self.sprintf("%GMLAN.service%"), \
            (self.subfunction, self.securityKey)


@Ecu.extend_pkt_with_logging(GMLAN_SAPR)
def GMLAN_SAPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    if self.subfunction % 2 == 0:
        return self.sprintf("%GMLAN.service%"), \
            (self.subfunction, None)
    else:
        return self.sprintf("%GMLAN.service%"), \
            (self.subfunction, self.securitySeed)


@Ecu.extend_pkt_with_logging(GMLAN_DDM)
def GMLAN_DDM_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.sprintf("%GMLAN_DDM.DPIDIdentifier%"), self.PIDData)


@Ecu.extend_pkt_with_logging(GMLAN_DDMPR)
def GMLAN_DDMPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_DDMPR.DPIDIdentifier%")


@Ecu.extend_pkt_with_logging(GMLAN_DPBA)
def GMLAN_DPBA_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.parameterIdentifier, self.memoryAddress, self.memorySize)


@Ecu.extend_pkt_with_logging(GMLAN_DPBAPR)
def GMLAN_DPBAPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), self.parameterIdentifier


@Ecu.extend_pkt_with_logging(GMLAN_RD)
def GMLAN_RD_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.dataFormatIdentifier, self.memorySize)


@Ecu.extend_pkt_with_logging(GMLAN_TD)
def GMLAN_TD_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.sprintf("%GMLAN_TD.subfunction%"), self.startingAddress,
         self.dataRecord)


@Ecu.extend_pkt_with_logging(GMLAN_WDBI)
def GMLAN_WDBI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.sprintf("%GMLAN_WDBI.dataIdentifier%"), self.dataRecord)


@Ecu.extend_pkt_with_logging(GMLAN_WDBIPR)
def GMLAN_WDBIPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_WDBIPR.dataIdentifier%")


@Ecu.extend_pkt_with_logging(GMLAN_RPSPR)
def GMLAN_RPSPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RPSPR.programmedState%")


@Ecu.extend_pkt_with_logging(GMLAN_PM)
def GMLAN_PM_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_PM.subfunction%")


@Ecu.extend_pkt_with_logging(GMLAN_RDI)
def GMLAN_RDI_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_RDI.subfunction%")


@Ecu.extend_pkt_with_logging(GMLAN_DC)
def GMLAN_DC_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_DC.CPIDNumber%")


@Ecu.extend_pkt_with_logging(GMLAN_DCPR)
def GMLAN_DCPR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        self.sprintf("%GMLAN_DCPR.CPIDNumber%")


@Ecu.extend_pkt_with_logging(GMLAN_NR)
def GMLAN_NR_get_log(self):
    # type: (Packet) -> Tuple[str, Any]
    return self.sprintf("%GMLAN.service%"), \
        (self.sprintf("%GMLAN_NR.requestServiceId%"),
         self.sprintf("%GMLAN_NR.returnCode%"))
