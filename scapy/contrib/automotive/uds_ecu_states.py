# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = UDS EcuState modifications
# scapy.contrib.status = library

from scapy.contrib.automotive.uds import UDS_DSCPR, UDS_ERPR, UDS_SAPR, \
    UDS_RDBPIPR, UDS_CCPR, UDS_TPPR, UDS_RDPR, UDS
from scapy.packet import Packet
from scapy.contrib.automotive.ecu import EcuState


__all__ = ["UDS_DSCPR_modify_ecu_state", "UDS_CCPR_modify_ecu_state",
           "UDS_ERPR_modify_ecu_state", "UDS_RDBPIPR_modify_ecu_state",
           "UDS_TPPR_modify_ecu_state", "UDS_SAPR_modify_ecu_state",
           "UDS_RDPR_modify_ecu_state"]


@EcuState.extend_pkt_with_modifier(UDS_DSCPR)
def UDS_DSCPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    state.session = self.diagnosticSessionType  # type: ignore


@EcuState.extend_pkt_with_modifier(UDS_ERPR)
def UDS_ERPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    state.reset()
    state.session = 1  # type: ignore


@EcuState.extend_pkt_with_modifier(UDS_SAPR)
def UDS_SAPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    if self.securityAccessType % 2 == 0:
        state.security_level = self.securityAccessType  # type: ignore


@EcuState.extend_pkt_with_modifier(UDS_CCPR)
def UDS_CCPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    state.communication_control = self.controlType  # type: ignore


@EcuState.extend_pkt_with_modifier(UDS_TPPR)
def UDS_TPPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    state.tp = 1  # type: ignore


@EcuState.extend_pkt_with_modifier(UDS_RDBPIPR)
def UDS_RDBPIPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    state.pdid = self.periodicDataIdentifier  # type: ignore


@EcuState.extend_pkt_with_modifier(UDS_RDPR)
def UDS_RDPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    oldstr = getattr(state, "req_download", "")
    newstr = str(req.fields)
    state.req_download = oldstr if newstr in oldstr else oldstr + newstr  # type: ignore  # noqa: E501


@EcuState.extend_pkt_with_modifier(UDS)
def UDS_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    if self.service == 0x77:  # UDS RequestTransferExitPositiveResponse
        try:
            state.download_complete = state.req_download  # type: ignore
        except (KeyError, AttributeError):
            pass
        state.req_download = ""  # type: ignore
