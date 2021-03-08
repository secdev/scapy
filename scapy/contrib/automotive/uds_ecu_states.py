# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = UDS EcuState modifications
# scapy.contrib.status = library

from scapy.contrib.automotive.uds import UDS_DSCPR, UDS_ERPR, UDS_SAPR, \
    UDS_RDBPIPR, UDS_CCPR, UDS_TPPR
from scapy.packet import Packet
from scapy.contrib.automotive.ecu import EcuState


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
