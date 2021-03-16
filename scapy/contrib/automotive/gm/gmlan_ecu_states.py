# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = GMLAN EcuState modifications
# scapy.contrib.status = library

from scapy.packet import Packet
from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_SAPR

__all__ = ["GMLAN_modify_ecu_state", "GMLAN_SAPR_modify_ecu_state"]


@EcuState.extend_pkt_with_modifier(GMLAN)
def GMLAN_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    if self.service == 0x50:
        state.session = 3  # type: ignore
    elif self.service == 0x60:
        state.reset()
        state.session = 1  # type: ignore
    elif self.service == 0x68:
        state.communication_control = 1  # type: ignore
    elif self.service == 0xe5:
        state.session = 2  # type: ignore
    elif self.service == 0x74:
        state.request_download = 1  # type: ignore
    elif self.service == 0x7e:
        state.tp = 1  # type: ignore


@EcuState.extend_pkt_with_modifier(GMLAN_SAPR)
def GMLAN_SAPR_modify_ecu_state(self, req, state):
    # type: (Packet, Packet, EcuState) -> None
    if self.subfunction % 2 == 0:
        state.security_level = self.subfunction  # type: ignore
