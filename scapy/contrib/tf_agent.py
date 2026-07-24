"""Tungsten Fabric vrouter punted packets helper.

Parses packets encapsulated into additional layer of ethernet and
agent header.

NOTE: do not import it for non-vrouter traces, it rebinds IP from Ether
(because vrouter uses same ethertype as IPv4)"""

# scapy.contrib.description = Tungsten Fabric vrouter punted packets
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import IntField, ByteField, ShortField, ShortEnumField, \
    ThreeBytesField
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

# Some encapsulated packets are MPLSoGRE or MPLSoUDP
import scapy.contrib.mpls               # noqa: F401

vrouter_agent_cmd_no = {0: "AGENT_CMD_SWITCH",
                        1: "AGENT_CMD_ROUTE",
                        2: "AGENT_TRAP_ARP",
                        3: "AGENT_TRAP_L2_PROTOCOLS",
                        4: "AGENT_TRAP_NEXTHOP",
                        5: "AGENT_TRAP_RESOLVE",
                        6: "AGENT_TRAP_FLOW_MISS",
                        7: "AGENT_TRAP_L3_PROTOCOLS",
                        8: "AGENT_TRAP_DIAG",
                        9: "AGENT_TRAP_ECMP_RESOLVE",
                        10: "AGENT_TRAP_SOURCE_MISMATCH",
                        11: "AGENT_TRAP_HANDLE_DF",
                        12: "AGENT_TRAP_ZERO_TTL",
                        13: "AGENT_TRAP_ICMP_ERROR",
                        14: "AGENT_TRAP_TOR_CONTROL_PKT",
                        15: "AGENT_TRAP_FLOW_ACTION_HOLD",
                        16: "AGENT_TRAP_ROUTER_ALERT"}


class InnerEther(Packet):
    name = "Ethernet"
    fields_desc = Ether.fields_desc[:]


class VrouterAgentHdr(Packet):
    name = "VrAgentHdr"
    fields_desc = [ShortField("ifindex", None),
                   ShortField("vrf", None),
                   ShortEnumField("cmd", 1, vrouter_agent_cmd_no),
                   IntField("param", None),
                   IntField("param_1", None),
                   IntField("param_2", None),
                   IntField("param_3", None),
                   IntField("param_4", None),
                   ByteField("param_5", None),
                   ThreeBytesField("param_5_pack", None)]

    def mysummary(self):
        summary = self.sprintf("%cmd% vif0/%ifindex% Vrf:%vrf%")
        if self.cmd == 6 or self.cmd == 15:
            summary += self.sprintf(" Flow:%param% Gen:%param_5%"
                                    " K(nh)=%param_1%")

        return summary

    def guess_payload_class(self, payload):
        return InnerEther


split_layers(Ether, IP, type=0x800)
bind_layers(Ether, VrouterAgentHdr, type=0x800)
bind_layers(InnerEther, IP, type=0x800)
bind_layers(InnerEther, IPv6, type=0x86DD)
bind_layers(InnerEther, ARP, type=0x0806)
