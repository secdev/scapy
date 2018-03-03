from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import UDP
from scapy.layers.dns import DNSQRField, DNSRRField, DNSRRCountField

"""
LLMNR (Link Local Multicast Node Resolution).

[RFC 4795]
"""

#############################################################################
###                           LLMNR (RFC4795)                             ###
#############################################################################
# LLMNR is based on the DNS packet format (RFC1035 Section 4)
# RFC also envisions LLMNR over TCP. Like vista, we don't support it -- arno

_LLMNR_IPv6_mcast_Addr = "FF02:0:0:0:0:0:1:3"
_LLMNR_IPv4_mcast_addr = "224.0.0.252"

class LLMNRQuery(Packet):
    name = "Link Local Multicast Node Resolution - Query"
    fields_desc = [ ShortField("id", 0),
                    BitField("qr", 0, 1),
                    BitEnumField("opcode", 0, 4, { 0:"QUERY" }),
                    BitField("c", 0, 1),
                    BitField("tc", 0, 2),
                    BitField("z", 0, 4),
                    BitEnumField("rcode", 0, 4, { 0:"ok" }),
                    DNSRRCountField("qdcount", None, "qd"),
                    DNSRRCountField("ancount", None, "an"),
                    DNSRRCountField("nscount", None, "ns"),
                    DNSRRCountField("arcount", None, "ar"),
                    DNSQRField("qd", "qdcount"),
                    DNSRRField("an", "ancount"),
                    DNSRRField("ns", "nscount"),
                    DNSRRField("ar", "arcount",0)]
    overload_fields = {UDP: {"sport": 5355, "dport": 5355 }}
    def hashret(self):
        return struct.pack("!H", self.id)

class LLMNRResponse(LLMNRQuery):
    name = "Link Local Multicast Node Resolution - Response"
    qr = 1
    def answers(self, other):
        return (isinstance(other, LLMNRQuery) and
                self.id == other.id and
                self.qr == 1 and
                other.qr == 0)

class _LLMNR(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if len(_pkt) >= 2:
            if (orb(_pkt[2]) & 0x80): # Response
                return LLMNRResponse
            else:                  # Query
                return LLMNRQuery
        return cls

bind_bottom_up(UDP, _LLMNR, dport=5355)
bind_bottom_up(UDP, _LLMNR, sport=5355)
bind_layers(UDP, _LLMNR, sport=5355, dport=5355)

# LLMNRQuery(id=RandShort(), qd=DNSQR(qname="vista.")))


