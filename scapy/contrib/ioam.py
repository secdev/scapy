# scapy.contrib.description = In-situ Operation Administration and Maintenance (IOAM)
# scapy.contrib.status = loads

'''
In-situ Operation Administration and Maintenance (IOAM)

Notice:
This is China Mobile Communications Corporation (CMCC) IOAM, instead of Cisco IOAM

IOAM Shim Reference:
https://datatracker.ietf.org/doc/rfc9486/
https://datatracker.ietf.org/doc/html/rfc8321

IOAM Report Packet Reference:
https://datatracker.ietf.org/doc/draft-ietf-netconf-udp-notif/12/

IOAM layer identifier:
IPv4.proto == 186
IPv6.NextHeader == 0x0 && IPv6.HBH.option_type == 0x11

Example Packet Format:
IOAMoIPv4       = Ether/IP/IOAM/Payload
IOAMoIPv4UDP    = Ether/IP/IOAM/UDP/Payload
IOAMoIPv4TCP    = Ether/IP/IOAM/TCP/Payload
IOAMoIPv4VxLAN  = Ether/IP/IOAM/UDP/VXLAN/Ether/IP/TCP/Payload
IOAMoIPv6IP     = Ether/IPv6/IPv6ExtHdrHopByHop(nh=59, options=[HBHOptIOAM(ioam=ioam)])/Payload # noqa: E501
IOAMoIPv6UDP    = Ether/IPv6/IPv6ExtHdrHopByHop(nh=socket.IPPROTO_UDP, options=[HBHOptIOAM(ioam=IOAM)])/UDP/Payload # noqa: E501
IOAMoIPv6TCP    = Ether/IPv6/IPv6ExtHdrHopByHop(nh=socket.IPPROTO_TCP, options=[HBHOptIOAM(ioam=IOAM)])/TCP/Payload # noqa: E501
IOAMoIPv6VxLAN  = Ether/IPv6/IPv6ExtHdrHopByHop(nh=socket.IPPROTO_UDP, options=[HBHOptIOAM(ioam=IOAM)])/UDP/VXLAN/Ether/IP/TCP/Payload # noqa: E501
'''

import socket
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField
from scapy.layers.inet import IP, TCP, UDP

IPPROTO_IOAM = 186


class IOAM(Packet):
    name = 'IOAM'
    fields_desc = [
        BitField('flow_id', 0, 20),
        BitField('color_val', 0, 1),
        BitField('delay_en', 0, 1),
        BitField('color_en', 0, 1),
        BitField('reserved', 0, 1),
        ByteField('next_protocol', 0),
    ]


bind_layers(IP, IOAM, proto=IPPROTO_IOAM)
bind_layers(IOAM, TCP, next_protocol=socket.IPPROTO_TCP)
bind_layers(IOAM, UDP, next_protocol=socket.IPPROTO_UDP)
