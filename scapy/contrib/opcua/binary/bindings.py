# coding=utf-8

from scapy.contrib.opcua.binary.tcp import UaTcp
from scapy.layers.inet import TCP
from scapy.packet import bind_layers


# Bind standard ports
# TODO: Make better layer bindings that do not depend on port numbers.
# TODO: investigate if possible to determine from MessageType
bind_layers(TCP, UaTcp, dport=4840)
bind_layers(TCP, UaTcp, sport=4840)
