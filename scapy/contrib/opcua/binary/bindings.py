# coding=utf-8
"""
This module contains bindings to bind the OPC UA layers to the TCP layer (note: OPC UA TCP is a layer on top of TCP)
"""
from scapy.contrib.opcua.binary.tcp import UaTcp
from scapy.layers.inet import TCP
from scapy.packet import bind_layers


# Bind standard ports
# TODO: Make better layer bindings that do not depend on port numbers.
# TODO: investigate if possible to determine from MessageType
bind_layers(TCP, UaTcp, dport=4840)  # We only need to bind UaTcp, since the dispatch_hook is used to determine
bind_layers(TCP, UaTcp, sport=4840)  # whether we are dealing with UaTcp or UaSecureConversation
