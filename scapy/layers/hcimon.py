# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Bluetooth HCI monitor layers, sockets and send/receive functions.
"""

import socket

from scapy.config import conf
from scapy.data import DLT_BLUETOOTH_LINUX_MONITOR
from scapy.packet import bind_layers, Packet
from scapy.fields import (
    ByteEnumField,
    LEShortField,
    ShortField,
    LEShortEnumField,
    StrFixedLenField,
    StrNullField,
    XLEShortField,
    LEMACField,
)
from scapy.data import MTU
from scapy.layers.bluetooth import (
    _BluetoothLibcSocket,
    sockaddr_hci,
    HCI_DEV_NONE,
    HCI_CHANNEL_MONITOR,
    HCI_Command_Hdr,
    HCI_Event_Hdr,
)


##########
# Layers #
##########

# https://elixir.bootlin.com/linux/v6.4.2/source/include/net/bluetooth/hci_mon.h#L27
class HCI_Mon_Hdr(Packet):
    name = 'Bluetooth Linux Monitor Transport Header'
    fields_desc = [
        LEShortEnumField('opcode', None, {
            0: "New index",
            1: "Delete index",
            2: "Command pkt",
            3: "Event pkt",
            4: "ACL TX pkt",
            5: "ACL RX pkt",
            6: "SCO TX pkt",
            7: "SCO RX pkt",
            8: "Open index",
            9: "Close index",
            10: "Index info",
            11: "Vendor diag",
            12: "System note",
            13: "User logging",
            14: "Ctrl open",
            15: "Ctrl close",
            16: "Ctrl command",
            17: "Ctrl event",
            18: "ISO TX pkt",
            19: "ISO RX pkt",
        }),
        LEShortField('adapter_id', None),
        LEShortField('len', None)
    ]


# https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LINUX_MONITOR.html
class HCI_Mon_Pcap_Hdr(HCI_Mon_Hdr):
    name = 'Bluetooth Linux Monitor Transport Pcap Header'
    fields_desc = [
        ShortField('adapter_id', None),
        ShortField('opcode', None)
    ]


class HCI_Mon_New_Index(Packet):
    name = 'Bluetooth Linux Monitor Transport New Index Packet'
    fields_desc = [
        ByteEnumField('bus', 0, {
            0x00: "BR/EDR",
            0x01: "AMP"
        }),
        ByteEnumField('type', 0, {
            0x00: "Virtual",
            0x01: "USB",
            0x02: "PC Card",
            0x03: "UART",
            0x04: "RS232",
            0x05: "PCI",
            0x06: "SDIO"
        }),
        LEMACField('addr', None),
        StrFixedLenField('devname', None, 8)
    ]


class HCI_Mon_Index_Info(Packet):
    name = 'Bluetooth Linux Monitor Transport Index Info Packet'
    fields_desc = [
        LEMACField('addr', None),
        XLEShortField('manufacturer', None)
    ]


class HCI_Mon_System_Note(Packet):
    name = 'Bluetooth Linux Monitor Transport System Note Packet'
    fields_desc = [
        StrNullField('note', None)
    ]


# https://elixir.bootlin.com/linux/v6.4.2/source/include/net/bluetooth/hci_mon.h#L34
bind_layers(HCI_Mon_Hdr, HCI_Mon_New_Index, opcode=0)
bind_layers(HCI_Mon_Hdr, HCI_Command_Hdr, opcode=2)
bind_layers(HCI_Mon_Hdr, HCI_Event_Hdr, opcode=3)
bind_layers(HCI_Mon_Hdr, HCI_Mon_Index_Info, opcode=10)
bind_layers(HCI_Mon_Hdr, HCI_Mon_System_Note, opcode=12)

conf.l2types.register(DLT_BLUETOOTH_LINUX_MONITOR, HCI_Mon_Pcap_Hdr)


###########
# Sockets #
###########

class BluetoothMonitorSocket(_BluetoothLibcSocket):
    desc = "Read/write over a Bluetooth monitor channel"

    def __init__(self):
        sa = sockaddr_hci()
        sa.sin_family = socket.AF_BLUETOOTH
        sa.hci_dev = HCI_DEV_NONE
        sa.hci_channel = HCI_CHANNEL_MONITOR
        super().__init__(
            socket_domain=socket.AF_BLUETOOTH,
            socket_type=socket.SOCK_RAW,
            socket_protocol=socket.BTPROTO_HCI,
            sock_address=sa)

    def recv(self, x=MTU):
        return HCI_Mon_Hdr(self.ins.recv(x))
