#!/usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

from scapy.supersocket import SuperSocket
from scapy.utils import PcapWriter


class SocketLogger:
    """
    A SuperSocket modifier that logs all sent and received packets to a PCAP file.
    """

    def __init__(self, sock: SuperSocket, pcap_writer: PcapWriter):
        """
        Initialize the Socket Logger.

        :param sock: The underlying socket (SuperSocket instance) to log packets from
        :param pcap_writer: Configured PcapWriter instance to log packets to
        """
        self.sock = sock
        self.pcap_writer = pcap_writer
        # Backup original send and recv methods
        self.sock_send_original = sock.send
        self.sock_recv_original = sock.recv
        # Attach the logger
        self.sock.send = self._send
        self.sock.recv = self._recv

    def _send(self, pkt):
        """
        Send a packet and log it to the PCAP file.

        :param pkt: The packet to send
        :return: Result of the send operation
        """
        len = self.sock_send_original(pkt)
        self.pcap_writer.write(pkt)
        return len

    def _recv(self, x=65535):
        """
        Receive a packet and log it to the PCAP file.

        :param x: Maximum size to receive
        :return: The received packet
        """
        pkt = self.sock_recv_original(x)
        if pkt:
            self.pcap_writer.write(pkt)
        return pkt

    def close(self):
        """
        Close the logger, flush the PCAP writer, and restore original socket methods.
        """
        # Restore original methods
        self.sock.send = self.sock_send_original
        self.sock.recv = self.sock_recv_original
        # Close the PCAP writer
        self.pcap_writer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
