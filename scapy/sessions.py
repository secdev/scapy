# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Sessions: decode flow of packets when sniffing
"""

from collections import defaultdict
from scapy.plist import PacketList
from scapy.compat import raw


class DefaultSession(object):
    """Default session: no stream decoding"""

    def __init__(self, prn, store):
        self.prn = prn
        self.store = store
        self.lst = []

    def toPacketList(self):
        return PacketList(self.lst, "Sniffed")

    def on_packet_received(self, pkt):
        """DEV: entry point. Will be called by sniff() for each
        received packet (that passes the filters).
        """
        if not pkt:
            return
        if self.store:
            self.lst.append(pkt)
        if self.prn:
            result = self.prn(pkt)
            if result is not None:
                print(result)


class IPSession(DefaultSession):
    """Defragment IP packets 'on-the-flow'.
    Usage:
      >>> sniff(session=IPSession)
    """

    def __init__(self, *args):
        DefaultSession.__init__(self, *args)
        self.fragments = defaultdict(lambda: [])

    def _ip_process_packet(self, packet):
        from scapy.layers.inet import _defrag_list, IP
        if IP not in packet:
            return packet
        ip = packet[IP]
        packet._defrag_pos = 0
        if ip.frag != 0 or ip.flags.MF:
            uniq = (ip.id, ip.src, ip.dst, ip.proto)
            self.fragments[uniq].append(packet)
            if not ip.flags.MF:  # end of frag
                try:
                    if self.fragments[uniq][0].frag == 0:
                        # Has first fragment (otherwise ignore)
                        defrag, missfrag = [], []
                        _defrag_list(self.fragments[uniq], defrag, missfrag)
                        defragmented_packet = defrag[0]
                        defragmented_packet = defragmented_packet.__class__(
                            raw(defragmented_packet)
                        )
                        return defragmented_packet
                finally:
                    del self.fragments[uniq]
        else:
            return packet

    def on_packet_received(self, pkt):
        pkt = self._ip_process_packet(pkt)
        DefaultSession.on_packet_received(self, pkt)
