## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Instanciate part of the customizations needed to support Microsoft Windows.
"""

from __future__ import absolute_import
from __future__ import print_function
import itertools
import os
import re
import socket
import subprocess
import sys
import time

from scapy.consts import LOOPBACK_NAME
from scapy.config import conf,ConfClass
from scapy.base_classes import Gen, SetGen
import scapy.plist as plist
from scapy.utils import PcapReader, tcpdump
from scapy.arch.pcapdnet import PcapTimeoutElapsed
from scapy.error import log_runtime
from scapy.data import MTU, ETH_P_ARP,ETH_P_ALL
import scapy.modules.six as six

WINDOWS = True


def sniff(count=0, store=1, offline=None, prn = None, stop_filter=None, lfilter=None, L2socket=None, timeout=None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets
Select interface to sniff by setting conf.iface. Use show_interfaces() to see interface names.
  count: number of packets to capture. 0 means infinity
  store: whether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
 filter: provide a BPF filter
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
stop_filter: python function applied to each packet to determine
             if we have to stop the capture after this packet
             ex: stop_filter = lambda x: x.haslayer(TCP)
    """
    c = 0

    if offline is None:
        log_runtime.info('Sniffing on %s' % conf.iface)
        if L2socket is None:
            L2socket = conf.L2listen
        s = L2socket(type=ETH_P_ALL, *arg, **karg)
    else:
        flt = karg.get('filter')
        s = PcapReader(offline if flt is None else
                       tcpdump(offline, args=["-w", "-", flt], getfd=True))
    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    while True:
        try:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break

            try:
                p = s.recv(MTU)
            except PcapTimeoutElapsed:
                continue
            if p is None:
                break
            if lfilter and not lfilter(p):
                continue
            if store:
                lst.append(p)
            c += 1
            if prn:
                r = prn(p)
                if r is not None:
                    print(r)
            if stop_filter and stop_filter(p):
                break
            if 0 < count <= c:
                break
        except KeyboardInterrupt:
            break
    s.close()
    return plist.PacketList(lst,"Sniffed")

import scapy.sendrecv
scapy.sendrecv.sniff = sniff

# If wpcap.dll is not available
if not (conf.use_winpcapy or conf.use_pcap or conf.use_dnet):
    from scapy.arch.windows.disable_sendrecv import *
