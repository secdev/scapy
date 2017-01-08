## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Instanciate part of the customizations needed to support Microsoft Windows.
"""

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

WINDOWS = True

def sndrcv(pks, pkt, timeout = 2, inter = 0, verbose=None, chainCC=0, retry=0, multi=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
        
    if verbose is None:
        verbose = conf.verb
    from scapy.sendrecv import debug
    debug.recv = plist.PacketList([],"Unanswered")
    debug.sent = plist.PacketList([],"Sent")
    debug.match = plist.SndRcvList([])
    nbrecv=0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    all_stimuli = tobesent = [p for p in pkt]
    notans = len(tobesent)

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]
    if retry < 0:
        retry = -retry
        autostop=retry
    else:
        autostop=0


    while retry >= 0:
        found=0
    
        if timeout < 0:
            timeout = None

        pid=1
        try:
            if WINDOWS or pid == 0:
                try:
                    try:
                        i = 0
                        if verbose:
                            print "Begin emission:"
                        for p in tobesent:
                            pks.send(p)
                            i += 1
                            time.sleep(inter)
                        if verbose:
                            print "Finished to send %i packets." % i
                    except SystemExit:
                        pass
                    except KeyboardInterrupt:
                        pass
                    except:
                        log_runtime.exception("--- Error sending packets")
                        log_runtime.info("--- Error sending packets")
                finally:
                    try:
                        sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
                    except:
                        pass
            if WINDOWS or pid > 0:
                # Timeout starts after last packet is sent (as in Unix version) 
                if timeout:
                    stoptime = time.time()+timeout
                else:
                    stoptime = 0
                remaintime = None
                try:
                    try:
                        while 1:
                            if stoptime:
                                remaintime = stoptime-time.time()
                                if remaintime <= 0:
                                    break
                            r = pks.recv(MTU)
                            if r is None:
                                continue
                            ok = 0
                            h = r.hashret()
                            if h in hsent:
                                hlst = hsent[h]
                                for i, sentpkt in enumerate(hlst):
                                    if r.answers(sentpkt):
                                        ans.append((sentpkt, r))
                                        if verbose > 1:
                                            os.write(1, "*")
                                        ok = 1
                                        if not multi:
                                            del hlst[i]
                                            notans -= 1
                                        else:
                                            if not hasattr(sentpkt, '_answered'):
                                                notans -= 1
                                            sentpkt._answered = 1
                                        break
                            if notans == 0 and not multi:
                                break
                            if not ok:
                                if verbose > 1:
                                    os.write(1, ".")
                                nbrecv += 1
                                if conf.debug_match:
                                    debug.recv.append(r)
                    except KeyboardInterrupt:
                        if chainCC:
                            raise
                finally:
                    if WINDOWS:
                        for p,t in zip(all_stimuli, sent_times):
                            p.sent_time = t
        finally:
            pass

        remain = list(itertools.chain(*hsent.itervalues()))
        if multi:
            remain = [p for p in remain if not hasattr(p, '_answered')]
            
        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        if len(tobesent) == 0:
            break
        retry -= 1
        
    if conf.debug_match:
        debug.sent=plist.PacketList(remain[:],"Sent")
        debug.match=plist.SndRcvList(ans[:])

    #clean the ans list to delete the field _answered
    if (multi):
        for s,r in ans:
            if hasattr(s, '_answered'):
                del(s._answered)
    
    if verbose:
        print "\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans)
    return plist.SndRcvList(ans),plist.PacketList(remain,"Unanswered")


import scapy.sendrecv as sendrecv
sendrecv.sndrcv = sndrcv

def sniff(count=0, store=1, offline=None, prn = None, stop_filter=None, lfilter=None, L2socket=None, timeout=None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets
Select interface to sniff by setting conf.iface. Use show_interfaces() to see interface names.
  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
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
    while 1:
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
                    print r
            if stop_filter and stop_filter(p):
                break
            if 0 < count <= c:
                break
        except KeyboardInterrupt:
            break
    s.close()
    return plist.PacketList(lst,"Sniffed")

import scapy.sendrecv
sendrecv.sniff = sniff

# If wpcap.dll is not available
if not (conf.use_winpcapy or conf.use_pcap or conf.use_dnet):
    from scapy.arch.windows.disable_sendrecv import *
