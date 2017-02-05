## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
VoIP (Voice over IP) related functions
"""

import os
###################
##  Listen VoIP  ##
###################

from scapy.sendrecv import sniff
from scapy.layers.inet import IP,UDP
from scapy.layers.rtp import RTP
from scapy.consts import WINDOWS
from scapy.config import conf

if WINDOWS:
    if conf.prog.sox is None:
        raise OSError("Sox must be installed to play VoIP packets")
else:
    from fcntl import fcntl

def merge(x,y,sample_size=2):
    m = ""
    ss=sample_size
    for i in xrange(len(x)/ss):
        m += x[ss*i:ss*(i+1)]+y[ss*i:ss*(i+1)]
    return  m


def voip_play(s1, list=None, **kargs):
    """Play VoIP packets with RAW data that
    are either sniffed either from an IP, or
    specified as a list.

    It will play only the incoming packets !
    
    :param s1: The IP of the src of all VoIP packets.
    :param list: (optional) A list of packets to load
    :type s1: string
    :type list: list

    :Example:

    >>> voip_play("64.2.142.189")
    while calling '411@ideasip.com'

    >>> voip_play(None, list)
    with list a list of packets with VoIP data
    in their RAW layer

    .. seealso:: voip_play2
    to play both the outcoming and incoming packets
    at the same time.

    .. seealso:: voip_play3
    to read RTP VoIP packets
    """
    if not WINDOWS:
        _command = "sox -t .ul - -t ossdsp /dev/dsp"
    else:
        _command = conf.prog.sox + " -t .ul - -t waveaudio"
    dsp,rd = os.popen2(_command)
    def play(pkt):
        if not pkt:
            return 
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return 
        ip=pkt.getlayer(IP)
        if s1 == ip.src:
            dsp.write(pkt.getlayer(conf.raw_layer).load[12:])
    try:
        if list is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in list:
                play(p)
    finally:
        dsp.close()
        rd.close()



def voip_play1(s1, list=None, **kargs):
    """Same than voip_play, backward compatibility
    """
    return voip_play(s1, list, **kargs)

def voip_play2(s1,**kargs):
    """
    Same than voip_play, but will play
    both incoming and outcoming packets.
    The sound will surely suffer distortion.

    Only supports sniffing.

    .. seealso:: voip_play
    to play only incoming packets.
    """
    if not WINDOWS:
        _command = "sox -t .ul -c 2 - -t ossdsp /dev/dsp"
    else:
        _command = conf.prog.sox + " -t .ul -c 2 - -t waveaudio"
    dsp,rd = os.popen2(_command)
    global last
    last = None
    def play(pkt):
        global last
        if not pkt:
            return 
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return 
        ip=pkt.getlayer(IP)
        if s1 in [ip.src, ip.dst]:
            if not last:
                last = []
                last.append(pkt)
                return
            load=last.pop()
            x1 = load.getlayer(conf.raw_layer).load[12:]
            if load.getlayer(IP).src == ip.src:
                x2 = ""
                last.append(pkt)
            else:
                x2 = pkt.getlayer(conf.raw_layer).load[12:]
            dsp.write(merge(x1,x2))
            
    sniff(store=0, prn=play, **kargs)

def voip_play3(lst=None,**kargs):
    """Same than voip_play, but made to
    read and play VoIP RTP packets
    
    .. seealso:: voip_play
    for basic VoIP packets
    """
    if not WINDOWS:
        _command = "sox -t .ul - -t ossdsp /dev/dsp"
    else:
        _command = conf.prog.sox + " -t .ul - -t waveaudio"
    dsp,rd = os.popen2(_command)
    try:
        def play(pkt, dsp=dsp):
            from scapy.config import conf
            if pkt and pkt.haslayer(UDP) and pkt.haslayer(RTP):
                dsp.write(pkt.getlayer(RTP).load)
        if lst is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in lst:
                play(p)
    finally:
        try:
            dsp.close()
            rd.close()
        except:
            pass

