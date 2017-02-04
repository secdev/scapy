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
from scapy.utils import get_temp_file
from scapy.consts import WINDOWS
from scapy.config import conf

if WINDOWS:
    if conf.prog.sox is None:
        raise OSError("Sox must be installed to play VoIP packets")
else:
    from fcntl import fcntl

def merge(x,y,sample_size=2):
    if len(x) > len(y):
        y += "\x00"*(len(x)-len(y))
    elif len(x) < len(y):
        x += "\x00"*(len(y)-len(x))
    m = ""
    ss=sample_size
    for i in xrange(len(x)/ss):
        m += x[ss*i:ss*(i+1)]+y[ss*i:ss*(i+1)]
    return  m
#    return  "".join(map(str.__add__, x, y))


def voip_play(s1,list=None,**kargs):
    """Play VoIP packets with RAW data that
    are either sniffed either from an IP, or
    specified as a list
    
    :param s1: The IP of the src or of the
    dst of any VoIP packet.
    :param list: (optional) A list of packets to load
    :type s1: string
    :type list: list

    :Example:

    >>> voip_play("64.2.142.189")
    while calling '411@ideasip.com'

    >>> voip_play(None, list)
    with list a list of packets with VoIP data
    in their RAW layer

    .. note:: On Windows, this will act like
    voip_play1

    .. seealso:: voip_play1
    to avoid using FIFO

    .. seealso:: voip_play3
    to read RTP VoIP packets
    """
    if WINDOWS:
        return voip_play1(s1, list, **kargs)
    FIFO1=get_temp_file()
    FIFO2=get_temp_file()
    
    os.mkfifo(FIFO1)
    os.mkfifo(FIFO2)
    try:
        os.system("soxmix -t .ul %s -t .ul %s -t ossdsp /dev/dsp &" % (FIFO1,FIFO2))
        
        c1=open(FIFO1,"w", 4096)
        c2=open(FIFO2,"w", 4096)
        fcntl.fcntl(c1.fileno(),fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(c2.fileno(),fcntl.F_SETFL, os.O_NONBLOCK)
    
    #    dsp,rd = os.popen2("sox -t .ul -c 2 - -t ossdsp /dev/dsp")
        def play(pkt, last=None):
            if last is None:
                last = []
            if not pkt:
                return 
            if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
                return 
            ip=pkt.getlayer(IP)
            if s1 in [ip.src, ip.dst]:
                if not last:
                    last.append(pkt)
                    return
                load=last.pop()
    #            x1 = load.load[12:]
                c1.write(load.load[12:])
                if load.getlayer(IP).src == ip.src:
    #                x2 = ""
                    c2.write("\x00"*len(load.load[12:]))
                    last.append(pkt)
                else:
    #                x2 = pkt.load[:12]
                    c2.write(pkt.load[12:])
    #            dsp.write(merge(x1,x2))
    
        if list is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in list:
                play(p)
    finally:
        os.unlink(FIFO1)
        os.unlink(FIFO2)



def voip_play1(s1,list=None,**kargs):
    """
    No-FIFO version of voip_play
    It will not store the data in a temp file, which
    might be faster

    .. seealso:: voip_play
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
        if s1 in [ip.src, ip.dst]:
            from scapy.config import conf
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

def voip_play2(s1,**kargs):
    # FIXME
    if not WINDOWS:
        _command = "sox -t .ul -c 2 - -t ossdsp /dev/dsp"
    else:
        _command = conf.prog.sox + " -t .ul -c 2 - -t waveaudio"
    dsp,rd = os.popen2(_command)
    def play(pkt, last=None):
        if last is None:
            last = []
        if not pkt:
            return 
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return 
        ip=pkt.getlayer(IP)
        if s1 in [ip.src, ip.dst]:
            if not last:
                last.append(pkt)
                return
            load=last.pop()
            x1 = load.load[12:]
#            c1.write(load.load[12:])
            if load.getlayer(IP).src == ip.src:
                x2 = ""
#                c2.write("\x00"*len(load.load[12:]))
                last.append(pkt)
            else:
                x2 = pkt.load[:12]
#                c2.write(pkt.load[12:])
            dsp.write(merge(x1,x2))
            
    sniff(store=0, prn=play, **kargs)

def voip_play3(lst=None,**kargs):
    """
    Read and play VoIP RTP packets
    
    .. seealso:: voip_play
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

