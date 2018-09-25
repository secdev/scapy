# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
VoIP (Voice over IP) related functions
"""

from __future__ import absolute_import
import os
###################
#   Listen VoIP   #
###################

from scapy.sendrecv import sniff
from scapy.layers.inet import IP, UDP
from scapy.layers.rtp import RTP
from scapy.consts import WINDOWS
from scapy.config import conf
from scapy.modules.six.moves import range


sox_base = "sox -t .ul %s - -t ossdsp /dev/dsp"

if WINDOWS:
    if conf.prog.sox is None:
        raise OSError("Sox must be installed to play VoIP packets")
    sox_base = "\"" + conf.prog.sox + "\" -t .ul %s - -t waveaudio"


def _merge_sound_bytes(x, y, sample_size=2):
    # TODO: find a better way to merge sound bytes
    # This will only add them one next to each other:
    # \xff + \xff ==> \xff\xff
    m = ""
    ss = sample_size
    min_ = 0
    if len(x) >= len(y):
        min_ = y
    elif len(x) < len(y):
        min_ = x
    r_ = len(min_)
    for i in range(r_ / ss):
        m += x[ss * i:ss * (i + 1)] + y[ss * i:ss * (i + 1)]
    return x[r_:], y[r_:], m


def voip_play(s1, lst=None, **kargs):
    """Play VoIP packets with RAW data that
    are either sniffed either from an IP, or
    specified as a list.

    It will play only the incoming packets !

    :param s1: The IP of the src of all VoIP packets.
    :param lst: (optional) A list of packets to load
    :type s1: string
    :type lst: list

    :Example:

    >>> voip_play("64.2.142.189")
    while calling '411@ideasip.com'

    >>> voip_play("64.2.142.189", lst)
    with list a list of packets with VoIP data
    in their RAW layer

    .. seealso:: voip_play2
    to play both the outcoming and incoming packets
    at the same time.

    .. seealso:: voip_play3
    to read RTP VoIP packets
    """

    dsp, rd = os.popen2(sox_base % "")

    def play(pkt):
        if not pkt:
            return
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return
        ip = pkt.getlayer(IP)
        if s1 == ip.src:
            dsp.write(pkt.getlayer(conf.raw_layer).load[12:])
    try:
        if lst is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in lst:
                play(p)
    finally:
        dsp.close()
        rd.close()


def voip_play1(s1, lst=None, **kargs):
    """Same than voip_play, backward compatibility
    """
    return voip_play(s1, lst, **kargs)


def voip_play2(s1, **kargs):
    """
    Same than voip_play, but will play
    both incoming and outcoming packets.
    The sound will surely suffer distortion.

    Only supports sniffing.

    .. seealso:: voip_play
    to play only incoming packets.
    """
    dsp, rd = os.popen2(sox_base % "-c 2")
    global x1, x2
    x1 = ""
    x2 = ""

    def play(pkt):
        global x1, x2
        if not pkt:
            return
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return
        ip = pkt.getlayer(IP)
        if s1 in [ip.src, ip.dst]:
            if ip.dst == s1:
                x1 += pkt.getlayer(conf.raw_layer).load[12:]
            else:
                x2 += pkt.getlayer(conf.raw_layer).load[12:]
            x1, x2, r = _merge_sound_bytes(x1, x2)
            dsp.write(r)

    sniff(store=0, prn=play, **kargs)


def voip_play3(lst=None, **kargs):
    """Same than voip_play, but made to
    read and play VoIP RTP packets, without
    checking IP.

    .. seealso:: voip_play
    for basic VoIP packets
    """
    dsp, rd = os.popen2(sox_base % "")

    def play(pkt, dsp=dsp):
        if pkt and pkt.haslayer(UDP) and pkt.haslayer(RTP):
            dsp.write(pkt.getlayer(RTP).load)
    try:
        if lst is None:
            sniff(store=0, prn=play, **kargs)
        else:
            for p in lst:
                play(p)
    finally:
        try:
            dsp.close()
            rd.close()
        except Exception:
            pass
