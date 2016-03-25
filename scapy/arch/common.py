## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Functions common to different architectures
"""

import socket
from fcntl import ioctl
import struct


def get_if(iff, cmd):
    """Ease SIOCGIF* ioctl calls"""

    sck = socket.socket()
    ifreq = ioctl(sck, cmd, struct.pack("16s16x", iff))
    sck.close()
    return ifreq
