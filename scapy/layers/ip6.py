## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.error import log_interactive
from scapy.packet import *
from scapy.fields import *


class IPv6(Packet):
    """See http://namabiiru.hongo.wide.ad.jp/scapy6"""
    name = "IPv6 not implemented here." 
    def __init__(self, *args, **kargs):
        log_interactive.error(self.name)
    def __repr__(self):
        return "<IPv6: ERROR not implemented>"
    
class _IPv6OptionHeader(Packet):
    """See http://namabiiru.hongo.wide.ad.jp/scapy6"""
    name = "IPv6 not implemented here."
    def __init__(self, *args, **kargs):
        log_interactive.error(self.name)
    def __repr__(self):
        return "<IPv6: ERROR not implemented>"


