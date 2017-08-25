## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Instanciate part of the customizations needed to support Microsoft Windows.
"""

from __future__ import absolute_import, print_function

from scapy.config import conf

# If wpcap.dll is not available
if not (conf.use_winpcapy or conf.use_pcap or conf.use_dnet):
    from scapy.arch.windows.disable_sendrecv import *
