# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Customization for the Solaris operation system.
"""

from scapy.arch.unix import *  # noqa: F401,F403

# IPPROTO_GRE is missing on Solaris
import socket
socket.IPPROTO_GRE = 47
