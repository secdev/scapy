## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Customization for the Solaris operation system.
"""

# IPPROTO_GRE is missing on Solaris
import socket
socket.IPPROTO_GRE = 47

LOOPBACK_NAME="lo0"

from unix import *
