## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
Aggregate top level objects from all TLS modules.
"""

#XXX Sort through imports when there is no python-ecdsa support.
#XXX Same thing for GCM, CCM...
#XXX no SSLv2 nor TLS 1.3 support

from scapy.layers.tls.cert import *

from scapy.layers.tls.automaton import *
from scapy.layers.tls.handshake import *
from scapy.layers.tls.keyexchange import *
from scapy.layers.tls.record import *
from scapy.layers.tls.session import *

from scapy.layers.tls.crypto.all import *

