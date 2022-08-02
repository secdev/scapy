# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury

"""
Aggregate top level objects from all TLS modules.
"""

from scapy.layers.tls.cert import *  # noqa: F401

from scapy.layers.tls.automaton_cli import *  # noqa: F401
from scapy.layers.tls.automaton_srv import *  # noqa: F401
from scapy.layers.tls.extensions import *  # noqa: F401
from scapy.layers.tls.handshake import *  # noqa: F401
from scapy.layers.tls.handshake_sslv2 import *  # noqa: F401
from scapy.layers.tls.keyexchange import *  # noqa: F401
from scapy.layers.tls.keyexchange_tls13 import *  # noqa: F401
from scapy.layers.tls.record import *  # noqa: F401
from scapy.layers.tls.record_sslv2 import *  # noqa: F401
from scapy.layers.tls.record_tls13 import *  # noqa: F401
from scapy.layers.tls.session import *  # noqa: F401

from scapy.layers.tls.crypto.all import *  # noqa: F401
