#! /usr/bin/env python

# Copyright (C) 2014 Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
# 2014 Alexis Sultan    <alexis.sultan@sfr.com>
# 2012 ffranz <ffranz@iniqua.com>
#
# This program is published under a GPLv2 license

# scapy.contrib.description = GTP
# scapy.contrib.status = loads

import time
import logging

from scapy.packet import bind_layers
from scapy.layers.inet import IP, UDP

import gtp_v1
import gtp_v2

# Bind GTP-C
bind_layers(UDP, gtp_v1.GTPHeader, dport=2123)
bind_layers(UDP, gtp_v1.GTPHeader, sport=2123)

# Bind GTP-U
bind_layers(UDP, gtp_v1.GTP_U_Header, dport=2152)
bind_layers(UDP, gtp_v1.GTP_U_Header, sport=2152)
bind_layers(gtp_v1.GTP_U_Header, IP, gtp_type=255)

if __name__ == "__main__":
    from scapy.all import *
    interact(mydict=globals(), mybanner="GTPv1 & GTPv2 add-on")
