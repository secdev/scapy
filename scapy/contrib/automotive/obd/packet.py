# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.status = skip

from scapy.packet import Packet


class OBD_Packet(Packet):
    def extract_padding(self, s):
        return '', s
