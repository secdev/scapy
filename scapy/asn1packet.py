## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Packet holding data in Abstract Syntax Notation (ASN.1).
"""

from packet import *

class ASN1_Packet(Packet):
    ASN1_root = None
    ASN1_codec = None    
    def init_fields(self):
        flist = self.ASN1_root.get_fields_list()
        self.do_init_fields(flist)
        self.fields_desc = flist    
    def self_build(self):
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        return self.ASN1_root.build(self)    
    def do_dissect(self, x):
        return self.ASN1_root.dissect(self, x)
        

