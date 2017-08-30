#! /usr/bin/env python

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = IGMP/IGMPv2
# scapy.contrib.status = loads

from __future__ import print_function
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import *
from scapy.layers.l2 import DestMACField, getmacbyip
from scapy.error import warning

def isValidMCAddr(ip):
    """convert dotted quad string to long and check the first octet"""
    FirstOct=atol(ip)>>24 & 0xFF
    return (FirstOct >= 224) and (FirstOct <= 239)

class IGMP(Packet):
    """IGMP Message Class for v1 and v2.

This class is derived from class Packet. You  need call "igmpize()"
so the packet is transformed according the RFC when sent.
a=Ether(src="00:01:02:03:04:05")
b=IP(src="1.2.3.4")
c=IGMP(type=0x12, gaddr="224.2.3.4")
x = a/b/c
x[IGMP].igmpize()
sendp(a/b/c, iface="en0")

    Parameters:
      type    IGMP type field, 0x11, 0x12, 0x16 or 0x17
      mrtime  Maximum Response time (zero for v1)
      gaddr   Multicast Group Address 224.x.x.x/4
      
See RFC2236, Section 2. Introduction for definitions of proper 
IGMPv2 message format   http://www.faqs.org/rfcs/rfc2236.html

  """
    name = "IGMP"
  
    igmptypes = { 0x11 : "Group Membership Query",
                  0x12 : "Version 1 - Membership Report",
                  0x16 : "Version 2 - Membership Report",
                  0x17 : "Leave Group"}

    fields_desc = [ ByteEnumField("type", 0x11, igmptypes),
                    ByteField("mrtime", 20),
                    XShortField("chksum", None),
                    IPField("gaddr", "0.0.0.0")]

    def post_build(self, p, pay):
        """Called implicitly before a packet is sent to compute and place IGMP checksum.

        Parameters:
          self    The instantiation of an IGMP class
          p       The IGMP message in hex in network byte order
          pay     Additional payload for the IGMP message
        """
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p

    def igmpize(self):
        """Applies IGMP rules to the packet"""
        gaddr = self.gaddr if self.gaddr else "0.0.0.0"
        underlayer = self.underlayer
        # The rules are:
        #   1.  the Max Response time is meaningful only in Membership Queries and should be zero 
        #       otherwise (RFC 2236, section 2.2)
        if self.type != 0x11:         # Rule 1
            self.mrtime = 0
        if isinstance(underlayer, IP):
            if (self.type == 0x11):
                if (gaddr == "0.0.0.0"):
                    underlayer.dst = "224.0.0.1"                        # IP rule 1
                elif isValidMCAddr(gaddr):
                    underlayer.dst = gaddr                             # IP rule 3a
                else:
                    warning("Invalid IGMP Group Address detected !")
                    return False
            elif ((self.type == 0x17) and isValidMCAddr(gaddr)):
                underlayer.dst = "224.0.0.2"                            # IP rule 2
            elif ((self.type == 0x12) or (self.type == 0x16)) and (isValidMCAddr(gaddr)):
                underlayer.dst = gaddr                                 # IP rule 3b
            else:
                warning("Invalid IGMP Type detected !")
                return False
            _root = self.firstlayer()
            if _root.haslayer(Ether):
                # Force recalculate Ether dst
                _root[Ether].dst = getmacbyip(underlayer.dst)
        return True

    def mysummary(self):
        """Display a summary of the IGMP object."""
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("IGMP: %IP.src% > %IP.dst% %IGMP.type% %IGMP.gaddr%")
        else:
            return self.sprintf("IGMP %IGMP.type% %IGMP.gaddr%")

bind_layers( IP,            IGMP,            frag=0,
                                             proto=2,
                                             ttl=1,
                                             options=[IPOption_Router_Alert()])
