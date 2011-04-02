#! /usr/bin/env python

# http://trac.secdev.org/scapy/ticket/31

# scapy.contrib.description = IGMPv3
# scapy.contrib.status = loads

from scapy.packet import *

""" Based on the following references
 http://www.iana.org/assignments/igmp-type-numbers
 http://www.rfc-editor.org/rfc/pdfrfc/rfc3376.txt.pdf

"""

#  TODO: Merge IGMPv3 packet Bindlayers correct for 
#        membership source/Group records
#        ConditionalField parameters for IGMPv3 commented out
#
# See RFC3376, Section 4. Message Formats for definitions of proper IGMPv3 message format
#   http://www.faqs.org/rfcs/rfc3376.html
#
# See RFC4286, For definitions of proper messages for Multicast Router Discovery.
#   http://www.faqs.org/rfcs/rfc4286.html
#

#import sys, socket, struct, time
from scapy.all import *
print "IGMPv3  is still under development - Nov 2010"


class IGMPv3gr(Packet):
  """IGMP Group Record for IGMPv3 Membership Report

  This class is derived from class Packet and should be concatenated to an
  instantiation of class IGMPv3. Within the IGMPv3 instantiation, the numgrp
  element will need to be manipulated to indicate the proper number of
  group records.
  """
  name = "IGMPv3gr"
  igmpv3grtypes = { 1 : "Mode Is Include",
                    2 : "Mode Is Exclude",
                    3 : "Change To Include Mode",
                    4 : "Change To Exclude Mode",
                    5 : "Allow New Sources",
                    6 : "Block Old Sources"}

  fields_desc = [ ByteEnumField("rtype", 1, igmpv3grtypes),
                      ByteField("auxdlen",0),
                  FieldLenField("numsrc", None, "srcaddrs"),
                        IPField("maddr", "0.0.0.0"),
                 FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"), "numsrc") ]
  #show_indent=0
#--------------------------------------------------------------------------
  def post_build(self, p, pay):
    """Called implicitly before a packet is sent.
    """
    p += pay
    if self.auxdlen != 0:
      print "NOTICE: A properly formatted and complaint V3 Group Record should have an Auxiliary Data length of zero (0)."
      print "        Subsequent Group Records are lost!"
    return p
#--------------------------------------------------------------------------
  def mysummary(self):
    """Display a summary of the IGMPv3 group record."""
    return self.sprintf("IGMPv3 Group Record %IGMPv3gr.type% %IGMPv3gr.maddr%")


class IGMPv3(Packet):
  """IGMP Message Class for v3.

  This class is derived from class Packet. 
  The fields defined below are a 
  direct interpretation of the v3 Membership Query Message. 
  Fields 'type'  through 'qqic' are directly assignable. 
  For 'numsrc', do not assign a value. 
  Instead add to the 'srcaddrs' list to auto-set 'numsrc'. To 
  assign values to 'srcaddrs', use the following methods:
    c = IGMPv3()
    c.srcaddrs = ['1.2.3.4', '5.6.7.8']
    c.srcaddrs += ['192.168.10.24']
  At this point, 'c.numsrc' is three (3)

  'chksum' is automagically calculated before the packet is sent.

  'mrcode' is also the Advertisement Interval field

  """
  name = "IGMPv3"
  igmpv3types = { 0x11 : "Membership Query",
                  0x22 : "Version 3 Membership Report",
                  0x30 : "Multicast Router Advertisement",
                  0x31 : "Multicast Router Solicitation",
                  0x32 : "Multicast Router Termination"}

  fields_desc = [ ByteEnumField("type", 0x11, igmpv3types),
                      ByteField("mrcode",0),
                    XShortField("chksum", None),
                    IPField("gaddr", "0.0.0.0")
                    ]
                                          # use float_encode()

    # if type = 0x11 (Membership Query), the next field is group address 
    #   ConditionalField(IPField("gaddr", "0.0.0.0"), "type", lambda x:x==0x11),
    # else if type = 0x22 (Membership Report), the next fields are 
    #         reserved and number of group records
    #ConditionalField(ShortField("rsvd2", 0), "type", lambda x:x==0x22),
    #ConditionalField(ShortField("numgrp", 0), "type", lambda x:x==0x22),
#                  FieldLenField("numgrp", None, "grprecs")]
    # else if type = 0x30 (Multicast Router Advertisement), the next fields are 
    #         query interval and robustness
    #ConditionalField(ShortField("qryIntvl", 0), "type", lambda x:x==0x30),
    #ConditionalField(ShortField("robust", 0), "type", lambda x:x==0x30),
#  The following are only present for membership queries
       #   ConditionalField(BitField("resv", 0, 4), "type", lambda x:x==0x11),
       #   ConditionalField(BitField("s", 0, 1), "type", lambda x:x==0x11),
       #   ConditionalField(BitField("qrv", 0, 3), "type", lambda x:x==0x11), 
       #  ConditionalField(ByteField("qqic",0), "type", lambda x:x==0x11),
    # ConditionalField(FieldLenField("numsrc", None, "srcaddrs"), "type", lambda x:x==0x11),
    # ConditionalField(FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"), "numsrc"), "type", lambda x:x==0x11),

#--------------------------------------------------------------------------
  def float_encode(self, value):
    """Convert the integer value to its IGMPv3 encoded time value if needed.
   
    If value < 128, return the value specified. If >= 128, encode as a floating 
    point value. Value can be 0 - 31744.
    """
    if value < 128:
      code = value
    elif value > 31743:
      code = 255
    else:
      exp=0
      value>>=3
      while(value>31):
        exp+=1
        value>>=1
      exp<<=4
      code = 0x80 | exp | (value & 0x0F)
    return code

#--------------------------------------------------------------------------
  def post_build(self, p, pay):
    """Called implicitly before a packet is sent to compute and place IGMPv3 checksum.

    Parameters:
      self    The instantiation of an IGMPv3 class
      p       The IGMPv3 message in hex in network byte order
      pay     Additional payload for the IGMPv3 message
    """
    p += pay
    if self.type in [0, 0x31, 0x32, 0x22]:   # for these, field is reserved (0)
      p = p[:1]+chr(0)+p[2:]
    if self.chksum is None:
      ck = checksum(p)
      p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
    return p

#--------------------------------------------------------------------------
  def mysummary(self):
    """Display a summary of the IGMPv3 object."""

    if isinstance(self.underlayer, IP):
      return self.underlayer.sprintf("IGMPv3: %IP.src% > %IP.dst% %IGMPv3.type% %IGMPv3.gaddr%")
    else:
      return self.sprintf("IGMPv3 %IGMPv3.type% %IGMPv3.gaddr%")

#--------------------------------------------------------------------------
  def igmpize(self, ip=None, ether=None):
    """Called to explicitely fixup associated IP and Ethernet headers

    Parameters:
      self    The instantiation of an IGMP class.
      ip      The instantiation of the associated IP class.
      ether   The instantiation of the associated Ethernet.

    Returns:
      True    The tuple ether/ip/self passed all check and represents
               a proper IGMP packet.
      False   One of more validation checks failed and no fields 
               were adjusted.

    The function will examine the IGMP message to assure proper format. 
    Corrections will be attempted if possible. The IP header is then properly 
    adjusted to ensure correct formatting and assignment. The Ethernet header
    is then adjusted to the proper IGMP packet format.
    """

# The rules are:
#   1.  ttl = 1 (RFC 2236, section 2)
#  igmp_binds = [ (IP, IGMP,   { "proto": 2 , "ttl": 1 }),
#   2.  tos = 0xC0 (RFC 3376, section 4)
#               (IP, IGMPv3, { "proto": 2 , "ttl": 1, "tos":0xc0 }),
#               (IGMPv3, IGMPv3gr, { }) ]
# The rules are:
#   1.  the Max Response time is meaningful only in Membership Queries and should be zero 
#       otherwise (RFC 2236, section 2.2)

    if (self.type != 0x11):         #rule 1
      self.mrtime = 0
      
    if (self.adjust_ip(ip) == True):
      if (self.adjust_ether(ip, ether) == True): return True
    return False

#--------------------------------------------------------------------------
  def adjust_ether (self, ip=None, ether=None):
    """Called to explicitely fixup an associated Ethernet header

    The function adjusts the ethernet header destination MAC address based on 
    the destination IP address.
    """
# The rules are:
#   1. send to the group mac address address corresponding to the IP.dst
    if ip != None and ip.haslayer(IP) and ether != None and ether.haslayer(Ether):
      iplong = atol(ip.dst)
      ether.dst = "01:00:5e:%02x:%02x:%02x" % ( (iplong>>16)&0x7F, (iplong>>8)&0xFF, (iplong)&0xFF )
      # print "igmpize ip " + ip.dst + " as mac " + ether.dst 
      return True
    else:
      return False

#--------------------------------------------------------------------------
  def adjust_ip (self, ip=None):
    """Called to explicitely fixup an associated IP header

    The function adjusts the IP header based on conformance rules 
    and the group address encoded in the IGMP message.
    The rules are:
    1. Send General Group Query to 224.0.0.1 (all systems)
    2. Send Leave Group to 224.0.0.2 (all routers)
    3a.Otherwise send the packet to the group address
    3b.Send reports/joins to the group address
    4. ttl = 1 (RFC 2236, section 2)
    5. send the packet with the router alert IP option (RFC 2236, section 2)
    """
    if ip != None and ip.haslayer(IP):
      if (self.type == 0x11):
        if (self.gaddr == "0.0.0.0"):
          ip.dst = "224.0.0.1"                   # IP rule 1
          retCode = True                     
        elif isValidMCAddr(self.gaddr):
          ip.dst = self.gaddr                    # IP rule 3a
          retCode = True
        else:
          print "Warning: Using invalid Group Address"
          retCode = False
      elif ((self.type == 0x17) and isValidMCAddr(self.gaddr)):
          ip.dst = "224.0.0.2"                   # IP rule 2
          retCode = True
      elif ((self.type == 0x12) or (self.type == 0x16)) and (isValidMCAddr(self.gaddr)):
          ip.dst = self.gaddr                    # IP rule 3b
          retCode = True
      else:
        print "Warning: Using invalid IGMP Type"
        retCode = False
    else:
      print "Warning: No IGMP Group Address set"
      retCode = False
    if retCode == True:
       ip.ttl=1                                  # IP Rule 4
       ip.options=[IPOption_Router_Alert()]      # IP rule 5
    return retCode


bind_layers( IP,        IGMPv3,      frag=0, proto=2, ttl=1, tos=0xc0)
bind_layers( IGMPv3,    IGMPv3gr,    frag=0, proto=2)
bind_layers( IGMPv3gr,  IGMPv3gr,    frag=0, proto=2)

