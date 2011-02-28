#! /usr/bin/env python

# scapy.contrib.description = IGMP/IGMPv2
# scapy.contrib.status = loads


#  TODO: scapy 2 has function getmacbyip, maybe it can replace igmpize
#          at least from the MAC layer

from scapy.all import *

#--------------------------------------------------------------------------
def isValidMCAddr(ip):
  """convert dotted quad string to long and check the first octet"""
  FirstOct=atol(ip)>>24 & 0xFF
  return (FirstOct >= 224) and (FirstOct <= 239)

#--------------------------------------------------------------------------

class IGMP(Packet):
  """IGMP Message Class for v1 and v2.

This class is derived from class Packet. You  need to "igmpize"
the IP and Ethernet layers before a full packet is sent.
a=Ether(src="00:01:02:03:04:05")
b=IP(src="1.2.3.4")
c=IGMP(type=0x12, gaddr="224.2.3.4")
c.igmpize(b, a)
print "Joining IP " + c.gaddr + " MAC " + a.dst
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
                      ByteField("mrtime",20),
                    XShortField("chksum", None),
                        IPField("gaddr", "0.0.0.0")]

#--------------------------------------------------------------------------
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

#--------------------------------------------------------------------------
  def mysummary(self):
    """Display a summary of the IGMP object."""

    if isinstance(self.underlayer, IP):
      return self.underlayer.sprintf("IGMP: %IP.src% > %IP.dst% %IGMP.type% %IGMP.gaddr%")
    else:
      return self.sprintf("IGMP %IGMP.type% %IGMP.gaddr%")

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


bind_layers( IP,            IGMP,            frag=0, proto=2)


