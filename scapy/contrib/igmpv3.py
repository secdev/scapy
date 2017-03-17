#! /usr/bin/env python

# This file has been has been downloaded from the Scapy Contrib at
# https://github.com/secdev/scapy/tree/master/scapy/contrib
#
# For licensing information please refer to Scapy's license:
# https://github.com/secdev/scapy/blob/master/LICENSE
#
#  The following changes have been done to the file:
#  - Remove the adjust_ether function as this is now done automatically by
#    Scapy
#    See getmacbyip() in scapy/layers/l2.py
#  - Add IGMPv3GR and IGMPv3Report classes for IGMPv3 Report Messages
#  - Make code compliant with PEP8, except by having lines longer than 79 chars

# http://trac.secdev.org/scapy/ticket/31
# scapy.contrib.description = IGMPv3
# scapy.contrib.status = loads

from scapy.all import (
    atol,
    checksum,
    IP,
    Ether,
    Packet,
    ByteEnumField,
    ByteField,
    FieldLenField,
    IPField,
    FieldListField,
    XByteField,
    XShortField,
    ShortField,
    IPOption_Router_Alert,
    BitField,
    bind_layers
)
""" IGMP Scapy Extension

This file implements an IGMPv3 extension based on the following references:
 http://www.iana.org/assignments/igmp-type-numbers
 http://www.rfc-editor.org/rfc/pdfrfc/rfc3376.txt.pdf

See RFC3376, Section 4. Message Formats for definitions of proper
 IGMPv3 message format
"""


def is_valid_mc_addr(ip):
    """convert dotted quad string to long and check the first octet"""
    first_oct = atol(ip) >> 24 & 0xFF
    max_oct = 224
    min_oct = 239
    return (first_oct >= max_oct) and (first_oct <= min_oct)


def get_cksum(self, payload):
    """return checksum of a given payload"""
    if self.chksum is None:
        ck = checksum(payload)
        pay = payload[:2] + chr(ck >> 8) + chr(ck & 0xff) + payload[4:]
    return pay


def adjust_ether(ip=None, ether=None):
    """
        Called to explicitely fixup an associated Ethernet header
        The function adjusts the ethernet header destination MAC address based
        on the destination IP address.
    """
    # The rules are:
    #   1. send to the group mac address address corresponding to the IP.dst
    if (ip is None and ip.haslayer(IP)) and \
       (ether is None and ether.haslayer(Ether)):
        if is_valid_mc_addr(ip.dst):
            iplong = atol(ip.dst)
            ether.dst = "01:00:5e:%02x:%02x:%02x" % ((iplong >> 16) & 0x7F,
                                                     (iplong >> 8) & 0xFF,
                                                     (iplong) & 0xFF)
            print("update MC -> ip " + ip.dst + " as mac " + ether.dst)
            return True
    else:
        return False


class IGMPv3GR(Packet):

    """IGMP Group Record for IGMPv3 Membership Report

    This class should be concatenated to an instantiation of class IGMPv3.
    An IGMPv3 Report message can have N amount of Group Records.
    Within the IGMPv3 instantiation, the numgrprecs element will
    need to be manipulated to indicate the proper number of group records.

    Example usage:

    Create as many Group Records as needed
    gr1 = IGMPv3GR()
    gr2 = IGMPv3GR()
    Append the GRs to an IGMPv3Report class:
    report = IGMPv3Report()/gr1/gr2
    Update the numgrprecs:
    report.numgrprecs = 2
    """
    name = "IGMPv3GR"
    igmpv3grtypes = {1: "IS_IN",
                     2: "IS_EX",
                     3: "TO_IN",
                     4: "TO_EX",
                     5: "ALLOW",
                     6: "BLOCK"}

    fields_desc = [ByteEnumField("rtype", 1, igmpv3grtypes),
                   ByteField("auxdlen", 0),
                   FieldLenField("numsrcs", None, count_of="srcaddrs"),
                   IPField("maddr", "0.0.0.0"),
                   FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"),
                                  "numsrcs")]

    def mysummary(self):
        """Display a summary of the IGMPv3 group record."""
        return self.sprintf("IGMPv3 Group Record \
                            %IGMPv3gr.type% %IGMPv3gr.maddr%")


class IGMPv3Report(Packet):

    """IGMP Report Class for v3.

    The IGMP v3 Report header differs significantly from other IGMP messages,
    therefore an specific class is implemented for it.

    'chksum' is automatically calculated before the packet is sent.
    """
    name = "IGMPv3Report"
    fields_desc = [XByteField("type", 0x22),  # Type 0x22 : "V3 Member Report"
                   ByteField("resv", 0),
                   XShortField("chksum", None),
                   ShortField("resv2", 0),
                   ShortField("numgrprecs", 0)]  # Update manually GR are added

    def igmpize(self, ip=None, ether=None):  # noqa
        """Called to explicitely fixup associated IP headers

        :param self: The instantiation of an IGMP class.
        :param ip: The instantiation of the associated IP class.
        :param ether: Ether is not required but leaving here to maintain
            compatibility with the v1 and v2 implementation
        """
        ip.dst = "224.0.0.22"  # RFC 3376, 4.2.14
        # RFC 3376, Section 4. Message Formats
        ip.proto = 2
        ip.ttl = 1
        ip.options = [IPOption_Router_Alert()]
        ip.tos = 0xc0
        adjust_ether(ip, ether)
        iplong = atol(ip.dst)
        ether.dst = "01:00:5e:%02x:%02x:%02x" % ((iplong >> 16) & 0x7F,
                                                 (iplong >> 8) & 0xFF,
                                                 (iplong) & 0xFF)

    def post_build(self, p, pay):
        """
            Called implicitly before a packet is sent to
            compute and place IGMPv3 checksum.
        """
        p += pay
        return get_cksum(self, p)

    def mysummary(self):
        """Display a summary of the IGMPv3 Report object."""
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("IGMPv3Report: \
                                           %IP.src% > %IP.dst% \
                                           %IGMPv3Report.type%")
        else:
            return self.sprintf("IGMPv3Report %IGMPv3.type%")


class IGMPv3(Packet):

    """IGMP Message Class for v3.

    The fields defined below are a direct interpretation of the v3
    Membership Query Message.
    For 'numsrc', do not assign a value. Instead add to the 'srcaddrs'
    list to auto-set 'numsrc'.
    To assign values to 'srcaddrs', use the following methods:
    cigmp = IGMPv3()
    cigmp.srcaddrs = ['1.2.3.4', '5.6.7.8']
    cigmp.srcaddrs += ['192.168.10.24']
    At this point, 'cigmp.numsrc' is three (3)

    'chksum' is automatically calculated before the packet is sent.
    'mrcode' is also the Advertisement Interval field
    """
    name = "IGMPv3"
    igmpv3types = {0x11: "Membership Query",
                   0x22: "Version 3 Membership Report",
                   0x30: "Multicast Router Advertisement",
                   0x31: "Multicast Router Solicitation",
                   0x32: "Multicast Router Termination"}

    fields_desc = [ByteEnumField("type", 0x11, igmpv3types),
                   ByteField("mrcode", 0),
                   XShortField("chksum", None),
                   IPField("gaddr", "0.0.0.0"),
                   BitField("resv", 0, 4),
                   BitField("s", 0, 1),
                   BitField("qrv", 0, 3),
                   ByteField("qqic", 0),
                   FieldLenField("numsrc", None, count_of="srcaddrs"),
                   FieldListField("srcaddrs", None, IPField("sa", "0.0.0.0"),
                                  "numsrc")]

    def float_encode(self, value):
        """Convert the integer value to its IGMPv3 encoded time value if
            needed.

        As defined in tools.ietf.org/html/rfc3376#section-4.1.1

        If value < min_val, return the value specified. If >= min_val, encode
        as a floating point value. Value can be 0 - 31744.
        """
        min_val = 128
        max_val = 31743
        counter = 31
        if value < min_val:
            code = value
        elif value > max_val:
            code = 255
        else:
            exp = 0
            value >>= 3
            while (value > counter):
                exp += 1
                value >>= 1
            exp <<= 4
            code = 0x80 | exp | (value & 0x0F)
        return code

    def post_build(self, payload, pay):
        """
        Called implicitly before a packet is sent to compute
        and place IGMPv3 checksum.

        :param self: The instantiation of an IGMPv3 class
        :param p: The IGMPv3 message in hex in network byte order
        :param pay: Additional payload for the IGMPv3 message
        """
        payload += pay
        if self.type in [0, 0x31, 0x32, 0x22]:   # for field is reserved (0)
            payload = payload[:1] + chr(0) + payload[2:]
        return get_cksum(self, payload)

    def mysummary(self):
        """
        Display a summary of the IGMPv3 object.
        """
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("IGMPv3: %IP.src% > %IP.dst% \
                                           %IGMPv3.type% %IGMPv3.gaddr%")
        else:
            return self.sprintf("IGMPv3 %IGMPv3.type% %IGMPv3.gaddr%")

    def igmpize(self, ip=None, ether=None):
        """
        Called to explicitely fixup associated IP and Ethernet headers

        :param self: The instantiation of an IGMP class.
        :param ip: The instantiation of the associated IP class.
        :param ether: Ether is not required but leaving here to maintain
            compatibility with the v1 and v2 implementation

        :returns:
            True: The tuple ip/self passed all check and represents
                a proper IGMP packet.
            False: One of more validation checks failed and no fields
                were adjusted.

        The function will examine the IGMP message to assure proper format.
        Corrections will be attempted if possible. The IP header is then
        properlyadjusted to ensure correct formatting and assignment.
        The Ethernet header is then adjusted to the proper IGMP packet format.

        The rules are:
            1. ttl = 1 (RFC 2236, section 2)
                igmp_binds = [ (IP, IGMP,   { "proto": 2 , "ttl": 1 }),
            2. tos = 0xC0 (RFC 3376, section 4)
                (IP, IGMPv3, { "proto": 2 , "ttl": 1, "tos":0xc0 }),
                (IGMPv3, IGMPv3gr, { }) ]

        The rules are:
            1. The Max Response time is meaningful only in Membership Queries
                and should be zero otherwise (RFC 2236, section 2.2)
        """
        if (self.type != 0x11):  # rule 1
            self.mrtime = 0
        if (self.adjust_ip(ip) is True):
            if (adjust_ether(ip, ether) is True):
                return True
        return False

    def adjust_ip(self, ip=None):
        """Called to explicitely fixup an associated IP header

        The function adjusts the IP header based on conformance rules
        and the group address encoded in the IGMP message.

        The rules are:
        1. Send General Group Query to 224.0.0.1 (all systems)
        2. Send Leave Group to 224.0.0.2 (all routers)
        3. Otherwise send the packet to the group address
        4. Send reports/joins to the group address
        5. ttl = 1 (RFC 2236, section 2)
        6. Send the pkt with router alert IP option (RFC 2236, section 2)

        """
        if ip is not None and ip.haslayer(IP):
            if (self.type == 0x11):
                if (self.gaddr == "0.0.0.0"):
                    ip.dst = "224.0.0.1"                   # IP rule 1
                    ret_code = True
                elif is_valid_mc_addr(self.gaddr):
                    ip.dst = self.gaddr                    # IP rule 3a
                    ret_code = True
                else:
                    print("Warning: Using invalid Group Address")
                    ret_code = False
            elif ((self.type == 0x17) and is_valid_mc_addr(self.gaddr)):
                ip.dst = "224.0.0.2"                   # IP rule 2
                ret_code = True
            elif ((self.type == 0x12) or (self.type == 0x16)) and \
                 (is_valid_mc_addr(self.gaddr)):
                ip.dst = self.gaddr                    # IP rule 3b
                ret_code = True
            else:
                print("Warning: Using invalid IGMP Type")
                ret_code = False
        else:
            print("Warning: No IGMP Group Address set")
            ret_code = False
        if ret_code is True:
            ip.ttl = 1                                  # IP Rule 4
            ip.options = [IPOption_Router_Alert()]      # IP rule 5
        return ret_code


if __name__ == '__main__':
    bind_layers(IP, IGMPv3Report, frag=0, proto=2, ttl=1, tos=0xc0)
    bind_layers(IP, IGMPv3, frag=0, proto=2, ttl=1, tos=0xc0)
    bind_layers(IGMPv3, IGMPv3GR, numgrprecs=1)
