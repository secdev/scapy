# This file is part of Scapy
# See https://scapy.net/ for more information

"""
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_ether.h	8.1 (Berkeley) 6/10/93
 */
"""

# This file contains data automatically generated using
# scapy/tools/generate_ethertypes.py
# based on OpenBSD public source.

DATA = b"""
#
# Ethernet frame types
#       This file describes some of the various Ethernet
#       protocol types that are used on Ethernet networks.
#
# This list could be found on:
#         http://www.iana.org/assignments/ethernet-numbers
#         http://www.iana.org/assignments/ieee-802-numbers
#
# <name>    <hexnumber> <alias1>...<alias35> #Comment
#
8023            0004                         # IEEE 802.3 packet
PUP             0200                         # Xerox PUP protocol - see 0A00
PUPAT           0200                         # PUP Address Translation - see 0A01
NS              0600                         # XNS
NSAT            0601                         # XNS Address Translation (3Mb only)
DLOG1           0660                         # DLOG (?)
DLOG2           0661                         # DLOG (?)
IPv4            0800                         # IP protocol
X75             0801                         # X.75 Internet
NBS             0802                         # NBS Internet
ECMA            0803                         # ECMA Internet
CHAOS           0804                         # CHAOSnet
X25             0805                         # X.25 Level 3
ARP             0806                         # Address resolution protocol
FRARP           0808                         # Frame Relay ARP (RFC1701)
VINES           0BAD                         # Banyan VINES
TRAIL           1000                         # Trailer packet
DCA             1234                         # DCA - Multicast
VALID           1600                         # VALID system protocol
RCL             1995                         # Datapoint Corporation (RCL lan protocol)
NBPCC           3C04                         # 3Com NBP Connect complete not registered
NBPDG           3C07                         # 3Com NBP Datagram (like XNS IDP) not registered
PCS             4242                         # PCS Basic Block Protocol
IMLBL           4C42                         # Information Modes Little Big LAN
MOPDL           6001                         # DEC MOP dump/load
MOPRC           6002                         # DEC MOP remote console
LAT             6004                         # DEC LAT
SCA             6007                         # DEC LAVC, SCA
AMBER           6008                         # DEC AMBER
RAWFR           6559                         # Raw Frame Relay (RFC1701)
UBDL            7000                         # Ungermann-Bass download
UBNIU           7001                         # Ungermann-Bass NIUs
UBNMC           7003                         # Ungermann-Bass ??? (NMC to/from UB Bridge)
UBBST           7005                         # Ungermann-Bass Bridge Spanning Tree
OS9             7007                         # OS/9 Microware
RACAL           7030                         # Racal-Interlan
HP              8005                         # HP Probe
TIGAN           802F                         # Tigan, Inc.
DECAM           8048                         # DEC Availability Manager for Distributed Systems DECamds (but someone at DEC says not)
VEXP            805B                         # Stanford V Kernel exp.
VPROD           805C                         # Stanford V Kernel prod.
ES              805D                         # Evans & Sutherland
VEECO           8067                         # Veeco Integrated Auto.
ATT             8069                         # AT&T
MATRA           807A                         # Matra
DDE             807B                         # Dansk Data Elektronik
MERIT           807C                         # Merit Internodal (or Univ of Michigan?)
ATALK           809B                         # AppleTalk
PACER           80C6                         # Pacer Software
SNA             80D5                         # IBM SNA Services over Ethernet
RETIX           80F2                         # Retix
AARP            80F3                         # AppleTalk AARP
VLAN            8100                         # IEEE 802.1Q VLAN tagging (XXX conflicts)
BOFL            8102                         # Wellfleet; BOFL (Breath OF Life) pkts [every 5-10 secs.]
HAYES           8130                         # Hayes Microcomputers (XXX which?)
VGLAB           8131                         # VG Laboratory Systems
IPX             8137                         # Novell (old) NetWare IPX (ECONFIG E option)
MUMPS           813F                         # M/MUMPS data sharing
FLIP            8146                         # Vrije Universiteit (NL) FLIP (Fast Local Internet Protocol)
NCD             8149                         # Network Computing Devices
ALPHA           814A                         # Alpha Micro
SNMP            814C                         # SNMP over Ethernet (see RFC1089)
XTP             817D                         # Protocol Engines XTP
SGITW           817E                         # SGI/Time Warner prop.
STP             8181                         # Scheduled Transfer STP, HIPPI-ST
IPv6            86DD                         # IP protocol version 6
RDP             8739                         # Control Technology Inc. RDP Without IP
MICP            873A                         # Control Technology Inc. Mcast Industrial Ctrl Proto.
IPAS            876C                         # IP Autonomous Systems (RFC1701)
SLOW            8809                         # 803.3ad slow protocols (LACP/Marker)
PPP             880B                         # PPP (obsolete by PPPOE)
MPLS            8847                         # MPLS Unicast
AXIS            8856                         # Axis Communications AB proprietary bootstrap/config
PPPOE           8864                         # PPP Over Ethernet Session Stage
PAE             888E                         # 802.1X Port Access Entity
AOE             88A2                         # ATA over Ethernet
QINQ            88A8                         # 802.1ad VLAN stacking
LLDP            88CC                         # Link Layer Discovery Protocol
PBB             88E7                         # 802.1Q Provider Backbone Bridging
XNSSM           9001                         # 3Com (Formerly Bridge Communications), XNS Systems Management
TCPSM           9002                         # 3Com (Formerly Bridge Communications), TCP/IP Systems Management
DEBNI           AAAA                         # DECNET? Used by VAX 6220 DEBNI
SONIX           FAF5                         # Sonix Arpeggio
VITAL           FF00                         # BBN VITAL-LanBridge cache wakeups
MAX             FFFF                         # Maximum valid ethernet type, reserved
"""
