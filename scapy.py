#! /usr/bin/env python

#############################################################################
##                                                                         ##
## scapy.py --- Interactive packet manipulation tool                       ##
##              see http://www.secdev.org/projects/scapy.html              ##
##              for more informations                                      ##
##                                                                         ##
## Copyright (C) 2003  Philippe Biondi <phil@secdev.org>                   ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

#
# $Log: scapy.py,v $
# Revision 0.9.17.9  2004/09/06 14:28:02  pbi
# - early radius support
#
# Revision 0.9.17.8  2004/09/06 14:17:11  pbi
# - added "store" parameter to sniff()
# - added AnsweringMachine class to handle request/response protocols
# - replaced bootpd by a AnsweringMachine subclass
# - created DHCP answering machine draft
#
# Revision 0.9.17.7  2004/09/03 22:11:35  pbi
# - finished airpwn()
#
# Revision 0.9.17.6  2004/08/13 16:49:51  pbi
# - added first version of airpwn() clone
#
# Revision 0.9.17.5  2004/08/11 15:25:08  pbi
# - added RIP protocol
#
# Revision 0.9.17.4  2004/08/09 14:00:20  pbi
# - added gzip support to sessions saving
# - can force pickle protocol to inferior values for pickle backward compatility
#
# Revision 0.9.17.3  2004/08/07 10:59:34  pbi
# - fixed self reloading when launched from a different directory
# - fixed session reloading problems with PacketList() and SndRcvAns()
# - added load_session(), save_session(), update_session()
#
# Revision 0.9.17.2  2004/07/28 21:16:12  pbi
# - added nsummary() method to SndRcvList() class
#
# Revision 0.9.17.1  2004/07/26 19:52:55  pbi
# Release 0.9.17
#
# Revision 0.9.16.18  2004/07/26 19:50:16  pbi
# - added ScapyPcapWriter class (William McVey)
#
# Revision 0.9.16.17  2004/07/26 19:24:48  pbi
# - do not need to be named 'scapy.py' anymore
# - use of PacketList() for rdpcap() and sniff()
# - fixed a bug in StrFixedLenField
# - early IKE and ISAKMP support
#
# Revision 0.9.16.16  2004/07/16 15:39:37  pbi
# - small fix on bootpd
#
# Revision 0.9.16.15  2004/07/10 13:13:25  pbi
# - finished testing ethertype in supersockets to decide wether or not to apply BPF filters
#
# Revision 0.9.16.14  2004/07/10 13:06:38  pbi
# - do not apply any BPF filter if ethertype is given to a supersocket (so that ARP requests will work
#   whatever the conf.except_filter value is)
#
# Revision 0.9.16.13  2004/07/09 09:11:15  pbi
# - changed the header and blocked the licence to GPLv2 only
#
# Revision 0.9.16.12  2004/07/09 09:07:41  pbi
# - added an independant routing table (conf.route) and methods to manipulate it
# - tweaked results stats
#
# Revision 0.9.16.11  2004/07/05 22:43:49  pbi
# - wrapper classes for results presentations and manipulation
# - sndrcv() retry auto adjustment when giving a negative value
#
# Revision 0.9.16.10  2004/07/05 08:53:41  pbi
# - added retry option to sndrcv()
# - improved debug class
# - added ottl() and hops() methods for IPTools class
# - improved UDP and ICMP summary()
#
# Revision 0.9.16.9  2004/06/07 16:09:21  pbi
# - fix again TCP.answers() and TCPerror.answers()
#
# Revision 0.9.16.8  2004/06/07 16:06:27  pbi
# - fixed conf.checkIPsrc behaviour of answers() and hashret() for TCP/UDP/TCPerror/UDPerror
# - added conf.debug_match to keep track of unanswered packets in debug.sent and debug.recv
#
# Revision 0.9.16.7  2004/06/07 09:20:43  pbi
# - added LEIntField and StrFixedLenField
# - added partial PrismHeader support
#
# Revision 0.9.16.6  2004/04/29 15:46:19  pbi
# - fixed fragment()
#
# Revision 0.9.16.5  2004/03/31 09:24:43  pbi
# - fix nmap fingerprint db parsing to handle the new format (Jochen Bartl)
#
# Revision 0.9.16.4  2004/03/23 08:45:10  pbi
# - Support for reading big endian pcap files (Pekka Pietikainen)
#
# Revision 0.9.16.3  2004/02/28 11:12:12  pbi
# - got rid of some future warnings (N. Bareil <nbareil@mouarf.org>)
# - improved BitField() for arbitrary length bit fields (N. Bareil <nbareil@mouarf.org>)
# - NTP protocol (N. Bareil <nbareil@mouarf.org>)
#
# Revision 0.9.16.2  2004/02/22 17:49:51  pbi
# added first sketch of a bootp daemon: bootpd()
#
# Revision 0.9.16.1  2004/01/26 18:01:00  pbi
# Release 0.9.16
#
# Revision 0.9.15.15  2004/01/26 18:00:08  pbi
# - added more text for DNS codes
#
# Revision 0.9.15.14  2004/01/15 13:24:48  pbi
# - fixed the case where IP field is a list of nets
# - randomize IPID in traceroute() to work better with conf.checkIPsrc=0
# - added make_tex_table() and make_lined_table()
# - added IPID_count() to identify machines with their IPID
# - added sport and dport args to fragleak()
#
# Revision 0.9.15.13  2004/01/11 11:47:07  pbi
# - srploop() and srloop() improvements
#
# Revision 0.9.15.12  2004/01/11 01:28:21  pbi
# - srloop() and srploop() improvements
#
# Revision 0.9.15.11  2004/01/11 01:07:05  pbi
# - srloop() and srploop() improvements
#
# Revision 0.9.15.10  2004/01/10 23:42:58  pbi
# - added srloop() and srploop() functions
#
# Revision 0.9.15.9  2004/01/10 23:40:51  pbi
# - added
#
# Revision 0.9.15.8  2004/01/09 16:42:42  pbi
# - improved send() and sendp() with parameters loop and verbose
#
# Revision 0.9.15.7  2004/01/09 16:04:07  pbi
# - fixed ARP opcodes values
#
# Revision 0.9.15.6  2004/01/09 15:53:46  pbi
# - added RARP and IARP req/resp description in ARP operation Enum field
#
# Revision 0.9.15.5  2003/12/19 15:54:30  pbi
# - added checkIPID and checkIPsrc options in conf to recognize IP in ICMP errors from broken IP stacks (see conf.__doc__)
# - changed default TCP source port to 20 (Muahahahah!)
# - tweaked TCP summary
# - changed default UDP source and destination ports to 53
# - created import_hexcap() to copy-paste an hexcap from tcpdump -xX, and get a string to feed IP() or ARP() or whatever
# - created make_table() to present results in a table from a list, and functions that map the list to x,y and z=f(x,y).
#
# Revision 0.9.15.4  2003/10/30 16:11:41  pbi
# - little enhancements to the DNS packets
# - added dyndns_add() and dyndns_del() (rfc2136)
# - fixed a format string error (3 times)
#
# Revision 0.9.15.3  2003/10/16 10:41:42  biondi
# - redesign summary() method
# - fixed Dot11 addresses fields
#
# Revision 0.9.15.2  2003/10/15 14:41:09  biondi
# - caching format size (calcsize()) in Field main class
# - allow first packet desassembly to fail in SuperSockets, falling back to Raw
#
# Revision 0.9.15.1  2003/10/02 15:24:29  pbi
# Release 0.9.15
#
# Revision 0.9.14.8  2003/10/02 15:16:26  pbi
# - small fix for p0f_base
# - lazy loading for p0f, queso and nmap knowledge databases
#
# Revision 0.9.14.7  2003/10/02 14:14:17  pbi
# - added a LongField
# - added classes and bonds for 802.11
# - added error handling and magic checks for rdpcap()
#
# Revision 0.9.14.6  2003/09/12 14:45:35  pbi
# - had Dot11 working
#
# Revision 0.9.14.5  2003/09/12 10:04:05  pbi
# - added summary() method to Packet objects
#
# Revision 0.9.14.4  2003/09/12 09:28:28  pbi
# - added SNAP protocol
# - catched broken pipe exception when shild die in sndrcv()
# - fixed default L2socket type in srp() and srp1() (ETH_P_ALL)
# - fixed format string in attach_filter()
#
# Revision 0.9.14.3  2003/09/10 08:47:41  pbi
# - fixed the fact that bpf filters were generated in cooked mode, and thus did
#   not work
# - filter on socket type ETH_P_ARP instead of using a bpf filter for ARP replies
# - fixed the way of handling the SuperSocket close.
# - uniformised the naming for interface parameter : iface instead of iff
# - fixed the FutureWarning for long integers
# - fixed a typo in 3 format strings (%*i instead of %i)
#
# Revision 0.9.14.2  2003/07/20 00:12:04  pbi
# -added "-i any" for tcpdump to compile filters even if they don't work on main interface
# - put PPP special case before layer 2 general case in a super socket
# - added th filter parameter to L3RawSocket
# - added a special case in getmacbyip() when loopback interface is concernet
# - added value for RAWIP linktype in pcap capture files
#
# Revision 0.9.14.1  2003/06/25 13:18:23  pbi
# Release 0.9.14, from 0.9.13.4
#
# Revision 0.9.13.4  2003/06/25 12:35:57  pbi
# - fixed a regression in L3PacketSocket for ppp links
#
# Revision 0.9.13.3  2003/05/31 14:01:12  biondi
# - more tweaks on Packet.sprintf(). Added __doc__.
#
# Revision 0.9.13.2  2003/05/31 13:17:42  biondi
# - small tweaks in Packet.sprintf()
#
# Revision 0.9.13.1  2003/05/16 13:34:30  pbi
# Release 0.9.13
#
# Revision 0.9.12.9  2003/05/16 13:32:38  pbi
# - fixed verbose parameter in nmap_fp()
#
# Revision 0.9.12.8  2003/05/16 13:28:49  pbi
# - small enhancements in self-documentation
# - added early experiemental support for BOOTP and 802.11
#
# Revision 0.9.12.7  2003/05/16 11:25:48  pbi
# - added workarroung python bug 643005 (socket.inet_aton("255.255.255.255"))
# - use answers() method instead of operator
# - added hashret() method : returns a hash that is invariant for a packet and its reply
# - use hashret() in sndrcv() for dramatic improvements for matching replies on big set of packets
# - change report_ports() to return a string instead of printing
#
# Revision 0.9.12.6  2003/05/16 09:28:40  pbi
# - improved the __repr__() method of Packet class
#
# Revision 0.9.12.5  2003/05/12 15:15:02  pbi
# - added minttl parameter to traceroute()
#
# Revision 0.9.12.4  2003/05/06 13:39:21  pbi
# - Improved random number object (thanks to O. Poyen)
#
# Revision 0.9.12.3  2003/05/06 10:45:27  pbi
# - fixed a name overlap on "type" in L2ListenSocket and L3PacketSocket (thanks to E. M. Hopper)
#
# Revision 0.9.12.2  2003/05/06 10:41:58  pbi
# - externalized conversion from probes to signature with nmap_probes2sig() use probe results from, say, a pcap file
#
# Revision 0.9.12.1  2003/04/27 10:07:30  pbi
# Release 0.9.12
#
# Revision 0.9.11.5  2003/04/27 10:04:03  pbi
# - Fixed long int conversion in attach_filter()
#
# Revision 0.9.11.4  2003/04/27 10:00:57  pbi
# - rectification in SetGen to unroll Gen instances in lists
# - Completed DNS types and qtypes names
# - Small tuning in nmap_match_one_sig()
# - Parallelized nmap_sig()
#
# Revision 0.9.11.3  2003/04/24 12:47:49  pbi
# - removed 4 byte IP string autorecognition. Never used and broken for 4 byte names
# - added "islist" flag to fields to distinguish a list value from a list of values
# - changed TCP options from dict to list to preserve order and redundancy
# - added conf.except_filter, to have every command ignore your own traffic (BPF filter)
# - worked in progress for nmap OS fingerprint. Added PU test. Fixed other tests.
# - added nmap_sig2txt() to transform a signature to its text form, suitable for nmap base
#
# Revision 0.9.11.2  2003/04/23 21:23:30  pbi
# - small fixes in init_queso()
# - experimental support of nmap fingerprinting (not complete yet)
#
# Revision 0.9.11.1  2003/04/22 14:38:16  pbi
# Release 0.9.11
#
# Revision 0.9.10.8  2003/04/22 14:37:32  pbi
# - fixed bug in getmacbyip() using dnet module
# - deactivated getmacbyip() using dnet module because it did not resolve unknown IPs
# - added some commands listed by lsc()
#
# Revision 0.9.10.7  2003/04/22 13:55:01  pbi
# - some getattr/setattr/delattr enhancements
#
# Revision 0.9.10.6  2003/04/22 13:52:00  pbi
# - added experimental support for QueSO OS fingerprinting. Has someone a *recent* database ?
#
# Revision 0.9.10.5  2003/04/18 17:45:15  pbi
# - improved the completer to complete with protocol fields
# - small fix in get_working_if()
#
# Revision 0.9.10.4  2003/04/16 14:53:36  pbi
# - added option to include padding or not
#
# Revision 0.9.10.3  2003/04/16 14:35:32  pbi
# - added L2dnetSocket()
# - improved arping()
#
# Revision 0.9.10.2  2003/04/16 12:40:40  pbi
# - fixed the case when the history file does not exist
#
# Revision 0.9.10.1  2003/04/14 15:43:45  pbi
# Release 0.9.10
#
# Revision 0.9.9.15  2003/04/14 15:42:47  pbi
# - added L3pcapListenSocket
# - fixed L3ListenSocket to use ETH_P_ALL instead of ETH_P_IP by default
#
# Revision 0.9.9.14  2003/04/14 14:57:53  pbi
# - reworked L3dnetSocket
#
# Revision 0.9.9.13  2003/04/14 13:53:28  pbi
# - added completion (rlcompleter) and history support
#
# Revision 0.9.9.12  2003/04/14 10:05:42  pbi
# - bugfixed the close() method of some supersockets
#
# Revision 0.9.9.11  2003/04/13 21:41:01  biondi
# - added get_working_if()
# - use get_working_if() for default interface
#
# Revision 0.9.9.10  2003/04/12 23:33:42  biondi
# - add DNS layer (do not compress when assemble, answers() is missing)
#
# Revision 0.9.9.9  2003/04/12 22:15:40  biondi
# - added EnumField
# - used EnumField for ARP(), ICMP(), IP(), EAPOL(), EAP(),...
#
# Revision 0.9.9.8  2003/04/11 16:52:29  pbi
# - better integration of libpcap and libdnet, if available
#
# Revision 0.9.9.7  2003/04/11 15:49:31  pbi
# - some tweaks about supersockets close() and __del__() (not satisfied)
# - added L3dnetSocket, that use libdnet and libpcap if available
#
# Revision 0.9.9.6  2003/04/11 13:46:49  pbi
# - fixed a regression in bitfield dissection
# - tweaked and fixed a lot of small things arround supersockets
#
# Revision 0.9.9.5  2003/04/10 14:50:22  pbi
# - clean session only if it is to be saved
# - forgot to give its name to Padding class
# - fixed the NoPayload comparison tests so that they work on reloaded sessions
#
# Revision 0.9.9.4  2003/04/10 13:45:22  pbi
# - Prepared the configuration of L2/L3 supersockets
#
# Revision 0.9.9.3  2003/04/08 18:34:48  pbi
# - little fix in L2ListenSocket.__del__()
# - added doc and options in Conf class
# - added promisc support for L3PacketSocket, so that you can get answers to spoofed packets
#
# Revision 0.9.9.2  2003/04/08 17:42:19  pbi
# - added extract_padding() method to UDP
#
# Revision 0.9.9.1  2003/04/08 17:23:33  pbi
# Release 0.9.9
#
# Revision 0.9.8.9  2003/04/08 17:22:25  pbi
# - use cPickle instead of pickle (quicker and works with __getattr__() recursion)
# - small fixes on send() and sendp()
#
# Revision 0.9.8.8  2003/04/08 16:48:04  pbi
# - EAPOL overload Ether dst with PAE_GROUP_ADDR
# - tuning in ports_report()
# - tuning in fragleak
#
# Revision 0.9.8.7  2003/04/07 15:32:10  pbi
# - uses /usr/bin/env invocation
#
# Revision 0.9.8.6  2003/04/07 14:57:12  pbi
# - catch error during payload dissection and consider payload as raw data
#
# Revision 0.9.8.5  2003/04/07 14:43:13  pbi
# - srp() becomes srp1() and sr() equivalent for L2 is called srp()
# - hastype() Packet methods renamed to haslayer()
# - added getlayer() Packet method
# - added padding detection for layers that have a length field
# - added fragment() that fragment an IP packet
# - added report_ports() to scan a machine and output LaTeX report
#
# Revision 0.9.8.4  2003/04/01 11:19:06  pbi
# - added FlagsField(), used for TCP and IP
# - rfc3514 compliance
#
# Revision 0.9.8.3  2003/03/28 14:55:18  pbi
# Added pkt2uptime() : uses TCP timestamp to predict when the machine was booted
#
# Revision 0.9.8.2  2003/03/27 15:58:54  pbi
# - fixed sprintf() regression to use attributes from a packet that are not fields (eg: payload)
#
# Revision 0.9.8.1  2003/03/27 15:43:20  pbi
# Release 0.9.8
#
# Revision 0.9.7.9  2003/03/27 15:07:42  pbi
# - add filter support for sr(), sr1() and srp()
# - use filters for getmacbyip() and traceroute() for better reliability under heavy load
#
# Revision 0.9.7.8  2003/03/27 14:45:11  pbi
# - better timeout management in sndrcv
# - bugfixed sys.exit() imbrication issues
# - some self documentation
# - added lsc()command
#
# Revision 0.9.7.7  2003/03/26 17:51:33  pbi
# - Added IPTool class, to add commands like whois() to IP layer.
# - Have unknown class attributes be asked to payload before raising an exception.
#
# Revision 0.9.7.6  2003/03/26 17:35:36  pbi
# More powerful sprintf format string : %[fmt[r],][cls[:nb].]field% where fmt is a classic one, r can be
# appended for raw substitution (ex: IP.flags=0x18 instead of SA), nb is the number of the layer we want
# (ex: for IP/IP packets, IP:2.src is the src of the upper IP layer). Special case : "%.time" is the creation time.
# Ex : p.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% %03xr,IP.proto% %r,TCP.flags%")
#
# Revision 0.9.7.5  2003/03/26 14:47:39  pbi
# Added creation time packet. Supported by read/write pcap.
#
# Revision 0.9.7.4  2003/03/26 14:25:09  pbi
# Added the NoPayload terminal class
#
# Revision 0.9.7.3  2003/03/26 13:31:11  pbi
# Fixed RCS Id
#
# Revision 0.9.7.2  2003/03/26 13:30:05  pbi
# Adding RCS Id
#
#


from __future__ import generators

RCSID="$Id: scapy.py,v 0.9.17.9 2004/09/06 14:28:02 pbi Exp $"

VERSION = RCSID.split()[2]+"beta"


def usage():
    print "Usage: scapy.py [-s sessionfile]"
    sys.exit(0)


##########[XXX]#=--
##
#   Next things to do :
#
#  - fields to manage variable length hw addr (ARP, BOOTP, etc.)
#  - improve pcap capture file support
#  - better self-doc
#
##
##########[XXX]#=--

################
##### Main #####
################


if __name__ == "__main__":
    import code,sys,cPickle,types,os,imp

    scapy_module = sys.argv[0][sys.argv[0].rfind("/")+1:]
    if not scapy_module:
        scapy_module = "scapy"
    else:
        if scapy_module.endswith(".py"):
            scapy_module = scapy_module[:-3]

    scapy=imp.load_module("scapy",*imp.find_module(scapy_module))
    
    __builtins__.__dict__.update(scapy.__dict__)

    import rlcompleter,readline
    import re

    class ScapyCompleter(rlcompleter.Completer):
        def global_matches(self, text):
            matches = []
            n = len(text)
            for list in [dir(__builtins__), session.keys()]:
                for word in list:
                    if word[:n] == text and word != "__builtins__":
                        matches.append(word)
            return matches
    

        def attr_matches(self, text):
            m = re.match(r"(\w+(\.\w+)*)\.(\w*)", text)
            if not m:
                return
            expr, attr = m.group(1, 3)
            try:
                object = eval(expr)
            except:
                object = eval(expr, session)
            if isinstance(object, scapy.Packet):
                words = filter(lambda x: x[0]!="_",dir(object))
                words += map(str, object.fields_desc)
            else:
                words = dir(object)
                if hasattr( object,"__class__" ):
                    words = words + rlcompleter.get_class_members(object.__class__)
            matches = []
            n = len(attr)
            for word in words:
                if word[:n] == attr and word != "__builtins__":
                    matches.append("%s.%s" % (expr, word))
            return matches

    readline.set_completer(ScapyCompleter().complete)
    readline.parse_and_bind("C-o: operate-and-get-next")
    readline.parse_and_bind("tab: complete")
    
    
    
    session=None
    session_name=""

    opts=getopt.getopt(sys.argv[1:], "hs:")
    iface = None
    try:
        for opt, parm in opts[0]:
	    if opt == "-h":
	        usage()
            elif opt == "-s":
                session_name = parm
        
	if len(opts[1]) > 0:
	    raise getopt.GetoptError("Too many parameters : [%s]" % string.join(opts[1]),None)


    except getopt.error, msg:
        print "ERROR:", msg
        sys.exit(1)


    if session_name:
        try:
            f=open(session_name)
            session=cPickle.load(f)
            f.close()
            print "Using session [%s]" % session_name
        except IOError:
            print "New session [%s]" % session_name
        except EOFError:
            print "Error opening session [%s]" % session_name
        except AttributeError:
            print "Error opening session [%s]. Attribute missing" %  session_name

        if session:
            if "conf" in session:
                scapy.conf.configure(session["conf"])
                session["conf"] = scapy.conf
        else:
            scapy.conf.session = session_name
            session={"conf":scapy.conf}
            
    else:
        session={"conf": scapy.conf}

    __builtins__.__dict__["scapy_session"] = session

    if scapy.conf.histfile:
        try:
            readline.read_history_file(scapy.conf.histfile)
        except IOError:
            pass

    code.interact(banner = "Welcome to Scapy (%s)"%VERSION, local=session)

    if scapy.conf.session:
        save_session(scapy.conf.session, session)

    if scapy.conf.histfile:
        readline.write_history_file(scapy.conf.histfile)
    
    sys.exit()

##################
##### Module #####
##################

import socket, sys, getopt, string, struct, time, random, os, traceback
import cPickle, types, gzip, re
from select import select
from fcntl import ioctl

try:
    import pcap
    PCAP = 1
except ImportError:
    PCAP = 0
try:
    import dnet
    DNET = 1
except ImportError:
    DNET = 0

# Workarround bug 643005 : https://sourceforge.net/tracker/?func=detail&atid=105470&aid=643005&group_id=5470
try:
    socket.inet_aton("255.255.255.255")
except socket.error:
    def inet_aton(x):
        if x == "255.255.255.255":
            return "\xff"*4
        else:
            return socket.inet_aton(x)
else:
    inet_aton = socket.inet_aton



############
## Consts ##
############

ETHER_ANY = "\x00"*6
ETHER_BROADCAST = "\xff"*6

ETH_P_ALL = 3
ETH_P_IP = 0x800
ETH_P_ARP = 0x806

# From net/if_arp.h
ARPHDR_ETHER = 1
ARPHDR_METRICOM = 23
ARPHDR_PPP = 512
ARPHDR_LOOPBACK = 772

# From bits/ioctls.h
SIOCGIFHWADDR  = 0x8927          # Get hardware address    
SIOCGIFADDR    = 0x8915          # get PA address          
SIOCGIFNETMASK = 0x891b          # get network PA mask     
SIOCGIFNAME    = 0x8910          # get iface name          
SIOCSIFLINK    = 0x8911          # set iface channel       
SIOCGIFCONF    = 0x8912          # get iface list          
SIOCGIFFLAGS   = 0x8913          # get flags               
SIOCSIFFLAGS   = 0x8914          # set flags               
SIOCGIFINDEX   = 0x8933          # name -> if_index mapping
SIOCGIFCOUNT   = 0x8938          # get number of devices


# From if.h
IFF_UP = 0x1               # Interface is up.
IFF_BROADCAST = 0x2        # Broadcast address valid.
IFF_DEBUG = 0x4            # Turn on debugging.
IFF_LOOPBACK = 0x8         # Is a loopback net.
IFF_POINTOPOINT = 0x10     # Interface is point-to-point link.
IFF_NOTRAILERS = 0x20      # Avoid use of trailers.
IFF_RUNNING = 0x40         # Resources allocated.
IFF_NOARP = 0x80           # No address resolution protocol.
IFF_PROMISC = 0x100        # Receive all packets.



# From netpacket/packet.h
PACKET_ADD_MEMBERSHIP  = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_RECV_OUTPUT     = 3
PACKET_RX_RING         = 5
PACKET_STATISTICS      = 6
PACKET_MR_MULTICAST    = 0
PACKET_MR_PROMISC      = 1
PACKET_MR_ALLMULTI     = 2


# From bits/socket.h
SOL_PACKET = 263
# From asm/socket.h
SO_ATTACH_FILTER = 26
SOL_SOCKET = 1

# From net/route.h
RTF_UP = 0x0001  # Route usable


MTU = 1600

    



###########
## Tools ##
###########


def sane(x):
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+"."
        else:
            r=r+i
    return r

def hexdump(x):
    x=str(x)
    l = len(x)
    for i in range(l):
        print "%02X" % ord(x[i]),
        if (i % 16 == 15):
            print " "+sane(x[i-15:i+1])
    if ((l%16) != 0): print "   "*(16-(l%16))+" "+sane(x[l-(l%16):])

def linehexdump(x):
    x = str(x)
    l = len(x)
    for i in range(l):
        print "%02X" % ord(x[i]),
    print " "+sane(x)



def checksum(pkt):
    pkt=str(pkt)
    s=0
    if len(pkt) % 2 == 1:
        pkt += "\0"
    for i in range(len(pkt)/2):
        s = s +  (struct.unpack("!H",pkt[2*i:2*i+2])[0])
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return  ~s & 0xffff

def warning(x):
    print "WARNING:",x


def mac2str(mac):
    return "".join(map(lambda x: chr(int(x,16)), mac.split(":")))

def str2mac(s):
    return ("%02x:"*6)[:-1] % tuple(map(ord, s)) 

def strxor(x,y):
    return "".join(map(lambda x,y:chr(ord(x)^ord(y)),x,y))



##############################
## Session saving/restoring ##
##############################


def save_session(fname, session=None, pickleProto=-1):
    if session is None:
        session = scapy_session
        
    if session.has_key("__builtins__"):
            del(session["__builtins__"])

    for k in session.keys():
        if type(session[k]) in [types.ClassType, types.ModuleType]:
             print "[%s] (%s) can't be saved. Deleted." % (k, type(session[k]))
             del(session[k])

    try:
        os.rename(fname, fname+".bak")
    except OSError:
        pass
    f=gzip.open(fname,"w")
    cPickle.dump(session, f, pickleProto)
    f.close()

def load_session(fname):
    try:
        s = cPickle.load(gzip.open(fname))
    except IOError:
        s = cPickle.load(open(fname))
    scapy_session.clear()
    scapy_session.update(s)

def update_session(fname):
    try:
        s = cPickle.load(gzip.open(fname))
    except IOError:
        s = cPickle.load(open(fname))
    scapy_session.update(s)


#################
## Debug class ##
#################

class debug:
    recv=[]
    sent=[]
    match=[]



####################
## IP Tools class ##
####################

class IPTools:
    """Add more powers to a class that have a "src" attribute."""
    def whois(self):
        os.system("whois %s" % self.src)
    def ottl(self):
	t = [32,64,128,255]+[self.ttl]
	t.sort()
	return t[t.index(self.ttl)+1]
    def hops(self):
        return self.ottl()-self.ttl-1 




##############################
## Routing/Interfaces stuff ##
##############################


def atol(x):
    try:
        ip = inet_aton(x)
    except socket.error:
        ip = inet_aton(socket.gethostbyname(x))
    return struct.unpack("I", ip)[0]
def ltoa(x):
    return socket.inet_ntoa(struct.pack("I", x))

class Route:
    def __init__(self):
        self.resync()
        self.s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def resync(self):
        self.routes = read_routes()

    def __repr__(self):
        rt = "Network         Netmask         Gateway         Iface\n"
        for net,msk,gw,iface,addr in self.routes:
            rt += "%-15s %-15s %-15s %s\n" % (ltoa(net),
                                              ltoa(msk),
                                              gw,
                                              iface)
        return rt

    def make_route(self, host=None, net=None, gw=None, dev=None):
        if host is not None:
            thenet,msk = host,32
        elif net is not None:
            thenet,msk = net.split("/")
            msk = int(msk)
        if gw is None:
            gw="0.0.0.0"
        if dev is None:
            if gw:
                nhop = gw
            else:
                nhop = thenet
            dev,ifaddr,x = self.route(nhop)
        else:    
            ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x",dev))
            ifaddr = socket.inet_ntoa(ifreq[20:24])
        return (atol(thenet),(1L<<msk)-1, gw, dev, ifaddr)

    def add(self, *args, **kargs):
        self.routes.append(self.make_route(*args,**kargs))

        
    def delt(self,  *args, **kargs):
        route = self.make_route(*args,**kargs)
        try:
            i=self.routes.index(route)
            del(self.routes[i])
        except ValueError:
            warning("no matching route found")
             
        

    def route(self,dst):
        try:
            dst=inet_aton(dst)
        except socket.error:
            dst=inet_aton(socket.gethostbyname(dst))
        dst=struct.unpack("I",dst)[0]
        pathes=[]
        for d,m,gw,i,a in self.routes:
            if (dst & m) == (d & m):
                pathes.append((m,(i,a,gw)))
        if not pathes:
            raise Exception("no route found")
        # Choose the more specific route (greatest netmask).
        # XXX: we don't care about metrics
        pathes.sort()
        return pathes[-1][1] 
            

def read_routes():
    f=open("/proc/net/route","r")
    routes = []
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x","lo"))
    addrfamily = struct.unpack("h",ifreq[16:18])[0]
    if addrfamily == socket.AF_INET:
        ifreq2 = ioctl(s, SIOCGIFNETMASK,struct.pack("16s16x","lo"))
        msk = struct.unpack("I",ifreq2[20:24])[0]
        dst = struct.unpack("I",ifreq[20:24])[0] & msk
        ifaddr = socket.inet_ntoa(ifreq[20:24])
        routes.append((dst, msk, "0.0.0.0", "lo", ifaddr))
    else:
        warning("Interface lo: unkownn address family (%i)"% addrfamily)

    for l in f.readlines()[1:]:
        iff,dst,gw,flags,x,x,x,msk,x,x,x = l.split()
        if int(flags,16) & RTF_UP == 0:
            continue
        ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x",iff))
        addrfamily = struct.unpack("h",ifreq[16:18])[0]
        if addrfamily == socket.AF_INET:
            ifaddr = socket.inet_ntoa(ifreq[20:24])
        else:
            warning("Interface %s: unkownn address family (%i)"%(iff, addrfamily))
            continue
        routes.append((long(dst,16),
                      long(msk,16),
                      socket.inet_ntoa(struct.pack("I",long(gw,16))),
                      iff, ifaddr))
    
    f.close()
    return routes


        
if PCAP:
    def get_if_list():
        # remove 'any' interface
        return map(lambda x:x[0],filter(lambda x:x[1] is None,pcap.findalldevs()))
    def get_working_if():
        try:
            return pcap.lookupdev()
        except pcap.pcapc.EXCEPTION:
            return 'lo'
else:
    def get_if_list():
        f=open("/proc/net/dev","r")
        lst = []
        f.readline()
        f.readline()
        for l in f:
            lst.append(l.split(":")[0].strip())
        return lst
    def get_working_if():
        for i in get_if_list():
            if i == 'lo':                
                continue
            ifflags = struct.unpack("16xH14x",get_if(i,SIOCGIFFLAGS))[0]
            if ifflags & IFF_UP:
                return i
        return "lo"
            

        
def get_if(iff,cmd):
    s=socket.socket()
    ifreq = ioctl(s, cmd, struct.pack("16s16x",iff))
    s.close()
    return ifreq

def get_if_hwaddr(iff):
    addrfamily, mac = struct.unpack("16xh6s8x",get_if(iff,SIOCGIFHWADDR))
    if addrfamily in [ARPHDR_ETHER,ARPHDR_LOOPBACK]:
        return str2mac(mac)
    else:
        raise Exception("Unsupported address family (%i)"%addrfamily)


def get_if_index(iff):
    return int(struct.unpack("I",get_if(iff, SIOCGIFINDEX)[16:20])[0])
    
def set_promisc(s,iff,val=1):
    mreq = struct.pack("IHH8s", get_if_index(iff), PACKET_MR_PROMISC, 0, "")
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    s.setsockopt(SOL_PACKET, cmd, mreq)


#####################
## ARP cache stuff ##
#####################

ARPTIMEOUT=120

# XXX Fill arp_cache with /etc/ether and arp cache
arp_cache={}

if 0 and DNET: ## XXX Can't use this because it does not resolve IPs not in cache
    dnet_arp_object = dnet.arp()
    def getmacbyip(ip):
        iff,a,gw = conf.route.route(ip)
        if iff == "lo":
            return "ff:ff:ff:ff:ff:ff"
        if gw != "0.0.0.0":
            ip = gw
        res = dnet_arp_object.get(dnet.addr(ip))
        if res is None:
            return None
        else:
            return res.ntoa()
else:
    def getmacbyip(ip):
        iff,a,gw = conf.route.route(ip)
        if iff == "lo":
            return "ff:ff:ff:ff:ff:ff"
        if gw != "0.0.0.0":
            ip = gw
    
        if arp_cache.has_key(ip):
            mac, timeout = arp_cache[ip]
            if timeout and (time.time()-timeout < ARPTIMEOUT):
                return mac
        
        res = srp1(Ether(dst=ETHER_BROADCAST)/ARP(op="who-has", pdst=ip),
                  type=ETH_P_ARP,
                  iface = iff,
                  timeout=2,
                  verbose=0)
        if res is not None:
            mac = res.payload.hwsrc
            arp_cache[ip] = (mac,time.time())
            return mac
        return None
    


############
## Protos ##
############

# Not used. Here only in case I need it in the future.

class ConstInstance(int):
    def __new__(cls, name, key, value):
        return int.__new__(cls,value)
    def __init__(self, name, key, value):
        int.__init__(self, value)
        self.__value = value
        self.__name = name
        self.__key = key
        self.__repr = name+"."+key
    def __repr__(self):
        return self.__repr
    def __eq__(self, other):
        return self.__repr == other.__repr__()
    def __hash__(self):
        return self.__repr.__hash__()


class ProtoEnumMetaClass:
    def __init__(self, name, bases, dict):
        self.__name__ = name
        self.__bases__= bases
        self.__dict = dict
        try:
            self.__consts = dict["consts"]
        except KeyError:
            self.__consts = {}
        for x,y in self.__consts.items():
            if type(y) is int:
                self.__consts[x] = ConstInstance(name, x, y)
    def __getattr__(self, attr):
        print "get", attr
        try:
            return self.__consts[attr]
        except KeyError:
            raise AttributeError, attr
        
        
ConstEnum = ProtoEnumMetaClass("ConstEnum", (), {"consts":{}})


####################
## Random numbers ##
####################

class RandNum:
    def __init__(self, min, max):
        self.min = min
        self.max = max
    def randint(self):
        # XXX: replace with sth that guarantee unicity
        return random.randint(self.min, self.max)
    def __getattr__(self, attr):
        return getattr(self.randint(), attr)

class RandByte(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 255)

class RandShort(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 65535)

class RandInt(RandNum):
    def __init__(self):
        # Well, 2147483647 won't be reached because max+1 must be int
        # and 2147483647+1 is longint. (random module limitation)
        RandNum.__init__(self, 0, 2147483646)
        




################
## Generators ##
################

class Gen:
    def __iter__(self):
        return iter([])
    

class SetGen(Gen):
    def __init__(self, set):
        if type(set) is list:
            self.set = set
        else:
            self.set = [set]
    def transf(self, element):
        return element
    def __iter__(self):
        for i in self.set:
            if (type(i) is tuple) and (len(i) == 2):
                if  (i[0] <= i[1]):
                    j=i[0]
                    while j <= i[1]:
                        yield j
                        j += 1
            elif isinstance(i, Gen):
                for j in i:
                    yield j
            else:
                yield i
    def __repr__(self):
        return "<SetGen %s>" % self.set.__repr__()


class Net(Gen):
    """Generate a list of IPs from a network address or a name"""
    name = "ip"
    def __init__(self, net):
        self.repr=net
        tmp=net.split('/')+["32"]

        try:
            ip=inet_aton(tmp[0])
        except socket.error:
            ip=socket.gethostbyname(tmp[0])
            ip=inet_aton(ip)
        
        self.ip=struct.unpack("!I", ip)[0]
        netsz=2**(32-int(tmp[1]))
        self.ip=self.ip&(~(netsz-1))
        self.size=netsz
    def __iter__(self):
        for i in xrange(self.size):
            yield socket.inet_ntoa(struct.pack("!I",self.ip+i))
    def __repr__(self):
        return "<Net %s>" % self.repr


#############
## Results ##
#############

class SndRcvAns:
    res = []
    def __init__(self, res):
        self.res = res
    def __repr__(self):
        stats={TCP:0,UDP:0,ICMP:0}
        other = 0
        for s,r in self.res:
            f = 0
            for p in stats:
                if r.haslayer(p):
                    stats[p] += 1
                    f = 1
                    break
            if not f:
                other += 1
        s = ""
        for p in stats:
            s += " %s:%i" % (p.name,stats[p])
        s += " Other:%i" % other
        return "<Results:%s>" % s
    def __getattr__(self, attr):
        return getattr(self.res, attr)
    def summary(self):
        for s,r in self.res:
            print s.summary(),"==>",r.summary()
    def nsummary(self):
        for i in range(len(self.res)):
            s,r = self.res[i]
            print "%04i %s ==> %s" % (i,s.summary(),r.summary())
    def make_table(self, *args, **kargs):
        return make_table(self.res, *args, **kargs)
    def make_lined_table(self, *args, **kargs):
        return make_lined_table(self.res, *args, **kargs)
    def make_tex_table(self, *args, **kargs):
        return make_tex_table(self.res, *args, **kargs)

class PacketList:
    res = []
    def __init__(self, res, name="PacketList"):
        self.res = res
        self.listname = name
    def __repr__(self):
        stats={TCP:0,UDP:0,ICMP:0}
        other = 0
        for r in self.res:
            f = 0
            for p in stats:
                if r.haslayer(p):
                    stats[p] += 1
                    f = 1
                    break
            if not f:
                other += 1
        s = ""
        for p in stats:
            s += " %s:%i" % (p.name,stats[p])
        s += " Other:%i" % other
        return "<%s:%s>" % (self.listname,s)
    def __getattr__(self, attr):
        return getattr(self.res, attr)
    def summary(self):
        for r in self.res:
            print r.summary()
    def nsummary(self):
        for i in range(len(self.res)):
            print "%04i %s" % (i,self.res[i].summary())


        
    
############
## Fields ##
############

class Field:
    islist=0
    def __init__(self, name, default, fmt="H"):
        self.name = name
        if fmt[0] in "@=<>!":
            self.fmt = fmt
        else:
            self.fmt = "!"+fmt
        self.default = self.any2i(None,default)
        self.sz = struct.calcsize(self.fmt)

    def h2i(self, pkt, x):
        return x
    def i2h(self, pkt, x):
        return x
    def m2i(self, pkt, x):
        return x
    def i2m(self, pkt, x):
        if x is None:
            x = 0
        return x
    def any2i(self, pkt, x):
        return x
    def i2repr(self, pkt, x):
	if x is None:
	    x = 0
        return repr(self.i2h(pkt,x))
    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, self.i2m(pkt,val))
    def getfield(self, pkt, s):
        return  s[self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:self.sz])[0])
    def copy(self, x):
        if hasattr(x, "copy"):
            return x.copy()
        elif type(x) is list:
            return x[:]
        else:
            return x
    def __eq__(self, other):
        return self.name == other
    def __hash__(self):
        return hash(self.name)
    def __repr__(self):
        return self.name




class MACField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")
    def i2m(self, pkt, x):
        return mac2str(x)
    def m2i(self, pkt, x):
        return str2mac(x)
    def any2i(self, pkt, x):
        if type(x) is str and len(x) is 6:
            x = self.m2i(pkt, x)
        return x
    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

class DestMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            dstip = None
            if isinstance(pkt.payload, IP):
                dstip = pkt.payload.dst
            elif isinstance(pkt.payload, ARP):
                dstip = pkt.payload.pdst
            if isinstance(dstip, Gen):
                warning("Dest mac not calculated if more than 1 dest IP (%s)"%repr(dstip))
                return None
            x = "ff:ff:ff:ff:ff:ff"
            if dstip is not None:
                m=getmacbyip(dstip)
                if m:
                    x = m
                else:
                    warning("Mac address for %s not found\n"%dstip)
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))
        
class SourceMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            dstip = None
            if isinstance(pkt.payload, IP):
                dstip = pkt.payload.dst
            elif isinstance(pkt.payload, ARP):
                dstip = pkt.payload.pdst
            if isinstance(dstip, Gen):
                warning("Source mac not calculated if more than 1 dest IP (%s)"%repr(dstip))
                return None
            x = "00:00:00:00:00:00"
            if dstip is not None:
                iff,a,gw = conf.route.route(dstip)
                m = get_if_hwaddr(iff)
                if m:
                    x = m
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))
        
class ARPSourceMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            dstip = pkt.pdst
            if isinstance(dstip, Gen):
                warning("Source mac not calculated if more than 1 dest IP (%s)"%repr(dstip))
                return None
            x = "00:00:00:00:00:00"
            if dstip is not None:
                iff,a,gw = conf.route.route(dstip)
                m = get_if_hwaddr(iff)
                if m:
                    x = m
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))

class Dot11AddrMACField(MACField):
    def is_applicable(self, pkt):
        return 1
    def addfield(self, pkt, s, val):
        if self.is_applicable(pkt):
            return MACField.addfield(self, pkt, s, val)
        else:
            return s        
    def getfield(self, pkt, s):
        if self.is_applicable(pkt):
            return MACField.getfield(self, pkt, s)
        else:
            return s,None

class Dot11Addr2MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type == 1:
            return pkt.subtype in [ 0xb, 0xa, 0xe, 0xf] # RTS, PS-Poll, CF-End, CF-End+CF-Ack
        return 1

class Dot11Addr3MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type in [0,2]:
            return 1
        return 0

class Dot11Addr4MACField(Dot11AddrMACField):
    def is_applicable(self, pkt):
        if pkt.type == 2:
            if pkt.FCfield & 0x3 == 0x3: # To-DS and From-DS are set
                return 1
        return 0
    
class IPField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "4s")
    def h2i(self, pkt, x):
        if type(x) is str:
            try:
                inet_aton(x)
            except socket.error:
                x = Net(x)
        elif type(x) is list:
            x = map(Net, x)
        return x
    def i2m(self, pkt, x):
        return inet_aton(x)
    def m2i(self, pkt, x):
        return socket.inet_ntoa(x)
    def any2i(self, pkt, x):
#        if type(x) is str and len(x) == 4:
#            x = self.m2i(pkt, x)
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

class SourceIPField(IPField):
    def __init__(self, name, dstname):
        IPField.__init__(self, name, None)
        self.dstname = dstname
    def i2m(self, pkt, x):
        if x is None:
            iff,x,gw = conf.route.route(getattr(pkt,self.dstname))
        return IPField.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            dst=getattr(pkt,self.dstname)
            if isinstance(dst,Gen):
                r = map(conf.route.route, dst)
                r.sort()
                if r[0] == r[-1]:
                    x=r[0][1]
                else:
                    warning("More than one possible route for %s"%repr(dst))
                    return None
            else:
                iff,x,gw = conf.route.route(dst)
        return IPField.i2h(self, pkt, x)

    


class ByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")
        
class XByteField(ByteField):
    def i2repr(self, pkt, x):
	if x is None:
	    x = 0
        return hex(self.i2h(pkt, x))

class X3BytesField(XByteField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "I")
    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, self.i2m(pkt,val))[:3]
    def getfield(self, pkt, s):
        return  s[3:], self.m2i(pkt, struct.unpack(self.fmt, "\x00"+s[:3])[0])


class ShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "H")

class XShortField(ShortField):
    def i2repr(self, pkt, x):
	if x is None:
	    x = 0
        return hex(self.i2h(pkt, x))


class IntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "I")

class LEIntField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "@I")

class XIntField(IntField):
    def i2repr(self, pkt, x):
	if x is None:
	    x = 0
        return hex(self.i2h(pkt, x))


class LongField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "Q")

class XLongField(LongField):
    def i2repr(self, pkt, x):
	if x is None:
	    x = 0
        return hex(self.i2h(pkt, x))



class StrField(Field):
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        return x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        return "",s

class StrFixedLenField(StrField):
    def __init__(self, name, default, length):
        StrField.__init__(self, name, default)
        self.length = length
    def getfield(self, pkt, s):
        return s[self.length:], self.m2i(pkt,s[:self.length])
    def addfield(self, pkt, s, val):
        return s+struct.pack("%ss"%self.length,self.i2m(pkt, val))
    

class StrLenField(StrField):
    def __init__(self, name, default, fld):
        StrField.__init__(self, name, default)
        self.fld = fld
    def getfield(self, pkt, s):
        l = getattr(pkt, self.fld)
        return s[l:], self.m2i(pkt,s[:l])

class FieldLenField(Field):
    def __init__(self, name, default, fld, fmt = "H"):
        Field.__init__(self, name, default, fmt)
        self.fld = fld
    def i2m(self, pkt, x):
        if x is None:
            x = len(getattr(pkt, self.fld))
        return x
    def i2h(self, pkt, x):
        if x is None:
            x = len(getattr(pkt, self.fld))
        return x

class LenField(Field):
    def i2m(self, pkt, x):
        if x is None:
            x = len(pkt.payload)
        return x

class BCDFloatField(Field):
    def i2m(self, pkt, x):
        return int(256*x)
    def m2i(self, pkt, x):
        return x/256.0

class BitField(Field):
    def __init__(self, name, default, size):
        Field.__init__(self, name, default)
        self.size = size
    def addfield(self, pkt, s, val):
        if val is None:
            val = 0
        if type(s) is tuple:
            s,bitsdone,v = s
        else:
            bitsdone = 0
            v = 0
        v <<= self.size
        v |= val & ((1L<<self.size) - 1)
        bitsdone += self.size
        while bitsdone >= 8:
            bitsdone -= 8
            s = s+struct.pack("!B", v >> bitsdone)
            v &= (1L<<bitsdone)-1
        if bitsdone:
            return s,bitsdone,v
        else:
            return s
    def getfield(self, pkt, s):
        if type(s) is tuple:
            s,bn = s
        else:
            bn = 0
        # we don't want to process all the string
        nb_bytes = (self.size+bn-1)/8 + 1
        w = s[:nb_bytes]

        # split the substring byte by byte
        bytes = struct.unpack('!%dB' % nb_bytes , w)

        b = 0L
        for c in range(nb_bytes):
            b |= long(bytes[c]) << (nb_bytes-c-1)*8

        # get rid of high order bits
        b &= (1L << (nb_bytes*8-bn+1)) - 1

        # remove low order bits
        b = b >> (nb_bytes*8 - self.size - bn)

        bn += self.size
        s = s[bn/8:]
        bn = bn%8
        if bn:
            return (s,bn),b
        else:
            return s,b

class XBitField(BitField):
    def i2repr(self, pkt, x):
        return hex(self.i2h(pkt,x))


class EnumField(Field):
    def __init__(self, name, default, enum, fmt = "H"):
        Field.__init__(self, name, default, fmt)
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if filter(lambda x: type(x) is str, keys):
            i2s,s2i = s2i,i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
    def any2i(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x
    def i2repr(self, pkt, x):
        return self.i2s.get(x, x)            


class BitEnumField(BitField,EnumField):
    def __init__(self, name, default, size, enum):
        EnumField.__init__(self, name, default, enum)
        self.size = size
    def any2i(self, pkt, x):
        return EnumField.any2i(self, pkt, x)
    def i2repr(self, pkt, x):
        return EnumField.i2repr(self, pkt, x)

class ShortEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "H")

class ByteEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "B")

class IntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "I")


class FlagsField(BitField):
    def __init__(self, name, default, size, names):
        BitField.__init__(self, name, default, size)
        self.multi = type(names) is list
        if self.multi:
            self.names = map(lambda x:[x], names)
        else:
            self.names = names
    def any2i(self, pkt, x):
        if type(x) is str:
            if self.multi:
                x = map(lambda y:[y], x.split("+"))
            y = 0
            for i in x:
                y |= 1 << self.names.index(i)
            x = y
        return x
    def i2repr(self, pkt, x):
        if self.multi:
            r = []
        else:
            r = ""
        i=0
        while x:
            if x & 1:
                r += self.names[i]
            i += 1
            x >>= 1
        if self.multi:
            r = "+".join(r)
        return r

            



class IPoptionsField(StrField):
    def i2m(self, pkt, x):
        return x+"\x00"*(3-((len(x)+3)%4))
    def getfield(self, pkt, s):
        opsz = (pkt.ihl-5)*4
        if opsz < 0:
            warning("bad ihl (%i). Assuming ihl=5"%pkt.ihl)
            opsz = 0
        return s[opsz:],s[:opsz]


TCPOptions = (
              { 2 : ("MSS","!H"),
                3 : ("WScale","!B"),
                4 : ["SAckOK",None],
                5 : ["SAck","!II"],
                8 : ["Timestamp","!II"],
                14 : ["AltChkSum","!BH"],
                15 : ["AltChkSumOpt",None]
                },
              { "MSS":2,
                "WScale":3,
                "SAckOK":4,
                "SAck":5,
                "Timestamp":8,
                "AltChkSum":14,
                "AltChkSumOpt":15,
                } )

class TCPOptionsField(StrField):
    islist=1
    def getfield(self, pkt, s):
        opsz = (pkt.dataofs-5)*4
        if opsz < 0:
            warning("bad dataofs (%i). Assuming dataofs=5"%pkt.dataofs)
            opsz = 0
        return s[opsz:],self.m2i(pkt,s[:opsz])
    def m2i(self, pkt, x):
        opt = []
        while x:
            onum = ord(x[0])
            if onum == 0:
                break
            if onum == 1:
                opt.append(("NOP",None))
                x=x[1:]
                continue
            olen = ord(x[1])
            oval = x[2:olen]
            if TCPOptions[0].has_key(onum):
                oname, ofmt = TCPOptions[0][onum]
                if ofmt:
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1:
                        oval = oval[0]
                opt.append((oname, oval))
            else:
                opt.append((onum, oval))
            x = x[olen:]
        return opt
    
    def i2m(self, pkt, x):
        opt = ""
        for oname,oval in x:
            if type(oname) is str:
                if oname == "NOP":
                    opt += "\x01"
                    continue
                elif TCPOptions[1].has_key(oname):
                    onum = TCPOptions[1][oname]
                    ofmt = TCPOptions[0][onum][1]
                    if ofmt is not None:
                        if type(oval) is not tuple:
                            oval = (oval,)
                        oval = struct.pack(ofmt, *oval)
                else:
                    warning("option [%s] unknown. Skipped."%oname)
                    continue
            else:
                onum = oname
                if type(oval) is not str:
                    warning("option [%i] is not string."%onum)
                    continue
            opt += chr(onum)+chr(2+len(oval))+oval
        return opt+"\x00"*(3-((len(opt)+3)%4))
    

class DNSStrField(StrField):
    def i2m(self, pkt, x):
        x = x.split(".")
        x = map(lambda y: chr(len(y))+y, x)
        x = "".join(x)
        if x[-1] != "\x00":
            x += "\x00"
        return x
    def getfield(self, pkt, s):
        n = ""
        while 1:
            l = ord(s[0])
            s = s[1:]
            if not l:
                break
            if l & 0xc0:
                raise Exception("DNS message can't be compressed at this point!")
            else:
                n += s[:l]+"."
                s = s[l:]
        return s, n


class DNSRRCountField(ShortField):
    def __init__(self, name, default, rr):
        ShortField.__init__(self, name, default)
        self.rr = rr
    def i2m(self, pkt, x):
        if x is None:
            x = getattr(pkt,self.rr)
            i = 0
            while isinstance(x, DNSRR) or isinstance(x, DNSQR):
                x = x.payload
                i += 1
            x = i
        return x
    def i2h(self, pkt, x):
        return self.i2m(pkt, x)


    

def DNSgetstr(s,p):
    name = ""
    q = 0
    while 1:
        if p >= len(s):
            warning("DNS RR prematured end (ofs=%i, len=%i)"%(p,len(s)))
            break
        l = ord(s[p])
        p += 1
        if l & 0xc0:
            if not q:
                q = p+1
            p = ((l & 0x3f) << 8) + ord(s[p]) - 12
            continue
        elif l > 0:
            name += s[p:p+l]+"."
            p += l
            continue
        break
    if q:
        p = q
    return name,p
        

class DNSRRField(StrField):
    def __init__(self, name, countfld, passon=1):
        StrField.__init__(self, name, None)
        self.countfld = countfld
        self.passon = passon
    def i2m(self, pkt, x):
        if x is None:
            return ""
        return str(x)
    def decodeRR(self, name, s, p):
        ret = s[p:p+10]
        type,cls,ttl,rdlen = struct.unpack("!HHIH", ret)
        p += 10
        rr = DNSRR("\x00"+ret+s[p:p+rdlen])
        if rr.type in [2, 3, 4, 5]:
            rr.rdata = DNSgetstr(s,p)[0]
        del(rr.rdlen)
        
        p += rdlen
        
        rr.rrname = name
        return rr,p
    def getfield(self, pkt, s):
        if type(s) is tuple :
            s,p = s
        else:
            p = 0
        ret = None
        c = getattr(pkt, self.countfld)
        while c:
            c -= 1
            name,p = DNSgetstr(s,p)
            rr,p = self.decodeRR(name, s, p)
            if ret is None:
                ret = rr
            else:
                ret.add_payload(rr)
        if self.passon:
            return (s,p),ret
        else:
            return s[p:],ret
            
            
class DNSQRField(DNSRRField):
    def decodeRR(self, name, s, p):
        ret = s[p:p+4]
        p += 4
        rr = DNSQR("\x00"+ret)
        rr.qname = name
        return rr,p
        
        

class RDataField(StrLenField):
    def m2i(self, pkt, s):
        if pkt.type == 1:
            s = socket.inet_ntoa(s)
        return s
    def i2m(self, pkt, s):
        if pkt.type == 1:
            if s:
                s = inet_aton(s)
        elif pkt.type in [2,3,4,5]:
            s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
            if ord(s[-1]):
                s += "\x00"
        return s

class RDLenField(Field):
    def __init__(self, name):
        Field.__init__(self, name, None, "H")
    def i2m(self, pkt, x):
        if x is None:
            rdataf = pkt.fieldtype["rdata"]
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    def i2h(self, pkt, x):
        if x is None:
            rdataf = pkt.fieldtype["rdata"]
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    
# seconds between 01-01-1900 and 01-01-1970
ntp_basetime = 2208988800

class TimeStampField(BitField):
    def __init__(self, name, default, size):
        BitField.__init__(self, name, default, size)
        self.size  = size
    def getfield(self, pkt, s):
        s,timestamp = BitField.getfield(self, pkt, s)

        if timestamp:
            # timestamp is a 64 bits field :
            #  + first 32 bits : number of seconds since 1900
            #  + last 32 bits  : fraction part
            timestamp >>= 32
            timestamp -= ntp_basetime
            
            from time import gmtime, strftime
            b = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(timestamp))
        else:
            b = 'None'
        
        return s, b
    def addfield(self, pkt, s, val):
        t = -1
        if type(val) is str:
            from time import strptime, mktime
            t = int(mktime(strptime(val))) + ntp_basetime + 3600
        else:
            if val == -1:
                from time import time
                t = int(time()) + ntp_basetime
            else:
                t = val
        t <<= 32
        return BitField.addfield(self,pkt,s, t)

class FloatField(BitField):
    def getfield(self, pkt, s):
        s,b = BitField.getfield(self, pkt, s)
        
        # fraction point between bits 15 and 16.
        sec = b >> 16
        frac = b & (1L << (32+1)) - 1
        frac /= 65536.0
        b = sec+frac
        return s,b    

###########################
## Packet abstract class ##
###########################


class Packet(Gen):
    name="abstract packet"

    fields_desc = []

    aliastypes = []
    overload_fields = {}

    underlayer = None

    payload_guess = []
    initialized = 0

    def __init__(self, pkt="", **fields):
        self.time  = time.time()
        self.aliastypes = [ self.__class__ ] + self.aliastypes
        self.default_fields = {}
        self.overloaded_fields = {}
        self.fields={}
        self.fieldtype={}
        self.__dict__["payload"] = NoPayload()
        for f in self.fields_desc:
            self.default_fields[f] = f.default
            self.fieldtype[f] = f
        self.initialized = 1
        if pkt:
            self.dissect(pkt)
        for f in fields.keys():
            self.fields[f] = self.fieldtype[f].any2i(self,fields[f])

    def add_payload(self, payload):
        if payload is None:
            return
        elif not isinstance(self.payload, NoPayload):
            self.payload.add_payload(payload)
        else:
            if isinstance(payload, Packet):
                self.__dict__["payload"] = payload
                payload.add_underlayer(self)
                for t in self.aliastypes:
                    if payload.overload_fields.has_key(t):
                        self.overloaded_fields = payload.overload_fields[t]
                        break
            elif type(payload) is str:
                self.__dict__["payload"] = Raw(load=payload)
            else:
                raise TypeError("payload must be either 'Packet' or 'str', not [%s]" % repr(payload))
    def remove_payload(self):
        self.payload.remove_underlayer(self)
        self.__dict__["payload"] = NoPayload()
        self.overloaded_fields = {}
    def add_underlayer(self, underlayer):
        self.underlayer = underlayer
    def remove_underlayer(self, underlayer):
        self.underlayer = None
    def copy(self):
        clone = self.__class__()
        clone.fields = self.fields.copy()
        for k in clone.fields:
            clone.fields[k]=self.fieldtype[k].copy(clone.fields[k])
        clone.default_fields = self.default_fields.copy()
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.overload_fields = self.overload_fields.copy()
        clone.underlayer=self.underlayer
        clone.__dict__["payload"] = self.payload.copy()
        clone.payload.add_underlayer(clone)
        return clone
    def __getattr__(self, attr):
        if self.initialized:
            fld = self.fieldtype.get(attr)
            if fld is None:
                i2h = lambda x,y: y
            else:
                i2h = fld.i2h
            for f in ["fields", "overloaded_fields", "default_fields"]:
                fields = self.__dict__[f]
                if fields.has_key(attr):
                    return i2h(self, fields[attr] )
            return getattr(self.payload, attr)
        raise AttributeError(attr)

    def __setattr__(self, attr, val):
        if self.initialized:
            if self.default_fields.has_key(attr):
                fld = self.fieldtype.get(attr)
                if fld is None:
                    any2i = lambda x,y: y
                else:
                    any2i = fld.any2i
                self.fields[attr] = any2i(self, val)
            elif attr == "payload":
                self.remove_payload()
                self.add_payload(val)
            else:
                self.__dict__[attr] = val
        else:
            self.__dict__[attr] = val
    def __delattr__(self, attr):
        if self.initialized:
            if self.fields.has_key(attr):
                del(self.fields[attr])
                return
            elif self.default_fields.has_key(attr):
                return
            elif attr == "payload":
                self.remove_payload()
                return
        if self.__dict__.has_key(attr):
            del(self.__dict__[attr])
        else:
            raise AttributeError(attr)
            
    def __repr__(self):
        s = ""
        for f in self.fields_desc:
            if f in self.fields:
                s += " %s=%s" % (f, f.i2repr(self, self.fields[f]))
            elif f in self.overloaded_fields:
                s += " %s=%s" % (f, f.i2repr(self, self.overloaded_fields[f]))
        return "<%s%s |%s>"% (self.__class__.__name__,
                              s, repr(self.payload))
    def __str__(self):
        return self.__iter__().next().build()
    def __div__(self, other):
        if isinstance(other, Packet):
            cloneA = self.copy()
            cloneB = other.copy()
            cloneA.add_payload(cloneB)
            return cloneA
        elif type(other) is str:
            return self/Raw(load=other)
        else:
            return other.__rdiv__(self)
    def __rdiv__(self, other):
        if type(other) is str:
            return Raw(load=other)/self
        else:
            raise TypeError
    def __len__(self):
        return len(self.__str__())
    def do_build(self):
        p=""
        for f in self.fields_desc:
            p = f.addfield(self, p, self.__getattr__(f))
        pkt = p+str(self.payload)
        return pkt
    
    def post_build(self, pkt):
        return pkt

    def build(self):
        return self.post_build(self.do_build())

    def extract_padding(self, s):
        return s,None

    def do_dissect(self, s):
        flist = self.fields_desc[:]
        flist.reverse()
        while s and flist:
            f = flist.pop()
            s,fval = f.getfield(self, s)
            self.fields[f] = fval
        payl,pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(Padding(pad))
    def do_dissect_payload(self, s):
        if s:
            cls = self.guess_payload_class()
            try:
                p = cls(s)
            except:
#                print "Warning: %s dissector failed" % cls.name
#                traceback.print_exc()
                p = Raw(s)
            self.add_payload(p)

    def dissect(self, s):
        return self.do_dissect(s)

    def guess_payload_class(self):
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                ok = 1
                for k in fval.keys():
                    if fval[k] != getattr(self,k):
                        ok = 0
                        break
                if ok:
                    return cls
        return None

    def hide_defaults(self):
        for k in self.fields.keys():
            if self.default_fields.has_key(k):
                if self.default_fields[k] == self.fields[k]:
                    del(self.fields[k])
        self.payload.hide_defaults()
            

    def __iter__(self):
        def loop(todo, done, self=self):
            if todo:
                eltname = todo.pop()
                elt = self.__getattr__(eltname)
                if not isinstance(elt, Gen):
                    if self.fieldtype[eltname].islist:
                        elt = SetGen([elt])
                    else:
                        elt = SetGen(elt)
                for e in elt:
                    done[eltname]=e
                    for x in loop(todo[:], done):
                        yield x
            else:
                if isinstance(self.payload,NoPayload):
                    payloads = [None]
                else:
                    payloads = self.payload
                for payl in payloads:
                    done2=done.copy()
                    for k in done2:
                        if isinstance(done2[k], RandNum):
                            done2[k] = int(done2[k])
                    pkt = self.__class__(**done2)
                    pkt.underlayer = self.underlayer
                    pkt.overload_fields = self.overload_fields.copy()
                    if payl is None:
                        yield pkt
                    else:
                        yield pkt/payl
        return loop(map(lambda x:str(x), self.fields.keys()), {})

    def send(self, s, slp=0):
        for p in self:
            s.send(str(p))
            if slp:
                time.sleep(slp)

    def __gt__(self, other):
        if isinstance(other, Packet):
            return other < self
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))
    def __lt__(self, other):
        if isinstance(other, Packet):
            return self.answers(other)
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))
        
    def hashret(self):
        return self.payload.hashret()
    def answers(self, other):
        return 0

    def haslayer(self, cls):
        if self.__class__ == cls:
            return 1
        return self.payload.haslayer(cls)
    def getlayer(self, cls):
        if self.__class__ == cls:
            return self
        return self.payload.getlayer(cls)
    

    def display(self, lvl=0):
        print "---[ %s ]---" % self.name
        for f in self.fields_desc:
            print "%s%-10s= %s" % ("   "*lvl, f.name, f.i2repr(self,self.__getattr__(f)))
        self.payload.display(lvl+1)

    def sprintf(self, fmt, relax=1):
        """sprintf(format, [relax=1]) -> str
where format is a string that can include directives. A directive begins and
ends by % and has the following format %[fmt[r],][cls[:nb].]field%.

fmt is a classic printf directive, "r" can be appended for raw substitution
(ex: IP.flags=0x18 instead of SA), nb is the number of the layer we want
(ex: for IP/IP packets, IP:2.src is the src of the upper IP layer).
Special case : "%.time%" is the creation time.
Ex : p.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% "
               "%03xr,IP.proto% %r,TCP.flags%")
"""
        s = ""
        while "%" in fmt:
            i = fmt.index("%")
            s += fmt[:i]
            fmt = fmt[i+1:]
            if fmt[0] == "%":
                fmt = fmt[1:]
                s += "%"
                continue
            else:
                try:
                    i = fmt.index("%")
                    sfclsfld = fmt[:i]
                    fclsfld = sfclsfld.split(",")
                    if len(fclsfld) == 1:
                        f = "s"
                        clsfld = fclsfld[0]
                    elif len(fclsfld) == 2:
                        f,clsfld = fclsfld
                    else:
                        raise Exception
                    cls,fld = clsfld.split(".")
                    num = 1
                    if ":" in cls:
                        cls,num = cls.split(":")
                        num = int(num)
                    fmt = fmt[i+1:]
                except:
                    raise Exception("Bad format string [%%%s%s]" % (fmt[:25], fmt[25:] and "..."))
                else:
                    if fld == "time":
                        val = time.strftime("%H:%M:%S.%%06i", time.localtime(self.time)) % int((self.time-int(self.time))*1000000)
                    elif cls == self.__class__.__name__ and hasattr(self, fld):
                        if num > 1:
                            val = self.payload.sprintf("%%%s,%s:%s.%s%%" % (f,cls,num-1,fld), relax)
                            f = "s"
                        elif f[-1] == "r":  # Raw field value
                            val = getattr(self,fld)
                            f = f[:-1]
                            if not f:
                                f = "s"
                        else:
                            val = getattr(self,fld)
                            if fld in self.fieldtype:
                                val = self.fieldtype[fld].i2repr(self,val)
                    else:
                        val = self.payload.sprintf("%%%s%%" % sfclsfld, relax)
                        f = "s"
                    s += ("%"+f) % val
            
        s += fmt
        return s

    def mysummary(self):
        return ""
    def summaryback(self, smallname=0):
        ret = ""
        if not smallname:
            ret = self.mysummary()
        if ret:
            smallname = 1
        else:
            ret = self.__class__.__name__
        if self.underlayer is not None:
            ret = "%s / %s" % (self.underlayer.summaryback(smallname),ret)
        return ret
    def summary(self, onlyname=0):
        if isinstance(self.payload, NoPayload):
            return self.summaryback()
        else:
            return self.payload.summary()
    def lastlayer(self,layer=None):
        return self.payload.lastlayer(self)
        

class NoPayload(Packet,object):
    def __new__(cls, *args, **kargs):
        singl = cls.__dict__.get("__singl__")
        if singl is None:
            cls.__singl__ = singl = object.__new__(cls)
            Packet.__init__(singl, *args, **kargs)
        return singl
    def __init__(self, *args, **kargs):
        pass
    def add_payload(self, payload):
        raise Exception("Can't add payload to NoPayload instance")
    def remove_payload(self):
        pass
    def add_underlayer(self,underlayer):
        pass
    def remove_underlayer(self):
        pass
    def copy(self):
        return self
    def __repr__(self):
        return ""
    def __str__(self):
        return ""
    def __getattr__(self, attr):
        if attr in self.__dict__:
            return self.__dict__[attr]
        elif attr in self.__class__.__dict__:
            return self.__class__.__dict__[attr]
        else:
            raise AttributeError, attr
    def hide_defaults(self):
        pass
    def __iter__(self):
        return iter([])
    def hashret(self):
        return ""
    def answers(self, other):
        return isinstance(other, NoPayload) or isinstance(other, Padding)
    def haslayer(self, cls):
        return 0
    def getlayer(self, cls):
        return None
    def display(self, lvl=0):
        pass
    def sprintf(self, fmt, relax):
        if relax:
            return "??"
        else:
            raise Exception("Format not found [%s]"%fmt)
    def summary(self):
        return self.summaryback()
    def lastlayer(self,layer):
        return layer
    

####################
## packet classes ##
####################
    
    
    
            
class Raw(Packet):
    name = "Raw"
    fields_desc = [ StrField("load", "") ]
    def answers(self, other):
        s = str(other)
        t = self.load
        l = min(len(s), len(t))
        return  s[:l] == t[:l]
        
class Padding(Raw):
    name = "Padding"

class Ether(Packet):
    name = "Ethernet"
    fields_desc = [ DestMACField("dst"),
                    SourceMACField("src"),
                    XShortField("type", 0x0000) ]
    def hashret(self):
        return struct.pack("H",self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return "%s > %s (%04x)" % (self.src, self.dst, self.type)

class Dot3(Packet):
    name = "802.3"
    fields_desc = [ MACField("dst", ETHER_BROADCAST),
                    MACField("src", ETHER_ANY),
                    LenField("len", None, "H") ]
    def extract_padding(self,s):
        l = self.len
        return s[:l],s[l:]
    def answers(self, other):
        if isinstance(other,Dot3):
            return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return "%s > %s" % (self.src, self.dst)


class LLC(Packet):
    name = "LLC"
    fields_desc = [ XByteField("dsap", 0x00),
                    XByteField("ssap", 0x00),
                    ByteField("ctrl", 0) ]

class SNAP(Packet):
    name = "SNAP"
    fields_desc = [ X3BytesField("OUI",0x000000),
                    XShortField("code", 0x000) ]


class Dot1Q(Packet):
    name = "802.1Q"
    aliastypes = [ Ether ]
    fields_desc =  [ BitField("prio", 0, 3),
                     BitField("id", 0, 1),
                     BitField("vlan", 1, 12),
                     XShortField("type", 0x0000) ]
    def answers(self, other):
        if isinstance(other,Dot1Q):
            if ( (self.type == other.type) and
                 (self.vlan == other.vlan) ):
                return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)
        return 0



class STP(Packet):
    name = "Spanning Tree Protocol"
    fields_desc = [ ShortField("proto", 0),
                    ByteField("version", 0),
                    ByteField("bpdutype", 0),
                    ByteField("bpduflags", 0),
                    ShortField("rootid", 0),
                    MACField("rootmac", ETHER_ANY),
                    IntField("pathcost", 0),
                    ShortField("bridgeid", 0),
                    MACField("bridgemac", ETHER_ANY),
                    ShortField("portid", 0),
                    ShortField("age", 1),
                    BCDFloatField("maxage", 20),
                    BCDFloatField("hellotime", 2),
                    BCDFloatField("fwddelay", 15) ]


class EAPOL(Packet):
    name = "EAPOL"
    fields_desc = [ ByteField("version", 1),
                    ByteEnumField("type", 0, ["EAP_PACKET", "START", "LOGOFF", "KEY", "ASF"]),
                    LenField("len", None, "H") ]
    
    EAP_PACKET= 0
    START = 1
    LOGOFF = 2
    KEY = 3
    ASF = 4
    def extract_padding(self, s):
        l = self.len
        return s[:l],s[l:]
    def hashret(self):
        return chr(self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,EAPOL):
            if ( (self.type == self.EAP_PACKET) and
                 (other.type == self.EAP_PACKET) ):
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return self.sprintf("EAPOL %EAPOL.type%")
             

class EAP(Packet):
    name = "EAP"
    fields_desc = [ ByteEnumField("code", 4, {1:"REQUEST",2:"RESPONSE",3:"SUCCESS",4:"FAILURE"}),
                    ByteField("id", 0),
                    ByteEnumField("type",0, {1:"ID",4:"MD5"}),
                    ByteField("len",None)]
    
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    TYPE_ID = 1
    TYPE_MD5 = 4
    def answers(self, other):
        if isinstance(other,EAP):
            if self.code == self.REQUEST:
                return 0
            elif self.code == self.RESPONSE:
                if ( (other.code == self.REQUEST) and
                     (other.type == self.type) ):
                    return 1
            elif other.code == self.RESPONSE:
                return 1
        return 0            
    def build(self):
        l = self.len
        if self.code in [EAP.SUCCESS, EAP.FAILURE]:
            if l is None:
                l = 4
            return struct.pack("!BBH",
                               self.code,
                               self.id,
                               l)+str(self.payload)
        else:
            payl = str(self.payload)
            if l is None:
                l = 5+len(payl)
            return struct.pack("!BBHB",
                               self.code,
                               self.id,
                               l,
                               self.type)+payl
             

class ARP(Packet):
    name = "ARP"
    fields_desc = [ XShortField("hwtype", 0x0001),
                    XShortField("ptype",  0x0800),
                    ByteField("hwlen", 6),
                    ByteField("plen", 4),
                    ShortEnumField("op", 1, {"who-has":1, "is-at":2, "RARP-req":3, "RARP-rep":4, "Dyn-RARP-req":5, "Dyn-RAR-rep":6, "Dyn-RARP-err":7, "InARP-req":8, "InARP-rep":9}),
                    ARPSourceMACField("hwsrc"),
                    SourceIPField("psrc","pdst"),
                    MACField("hwdst", ETHER_ANY),
                    IPField("pdst", "0.0.0.0") ]
    who_has = 1
    is_at = 2
    def answers(self, other):
        if isinstance(other,ARP):
            if ( (self.op == self.is_at) and
                 (other.op == self.who_has) and
                 (self.psrc == other.pdst) ):
                return 1
    def extract_padding(self, s):
        return "",s
    def mysummary(self):
        if self.op == self.is_at:
            return "ARP is at %s says %s" % (self.hwsrc, self.psrc)
        elif self.op == self.who_has:
            return "ARP who has %s says %s" % (self.pdst, self.psrc)
        else:
            return "ARP %ARP.op% %ARP.psrc% > %ARP.pdst%"
                 

class IP(Packet, IPTools):
    name = "IP"
    fields_desc = [ BitField("version" , 4 , 4),
                    BitField("ihl", None, 4),
                    XByteField("tos", 0),
                    ShortField("len", None),
                    ShortField("id", 1),
                    FlagsField("flags", 0, 3, ["MF","DF","evil"]),
                    BitField("frag", 0, 13),
                    ByteField("ttl", 64),
                    ByteEnumField("proto", 0, {0:"IP",1:"ICMP",6:"TCP",17:"UDP",47:"GRE"}),
                    XShortField("chksum", None),
                    #IPField("src", "127.0.0.1"),
                    SourceIPField("src","dst"),
                    IPField("dst", "127.0.0.1"),
                    IPoptionsField("options", "") ]
    def post_build(self, p):
        ihl = self.ihl
        if ihl is None:
            ihl = 5+((len(self.options)+3)/4)
            p = chr((self.version<<4) | ihl&0x0f)+p[1:]
        if self.len is None:
            l = len(p)
            p = p[:2]+struct.pack("!H", l)+p[4:]
        if self.chksum is None:
            ck = checksum(p[:ihl*4])
            p = p[:10]+chr(ck>>8)+chr(ck&0xff)+p[12:]
        return p

    def extract_padding(self, s):
        l = self.len - (self.ihl << 2)
        return s[:l],s[l:]

    def send(self, s, slp=0):
        for p in self:
            try:
                s.sendto(str(p), (p.dst,0))
            except socket.error, msg:
                print msg
            if slp:
                time.sleep(slp)
    def hashret(self):
        if ( (self.proto == socket.IPPROTO_ICMP)
             and (isinstance(self.payload, ICMP))
             and (self.payload.type in [3,4,5,11,12]) ):
            return self.payload.payload.hashret()
        else:
            if conf.checkIPsrc:
                return strxor(inet_aton(self.src),inet_aton(self.dst))+struct.pack("B",self.proto)+self.payload.hashret()
            else:
                return struct.pack("B", self.proto)+self.payload.hashret()
    def answers(self, other):
        if not isinstance(other,IP):
            return 0
        if (self.dst != other.src):
            return 0
        if ( (self.proto == socket.IPPROTO_ICMP) and
             (isinstance(self.payload, ICMP)) and
             (self.payload.type in [3,4,5,11,12]) ):
            # ICMP error message
            return self.payload.payload.answers(other)

        else:
            if ( (self.src != other.dst) or
                 (self.proto != other.proto) ):
                return 0
            return self.payload.answers(other.payload)
    def mysummary(self):
        return "%s > %s (%i)" % (self.src,self.dst, self.proto)
                 
    

class TCP(Packet):
    name = "TCP"
    fields_desc = [ ShortField("sport", 20),
                    ShortField("dport", 80),
                    IntField("seq", 0),
                    IntField("ack", 0),
                    BitField("dataofs", None, 4),
                    BitField("reserved", 0, 4),
                    FlagsField("flags", 0x2, 8, "FSRPAUEC"),
                    ShortField("window", 0),
                    XShortField("chksum", None),
                    ShortField("urgptr", 0),
                    TCPOptionsField("options", {}) ]
    def post_build(self, p):
        dataofs = self.dataofs
        if dataofs is None:
            dataofs = 5+((len(self.fieldtype["options"].i2m(self,self.options))+3)/4)
            p = p[:12]+chr((dataofs << 4) | ord(p[12])&0x0f)+p[13:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     len(p))
                ck=checksum(psdhdr+p)
                p=p[:16]+chr(ck >> 8)+chr(ck & 0xff)+p[18:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def hashret(self):
        if conf.checkIPsrc:
            return struct.pack("H",self.sport ^ self.dport)+self.payload.hashret()
        else:
            return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.dport) and
                    (self.dport == other.sport)):
                return 0
        if (abs(other.seq-self.ack) > 2):
            return 0
        return 1
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("TCP %IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% %TCP.flags%")
        else:
            return self.sprintf("TCP %TCP.sport% > %TCP.dport% %TCP.flags%")

class UDP(Packet):
    name = "UDP"
    fields_desc = [ ShortField("sport", 53),
                    ShortField("dport", 53),
                    ShortField("len", None),
                    XShortField("chksum", None), ]
    def post_build(self, p):
        l = self.len
        if l is None:
            l = len(p)
            p = p[:4]+struct.pack("!H",l)+p[6:]
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                psdhdr = struct.pack("!4s4sHH",
                                     inet_aton(self.underlayer.src),
                                     inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     len(p))
                ck=checksum(psdhdr+p)
                p=p[:6]+chr(ck >> 8)+chr(ck & 0xff)+p[8:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def extract_padding(self, s):
        l = self.len - 8
        return s[:l],s[l:]
    def hashret(self):
        if conf.checkIPsrc:
            return struct.pack("H",self.sport ^ self.dport)+self.payload.hashret()
        else:
            return self.payload.hashret()
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.dport) and
                    (self.dport == other.sport)):
                return 0
        return 1
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return "UDP %s:%i > %s:%i" % (self.underlayer.src, self.sport,
                                    self.underlayer.dst, self.dport)
        else:
            return "UDP %i > %i" % (self.sport, self.dport)
    

icmptypes = { 0 : "echo-reply",
              3 : "dest-unreach",
              4 : "source-quench",
              5 : "redirect",
              8 : "echo-request",
              9 : "router-advertisement",
              10 : "router-solicitation",
              11 : "time-exceeded",
              12 : "parameter-problem",
              13 : "timestamp-request",
              14 : "timestamp-reply",
              17 : "address-mask-request",
              18 : "address-mask-reply" }

class ICMP(Packet):
    name = "ICMP"
    fields_desc = [ ByteEnumField("type",8, icmptypes),
                    ByteField("code",0),
                    XShortField("chksum", None),
                    XShortField("id",0),
                    XShortField("seq",0) ]
    def post_build(self, p):
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
        return p
    
    def hashret(self):
        return struct.pack("HH",self.id,self.seq)+self.payload.hashret()
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if ( (other.type,self.type) in [(8,0),(13,14),(17,18)] and
             self.id == other.id and
             self.seq == other.seq ):
            return 1
        return 0

    def guess_payload_class(self):
        if self.type in [3,4,5,11,12]:
            return IPerror
        else:
            return None
    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("ICMP %IP.src% %ICMP.type% %ICMP.code%")
        else:
            return self.sprintf("ICMP %ICMP.type% %ICMP.code%")
    
        



class IPerror(IP):
    name = "IP in ICMP"
    def answers(self, other):
        if not isinstance(other, IP):
            return 0
        if not ( ((conf.checkIPsrc == 0) or (self.dst == other.dst)) and
                 (self.src == other.src) and
                 ( ((conf.checkIPID == 0)
                    or (self.id == other.id)
                    or (self.id == socket.htons(other.id) and conf.checkIPID == 1))) and
                 (self.proto == other.proto) ):
            return 0
        return self.payload.answers(other.payload)
    def mysummary(self):
        return Packet.mysummary(self)


class TCPerror(TCP):
    name = "TCP in ICMP"
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        if self.seq is not None:
            if self.seq != other.seq:
                return 0
        if self.ack is not None:
            if self.ack != other.ack:
                return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)


class UDPerror(UDP):
    name = "UDP in ICMP"
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if conf.checkIPsrc:
            if not ((self.sport == other.sport) and
                    (self.dport == other.dport)):
                return 0
        return 1
    def mysummary(self):
        return Packet.mysummary(self)

                    

class ICMPerror(ICMP):
    name = "ICMP in ICMP"
    def answers(self, other):
        if not isinstance(other,ICMP):
            return 0
        if not ((self.type == other.type) and
                (self.code == other.code)):
            return 0
        if self.code in [0,8,13,14,17,18]:
            if (self.id == other.id and
                self.seq == other.seq):
                return 1
            else:
                return 0
        else:
            return 1
    def mysummary(self):
        return Packet.mysummary(self)

                
class LLPPP(Packet):
    name = "PPP Link Layer"
            
        
class DNS(Packet):
    name = "DNS"
    fields_desc = [ ShortField("id",0),
                    BitField("qr",0, 1),
                    BitEnumField("opcode", 0, 4, {0:"QUERY",1:"IQUERY",2:"STATUS"}),
                    BitField("aa", 0, 1),
                    BitField("tc", 0, 1),
                    BitField("rd", 0, 1),
                    BitField("ra", 0 ,1),
                    BitField("z", 0, 3),
                    BitEnumField("rcode", 0, 4, {0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"}),
                    DNSRRCountField("qdcount", None, "qd"),
                    DNSRRCountField("ancount", None, "an"),
                    DNSRRCountField("nscount", None, "ns"),
                    DNSRRCountField("arcount", None, "ar"),
                    DNSQRField("qd", "qdcount"),
                    DNSRRField("an", "ancount"),
                    DNSRRField("ns", "nscount"),
                    DNSRRField("ar", "arcount",0) ]


dnstypes = { 0:"ANY", 255:"ALL",
             1:"A", 2:"NS", 3:"MD", 4:"MD", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG",
             9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT",
             17:"RP",18:"AFSDB",28:"AAAA", 33:"SRV",38:"A6",39:"DNAME"}

dnsqtypes = {251:"IXFR",252:"AXFR",253:"MAILB",254:"MAILA",255:"ALL"}
dnsqtypes.update(dnstypes)
dnsclasses =  {1: 'IN',  2: 'CS',  3: 'CH',  4: 'HS',  255: 'ANY'}


class DNSQR(Packet):
    name = "DNS Question Record"
    fields_desc = [ DNSStrField("qname",""),
                    ShortEnumField("qtype", 1, dnsqtypes),
                    ShortEnumField("qclass", 1, dnsclasses) ]
                    
                    

class DNSRR(Packet):
    name = "DNS Resource Record"
    fields_desc = [ DNSStrField("rrname",""),
                    ShortEnumField("type", 1, dnstypes),
                    ShortEnumField("rclass", 1, dnsclasses),
                    IntField("ttl", 0),
                    RDLenField("rdlen"),
                    RDataField("rdata", "", "rdlen") ]

class BOOTP(Packet):
    name = "BOOTP"
    fields_desc = [ ByteEnumField("op",1, {1:"BOOTREQUEST", 2:"BOOTREPLY"}),
                    ByteField("htype",1),
                    ByteField("hlen",6),
                    ByteField("hops",0),
                    IntField("xid",0),
                    ShortField("secs",0),
                    FlagsField("flags", 0, 16, "???????????????B"),
                    IPField("ciaddr","0.0.0.0"),
                    IPField("yiaddr","0.0.0.0"),
                    IPField("siaddr","0.0.0.0"),
                    IPField("giaddr","0.0.0.0"),
                    Field("chaddr","", "16s"),
                    Field("sname","","64s"),
                    Field("file","","128s"),
                    StrField("options","") ]

dhcpmagic="".join(map(chr,[99,130,83,99]))


class Dot11(Packet):
    name = "802.11"
    fields_desc = [
                    BitField("subtype", 0, 4),
                    BitEnumField("type", 0, 2, ["Management", "Control", "Data", "Reserved"]),
                    BitField("proto", 0, 2),
                    FlagsField("FCfield", 0, 8, ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]),
                    ShortField("ID",0),
                    MACField("addr1", ETHER_ANY),
                    Dot11Addr2MACField("addr2", ETHER_ANY),
                    Dot11Addr3MACField("addr3", ETHER_ANY),
                    ShortField("SC", 0),
                    Dot11Addr4MACField("addr4", ETHER_ANY) 
                    ]
    def mysummary(self):
        return self.sprintf("802.11 %Dot11.type% %Dot11.subtype% %Dot11.addr1%")

capability_list = [ "res8", "res9", "short-slot", "res11",
                    "res12", "DSSS-OFDM", "res14", "res15",
                   "ESS", "IBSS", "CFP", "CFP-req",
                   "privacy", "short-preamble", "PBCC", "agility"]

reason_code = {0:"reserved",1:"unspec", 2:"auth-expired",
               3:"deauth-ST-leaving",
               4:"inactivity", 5:"AP-full", 6:"class2-from-nonauth",
               7:"class3-from-nonass", 8:"disas-ST-leaving",
               9:"ST-not-auth"}

status_code = {0:"success", 1:"failure", 10:"cannot-support-all-cap",
               11:"inexist-asso", 12:"asso-denied", 13:"algo-unsupported",
               14:"bad-seq-num", 15:"challenge-failure",
               16:"timeout", 17:"AP-full",18:"rate-unsupported" }

class Dot11Beacon(Packet):
    name = "802.11 Beacon"
    fields_desc = [ LongField("timestamp", 0),
                    ShortField("beacon_interval", 0x6400),
                    FlagsField("cap", 0, 16, capability_list) ]
    

class Dot11Elt(Packet):
    name = "802.11 Information Element"
    fields_desc = [ ByteEnumField("ID", 0, {0:"SSID", 1:"Rates", 2: "FHset", 3:"DSset", 4:"CFset", 5:"TIM", 6:"IBSSset", 16:"challenge"}),
                    FieldLenField("len", None, "info", "B"),
                    StrLenField("info", "", "len") ]
    def sum(self):
        return self.sprintf("Info %Dot11Elt.ID%")

class Dot11ATIM(Packet):
    name = "802.11 ATIM"

class Dot11Disas(Packet):
    name = "802.11 Disassociation"
    fields_desc = [ ShortEnumField("reason", 1, reason_code) ]

class Dot11AssoReq(Packet):
    name = "802.11 Association Request"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    ShortField("listen_interval", 0xc800) ]


class Dot11AssoResp(Packet):
    name = "802.11 Association Response"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    ShortField("status", 0),
                    ShortField("AID", 0) ]

class Dot11ReassoReq(Packet):
    name = "802.11 Reassociation Request"
    fields_desc = [ FlagsField("cap", 0, 16, capability_list),
                    MACField("current_AP", ETHER_ANY),
                    ShortField("listen_interval", 0xc800) ]


class Dot11ReassoResp(Dot11AssoResp):
    name = "802.11 Reassociation Response"

class Dot11ProbeReq(Packet):
    name = "802.11 Probe Request"
    
class Dot11ProbeResp(Packet):
    name = "802.11 Probe Response"
    fields_desc = [ LongField("timestamp", 0),
                    ShortField("beacon_interval", 0x6400),
                    FlagsField("cap", 0, 16, capability_list) ]
    
class Dot11Auth(Packet):
    name = "802.11 Authentication"
    fields_desc = [ ShortEnumField("algo", 0, ["open", "sharedkey"]),
                    ShortField("seqnum", 0),
                    ShortEnumField("status", 0, status_code) ]

class Dot11Deauth(Packet):
    name = "802.11 Deauthentication"
    fields_desc = [ ShortEnumField("reason", 1, reason_code) ]


class PrismHeader(Packet):
    """ iwpriv wlan0 monitor 3 """
    fields_desc = [ LEIntField("msgcode",68),
                    LEIntField("len",144),
                    StrFixedLenField("dev","",16),
                    StrFixedLenField("truc","",68),
                    LEIntField("signal",0),
                    LEIntField("toto1",0),
                    LEIntField("toto2",0),
                    LEIntField("noise",0),
                    StrFixedLenField("tit","",36)                    
                    ]


class NTP(Packet):
    # RFC 1769
    name = "NTP"
    fields_desc = [ 
         BitEnumField('leap', 0, 2,
                      { 0: 'nowarning',
                        1: 'longminute',
                        2: 'shortminute',
                        3: 'notsync'}),
         BitField('version', 3, 3),
         BitEnumField('mode', 3, 3,
                      { 0: 'reserved',
                        1: 'sym_active',
                        2: 'sym_passive',
                        3: 'client',
                        4: 'server',
                        5: 'broadcast',
                        6: 'control',
                        7: 'private'}),
         BitField('stratum', 2, 8),
         BitField('poll', 0xa, 8),          ### XXX : it's a signed int
         BitField('precision', 0, 8),       ### XXX : it's a signed int
         FloatField('delay', 0, 32),
         FloatField('dispersion', 0, 32),
         IPField('id', "127.0.0.1"),
         TimeStampField('ref', 0, 64),
         TimeStampField('orig', -1, 64),  # -1 means current time
         TimeStampField('recv', 0, 64),
         TimeStampField('sent', -1, 64) 
         ]



class Radius(Packet):
    name = "Radius"
    fields_desc = [ ByteEnumField("code", 1, {1: "Access-Request",
                                              2: "Access-Accept",
                                              3: "Access-Reject",
                                              4: "Accounting-Request",
                                              5: "Accounting-Accept",
                                              11:"Access-Challenge",
                                              12:"Status-Server",
                                              13:"Status-Client",
                                              255:"Reserved"} ),
                    ByteField("id", 0),
                    ShortField("len", None),
                    StrFixedLenField("authenticator","",16) ]
    def post_build(self, p):
        l = self.len
        if l is None:
            l = len(p)
            p = p[:2]+struct.pack("!H",l)+p[4:]
        return p




class RIP(Packet):
    name = "RIP header"
    fields_desc = [
        ByteEnumField("command",1,{1:"req",2:"resp",3:"traceOn",4:"traceOff",5:"sun",
                                   6:"trigReq",7:"trigResp",8:"trigAck",9:"updateReq",
                                   10:"updateResp",11:"updateAck"}),
        ByteField("version",1),
        ShortField("null",0),
        ]

class RIPEntry(Packet):
    name = "RIP entry"
    fields_desc = [
        ShortEnumField("AF",2,{2:"IP"}),
        ShortField("RouteTag",0),
        IPField("addr","0.0.0.0"),
        IPField("mask","0.0.0.0"),
        IPField("nextHop","0.0.0.0"),
        IntEnumField("metric",1,{16:"Unreach"}),
        ]
        



ISAKMP_payload_type = ["None","SA","P","T","KE","ID","CERT","CR","HASH",
                       "SIG","Nonce","N","D","VID"]

ISAKMP_exchange_type = ["None","base","identity prot.",
                        "auth only", "aggressive", "info"]

class ISAKMP(Packet): # rfc2408
    name = "ISAKMP"
    fields_desc = [
        StrFixedLenField("init_cookie","",8),
        StrFixedLenField("resp_cookie","",8),
        ByteEnumField("next_payload",0,ISAKMP_payload_type),
        XByteField("version",0x10),
        ByteEnumField("exch_type",0,ISAKMP_exchange_type),
        ByteField("flags",0), # XXX use a Flag field
        IntField("id",0),
        IntField("length",None)
        ]


    def post_build(self, p):
        if self.length is None:
            p = p[:24]+struct.pack("!I",len(p))+p[28:]
        return p
       

class ISAKMP_payload(Packet):
    name = "ISAKMP payload"
    fields_desc = [
        ByteEnumField("next_payload",None,ISAKMP_payload_type),
        ByteField("res",0),
        ShortField("length",None),
        Field("load",""),
        ]
    def post_build(self, p):
        if self.length is None:
            p = p[:2]+struct.pack("!H",4+len(self.load))+p[4:]
        if self.next_payload is None:
            t = getattr(getattr(self.payload,"load", NoPayload), "ISAKMP_payload_type",0)
            if t:
                p = chr(t)+p[1:]
        return p
                     
        

class IKE_SA(Packet):
    name = "IKE SA"
    ISAKMP_payload_type = 0
    fields_desc = [
        IntEnumField("DOI",1,{1:"IPSEC"}),
        IntEnumField("situation",1,{1:"identity"}),
        Field("load",""),
        ]
    
class IKE_proposal(Packet):
    name = "IKE proposal"
    ISAKMP_payload_type = 0
    fields_desc = [
        ByteField("proposal",1),
        ByteEnumField("proto",1,{1:"ISAKMP"}),
        ByteField("SPIsize",0),
        ByteField("trans_nb",None),
        Field("transforms","")
        ]
    def post_build(self,p):
        if self.trans_nb is None:
            n = 0
            i = self.transforms
            while isinstance(IKETransform,i):
                n += 1
                i = i.payload
            p = p[:3]+chr(n)+p[4:]
        return p

class IKETransform(Packet):
    name = "IKE Transform"
    ISAKMP_payload_type = 3
    field_desc = [
        ByteField("num",None),
        ByteEnumField("id",1,{1:"KEY_IKE"}),
        ShortField("res",0),
#        SAattrField("attr"),
        XIntField("enc",0x80010005L),
        XIntField("hash",0x80020002L),
        XIntField("auth",0x80030001L),
        XIntField("group",0x80040002L),
        XIntField("life_type",0x800b0001L),
        XIntField("durationh",0x000c0004L),
        XIntField("durationl",0x00007080L),
        ]
        
        
        
        



#################
## Bind layers ##
#################
    

def bind_layers(lower, upper, fval):
    lower.payload_guess = lower.payload_guess[:]
    upper.overload_fields = upper.overload_fields.copy()
    lower.payload_guess.append((fval, upper))
    upper.overload_fields[lower] = fval
    
    

layer_bonds = [ ( Dot3,   LLC,      { } ),
                ( PrismHeader, Dot11, { }),
                ( Dot11,  LLC,      { "type" : 2 } ),
                ( LLPPP,  IP,       { } ),
                ( Ether,  LLC,      { "type" : 0x007a } ),
                ( Ether,  Dot1Q,    { "type" : 0x8100 } ),
                ( Ether,  Ether,    { "type" : 0x0001 } ),
                ( Ether,  ARP,      { "type" : 0x0806 } ),
                ( Ether,  IP,       { "type" : 0x0800 } ),
                ( Ether,  EAPOL,    { "type" : 0x888e } ),
                ( Ether,  EAPOL,    { "type" : 0x888e, "dst" : "01:80:c2:00:00:03" } ),
                ( EAPOL,  EAP,      { "type" : EAPOL.EAP_PACKET } ),
                ( LLC,    STP,      { "dsap" : 0x42 , "ssap" : 0x42 } ),
                ( LLC,    SNAP,     { "dsap" : 0xAA , "ssap" : 0xAA } ),
                ( SNAP,   Dot1Q,    { "code" : 0x8100 } ),
                ( SNAP,   Ether,    { "code" : 0x0001 } ),
                ( SNAP,   ARP,      { "code" : 0x0806 } ),
                ( SNAP,   IP,       { "code" : 0x0800 } ),
                ( SNAP,   EAPOL,    { "code" : 0x888e } ),
                ( IPerror,IPerror,  { "proto" : socket.IPPROTO_IP } ),
                ( IPerror,ICMPerror,{ "proto" : socket.IPPROTO_ICMP } ),
                ( IPerror,TCPerror, { "proto" : socket.IPPROTO_TCP } ),
                ( IPerror,UDPerror, { "proto" : socket.IPPROTO_UDP } ),
                ( IP,     IP,       { "proto" : socket.IPPROTO_IP } ),
                ( IP,     ICMP,     { "proto" : socket.IPPROTO_ICMP } ),
                ( IP,     TCP,      { "proto" : socket.IPPROTO_TCP } ),
                ( IP,     UDP,      { "proto" : socket.IPPROTO_UDP } ),
                ( UDP,    DNS,      { "dport" : 53 } ),
                ( UDP,    ISAKMP,   { "sport" : 500, "dport" : 500 } ),
                ( UDP,    NTP,      { "sport" : 123, "dport" : 123 } ),
                ( UDP,    BOOTP,    { "sport" : 68, "dport" : 67 } ),
                ( UDP,    BOOTP,    { "sport" : 67, "dport" : 68 } ),
                ( UDP,    RIP,      { "sport" : 520 } ),
                ( UDP,    RIP,      { "dport" : 520 } ),
                ( UDP,    DNS,      { "sport" : 53 } ),
                ( RIP,    RIPEntry, { } ),
                ( RIPEntry,RIPEntry,{ } ),
                ( Dot11, Dot11AssoReq,    { "type" : 0, "subtype" : 0 } ),
                ( Dot11, Dot11AssoResp,   { "type" : 0, "subtype" : 1 } ),
                ( Dot11, Dot11ReassoReq,  { "type" : 0, "subtype" : 2 } ),
                ( Dot11, Dot11ReassoResp, { "type" : 0, "subtype" : 3 } ),
                ( Dot11, Dot11ProbeReq,   { "type" : 0, "subtype" : 4 } ),
                ( Dot11, Dot11ProbeResp,  { "type" : 0, "subtype" : 5 } ),
                ( Dot11, Dot11Beacon,     { "type" : 0, "subtype" : 8 } ),
                ( Dot11, Dot11ATIM ,      { "type" : 0, "subtype" : 9 } ),
                ( Dot11, Dot11Disas ,     { "type" : 0, "subtype" : 10 } ),
                ( Dot11, Dot11Auth,       { "type" : 0, "subtype" : 11 } ),
                ( Dot11, Dot11Deauth,     { "type" : 0, "subtype" : 12 } ),
                ( Dot11Beacon, Dot11Elt,     {} ),
                ( Dot11AssoReq, Dot11Elt,    {} ),
                ( Dot11AssoResp, Dot11Elt,   {} ),
                ( Dot11ReassoReq, Dot11Elt,  {} ),
                ( Dot11ReassoResp, Dot11Elt, {} ),
                ( Dot11ProbeReq, Dot11Elt,   {} ),
                ( Dot11ProbeResp, Dot11Elt,  {} ),
                ( Dot11Auth, Dot11Elt,       {} ),
                ( Dot11Elt, Dot11Elt,        {} ),
                ]

for l in layer_bonds:
    bind_layers(*l)
                

###################
## Fragmentation ##
###################

def fragment(pkt, fragsize=1480):
    fragsize = (fragsize+7)/8*8
    pkt = pkt.copy()
    pkt.flags = "MF"
    lst = []
    for p in pkt:
        q = p.copy()
        del(q.payload)
        s = str(p.payload)
        nb = (len(s)+fragsize-1)/fragsize
        for i in range(nb):            
            r = Raw(load=s[i*fragsize:(i+1)*fragsize])
            r.overload_fields = p.payload.overload_fields.copy()
            if i == nb-1:
                q.flags=0
            q.frag = i*fragsize/8
            q.add_payload(r)
            lst.append(q)
    return lst


###################
## Super sockets ##
###################


# According to libdnet
LLTypes = { ARPHDR_ETHER : Ether,
            ARPHDR_METRICOM : Ether,
            ARPHDR_LOOPBACK : Ether,
	    101 : IP,
            801 : Dot11,
            802 : PrismHeader,
            105 : Dot11,
            }

L3Types = { ETH_P_IP : IP,
            ETH_P_ARP : ARP,
            ETH_P_ALL : IP
            }



class SuperSocket:
    closed=0
    def __init__(self, family=socket.AF_INET,type=socket.SOCK_STREAM, proto=0):
        self.ins = socket.socket(family, type, proto)
        self.outs = self.ins
        self.promisc=None
    def send(self, x):
        return self.outs.send(str(x))
    def recv(self, x):
        return Raw(self.ins.recv(x))
    def fileno(self):
        return self.ins.fileno()
    def close(self):
        if self.closed:
            return
        self.closed=1
        if self.ins != self.outs:
            if self.outs and self.outs.fileno() != -1:
                self.outs.close()
        if self.ins and self.ins.fileno() != -1:
            self.ins.close()
    def bind_in(self, addr):
        self.ins.bind(addr)
    def bind_out(self, addr):
        self.outs.bind(addr)


class L3RawSocket(SuperSocket):
    def __init__(self, type = ETH_P_IP, filter=None):
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
    def recv(self, x):
        return Ether(self.ins.recv(x)).payload
    def send(self, x):
        try:
            self.outs.sendto(str(x),(x.dst,0))
        except socket.error,msg:
            print msg
        


class L3PacketSocket(SuperSocket):
    def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None):
        self.type = type
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        if conf.except_filter:
            if filter:
                filter = "(%s) and not (%s)" % (filter, conf.except_filter)
            else:
                filter = "not (%s)" % conf.except_filter
        if filter is not None:
            attach_filter(self.ins, filter)
        self.outs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        if promisc is None:
            promisc = conf.promisc
        self.promisc = promisc
        if iface is None:
            self.iff = get_if_list()
        else:
            if iface.__class__ is list:
                self.iff = iface
            else:
                self.iff = [iface]
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i)
    def close(self):
        if self.closed:
            return
        self.closed=1
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)
    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        # XXX: if sa_ll[2] == socket.PACKET_OUTGOING : skip
        if LLTypes.has_key(sa_ll[3]):
            cls = LLTypes[sa_ll[3]]
            lvl = 2
        elif L3Types.has_key(sa_ll[1]):
            cls = L3Types[sa_ll[1]]
            lvl = 3
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            cls = Ether
            lvl = 2

        try:
            pkt = cls(pkt)
        except:
            pkt = Raw(pkt)
        if lvl == 2:
            pkt = pkt.payload
        return pkt
    
    def send(self, x):
        if hasattr(x,"dst"):
            iff,a,gw = conf.route.route(x.dst)
        else:
            iff = conf.iface
        sdto = (iff, self.type)
        self.outs.bind(sdto)
        sn = self.outs.getsockname()
        if sn[3] == ARPHDR_PPP:
            sdto = (iff, ETH_P_IP)
        elif LLTypes.has_key(sn[3]):
            x = LLTypes[sn[3]]()/x
        self.outs.sendto(str(x), sdto)



class L2Socket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, filter=None):
        if iface is None:
            iface = conf.iface
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        self.ins.bind((iface, type))
        self.outs = self.ins
        sa_ll = self.outs.getsockname()
        if LLTypes.has_key(sa_ll[3]):
            self.LL = LLTypes[sa_ll[3]]
        elif L3Types.has_key(sa_ll[1]):
            self.LL = L3Types[sa_ll[1]]
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            self.LL = Ether
    def recv(self, x):
        p = self.ins.recv(x)
        try:
            q = self.LL(p)
        except:
            q = Raw(p)
        return q


class L2ListenSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
        self.type = type
        self.outs = None
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        if iface is not None:
            self.ins.bind((iface, type))
        if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter is not None:
                attach_filter(self.ins, filter)
        if promisc is None:
            promisc = conf.sniff_promisc
        self.promisc = promisc
        if iface is None:
            self.iff = get_if_list()
        else:
            if iface.__class__ is list:
                self.iff = iface
            else:
                self.iff = [iface]
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i)
    def close(self):
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i, 0)
        SuperSocket.close(self)

    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        if LLTypes.has_key(sa_ll[3]):
            cls = LLTypes[sa_ll[3]]
        elif L3Types.has_key(sa_ll[1]):
            cls = L3Types[sa_ll[1]]
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%i). Using Ethernet" % (sa_ll[0],sa_ll[1],sa_ll[3]))
            cls = Ether

        try:
            pkt = cls(pkt)
        except:
            pkt = Raw(pkt)
        return pkt
    
    def send(self, x):
        raise Exception("Can't send anything with L2ListenSocket")



if DNET and PCAP:
    # XXX: works only for Ethernet
    class L3dnetSocket(SuperSocket):
        def __init__(self, type = None, filter=None, promisc=None, iface=None):
            self.iflist = {}
            self.ins = pcap.pcapObject()
            if iface is None:
                iface = "any"
            self.ins.open_live(iface, 1600, 0, 100)
            if conf.except_filter:
                if filter:
                    filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                else:
                    filter = "not (%s)" % conf.except_filter
            if filter:
                self.ins.setfilter(filter, 0, 0)
        def send(self, x):
            if hasattr(x,"dst"):
                iff,a,gw = conf.route.route(x.dst)
            else:
                iff = conf.iface
            ifs = self.iflist.get(iff)
            if ifs is None:
                self.iflist[iff] = ifs = dnet.eth(iff)
            ifs.send(str(Ether()/x))
        def recv(self,x):
            return Ether(self.ins.next()[1][2:]).payload
        def close(self):
            if hasattr(self, "ins"):
                del(self.ins)
            if hasattr(self, "outs"):
                del(self.outs)

    class L2dnetSocket(SuperSocket):
        def __init__(self, iface = None, type = ETH_P_ALL, filter=None):
            if iface is None:
                iface = conf.iface
            self.ins = pcap.pcapObject()
            self.ins.open_live(iface, 1600, 0, 100)
            if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if filter:
                    self.ins.setfilter(filter, 0, 0)
            self.outs = dnet.eth(iface)
        def recv(self,x):
            return Ether(self.ins.next()[1])
        def close(self):
            if hasattr(self, "ins"):
                del(self.ins)
            if hasattr(self, "outs"):
                del(self.outs)
        
    
    


if PCAP:
    class L2pcapListenSocket(SuperSocket):
        def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
            self.type = type
            self.outs = None
            self.ins = pcap.pcapObject()
            if iface is None:
                iface = "any"
            if promisc is None:
                promisc = conf.sniff_promisc
            self.promisc = promisc
            self.ins.open_live(iface, 1600, self.promisc, 100)
            if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if filter:
                    self.ins.setfilter(filter, 0, 0)

        def close(self):
            del(self.ins)
    
        def recv(self, x):
            return Ether(self.ins.next()[1][2:])
        
        def send(self, x):
            raise Exception("Can't send anything with L2pcapListenSocket")
    


####################
## Send / Receive ##
####################




def sndrcv(pks, pkt, timeout = 2, inter = 0, verbose=None, chainCC=0,retry=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
        
    if verbose is None:
        verbose = conf.verb
    debug.recv = PacketList([],"Unanswered")
    debug.sent = PacketList([],"Sent")
    debug.match = SndRcvAns([])
    nbrecv=0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    tobesent = [p for p in pkt]
    notans = len(tobesent)

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]
    if retry < 0:
        retry = -retry
        autostop=retry
    else:
        autostop=0


    while retry >= 0:
        found=0
    
        
        if timeout < 0:
            timeout = None
            
        rdpipe,wrpipe = os.pipe()
        rdpipe=os.fdopen(rdpipe)
        wrpipe=os.fdopen(wrpipe,"w")
    
        pid = os.fork()
        if pid == 0:
            sys.stdin.close()
            rdpipe.close()
            try:
                i = 0
                if verbose:
                    print "Begin emission:"
                for p in tobesent:
                    pks.send(p)
                    i += 1
                    time.sleep(inter)
                if verbose:
                    print "Finished to send %i packets." % i
            except SystemExit:
                pass
            except KeyboardInterrupt:
                pass
            except:
                print "--- Error in child %i" % os.getpid()
                traceback.print_exc()
                print "--- End of error in child %i" % os.getpid()
                sys.exit()
            else:
                cPickle.dump(arp_cache, wrpipe)
                wrpipe.close()
            sys.exit()
        elif pid < 0:
            print "fork error"
        else:
            wrpipe.close()
            finished = 0
            remaintime = timeout
            inmask = [rdpipe,pks]
            try:
                while 1:
                    start = time.time()
                    inp, out, err = select(inmask,[],[], remaintime)
                    if len(inp) == 0:
                        break
                    if rdpipe in inp:
                        finished = 1
                        del(inmask[inmask.index(rdpipe)])
                        continue
                    r = pks.recv(MTU)
                    ok = 0
                    h = r.hashret()
                    if h in hsent:
                        hlst = hsent[h]
                        for i in range(len(hlst)):
                            if r.answers(hlst[i]):
                                ans.append((hlst[i],r))
                                if verbose > 1:
                                    os.write(1, "*")
                                ok = 1
                                notans -= 1
                                del(hlst[i])
                                break
                    if notans == 0:
                        break
                    if not ok:
                        if verbose > 1:
                            os.write(1, ".")
                        nbrecv += 1
                        if conf.debug_match:
                            debug.recv.append(r)
                    if finished and remaintime:
                        end = time.time()
                        remaintime -= end-start
                        if remaintime < 0:
                            break
            except KeyboardInterrupt:
                if chainCC:
                    raise KeyboardInterrupt
    
            try:
                ac = cPickle.load(rdpipe)
            except EOFError:
                warning("Child died unexpectedly. Packets may have not been sent")
            else:
                arp_cache.update(ac)
                os.waitpid(pid,0)
    
        remain = reduce(list.__add__, hsent.values())
        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        retry -= 1
        
    if conf.debug_match:
        debug.sent=PacketList(remain[:],"Sent")
        debug.match=SndRcvAns(ans[:])
    if verbose:
        print "\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans)
    return SndRcvAns(ans),PacketList(remain,"Unanswered"),debug.recv


def __gen_send(s, x, inter=0, loop=0, verbose=None, *args, **kargs):
    if not isinstance(x, Gen):
        x = SetGen(x)
    if verbose is None:
        verbose = conf.verb
    n = 0
    try:
        while 1:
            for p in x:
                s.send(p)
                n += 1
                if verbose:
                    os.write(1,".")
                time.sleep(inter)
            if not loop:
                break
    except KeyboardInterrupt:
        pass
    s.close()
    if verbose:
        print "\nSent %i packets." % n

def send(x, inter=0, loop=0, verbose=None, *args, **kargs):
    """Send packets at layer 3
send(packets, [inter=0], [loop=0], [verbose=conf.verb]) -> None"""
    __gen_send(conf.L3socket(*args, **kargs), x, inter=inter, loop=loop, verbose=verbose)

def sendp(x, inter=0, loop=0, verbose=None, *args, **kargs):
    """Send packets at layer 2
send(packets, [inter=0], [loop=0], [verbose=conf.verb]) -> None"""
    __gen_send(conf.L2socket(*args, **kargs), x, inter=inter, loop=loop, verbose=verbose)
    
def sr(x,filter=None, iface=None, *args,**kargs):
    """Send and receive packets at layer 3"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    s = conf.L3socket(filter=filter, iface=iface)
    a,b,c=sndrcv(s,x,*args,**kargs)
    s.close()
    return a,b

def sr1(x,filter=None,iface=None, *args,**kargs):
    """Send packets at layer 3 and return only the first answer"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    s=conf.L3socket(filter=filter, iface=iface)
    a,b,c=sndrcv(s,x,*args,**kargs)
    s.close()
    if len(a) > 0:
        return a[0][1]
    else:
        return None

def srp(x,iface=None,filter=None,type=ETH_P_ALL, *args,**kargs):
    """Send and receive packets at layer 2"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(conf.L2socket(iface=iface, filter=filter, type=type),x,*args,**kargs)
    return a,b

def srp1(x,iface=None,filter=None,type=ETH_P_ALL, *args,**kargs):
    """Send and receive packets at layer 2 and return only the first answer"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(conf.L2socket(iface=iface, filter=filter, type=type),x,*args,**kargs)
    if len(a) > 0:
        return a[0][1]
    else:
        return None

def __sr_loop(srfunc, pkts, prn=lambda x:x[1].summary(), prnfail=lambda x:x.summary(), inter=1, timeout=0, count=None, verbose=0,  *args, **kargs):
    n = 0
    r = 0
    if timeout == 0:
        timeout = min(2*inter, 5)
    try:
        while 1:
            if count is not None:
                if count == 0:
                    break
                count -= 1
            start = time.time()
            print "\rsend...\r",
            res = srfunc(pkts, timeout=timeout, verbose=0, chainCC=1, *args, **kargs)
            n += len(res[0])+len(res[1])
            r += len(res[0])
            if prn and len(res[0]) > 0:
                msg = "RECV %i:" % len(res[0])
                print  "\r%s" % msg,
                for p in res[0]:
                    print prn(p)
                    print " "*len(msg),
            if prnfail and len(res[1]) > 0:
                msg = "fail %i:" % len(res[1])
                print "\r%s" % msg,
                for p in res[1]:
                    print prnfail(p)
                    print " "*len(msg),
            if not (prn or prnfail):
                print "recv:%i  fail:%i" % tuple(map(len, res[:2]))
            end=time.time()
            if end-start < inter:
                time.sleep(inter+start-end)
    except KeyboardInterrupt:
        pass
    print "\nSent %i packets, received %i packets. %3.1f%% hits." % (n,r,100.0*r/n)

def srloop(pkts, *args, **kargs):
    """Send a packet at layer 3 in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    __sr_loop(sr, pkts, *args, **kargs)

def srploop(pkts, *args, **kargs):
    """Send a packet at layer 2 in loop and print the answer each time
srloop(pkts, [prn], [inter], [count], ...) --> None"""
    __sr_loop(srp, pkts, *args, **kargs)

           


#############################
## pcap capture file stuff ##
#############################

def wrpcap(filename, pkt):
    f=open(filename,"w")
    f.write(struct.pack("IHHIIII",
                        0xa1b2c3d4L,
                        2, 4,
                        0,
                        0,
                        MTU,
                        1)) # XXX Find the link type
    for p in pkt:
        s = str(p)
        l = len(s)
        sec = int(p.time)
        usec = int((p.time-sec)*1000000)
        f.write(struct.pack("IIII", sec, usec, l, l))
        f.write(s)
    f.close()

def rdpcap(filename):
    res=[]
    f=open(filename)
    magic = f.read(4)
    if struct.unpack("<I",magic) == (0xa1b2c3d4L,):
       endian = "<"
    elif struct.unpack(">I",magic) == (0xa1b2c3d4L,):
       endian = ">"
    else:
        warning("Not a pcap capture file (bad magic)")
        return []
    hdr = f.read(20)
    if len(hdr)<20:
        warning("Invalid pcap file")
        return res
    vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(endian+"HHIIII",hdr)
    LLcls = LLTypes.get(linktype, Raw)
    if LLcls == Raw:
        warning("LL type unknown. Using Raw packets")
    while 1:
        hdr = f.read(16)
        if len(hdr) < 16:
            break
        sec,usec,caplen,olen = struct.unpack(endian+"IIII", hdr )
        p = LLcls(f.read(caplen))
        p.time = sec+0.000001*usec
        res.append(p)
    f.close()
    filename = filename[filename.rfind("/")+1:]
    return PacketList(res,filename)


class ScapyPcapWriter:
        """A pcap writer with more control than wrpcap()

        This routine is based entirely on scapy.wrpcap(), but adds capability
        of writing one packet at a time in a streaming manner.
        """
        def __init__(self, filename):
                self.f = open(filename,"w")
                self.f.write(struct.pack("IHHIIII",
                                                0xa1b2c3d4L,
                                                2, 4,
                                                0,
                                                0,
                                                scapy.MTU,
                                                1)) # XXX Find the link type

        def write(self, packets):
                """accepts a either a single packet or a list of packets
                to be written to the dumpfile
                """
                if type(packets) == type(list):
                        for p in packets:
                                self.write_packet(p)
                else:
                        self.write_packet(packets)

        def write_packet(self, packet):
                """writes a single packet to the pcap file
                """
                s = str(packet)
                l = len(s)
                sec = int(packet.time)
                usec = int((packet.time-sec)*1000000)
                self.f.write(struct.pack("IIII", sec, usec, l, l))
                self.f.write(s)

        def __del__(self):
                self.f.close()



def import_hexcap():
    p = ""
    try:
        while 1:
            l = raw_input()
            l = l[l.find("   ")+3:]
            l = l[:l.find("   ")]
            l = "".join(l.split())
            p += l
    except EOFError:
        pass
    p2=""
    for i in range(len(p)/2):
        p2 += chr(int(p[2*i:2*i+2],16))
    return p2
        

###############
## BPF stuff ##
###############


def attach_filter(s, filter):
    # XXX We generate the filter on the interface conf.iface 
    # because tcpdump open the "any" interface and ppp interfaces
    # in cooked mode. As we use them in raw mode, the filter will not
    # work... one solution could be to use "any" interface and translate
    # the filter from cooked mode to raw mode
    # mode
    f = os.popen("tcpdump -i %s -ddd -s 1600 '%s'" % (conf.iface,filter))
    lines = f.readlines()
    if f.close():
        raise Exception("Filter parse error")
    nb = int(lines[0])
    bpf = ""
    for l in lines[1:]:
        bpf += struct.pack("HBBI",*map(long,l.split()))

    # XXX. Argl! We need to give the kernel a pointer on the BPF,
    # python object header seems to be 20 bytes
    bpfh = struct.pack("HI", nb, id(bpf)+20)  
    s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, bpfh)


#####################
## knowledge bases ##
#####################

class KnowledgeBase:
    def __init__(self, filename):
        self.filename = filename
        self.base = None

    def lazy_init(self):
        self.base = ""

    def reload(self, filename = None):
        if filename is not None:
            self.filename = filename
        oldbase = self.base
        self.base = None
        self.lazy_init()
        if self.base is None:
            self.base = oldbase

    def get_base(self):
        if self.base is None:
            self.lazy_init()
        return self.base
    


###############
## p0f stuff ##
###############

# File format:
#
# wwww:ttt:mmm:D:W:S:N:I:OS Description
#
# wwww - window size
# ttt  - time to live
# mmm  - maximum segment size
# D    - don't fragment flag  (0=unset, 1=set) 
# W    - window scaling (-1=not present, other=value)
# S    - sackOK flag (0=unset, 1=set)
# N    - nop flag (0=unset, 1=set)
# I    - packet size (-1 = irrevelant)



class p0fKnowledgeBase(KnowledgeBase):
    def __init__(self, filename):
        KnowledgeBase.__init__(self, filename)
        self.ttl_range=[255]
    def lazy_init(self):
        try:
            f=open(self.filename)
        except IOError:
            warning("Can't open base %s" % self.filename)
            return
        try:
            self.base = []
            for l in f:
                if l[0] in ["#","\n"]:
                    continue
                l = tuple(l.split(":"))
                if len(l) < 9:
                    continue
                li = map(int,l[:8])
                if li[1] not in self.ttl_range:
                    self.ttl_range.append(li[1])
                    self.ttl_range.sort()
                self.base.append((li,":".join(l[8:])[:-1]))
        except:
            warning("Can't parse p0f database (new p0f version ?)")
            self.base = None
        f.close()


def packet2p0f(pkt):
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    if not isinstance(pkt, IP) or not isinstance(pkt.payload, TCP):
        raise TypeError("Not a TCP/IP packet")
    if pkt.payload.flags & 0x13 != 0x02: #S,!A,!F
        raise TypeError("Not a syn packet")

    if "MSS" in pkt.payload.options:
        mss = pkt.payload.options["MSS"]
    else:
        mss = -1
    if "WScale" in pkt.payload.options:
        wscale = pkt.payload.options["WScale"]
    else:
        wscale = -1
    t = p0f_kdb.ttl_range[:]
    t += [pkt.ttl]
    t.sort()
    ttl=t[t.index(pkt.ttl)+1]
        
    return (pkt.payload.window,
            ttl,
            mss,
            pkt.flags & 0x2 != 0,
            wscale,
            "SAckOK" in pkt.payload.options,
            "NOP" in pkt.payload.options,
            pkt.len)

def p0f_dist(x,y):
    d = 0
    for i in range(len(x)):
        if x[i] != y[i]:
            d += 1
    if x[-1] == -1 ^ y[-1] == -1: # packet len was irrelevant
        d -= 1
    return d
    

def p0f(pkt):
    """Passive OS fingerprinting: which OS emitted this TCP SYN ?
p0f(packet) -> accuracy, [list of guesses]
"""
    pb = p0f_kdb.get_base()
    if not pb:
        warning("p0f base empty.")
        return []
    s = len(pb[0][0])
    r = []
    min = s+1
    sig = packet2p0f(pkt)
    for b,name in pb:
        d = p0f_dist(sig,b)
        if d < min:
            r = []
            min = d
        if d == min:
            r.append(name)
    accurracy = ( 1.0-(1.0*min)/s )
    return accurracy,r
            

def prnp0f(pkt):
    try:
        print p0f(pkt)
    except:
        pass
    

def pkt2uptime(pkt, HZ=100):
    """Calculate the date the machine which emitted the packet booted using TCP timestamp
pkt2uptime(pkt, [HZ=100])"""
    if not isinstance(pkt, Packet):
        raise TypeError("Not a TCP packet")
    if isinstance(pkt,NoPayload):
        raise TypeError("Not a TCP packet")
    if not isinstance(pkt, TCP):
        return pkt2uptime(pkt.payload)
    if "Timestamp" not in pkt.options:
        raise TypeError("No timestamp option")
    t = pkt.options["Timestamp"][0]
    t = pkt.time-t*1.0/HZ
    return time.ctime(t)
    


#################
## Queso stuff ##
#################


def quesoTCPflags(flags):
    if flags == "-":
        return "-"
    flv = "FSRPAUXY"
    v = 0
    for i in flags:
        v |= 2**flv.index(i)
    return "%x" % v

class QuesoKnowledgeBase(KnowledgeBase):
    def lazy_init(self):
        try:
            f = open(self.filename)
        except IOError:
            return
        self.base = {}
        p = None
        try:
            for l in f:
                l = l.strip()
                if not l or l[0] == ';':
                    continue
                if l[0] == '*':
                    if p is not None:
                        p[""] = name
                    name = l[1:].strip()
                    p = self.base
                    continue
                if l[0] not in list("0123456"):
                    continue
                res = l[2:].split()
                res[-1] = quesoTCPflags(res[-1])
                res = " ".join(res)
                if not p.has_key(res):
                    p[res] = {}
                p = p[res]
            if p is not None:
                p[""] = name
        except:
            self.base = None
            warning("Can't load queso base [%s]", self.filename)
        f.close()
            
        

    
def queso_sig(target, dport=80, timeout=3):
    p = queso_kdb.get_base()
    ret = []
    for flags in ["S", "SA", "F", "FA", "SF", "P", "SEC"]:
        ans, unans = sr(IP(dst=target)/TCP(dport=dport,flags=flags,seq=RandInt()),
                        timeout=timeout, verbose=0)
        if len(ans) == 0:
            rs = "- - - -"
        else:
            s,r = ans[0]
            rs = "%i" % (r.seq != 0)
            if not r.ack:
                r += " 0"
            elif r.ack-s.seq > 666:
                rs += " R" % 0
            else:
                rs += " +%i" % (r.ack-s.seq)
            rs += " %X" % r.window
            rs += " %x" % r.payload.flags
        ret.append(rs)
    return ret
            
def queso_search(sig):
    p = queso_kdb.get_base()
    sig.reverse()
    ret = []
    try:
        while sig:
            s = sig.pop()
            p = p[s]
            if p.has_key(""):
                ret.append(p[""])
    except KeyError:
        pass
    return ret
        

def queso(*args,**kargs):
    """Queso OS fingerprinting
queso(target, dport=80, timeout=3)"""
    return queso_search(queso_sig(*args, **kargs))



######################
## nmap OS fp stuff ##
######################


class NmapKnowledgeBase(KnowledgeBase):
    def lazy_init(self):
        try:
            f=open(self.filename)
        except IOError:
            return

        self.base = []
        name = None
        try:
            for l in f:
                l = l.strip()
                if not l or l[0] == "#":
                    continue
                if l[:12] == "Fingerprint ":
                    if name is not None:
                        self.base.append((name,sig))
                    name = l[12:].strip()
                    sig={}
                    p = self.base
                    continue
                elif l[:6] == "Class ":
                    continue
                op = l.find("(")
                cl = l.find(")")
                if op < 0 or cl < 0:
                    warning("error reading nmap os fp base file")
                    continue
                test = l[:op]
                s = map(lambda x: x.split("="), l[op+1:cl].split("%"))
                si = {}
                for n,v in s:
                    si[n] = v
                sig[test]=si
            if name is not None:
                self.base.append((name,sig))
        except:
            self.base = None
            warning("Can't read nmap database [%s](new nmap version ?)" % base.filename)
        f.close()
        
def TCPflags2str(f):
    fl="FSRPAUEC"
    s=""
    for i in range(len(fl)):
        if f & 1:
            s = fl[i]+s
        f >>= 1
    return s

def nmap_tcppacket_sig(pkt):
    r = {}
    if pkt is not None:
#        r["Resp"] = "Y"
        r["DF"] = (pkt.flags & 2) and "Y" or "N"
        r["W"] = "%X" % pkt.window
        r["ACK"] = pkt.ack==2 and "S++" or pkt.ack==1 and "S" or "O"
        r["Flags"] = TCPflags2str(pkt.payload.flags)
        r["Ops"] = "".join(map(lambda x: x[0][0],pkt.payload.options))
    else:
        r["Resp"] = "N"
    return r


def nmap_udppacket_sig(S,T):
    r={}
    if T is None:
        r["Resp"] = "N"
    else:
        r["DF"] = (T.flags & 2) and "Y" or "N"
        r["TOS"] = "%X" % T.tos
        r["IPLEN"] = "%X" % T.len
        r["RIPTL"] = "%X" % T.payload.payload.len
        r["RID"] = S.id == T.payload.payload.id and "E" or "F"
        r["RIPCK"] = S.chksum == T.getlayer(IPerror).chksum and "E" or T.getlayer(IPerror).chksum == 0 and "0" or "F"
        r["UCK"] = S.payload.chksum == T.getlayer(UDPerror).chksum and "E" or T.getlayer(UDPerror).chksum ==0 and "0" or "F"
        r["ULEN"] = "%X" % T.getlayer(UDPerror).len
        r["DAT"] = T.getlayer(Raw) is None and "E" or S.getlayer(Raw).load == T.getlayer(Raw).load and "E" or "F"
    return r
    


def nmap_match_one_sig(seen, ref):
    c = 0
    for k in seen.keys():
        if ref.has_key(k):
            if seen[k] in ref[k].split("|"):
                c += 1
    if c == 0 and seen.get("Resp") == "N":
        return 0.7
    else:
        return 1.0*c/len(seen.keys())
        
        

def nmap_sig(target, oport=80, cport=81, ucport=1):
    res = {}

    tcpopt = [ ("WScale", 10),
               ("NOP",None),
               ("MSS", 256),
               ("Timestamp",(123,0)) ]
    tests = [ IP(dst=target, id=1)/TCP(seq=1, sport=5001, dport=oport, options=tcpopt, flags="CS"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5002, dport=oport, options=tcpopt, flags=0),
              IP(dst=target, id=1)/TCP(seq=1, sport=5003, dport=oport, options=tcpopt, flags="SFUP"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5004, dport=oport, options=tcpopt, flags="A"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5005, dport=cport, options=tcpopt, flags="S"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5006, dport=cport, options=tcpopt, flags="A"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5007, dport=cport, options=tcpopt, flags="FPU"),
              IP(str(IP(dst=target)/UDP(sport=5008,dport=ucport)/(300*"i"))) ]

    ans, unans = sr(tests, timeout=2)
    ans += map(lambda x: (x,None), unans)

    for S,T in ans:
        if S.sport == 5008:
            res["PU"] = nmap_udppacket_sig(S,T)
        else:
            t = "T%i" % (S.sport-5000)
            if T is not None and T.haslayer(ICMP):
                warning("Test %s answered by an ICMP" % t)
                T=None
            res[t] = nmap_tcppacket_sig(T)

    return res

def nmap_probes2sig(tests):
    tests=tests.copy()
    res = {}
    if "PU" in tests:
        res["PU"] = nmap_udppacket_sig(*tests["PU"])
        del(tests["PU"])
    for k in tests:
        res[k] = nmap_tcppacket_sig(tests[k])
    return res
        

def nmap_search(sigs):
    guess = 0,[]
    for os,fp in nmap_kdb.get_base():
        c = 0.0
        for t in sigs.keys():
            if t in fp:
                c += nmap_match_one_sig(sigs[t], fp[t])
        c /= len(sigs.keys())
        if c > guess[0]:
            guess = c,[ os ]
        elif c == guess[0]:
            guess[1].append(os)
    return guess
    
    
def nmap_fp(target, oport=80, cport=81):
    """nmap fingerprinting
nmap_fp(target, [oport=80,] [cport=81,]) -> list of best guesses with accuracy
"""
    sigs = nmap_sig(target, oport, cport)
    return nmap_search(sigs)
        

def nmap_sig2txt(sig):
    torder = ["TSeq","T1","T2","T3","T4","T5","T6","T7","PU"]
    korder = ["Class", "gcd", "SI", "IPID", "TS",
              "Resp", "DF", "W", "ACK", "Flags", "Ops",
              "TOS", "IPLEN", "RIPTL", "RID", "RIPCK", "UCK", "ULEN", "DAT" ]
    txt=[]
    for i in sig.keys():
        if i not in torder:
            torder.append(i)
    for t in torder:
        sl = sig.get(t)
        if sl is None:
            continue
        s = []
        for k in korder:
            v = sl.get(k)
            if v is None:
                continue
            s.append("%s=%s"%(k,v))
        txt.append("%s(%s)" % (t, "%".join(s)))
    return "\n".join(txt)
            
        



###################
## User commands ##
###################


def sniff(count=0, store=1, prn = None, *arg, **karg):
    """Sniff packets
sniff([count,] [prn,] + L2ListenSocket args) -> list of packets
    """
    c = 0
    s = conf.L2listen(type=ETH_P_ALL, *arg, **karg)
    lst = []
    while 1:
        try:
            p = s.recv(MTU)
            if store:
                lst.append(p)
            c += 1
            if prn:
                r = prn(p)
                if r is not None:
                    print r
            if count > 0 and c >= count:
                break
        except KeyboardInterrupt:
            break
    return PacketList(lst,"Sniffed")



def arpcachepoison(target, victim, interval=60):
    """Poison target's cache with (your MAC,victim's IP) couple
arpcachepoison(target, victim, [interval=60]) -> None
"""
    tmac = getmacbyip(target)
    p = Ether(dst=tmac)/ARP(op="who-has", psrc=victim, pdst=target)
    try:
        while 1:
            sendp(p)
            if conf.verb > 1:
                os.write(1,".")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

def traceroute(target, maxttl=30, dport=80, sport=RandShort(),minttl=1):
    """Instant TCP traceroute
traceroute(target, [maxttl=30], [dport=80], [sport=80]) -> None
"""
    a,b = sr(IP(dst=target, id=RandShort(), ttl=(minttl,maxttl))/TCP(seq=RandInt(),sport=sport, dport=dport),
             timeout=2, filter="(icmp and icmp[0]=11) or (tcp and (tcp[13] & 0x16 > 0x10))")
    res = {}
    for s,r in a:
        if r.haslayer(ICMP):
            res[s.ttl] = r.sprintf("%-15s,IP.src%")
        else:
            res[s.ttl] = r.sprintf("%-15s,IP.src% %TCP.flags%")
    for s in b:
        res[s.ttl] = ""
    lst = res.keys()
    lst.sort()
    for i in lst:
        print "%2i %s" % (i, res[i])
    

def arping(net, iface=None):
    """Send ARP who-has requests to determine which hosts are up
arping(net, iface=conf.iface) -> None"""
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net),
                    filter="arp and arp[7] = 2", timeout=2, iface=iface)
    for s,r in ans:
        print r.sprintf("%Ether.src% %ARP.psrc%")
    last = ans,unans

def dyndns_add(nameserver, name, rdata, type="A", ttl=10):
    """Send a DNS add message to a nameserver for "name" to have a new "rdata"
dyndns_add(nameserver, name, rdata, type="A", ttl=10) -> result code (0=ok)

example: dyndns_add("ns1.toto.com", "dyn.toto.com", "127.0.0.1")
RFC2136
"""
    zone = name[name.find(".")+1:]
    r=sr1(IP(dst=nameserver)/UDP()/DNS(opcode=5,
                                       qd=[DNSQR(qname=zone, qtype="SOA")],
                                       ns=[DNSRR(rrname=name, type="A",
                                                 ttl=ttl, rdata=rdata)]),
          verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1
    
    
    

def dyndns_del(nameserver, name, type="ALL", ttl=10):
    """Send a DNS delete message to a nameserver for "name"
dyndns_del(nameserver, name, type="ANY", ttl=10) -> result code (0=ok)

example: dyndns_del("ns1.toto.com", "dyn.toto.com")
RFC2136
"""
    zone = name[name.find(".")+1:]
    r=sr1(IP(dst=nameserver)/UDP()/DNS(opcode=5,
                                       qd=[DNSQR(qname=zone, qtype="SOA")],
                                       ns=[DNSRR(rrname=name, type=type,
                                                 rclass="ANY", ttl=0, rdata="")]),
          verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1
    


#####################
## Reporting stuff ##
#####################

def report_ports(target, ports):
    """portscan a target and output a LaTeX table
report_ports(target, ports) -> string"""
    ans,unans = sr(IP(dst=target)/TCP(dport=ports),timeout=5)
    rep = "\\begin{tabular}{|r|l|l|}\n\\hline\n"
    for s,r in ans:
        if not r.haslayer(ICMP):
            if r.payload.flags == 0x12:
                rep += r.sprintf("%TCP.sport% & open & SA \\\\\n")
    rep += "\\hline\n"
    for s,r in ans:
        if r.haslayer(ICMP):
            rep += r.sprintf("%TCPerror.dport% & closed & ICMP type %ICMP.type%/%ICMP.code% from %IP.src% \\\\\n")
        elif r.payload.flags != 0x12:
            rep += r.sprintf("%TCP.sport% & closed & TCP %TCP.flags% \\\\\n")
    rep += "\\hline\n"
    for i in unans:
        rep += i.sprintf("%TCP.dport% & ? & unanswered \\\\\n")
    rep += "\\hline\n\\end{tabular}\n"
    return rep


def __make_table(yfmtfunc, fmtfunc, endline, list, fx, fy, fz, sortx=None, sorty=None):
    vx = {}
    vy = {}
    vz = {}
    l = 0
    for e in list:
        xx = str(fx(e))
        yy = str(fy(e))
        zz = str(fz(e))
        l = max(len(yy),l)
        vx[xx] = max(vx.get(xx,0), len(xx), len(zz))
        vy[yy] = None
        vz[(xx,yy)] = zz

    vxk = vx.keys()
    vyk = vy.keys()
    if sortx:
        vxk.sort(sortx)
    else:
        vxk.sort()
    if sorty:
        vyk.sort(sorty)
    else:
        vyk.sort()

    fmt = yfmtfunc(l)
    print fmt % "",
    for x in vxk:
        vx[x] = fmtfunc(vx[x])
        print vx[x] % x,
    print endline
    for y in vyk:
        print fmt % y,
        for x in vxk:
            print vx[x] % vz.get((x,y), "-"),
        print endline

def make_table(*args, **kargs):
    __make_table(lambda l:"%%-%is" % l, lambda l:"%%-%is" % l, "", *args, **kargs)
    
def make_lined_table(*args, **kargs):
    __make_table(lambda l:"%%-%is |" % l, lambda l:"%%-%is |" % l, "", *args, **kargs)

def make_tex_table(*args, **kargs):
    __make_table(lambda l: "%s", lambda l: "& %s", "\\\\", *args, **kargs)
    

######################
## Online doc stuff ##
######################


def lsc(cmd=None):
    """List user commands"""
    if cmd is None:
        for c in user_commands:
            doc = "No doc. available"
            if c.__doc__:
                doc = c.__doc__.split("\n")[0]
            
            print "%-16s : %s" % (c.__name__, doc)
    else:
        print cmd.__doc__

def ls(obj=None):
    """List  available layers, or infos on a given layer"""
    if obj is None:
        for i in __builtins__:
            obj = __builtins__[i]
            if not type(obj) is types.ClassType:
                continue
            if issubclass(obj, Packet):
                print "%-10s : %s" %(i,obj.name)
    else:
        if type(obj) is types.ClassType and issubclass(obj, Packet):
            for f in obj.fields_desc:
                print "%-10s : %-20s = (%s)" % (f.name, f.__class__.__name__,  repr(f.default))
        elif isinstance(obj, Packet):
            for f in obj.fields_desc:
                print "%-10s : %-20s = %-15s (%s)" % (f.name, f.__class__.__name__, repr(getattr(obj,f.name)), repr(f.default))
            if not isinstance(obj.payload, NoPayload):
                print "--"
                ls(obj.payload)
                

        else:
            print "Not a packet class. Type 'ls()' to list packet classes."


    


user_commands = [ sr, sr1, srp, srp1, srloop, srploop, sniff, p0f, arpcachepoison, send, sendp, traceroute, arping, ls, lsc, queso, nmap_fp, report_ports, dyndns_add, dyndns_del ]


########################
## Answering machines ##
########################

class AnsweringMachine:
    function_name = "Template"
    filter = None
    default_kargs = { "store":0 }
    
    def __init__(self, *args, **kargs):
        if self.filter:
            kargs.setdefault("filter",self.filter)
        self.def_args = args
        self.def_kargs = self.default_kargs.copy()
        self.def_kargs.setdefault("prn", self.reply)
        self.def_kargs.update(kargs)
        self.iface = self.def_kargs.get("iface",None)

    def is_request(self, req):
        return 1

    def make_reply(self, req):
        return req

    def send_reply(self, reply):
        send(reply, iface=self.iface)


    def reply(self, pkt):
        if not self.is_request(pkt):
            return
        reply = self.make_reply(pkt)
        self.send_reply(reply)

    def run(self, *args, **kargs):
        a = self.def_args + args
        ka = self.def_kargs.copy()
        ka.update(kargs)
        self.iface = ka.get("iface",None)
        
        try:
            sniff(*a, **ka)
        except KeyboardInterrupt:
            print "Interrupted by user"
            pass
        

class BOOTP_am(AnsweringMachine):
    function_name = "bootpd"
    filter = "udp and port 68 and port 67"
    def __init__(self, ipset=Net("192.168.1.128/25"),gw="192.168.1.1", *args,**kargs):
        AnsweringMachine.__init__(self, *args, **kargs)
        if type(ipset) is str:
            ipset = Net(ipset)
        if isinstance(ipset,Gen):
            ipset = [k for k in ipset]
            ipset.reverse()
        if len(ipset) == 1:
            ipset, = ipset
        self.ipset = ipset
        self.gw = gw
        self.leases = {}

    def is_request(self, req):
        print repr(req)
        if not req.haslayer(BOOTP):
            return 0
        reqb = req.getlayer(BOOTP)
        if reqb.op != 1:
            return 0
        return 1
        
    def make_reply(self, req):        
        mac = req.src
        if type(self.ipset) is list:
            if not self.leases.has_key(mac):
                self.leases[mac] = self.ipset.pop()
            ip = self.leases[mac]
        else:
            ip = ipset
        if conf.verb >= 1:
            print "Reply %s to %s" % (ip,mac)
            
        repb = req.getlayer(BOOTP).copy()
        repb.options = ""
        repb.op="BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        rep=Ether(dst=mac)/IP(dst=ip)/UDP(sport=req.dport,dport=req.sport)/repb
        return rep

    def send_reply(self, reply):
        sendp(reply, iface=self.iface)


class DHCP_am(BOOTP_am):
    function_name="dhcpd"
    def is_request(self, req):
        if not BOOTP_am.is_request(self, req):
            return 02
        if req.getlayer(BOOTP).options[:4] != "'c\x82Sc":
            return 0
        return 1
    def make_reply(self, req):
        dhcprespmap={"\x01":"\x02","\x03":"\x05"}
        resp = BOOTP_am.make_reply(self, req)
        opt = req.getlayer(BOOTP).options
        resp.getlayer(BOOTP).options = opt[:6]+dhcprespmap[opt[6]]+opt[7:]


def bootpd2(*args, **kargs):
    BOOTP_am(*args, **kargs).run()



AM_classes = [ BOOTP_am, DHCP_am ]

for am in AM_classes:
    locals()[am.function_name] = lambda *args,**kargs: am(*args,**kargs).run()




###################
## Testing stuff ##
###################



def IPID_count(lst, funcID=lambda x:x[1].id, funcpres=lambda x:x[1].summary()):
    idlst = map(funcID, lst)
    idlst.sort()
    classes = [idlst[0]]+map(lambda x:x[1],filter(lambda (x,y): abs(x-y)>50, map(lambda x,y: (x,y),idlst[:-1], idlst[1:])))
    lst = map(lambda x:(funcID(x), funcpres(x)), lst)
    lst.sort()
    print "Probably %i classes:" % len(classes), classes
    for id,pr in lst:
        print "%5i" % id, pr
    
    
    
            

last=None


def icmping(net):
    global last
    ans, unans, x = sndrcv(conf.L3socket(),IP(dst=net)/ICMP())
    for s,r in ans:
        print r.src
    last = ans,unans,x

def tcping(net, port):
    global last
    ans, unans, x = sndrcv(conf.L3socket(),IP(dst=net)/TCP(dport=port, flags=2))
    for s,r in ans:
        if isinstance(r.payload,TCP):
            print r.src,r.payload.sport, r.payload.flags
        else:
            print r.src,"icmp",r.payload.type
    last = ans, unans, x

def tcptraceroute(net, port=80):
    global last
    ans, unans, x = sndrcv(conf.L3socket(),
                           IP(dst=net,
                              id=RandShort(),
                              ttl=(1,25))/TCP(seq=RandInt(),
                                              dport=port,
                                              flags=2))
    ans.sort(lambda (s1,r1),(s2,r2): cmp(s1.ttl,s2.ttl))
    for s,r in ans:
        if isinstance(r.payload, ICMP):
            print "%2i: %s" % (s.ttl,r.src)
        else:
            print "%2i: %s <- %#02x" % (s.ttl,r.src,r.payload.flags)
    last = ans, unans, x


def goarp():
    arping(Net("172.16.1.0/28"))

def goicmp():
    icmping(Net("172.16.1.0/28"))

def gotcp():
    tcping(Net("172.16.1.0/28"),[80,443])

def gotrace():
    tcptraceroute(Net("www.google.com"))



def tethereal(*args,**kargs):
    sniff(prn=lambda x: x.display(),*args,**kargs)



def fragleak(target,sport=123, dport=123):
    load = "XXXXYYYYYYYYYY"
#    getmacbyip(target)
#    pkt = IP(dst=target, id=RandShort(), options="\x22"*40)/UDP()/load
    pkt = IP(dst=target, id=RandShort(), options="\x00"*40, flags=1)/UDP(sport=sport, dport=sport)/load
    s=conf.L3socket()
    intr=0
    found={}
    try:
        while 1:
            try:
                if not intr:
                    s.send(pkt)
                sin,sout,serr = select([s],[],[],0.2)
                if not sin:
                    continue
                ans=s.recv(1600)
                if not isinstance(ans, IP):
                    continue
                if not isinstance(ans.payload, ICMP):
                    continue
                if not isinstance(ans.payload.payload, IPerror):
                    continue
                if ans.payload.payload.dst != target:
                    continue
                if ans.src  != target:
                    print "leak from", ans.src,


#                print repr(ans)
                if not ans.haslayer(Padding):
                    continue

                
#                print repr(ans.payload.payload.payload.payload)
                
#                if not isinstance(ans.payload.payload.payload.payload, Raw):
#                    continue
#                leak = ans.payload.payload.payload.payload.load[len(load):]
                leak = ans.getlayer(Padding).load
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak)
            except KeyboardInterrupt:
                if intr:
                    raise KeyboardInterrupt
                intr=1
    except KeyboardInterrupt:
        pass


plst=[]
def get_toDS():
    global plst
    while 1:
        p,=sniff(iface="eth1",count=1)
        if not isinstance(p,Dot11):
            continue
        if p.FCfield & 1:
            plst.append(p)
            print "."


#    if not ifto.endswith("ap"):
#        print "iwpriv %s hostapd 1" % ifto
#        os.system("iwpriv %s hostapd 1" % ifto)
#        ifto += "ap"
#        
#    os.system("iwconfig %s mode monitor" % iffrom)
#    

def airpwn(iffrom, ifto, replace, pattern="", ignorepattern=""):
    """Before using this, initialize "iffrom" and "ifto" interfaces:
iwconfig iffrom mode monitor
iwpriv orig_ifto hostapd 1
ifconfig ifto up
note: if ifto=wlan0ap then orig_ifto=wlan0
note: ifto and iffrom must be set on the same channel
ex:
ifconfig eth1 up
iwconfig eth1 mode monitor
iwconfig eth1 channel 11
iwpriv wlan0 hostapd 1
ifconfig wlan0ap up
iwconfig wlan0 channel 11
iwconfig wlan0 essid dontexist
iwconfig wlan0 mode managed
"""
    
    ptrn = re.compile(pattern)
    iptrn = re.compile(ignorepattern)
    def do_airpwn(p, ifto=ifto, replace=replace, ptrn=ptrn, iptrn=iptrn):
        if not isinstance(p,Dot11):
            return
        if not p.FCfield & 1:
            return
        if not p.haslayer(TCP):
            return
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)
        pay = str(tcp.payload)
#        print "got tcp"
        if not ptrn.match(pay):
            return
#        print "match 1"
        if iptrn.match(pay):
            return
#        print "match 2"
        del(p.payload.payload.payload)
        p.FCfield="from-DS"
        p.addr1,p.addr2 = p.addr2,p.addr1
        q = p.copy()
        p /= IP(src=ip.dst,dst=ip.src)
        p /= TCP(sport=tcp.dport, dport=tcp.sport,
                 seq=tcp.ack, ack=tcp.seq+len(pay),
                 flags="PA")
        q = p.copy()
        p /= replace
        q.ID += 1
        q.getlayer(TCP).flags="RA"
        q.getlayer(TCP).seq+=len(replace)
        
        sendp([p,q], iface=ifto, verbose=0)
#        print "send",repr(p)        
#        print "send",repr(q)
        print p.sprintf("Sent %IP.src%:%IP.sport% > %IP.dst%:%TCP.dport%")

    sniff(iface=iffrom,prn=do_airpwn)

            
        
    
        


############
## Config ##
############

class ConfClass:
    def configure(self, cnf):
        self.__dict__ = cnf.__dict__.copy()
    def __repr__(self):
        return str(self)
    def __str__(self):
        s="Version    = %s\n" % VERSION
        keys = self.__class__.__dict__.copy()
        keys.update(self.__dict__)
        keys = keys.keys()
        keys.sort()
        for i in keys:
            if i[0] != "_":
                s += "%-10s = %s\n" % (i, repr(getattr(self, i)))
        return s[:-1]
    def reset(self):
        self.__dict__ = {}
        


class Conf(ConfClass):
    """This object contains the configuration of scapy.
session  : filename where the session will be saved
stealth  : if 1, prevents any unwanted packet to go out (ARP, DNS, ...)
checkIPID: if 0, doesn't check that IPID matches between IP sent and ICMP IP citation received
           if 1, checks that they either are equal or byte swapped equals (bug in some IP stacks)
           if 2, strictly checks that they are equals
checkIPsrc: if 1, checks IP src in IP and ICMP IP citation match (bug in some NAT stacks)
iff      : selects the default output interface for srp() and sendp(). default:"eth0")
verb     : level of verbosity, from 0 (almost mute) to 3 (verbose)
promisc  : default mode for listening socket (to get answers if you spoof on a lan)
sniff_promisc : default mode for sniff()
filter   : bpf filter added to every sniffing socket to exclude traffic from analysis
histfile : history file
padding  : includes padding in desassembled packets
except_filter : BPF filter for packets to ignore
debug_match : when 1, store received packet that are not matched into debug.recv
route    : holds the Scapy routing table and provides methods to manipulate it
"""
    session = ""  
    stealth = "not implemented"
    iface = get_working_if()
    checkIPID = 1
    checkIPsrc = 1
    verb = 2
    promisc = "not implemented"
    sniff_promisc = 0
    L3socket = L3PacketSocket
    L2socket = L2Socket
    L2listen = L2ListenSocket
    histfile = os.path.join(os.environ["HOME"], ".scapy_history")
    padding = 1
    p0f_base ="/etc/p0f.fp"
    queso_base ="/etc/queso.conf"
    nmap_base ="/usr/share/nmap/nmap-os-fingerprints"
    except_filter = ""
    debug_match = 0
    route = Route()
        

conf=Conf()

p0f_kdb = p0fKnowledgeBase(conf.p0f_base)
queso_kdb = QuesoKnowledgeBase(conf.queso_base)
nmap_kdb = NmapKnowledgeBase(conf.nmap_base)
