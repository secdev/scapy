#! /usr/bin/env python

#############################################################################
##                                                                         ##
## scapy.py --- Interactive packet manipulation tool                       ##
##              see http://www.cartel-securite.net/pbiondi/scapy.html      ##
##              for more informations                                      ##
##                                                                         ##
## Copyright (C) 2003  Philippe Biondi <biondi@cartel-securite.fr>         ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License as published by the   ##
## Free Software Foundation; either version 2, or (at your option) any     ##
## later version.                                                          ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

#
# $Log: scapy.py,v $
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

RCSID="$Id: scapy.py,v 0.9.12.2 2003/05/06 10:41:58 pbi Exp $"

VERSION = RCSID.split()[2]+"beta"


def usage():
    print "Usage: scapy.py [-s sessionfile]"
    sys.exit(0)


##########[XXX]#=--
##
#   Next things to do :
#
#  - improve pcap capture file support
#  - better self-doc
#
##
##########[XXX]#=--

################
##### Main #####
################


if __name__ == "__main__":
    import code,sys,cPickle,types,os
    import scapy
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

    if scapy.conf.histfile:
        try:
            readline.read_history_file(scapy.conf.histfile)
        except IOError:
            pass

    code.interact(banner = "Welcome to Scapy (%s)"%VERSION, local=session)

    if scapy.conf.session:

        if session.has_key("__builtins__"):
            del(session["__builtins__"])

        for k in session.keys():
            if type(session[k]) in [types.ClassType, types.ModuleType]:
                 print "[%s] (%s) can't be saved. Deleted." % (k, type(session[k]))
                 del(session[k])

        try:
            os.rename(scapy.conf.session, scapy.conf.session+".bak")
        except OSError:
            pass
        f=open(scapy.conf.session,"w")
        cPickle.dump(session, f)
        f.close()

    if scapy.conf.histfile:
        readline.write_history_file(scapy.conf.histfile)
    
    sys.exit()

##################
##### Module #####
##################

import socket, sys, getopt, string, struct, time, random, os, traceback
import pickle, types
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


####################
## IP Tools class ##
####################

class IPTools:
    """Add more powers to a class that have a "src" attribute."""
    def whois(self):
        os.system("whois %s" % self.src)




##############################
## Routing/Interfaces stuff ##
##############################

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

def choose_route(dst):
    routes = read_routes()
    dst=struct.unpack("I",socket.inet_aton(dst))[0]
    pathes=[]
    for d,m,gw,i,a in routes:
        if (dst & m) == (d & m):
            pathes.append((m,(i,a,gw)))
    if not pathes:
        raise Exception("no route found")
    # Choose the more specific route (greatest netmask).
    # XXX: we don't care about metrics
    pathes.sort()
    return pathes[-1][1] 


        
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
        iff,a,gw = choose_route(ip)
        if gw != "0.0.0.0":
            ip = gw
        res = dnet_arp_object.get(dnet.addr(ip))
        if res is None:
            return None
        else:
            return res.ntoa()
else:
    def getmacbyip(ip):
        iff,a,gw = choose_route(ip)
        if gw != "0.0.0.0":
            ip = gw
    
        if arp_cache.has_key(ip):
            mac, timeout = arp_cache[ip]
            if timeout and (time.time()-timeout < ARPTIMEOUT):
                return mac
        
        res = srp1(Ether(dst=ETHER_BROADCAST)/ARP(op="who-has", pdst=ip),
                  filter="arp",
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
    def __add__(self, val):
        return self.randint() + val
    def __sub__(self, val):
        return self.randint() - val
    def __mul__(self, val):
        return self.randint() * val
    def __div__(self, val):
        return self.randint() / val
    def __mod__(self, val):
        return self.randint() % val
    def __divmod__(self, val):
        return divmod(self.randint(), val)
    def __and__(self, val):
        return self.randint() & val
    def __or__(self, val):
        return self.randint() | val
    def __xor__(self, val):
        return self.randint() ^ val
    def __pow__(self, val):
        return self.randint() ** val
    def __cmp__(self, val):
        return cmp(self.randint(), val)
    def __neg__(self):
        return -self.randint()
    def __pos__(self):
        return +self.randint()
    def __abs__(self):
        return self.randint()
    def __nonzero__(self):
        return self.randint()
    def __repr__(self):
        return repr(self.randint())
    def __str__(self):
        return str(self.randint())
    def __int__(self):
        return self.randint()
    def __hex__(self):
        return hex(self.randint())

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
            ip=socket.inet_aton(tmp[0])
        except socket.error:
            ip=socket.gethostbyname(tmp[0])
            ip=socket.inet_aton(ip)
        
        self.ip=struct.unpack("!I", ip)[0]
        netsz=2**(32-int(tmp[1]))
        self.ip=self.ip&(~(netsz-1))
        self.size=netsz
    def __iter__(self):
        for i in xrange(self.size):
            yield socket.inet_ntoa(struct.pack("!I",self.ip+i))
    def __repr__(self):
        return "<Net %s>" % self.repr

############
## Fields ##
############

class Field:
    islist=0
    def __init__(self, name, default, fmt="H"):
        self.name = name
        self.fmt = "!"+fmt
        self.default = self.any2i(None,default)

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
        sz = struct.calcsize(self.fmt)
        return  s[sz:], self.m2i(pkt, struct.unpack(self.fmt, s[:sz])[0])
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
                iff,a,gw = choose_route(dstip)
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
                iff,a,gw = choose_route(dstip)
                m = get_if_hwaddr(iff)
                if m:
                    x = m
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))
        

    
class IPField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "4s")
    def h2i(self, pkt, x):
        if type(x) is str:
            try:
                socket.inet_aton(x)
            except socket.error:
                x = Net(x)
        return x
    def i2m(self, pkt, x):
        return socket.inet_aton(x)
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
            iff,x,gw = choose_route(getattr(pkt,self.dstname))
        return IPField.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            dst=getattr(pkt,self.dstname)
            if isinstance(dst,Gen):
                r = map(choose_route, dst)
                r.sort()
                if r[0] == r[-1]:
                    x=r[0][1]
                else:
                    warning("More than one possible route for %s"%repr(dst))
                    return None
            else:
                iff,x,gw = choose_route(dst)
        return IPField.i2h(self, pkt, x)

    


class ByteField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "B")
        
class XByteField(ByteField):
    def i2repr(self, pkt, x):
	if x is None:
	    x = 0
        return hex(self.i2h(pkt, x))

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

class XIntField(IntField):
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
        v |= val & ((1<<self.size) - 1)
        bitsdone += self.size
        while bitsdone >= 8:
            bitsdone -= 8
            s = s+struct.pack("!B", v >> bitsdone)
            v &= (1<<bitsdone)-1
        if bitsdone:
            return s,bitsdone,v
        else:
            return s
    def getfield(self, pkt, s):
        if type(s) is tuple:
            s,bn = s
        else:
            bn = 0
        fmt,sz=[("!B",1),("!H",2),("!I",4),("!I",4)][self.size/8]
        b = struct.unpack(fmt, s[:sz])[0] << bn
        b >>= (sz*8-self.size)
        b &= (1 << self.size)-1
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
        y = self.i2s.get(x)
        if y is None:
            y = x
        return y            

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
            s = socket.inet_aton(s)
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
        for fname in self.fields.keys():
            try:
                ftype = self.fieldtype[fname]
            except KeyError:
                pass  # unknown field => don't display
            else:
                s=s+" %s=%s" % (fname, ftype.i2repr(self, self.fields[fname]))
        for fname in self.overloaded_fields.keys():
            if not self.fields.has_key(fname):
                ftype = self.fieldtype[fname]
                s=s+" %s=%s" % (fname, ftype.i2repr(self, self.overloaded_fields[fname]))
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
                            print "toto"
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
    

####################
## Packet classes ##
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
    def answers(self, other):
        if isinstance(other,Ether):
            if self.type == other.type:
                return self.payload < other.payload
        return 0
    

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


class LLC(Packet):
    name = "LLC"
    fields_desc = [ XByteField("dsap", 0x00),
                    XByteField("ssap", 0x00),
                    ByteField("ctrl", 0) ]


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
                return self.payload < other.payload
        else:
            return self.payload < other
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
    def answers(self, other):
        if isinstance(other,EAPOL):
            if ( (self.type == self.EAP_PACKET) and
                 (other.type == self.EAP_PACKET) ):
                return self.payload < other.payload
        return 0
             

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
                    ShortEnumField("op", 1, {"who-has":1, "is-at":2}),
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
                    ByteEnumField("proto", 0, {0:"IP",1:"ICMP",6:"TCP",17:"UDP"}),
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
    def answers(self, other):
        if not isinstance(other,IP):
            return 0
        if (self.dst != other.src):
            return 0
        if ( (self.proto == socket.IPPROTO_ICMP) and
             (isinstance(self.payload, ICMP)) and
             (self.payload.type in [3,4,5,11,12]) ):
            # ICMP error message
            return self.payload.payload < other

        else:
            if ( (self.src != other.dst) or
                 (self.proto != other.proto) ):
                return 0
            return self.payload < other.payload
                 
    

class TCP(Packet):
    name = "TCP"
    fields_desc = [ ShortField("sport", 80),
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
                                     socket.inet_aton(self.underlayer.src),
                                     socket.inet_aton(self.underlayer.dst),
                                     self.underlayer.proto,
                                     len(p))
                ck=checksum(psdhdr+p)
                p=p[:16]+chr(ck >> 8)+chr(ck & 0xff)+p[18:]
            else:
                warning("No IP underlayer to compute checksum. Leaving null.")
        return p
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
        if not ((self.sport == other.dport) and
                (self.dport == other.sport)):
            return 0
        if (abs(other.seq-self.ack) > 2):
            return 0
        return 1

class UDP(Packet):
    name = "UDP"
    fields_desc = [ ShortField("sport", 80),
                    ShortField("dport", 80),
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
                                     socket.inet_aton(self.underlayer.src),
                                     socket.inet_aton(self.underlayer.dst),
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
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if not ((self.sport == other.dport) and
                (self.dport == other.sport)):
            return 0
        return 1
    

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
        



class IPerror(IP):
    name = "IP in ICMP citation"
    def answers(self, other):
        if not isinstance(other, IP):
            return 0
        if not ( (self.dst == other.dst) and
                 (self.src == other.src) and
                 (self.id == other.id) and
                 (self.proto == other.proto) ):
            return 0
        return self.payload.answers(other.payload)


class TCPerror(TCP):
    name = "TCP in ICMP citation"
    def answers(self, other):
        if not isinstance(other, TCP):
            return 0
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

class UDPerror(UDP):
    name = "UDP in ICMP citation"
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if not ((self.sport == other.sport) and
                (self.dport == other.dport)):
            return 0
        return 1
                    

class ICMPerror(ICMP):
    name = "ICMP in ICMP citation"
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
                
class LLPPP(Packet):
    name = "PPP Link Layer"
            
        
class DNS(Packet):
    name = "DNS"
    fields_desc = [ ShortField("id",0),
                    BitField("qr",0, 1),
                    BitField("opcode", 0, 4),
                    BitField("aa", 0, 1),
                    BitField("tc", 0, 1),
                    BitField("rd", 0, 1),
                    BitField("ra", 0 ,1),
                    BitField("z", 0, 3),
                    BitField("rcode", 0, 4),
                    DNSRRCountField("qdcount", None, "qd"),
                    DNSRRCountField("ancount", None, "an"),
                    DNSRRCountField("nscount", None, "ns"),
                    DNSRRCountField("arcount", None, "ar"),
                    DNSQRField("qd", "qdcount"),
                    DNSRRField("an", "ancount"),
                    DNSRRField("ns", "nscount"),
                    DNSRRField("ar", "arcount",0) ]


dnstypes = { 1:"A", 2:"NS", 3:"MD", 4:"MD", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG",
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
                    ShortEnumField("class", 1, dnsclasses),
                    IntField("ttl", 0),
                    RDLenField("rdlen"),
                    RDataField("rdata", "", "rdlen") ]


#################
## Bind layers ##
#################
    

def bind_layers(lower, upper, fval):
    lower.payload_guess = lower.payload_guess[:]
    upper.overload_fields = upper.overload_fields.copy()
    lower.payload_guess.append((fval, upper))
    upper.overload_fields[lower] = fval
    
    

layer_bonds = [ ( Dot3,   LLC,      { } ),
                ( LLPPP,  IP,       { } ),
                ( Ether,  Dot1Q,    { "type" : 0x8100 } ),
                ( Ether,  Ether,    { "type" : 0x0001 } ),
                ( Ether,  ARP,      { "type" : 0x0806 } ),
                ( Ether,  IP,       { "type" : 0x0800 } ),
                ( Ether,  EAPOL,    { "type" : 0x888e } ),
                ( Ether,  EAPOL,    { "type" : 0x888e, "dst" : "01:80:c2:00:00:03" } ),
                ( EAPOL,  EAP,      { "type" : EAPOL.EAP_PACKET } ),
                ( LLC,    STP,      { "dsap" : 0x42 , "ssap" : 0x42 } ),
                ( IPerror,IPerror,  { "proto" : socket.IPPROTO_IP } ),
                ( IPerror,ICMPerror,{ "proto" : socket.IPPROTO_ICMP } ),
                ( IPerror,TCPerror, { "proto" : socket.IPPROTO_TCP } ),
                ( IPerror,UDPerror, { "proto" : socket.IPPROTO_UDP } ),
                ( IP,     IP,       { "proto" : socket.IPPROTO_IP } ),
                ( IP,     ICMP,     { "proto" : socket.IPPROTO_ICMP } ),
                ( IP,     TCP,      { "proto" : socket.IPPROTO_TCP } ),
                ( IP,     UDP,      { "proto" : socket.IPPROTO_UDP } ),
                ( UDP,    DNS,      { "sport" : 53 } ),
                ( UDP,    DNS,      { "dport" : 53 } ),
                ]

for l in layer_bonds:
    bind_layers(*l)
                

###################
## Fragmentation ##
###################

def fragment(pkt, fragsize=1480):
    fragsize = (fragsize/8)*8
    h = pkt.copy()
    h.flags = "MF"
    del(h.payload)
    lst = []
    for p in pkt.payload:
        s = str(p)
        nb = len(s)/fragsize+1
        for i in range(nb):
            r = Raw(load=s[i*fragsize:(i+1)*fragsize])
            r.overload_fields = p.overload_fields.copy()
            h2 = h.copy()
            if i == nb-1:
                h2.flags=0
            h2.frag = i*fragsize/8
            h2.add_payload(r)
            lst.append(h2)
    return lst


###################
## Super sockets ##
###################


# According to libdnet
LLTypes = { ARPHDR_ETHER : Ether,
            ARPHDR_METRICOM : Ether,
            ARPHDR_LOOPBACK : Ether,
            }

L3Types = { ETH_P_IP : IP,
            ETH_P_ARP : ARP,
            ETH_P_ALL : IP
            }



class SuperSocket:
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
        if self.ins != self.outs:
            if self.outs and self.outs.fileno() != -1:
                self.outs.close()
        if self.ins and self.ins.fileno() != -1:
            self.ins.close()
    def bind_in(self, addr):
        self.ins.bind(addr)
    def bind_out(self, addr):
        self.outs.bind(addr)
    def __del__(self):
        self.close()

class L3RawSocket(SuperSocket):
    def __init__(self, type = ETH_P_IP):
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
            if type(iface) is list:
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
        # XXX: if sa_ll[2] == socket.PACKET_OUTGOING : skip
        if LLTypes.has_key(sa_ll[3]):
            cls = LLTypes[sa_ll[3]]
            lvl = 2
        elif L3Types.has_key(sa_ll[1]):
            cls = L3Types[sa_ll[1]]
            lvl = 3
        else:
            warning("Unable to guess type (interface=%s protocol=%#x family=%*i). Using Ethernet" % sa_ll[:4])
            cls = Ether
            lvl = 2

        pkt = cls(pkt)
        if lvl == 2:
            pkt = pkt.payload
        return pkt
    
    def send(self, x):
        if hasattr(x,"dst"):
            iff,a,gw = choose_route(x.dst)
        else:
            iff = conf.iff
        self.outs.bind((iff, self.type))
        sn = self.outs.getsockname()
        if LLTypes.has_key(sn[3]):
            x = LLTypes[sn[3]]()/x
        self.outs.sendto(str(x), (iff, self.type))



class L2Socket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, filter=None):
        if iface is None:
            iface = conf.iff
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
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
            warning("Unable to guess type (interface=%s protocol=%#x family=%*i). Using Ethernet" % sa_ll[:4])
            self.LL = Ether
    def recv(self, x):
        return self.LL(self.ins.recv(x))



class L2ListenSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
        self.type = type
        self.outs = None
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        if iface is not None:
            self.ins.bind((iface, type))
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
            if type(iface) is list:
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
            warning("Unable to guess type (interface=%s protocol=%#x family=%*i). Using Ethernet" % sa_ll[:3])
            cls = Ether

        pkt = cls(pkt)
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
                iff,a,gw = choose_route(x.dst)
            else:
                iff = conf.iff
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
                iface = conf.iff
            self.ins = pcap.pcapObject()
            self.ins.open_live(iface, 1600, 0, 100)
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




def sndrcv(pks, pkt, timeout = 2, inter = 0, verbose=None):

    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
        
    if verbose is None:
        verbose = conf.verb
    recv = []
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    sent = [p for p in pkt]

    
    if timeout < 0:
        timeout = None
        
    rdpipe,wrpipe = os.pipe()
    rdpipe=os.fdopen(rdpipe)
    wrpipe=os.fdopen(wrpipe,"w")

    pid = os.fork()
    if pid == 0:
        rdpipe.close()
        try:
            i = 0
            for p in sent:
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
            pickle.dump(arp_cache, wrpipe)
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
                for i in range(len(sent)):
                    if sent[i] > r:
                        ans.append((sent[i],r))
                        if verbose > 1:
                            os.write(1, "*")
                        ok = 1
                        del(sent[i])
                        break
                if len(sent) == 0:
                    break
                if not ok:
                    if verbose > 1:
                        os.write(1, ".")
                    recv.append(r)
                if finished and remaintime:
                    end = time.time()
                    remaintime -= end-start
                    if remaintime < 0:
                        break
        except KeyboardInterrupt:
            pass

        ac = pickle.load(rdpipe)
        arp_cache.update(ac)
        os.waitpid(pid,0)

    if verbose:
        print "\nReceived %i packets, got %i answers, remaining %i packets" % (len(recv)+len(ans), len(ans), len(sent))
    return ans,sent,recv


def send(x, inter=0, *args, **kargs):
    """Send packets at layer 3"""
    if not isinstance(x, Gen):
        x = SetGen(x)
    s=conf.L3socket(*args, **kargs)
    for p in x:
        s.send(p)
        time.sleep(inter)

def sendp(x, inter=0, *args, **kargs):
    """Send packets at layer 2"""
    if not isinstance(x, Gen):
        x = SetGen(x)
    s=conf.L2socket(*args, **kargs)
    for p in x:
        s.send(p)
        time.sleep(inter)


    
def sr(x,filter=None, *args,**kargs):
    """Send and receive packets at layer 3"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(conf.L3socket(filter=filter),x,*args,**kargs)
    return a,b

def sr1(x,filter=None, *args,**kargs):
    """Send and receive packets at layer 3 and return only the first answer"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(conf.L3socket(filter=filter),x,*args,**kargs)
    if len(a) > 0:
        return a[0][1]
    else:
        return None

def srp(x,iface=None,filter=None, *args,**kargs):
    """Send and receive packets at layer 2"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(conf.L2socket(iface=iface, filter=filter),x,*args,**kargs)
    return a,b

def srp1(x,iface=None,filter=None, *args,**kargs):
    """Send and receive packets at layer 2 and return only the first answer"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(conf.L2socket(iface=iface, filter=filter),x,*args,**kargs)
    if len(a) > 0:
        return a[0][1]
    else:
        return None



#############################
## pcap capture file stuff ##
#############################

def wrpcap(filename, pkt):
    f=open(filename,"w")
    f.write(struct.pack("IHHIIII",
                        0xa1b2c3d4,
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
    hdr = f.read(24)
    if len(hdr)<24:
        warning("Invalid pcap file")
        return res
    magic,vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack("IHHIIII",hdr)
    LLcls=LLTypes[linktype]
    while 1:
        hdr = f.read(16)
        if len(hdr) < 16:
            break
        sec,usec,caplen,olen = struct.unpack("IIII", hdr )
        p = LLcls(f.read(caplen))
        p.time = sec+0.000001*usec
        res.append(p)
    f.close()
    return res


###############
## BPF stuff ##
###############


def attach_filter(s, filter):
    f = os.popen("tcpdump -ddd -s 1600 '%s'" % filter)
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



p0f_base = []
p0f_ttl_range=[255]

def init_p0f(base=None,reset=1):
    global p0f_base
    global p0f_ttl_range
    if reset:
        p0f_base=[]
        p0f_ttl_range=[255]
    if base is None:
        base = conf.p0f_base
    try:
        f=open(base)
    except IOError:
        return
    for l in f:
        if l[0] in ["#","\n"]:
            continue
        l = tuple(l.split(":"))
        if len(l) < 9:
            continue
        li = map(int,l[:8])
        if li[1] not in p0f_ttl_range:
            p0f_ttl_range.append(li[1])
            p0f_ttl_range.sort()
        p0f_base.append((li,":".join(l[8:])[:-1]))
    f.close()




def packet2p0f(pkt):
    if not isinstance(pkt, Packet):
        raise TypeError("Not a TCP/IP packet")
    if not isinstance(pkt, IP):
        return packet2p0f(pkt.payload)
    if not isinstance(pkt.payload, TCP):
        raise TypeError("Not a TCP packet")
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
    t = p0f_ttl_range[:]
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
    """Passive OS fingerprinting: guess the OS that emitted this TCP syn
p0f(packet) -> accuracy, [list of guesses]
"""
    if len(p0f_base) == 0:
        warning("p0f base empty.")
        return []
    s = len(p0f_base[0][0])
    r = []
    min = s+1
    sig = packet2p0f(pkt)
    for b,name in p0f_base:
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

queso_base={}

def quesoTCPflags(flags):
    if flags == "-":
        return "-"
    flv = "FSRPAUXY"
    v = 0
    for i in flags:
        v |= 2**flv.index(i)
    return "%x" % v

def init_queso(base=None, reset=1):
    global queso_base 
    if reset:
        queso_base = {}
    if base is None:
        base = conf.queso_base
    try:
        f = open(base)
    except IOError:
        return
    p = None
    for l in f:
        l = l.strip()
        if not l or l[0] == ';':
            continue
        if l[0] == '*':
            if p is not None:
                p[""] = name
            name = l[1:].strip()
            p = queso_base
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
    f.close()
        
        

    
def queso_sig(target, dport=80, timeout=3):
    global queso_base
    p = queso_base
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
    p = queso_base
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
    """Guess the operating system of a machine looking at its TCP stack behaviour
queso(target, dport=80, timeout=3)"""
    return queso_search(queso_sig(*args, **kargs))



######################
## nmap OS fp stuff ##
######################

nmap_base = []

def init_nmap(base=None, reset=1):
    global nmap_base
    if reset:
        nmap_base=[]
    if base is None:
        base = conf.nmap_base
    try:
        f=open(base)
    except IOError:
        return

    name = None
    for l in f:
        l = l.strip()
        if not l or l[0] == "#":
            continue
        if l[:12] == "Fingerprint ":
            if name is not None:
                nmap_base.append((name,sig))
            name = l[12:].strip()
            sig={}
            p = nmap_base
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
        nmap_base.append((name,sig))
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

    ans, unans = sr(tests, timeout=2, verbose=2)
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
    for os,fp in nmap_base:
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


def sniff(count=0, prn = None, *arg, **karg):
    """Sniff packets
sniff([count,] [prn,] + L2ListenSocket args) -> list of packets
    """
    c = 0
    s = conf.L2listen(type=ETH_P_ALL, *arg, **karg)
    lst = []
    while 1:
        try:
            p = s.recv(1600)
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
    return lst



def arpcachepoison(target, victim, interval=60):
    """Poison target's cache with (your MAC,victim's IP) couple
arpspoof(target, victim, [interval=60]) -> None
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

def traceroute(target, maxttl=30, dport=80, sport=RandShort()):
    """Instant TCP traceroute
traceroute(target, [maxttl=30], [dport=80], [sport=80]) -> None
"""
    a,b = sr(IP(dst=target, ttl=(1,maxttl))/TCP(seq=RandInt(),sport=sport, dport=dport),
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
arping(net, iface=conf.iff) -> None"""
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net),
                    filter="arp and arp[7] = 2", timeout=2, iface=iface)
    for s,r in ans:
        print r.payload.psrc
    last = ans,unans


#####################
## Reporting stuff ##
#####################

def report_ports(target, ports):
    ans,unans = sr(IP(dst=target)/TCP(dport=ports),timeout=5)
    print "\\begin{tabular}{|l|l|l|}\n\\hline"
    for s,r in ans:
        if not r.haslayer(ICMP):
            if r.payload.flags == 0x12:
                print r.sprintf("%TCP.sport% & open & SA \\\\")
    print "\\hline"
    for s,r in ans:
        if r.haslayer(ICMP):
            print r.sprintf("%TCPerror.dport% & closed & ICMP type %ICMP.type%/%ICMP.code% from %IP.src% \\\\")
        elif r.payload.flags != 0x12:
            print r.sprintf("%TCP.sport% & closed & TCP %TCP.flags% \\\\")
    print "\\hline"
    for i in unans:
        print i.sprintf("%TCP.dport% & ? & unanswered \\\\")
    print "\\hline\n\\end{tabular}"


    

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
                print "%-10s : %s (%s)" % (f.name, f.__class__.__name__, repr(f.default))
        else:
            print "Not a packet class. Type 'ls()' to list packet classes."


    


user_commands = [ sr, sr1, srp, sniff, p0f, arpcachepoison, send, sendp, traceroute, arping, ls, lsc, queso ]


###################
## Testing stuff ##
###################
            
            

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
    sniff(prnt_cb=lambda x: x.display(),*args,**kargs)



def fragleak(target):
    load = "XXXXYYYYYYYYYY"
#    getmacbyip(target)
#    pkt = IP(dst=target, id=RandShort(), options="\x22"*40)/UDP()/load
    pkt = IP(dst=target, id=RandShort(), options="\x00"*40, flags=1)/UDP()/load
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



############
## Config ##
############

class ConfClass:
    def configure(self, cnf):
        self.__dict__ = cnf.__dict__.copy()
    def __repr__(self):
        return str(self)
    def __str__(self):
        s=""
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
stealth  : if 1, prevent any unwanted packet to go out (ARP, DNS, ...)
iff      : select the default output interface for srp() and sendp(). default:"eth0")
verb     : level of verbosity, from 0 (almost mute) to 3 (verbose)
promisc  : default mode for listening socket (to get answers if you spoof on a lan)
sniff_promisc : default mode for sniff()
filter   : bpf filter added to every sniffing socket to exclude traffic from analysis
histfile : history file
padding  : include padding in desassembled packets
except_filter : BPF filter for packets to ignore
"""
    session = ""  
    stealth = "not implemented"
    iff = get_working_if()
    verb = 2
    promisc = "not implemented"
    sniff_promisc = 0
    filter = "not implemented"
    L3socket = L3PacketSocket
    L2socket = L2Socket
    L2listen = L2ListenSocket
    histfile = os.path.join(os.environ["HOME"], ".scapy_history")
    padding = 1
    p0f_base ="/etc/p0f.fp"
    queso_base ="/etc/queso.conf"
    nmap_base ="/usr/share/nmap/nmap-os-fingerprints"
    except_filter = ""
        

conf=Conf()

init_p0f()
init_queso()
init_nmap()
