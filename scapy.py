#! /usr/bin/python

#############################################################################
##                                                                         ##
## scapy.py --- Low-Level network scanner                                  ##
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

RCSID="$Id: scapy.py,v 0.9.8.1 2003/03/27 15:43:20 pbi Exp $"

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
#  - add lsc() to list commands
#
##
##########[XXX]#=--

################
##### Main #####
################


if __name__ == "__main__":
    import code,sys,pickle,types,os
    import scapy
    __builtins__.__dict__.update(scapy.__dict__)

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
            session=pickle.load(f)
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

    if iface is not None:
        pass


    code.interact(banner = "Welcome to Scapy (%s)"%VERSION, local=session)

    if session.has_key("__builtins__"):
        del(session["__builtins__"])

    for k in session.keys():
        if type(session[k]) in [types.ClassType, types.ModuleType]:
             print "[%s] (%s) can't be saved. Deleted." % (k, type(session[k]))
             del(session[k])

    if scapy.conf.session:
        try:
            os.rename(scapy.conf.session, scapy.conf.session+".bak")
        except OSError:
            pass
        f=open(scapy.conf.session,"w")
        pickle.dump(session, f)
        f.close()
        
    sys.exit()

##################
##### Module #####
##################

import socket, sys, getopt, string, struct, time, random, os, traceback
import pickle, types
from select import select
from fcntl import ioctl

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

class param:
    iface="eth0"

############
## Config ##
############

class ConfClass:
    def configure(self, cnf):
        self.__dict__ = cnf.__dict__.copy()
    def __repr__(self):
        s=""
        keys = self.__class__.__dict__.copy()
        keys.update(self.__dict__)
        keys = keys.keys()
        keys.sort()
        for i in keys:
            if i[0] != "_":
                s += " %s=%s" % (i, repr(getattr(self, i)))
        return "<Conf%s>" % s
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
    session = ""  # filename where the session will be saved
    stealth = "not implemented"
    iff = "eth0"
    verb = 2
    promisc = 0
        

conf=Conf()

    



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




###################
## Routing stuff ##
###################




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

def get_if_list():
    f=open("/proc/net/dev","r")
    lst = []
    f.readline()
    f.readline()
    for l in f:
        lst.append(l.split(":")[0].strip())
    return lst

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

def getmacbyip(ip):
    iff,a,gw = choose_route(ip)
    if gw != "0.0.0.0":
        ip = gw

    if arp_cache.has_key(ip):
        mac, timeout = arp_cache[ip]
        if timeout and (time.time()-timeout < ARPTIMEOUT):
            return mac

    
    res = srp(Ether(dst=ETHER_BROADCAST)/ARP(op=ARP.who_has,
                                            pdst=ip),
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
        if type(x) is str and len(x) == 4:
            x = self.m2i(pkt, x)
        return self.h2i(pkt,x)
    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

class SourceIPField(IPField):
    def __init__(self, name, dstname):
        IPField.__init__(self, name, None)
        self.dstname = dstname
    def i2m(self, pkt, x):
        if x is None:
            iff,x,gw = choose_route(pkt.__getattr__(self.dstname))
        return IPField.i2m(self, pkt, x)
    def i2h(self, pkt, x):
        if x is None:
            dst=pkt.__getattr__(self.dstname)
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
    def addfield(self, packet, s, val):
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
    def getfield(self, packet, s):
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


class TCPFlagsField(BitField):
    TCPFlagsNames = "FSRPAUEC"
    def any2i(self, pkt, x):
        if type(x) is str:
            y = 0
            for i in x:
                y |= 1 << self.TCPFlagsNames.index(i)
            x = y
        return x
    def i2repr(self, pkt, x):
        r = ""
        i=0
        while x:
            if x & 1:
                r += self.TCPFlagsNames[i]
            i += 1
            x >>= 1
        return r

            



class IPoptionsField(StrField):
    def i2m(self, pkt, x):
        return x+"\x00"*(3-((len(x)+3)%4))
    def getfield(self, packet, s):
        opsz = (packet.ihl-5)*4
        if opsz < 0:
            warning("bad ihl (%i). Assuming ihl=5"%packet.ihl)
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
    def getfield(self, packet, s):
        opsz = (packet.dataofs-5)*4
        if opsz < 0:
            warning("bad dataofs (%i). Assuming dataofs=5"%packet.dataofs)
            opsz = 0
        return s[opsz:],self.m2i(pkt,s[:opsz])
    def m2i(self, pkt, x):
        opt = {}
        while x:
            onum = ord(x[0])
            if onum == 0:
                break
            if onum == 1:
                opt["NOP"] = ()
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
                opt[oname] = oval
            else:
                opt[onum] = oval
            x = x[olen:]
        return opt
    
    def i2m(self, pkt, x):
        opt = ""
        for oname in x:
            oval = x[oname]
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
    
    

###########################
## Packet abstract class ##
###########################


class Packet(Gen):
    name="abstract packet"

    fields_desc = []

    aliastypes = []
    overload_fields = {}

    underlayer = None

    payload_type_field = None
    payload_guess = []


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
        if pkt:
            self.dissect(pkt)
        for f in fields.keys():
            self.fields[f] = self.fieldtype[f].any2i(self,fields[f])

    def add_payload(self, payload):
        if payload is None:
            return
        elif self.payload != NoPayload():
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
        clone.underlayer=self.underlayer
        clone.__dict__["payload"] = self.payload.copy()
        clone.payload.add_underlayer(clone)
        return clone
    def __getattr__(self, attr):
        if self.__dict__.has_key("fieldtype") and self.fieldtype.has_key(attr):
            i2h = self.fieldtype[attr].i2h
        else:
            i2h = lambda x,y: y
        if self.__dict__.has_key("fields") and self.fields.has_key(attr):
            return i2h(self, self.fields[attr])
        elif self.__dict__.has_key("overloaded_fields") and self.overloaded_fields.has_key(attr):
            return i2h(self, self.overloaded_fields[attr])
        elif self.__dict__.has_key("default_fields") and self.default_fields.has_key(attr):
            return i2h(self, self.default_fields[attr])
        elif self.__dict__.has_key(attr):
            return self.__dict__[attr]
        else:
            return getattr(self.payload,attr)
#            raise AttributeError, attr
    def __setattr__(self, attr, val):
        if self.__dict__.has_key("fieldtype") and self.fieldtype.has_key(attr):
            any2i = self.fieldtype[attr].any2i
        else:
            any2i = lambda x,y: y
        if ( self.__dict__.has_key("fields") and
             ( ( self.fields.has_key(attr) or
                 ( self.__dict__.has_key("default_fields") and
                   self.default_fields.has_key(attr) ) ) ) ):
                self.fields[attr] = any2i(self,val)
        elif attr == "payload":
            self.remove_payload()
            self.add_payload(val)
        else:
            self.__dict__[attr] = val
    def __delattr__(self, attr):
        if self.__dict__.has_key("fields") and self.fields.has_key(attr):
            del(self.fields[attr])
        elif self.__dict__.has_key("overloaded_fields") and self.overloaded_fields.has_key(attr):
            pass
        elif self.__dict__.has_key("default_fields") and self.default_fields.has_key(attr):
            pass
        elif attr == "payload":
            self.remove_payload()
        elif self.__dict__.has_key(attr):
            del(self.__dict__[attr])
        else:
            raise AttributeError, attr
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
            return Raw(load=other)/self.str
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

    def do_dissect(self, s):
        flist = self.fields_desc[:]
        flist.reverse()
        while s and flist:
            f = flist.pop()
            s,fval = f.getfield(self, s)
            self.fields[f] = fval
        self.do_dissect_payload(s)
    def do_dissect_payload(self, s):
        if s:
            cls = self.guess_payload_class()
            if cls is None:
                cls = Raw
            self.add_payload(cls(s))

    def dissect(self, s):
        return self.do_dissect(s)

    def guess_payload_class(self):
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                ok = 1
                for k in fval.keys():
                    if fval[k] != self.__getattr__(k):
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
                    elt = SetGen(elt)
                for e in elt:
                    done[eltname]=e
                    for x in loop(todo[:], done):
                        yield x
            else:
                if self.payload == NoPayload():
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

    def hastype(self, cls):
        if self.__class__ == cls:
            return 1
        return self.payload.hastype(cls)

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
                            val = self.payload.sprintf("%%%s,%s:%s.%s%%" % (f,cls,num-1,fld), relax)
                            f = "s"
                        elif f[-1] == "r":  # Raw field value
                            val = getattr(self,fld)
                            f = f[:-1]
                            if not f:
                                f = "s"
                        else:
                            val = self.fieldtype[fld].i2repr(self,(getattr(self,fld)))
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
        return self == other
    def hastype(self, cls):
        return 0
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
        return str(self) == str(other)
        
class Ether(Packet):
    name = "Ethernet"
    payload_type_field = "type"
    fields_desc = [ DestMACField("dst"),
#                   MACField("dst", ETHER_BROADCAST),
                    SourceMACField("src"),
#                   MACField("src", ETHER_ANY),
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
    def answers(self, other):
        if isinstance(other,Ether):
            if self.type == other.type:
                return self.payload < other.payload
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
                    ByteField("type", 0),
                    LenField("len", None, "H") ]
    
    EAP_PACKET= 0
    START = 1
    LOGOFF = 2
    KEY = 3
    ASF = 4
    def answers(self, other):
        if isinstance(other,EAPOL):
            if ( (self.type == self.EAP_PACKET) and
                 (other.type == self.EAP_PACKET) ):
                return self.payload < other.payload
        return 0
             

class EAP(Packet):
    name = "EAP"
    fields_desc = [ ByteField("code", 4),
                    ByteField("id", 0),
                    ByteField("type",0),
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
                    ShortField("op", 1),
#                    MACField("hwsrc", ETHER_ANY),
                    ARPSourceMACField("hwsrc"),
#                    IPField("psrc", "127.0.0.1"),
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
                    BitField("flags", 0, 3),
                    BitField("frag", 0, 13),
                    ByteField("ttl", 64),
                    ByteField("proto", 0),
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
                    TCPFlagsField("flags", 0x2, 8),
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
        if (abs(other.seq-self.ack) >= 2):
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
    def answers(self, other):
        if not isinstance(other, UDP):
            return 0
        if not ((self.sport == other.dport) and
                (self.dport == other.sport)):
            return 0
        return 1
    
    
                    
class ICMP(Packet):
    name = "ICMP"
    fields_desc = [ ByteField("type",8),
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
        return self.payload < other.payload


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
                ]

for l in layer_bonds:
    bind_layers(*l)
                

#####################
## Default sockets ##
#####################

pkt=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
pkt.bind(("eth0", 0))
raw=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)


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
    def send(self, x):
        return self.outs.send(str(x))
    def recv(self, x):
        return Raw(self.ins.recv(x))
    def fileno(self):
        return self.fileno_in()
    def fileno_in(self):
        return self.ins.fileno()
    def close(self):
        self.ins.close()
        if self.ins != self.outs:
            self.outs.close()
    def bind_in(self, addr):
        self.ins.bind(addr)
    def bind_out(self, addr):
        self.outs.bind(addr)
        

class L3RawSocket(SuperSocket):
    def __init__(self, iface = None, type = ETH_P_IP):
        if iface is None:
            iface = conf.iff
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, type)
        self.ins.bind((iface, type))
    def recv(self, x):
        return Ether(self.ins.recv(x)).payload
    def send(self, x):
        try:
            self.outs.sendto(str(x),(x.dst,0))
        except socket.error,msg:
            print msg
        


class L3PacketSocket(SuperSocket):
    def __init__(self, type = ETH_P_IP, filter=None):
        self.type = type
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        if filter is not None:
            attach_filter(self.ins, filter)
        self.outs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
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
        iff,a,gw = choose_route(x.dst)
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
    def __init__(self, iface = None, type = ETH_P_IP, promisc=None, filter=None):
        self.type = type
        self.outs = None
        self.ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
        if iface is not None:
            self.ins.bind((iface, type))
        if filter is not None:
            attach_filter(self.ins, filter)
        if promisc is None:
            promisc = conf.promisc
        self.promisc = promisc
        if iface is None:
            self.iff = get_if_list()
        else:
            self.iff = [iface]
        if self.promisc:
            for i in self.iff:
                set_promisc(self.ins, i)
    def __del__(self):
        if self.promisc:
            for i in iff:
                set_promisc(self.ins, i, 0)

    def recv(self, x):
        pkt, sa_ll = self.ins.recvfrom(x)
        # XXX: if sa_ll[2] == 4 (OUTGOING_PACKET) : skip
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


####################
## Send / Receive ##
####################

def send(x, iface=None, slp=-1):
    if iface is None:
        iface = param.iface
    s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((iface, 0))
    if slp >= 0:
        try:
            while 1:
                s.send(str(x))
                time.sleep(slp)
        except KeyboardInterrupt:
            pass
    else:
        s.send(str(x))
    s.close()




def sndrcv(pks, pkt, timeout = 2, inter = 0, verbose=None):

    if not isinstance(pkt, Packet):
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


def send(x, *args, **kargs):
    """Send packets at layer 3"""
    s=L3PacketSocket()
    s.send(x)

def sendp(x, *args, **kargs):
    """Send packets at layer 2"""
    s=L2Socket()
    s.send(x)



    
def sr(x,filter=None, *args,**kargs):
    """Send and receive packets at layer 3"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(L3PacketSocket(filter=filter),x,*args,**kargs)
    return a,b

def sr1(x,filter=None, *args,**kargs):
    """Send and receive packets at layer 3 and return only the first answer"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(L3PacketSocket(filter=filter),x,*args,**kargs)
    if len(a) > 0:
        return a[0][1]
    else:
        return None

def srp(x,iface=None,filter=None, *args,**kargs):
    """Send and receive packets at layer 2"""
    if not kargs.has_key("timeout"):
        kargs["timeout"] = -1
    a,b,c=sndrcv(L2Socket(iface=iface, filter=filter),x,*args,**kargs)
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
        bpf += struct.pack("HBBI",*map(int,l.split()))

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


POF_BASE="/etc/p0f.fp"

p0f_base = []
p0f_ttl_range=[255]

def init_p0f(base=None,reset=1):
    global p0f_base
    global p0f_ttl_range
    if reset:
        p0f_base=[]
        p0f_ttl_range=[255]
    if base is None:
        base = POF_BASE
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


init_p0f()


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
    


    


###################
## User commands ##
###################


def sniff(count=0, prn = None, *arg, **karg):
    """Sniff packets
sniff([count,] [prn,] + L2ListenSocket args) -> list of packets
    """
    c = 0
    s = L2ListenSocket(type=ETH_P_ALL, *arg, **karg)
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
    p = Ether(dst=tmac)/ARP(op=ARP.who_has, psrc=victim, pdst=target)
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
             timeout=5, filter="(icmp and icmp[0]=11) or (tcp and (tcp[13] & 0x16 > 0x10))")
    res = {}
    for s,r in a:
        if r.hastype(ICMP):
            res[s.ttl] = r.sprintf("%-15s,IP.src%")
        else:
            res[s.ttl] = r.sprintf("%-15s,IP.src% %TCP.flags%")
    for s in b:
        res[s.ttl] = ""
    lst = res.keys()
    lst.sort()
    for i in lst:
        print "%2i %s" % (i, res[i])
    



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


    


user_commands = [ sr, sr1, srp, sniff, p0f, arpcachepoison, send, sendp, traceroute, ls, lsc ]


###################
## Testing stuff ##
###################
            
            

last=None

def arping(net):
    global last
    ans, unans, x = sndrcv(PacketRawSocket(iface=iface), Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net))
    for s,r in ans:
        print r.payload.psrc
    last = ans,unans,x

def icmping(net):
    global last
    ans, unans, x = sndrcv(InetPacketSocket(),IP(dst=net)/ICMP())
    for s,r in ans:
        print r.src
    last = ans,unans,x

def tcping(net, port):
    global last
    ans, unans, x = sndrcv(InetPacketSocket(),IP(dst=net)/TCP(dport=port, flags=2))
    for s,r in ans:
        if isinstance(r.payload,TCP):
            print r.src,r.payload.sport, r.payload.flags
        else:
            print r.src,"icmp",r.payload.type
    last = ans, unans, x

def tcptraceroute(net, port=80):
    global last
    ans, unans, x = sndrcv(InetPacketSocket(),
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
    pkt = IP(dst=target, id=RandShort(), options="\x22"*40)/UDP()/load
#    pkt = IP(dst=target, id=RandShort(), options="", flags=1)/UDP()/load
    s=L3PacketSocket()
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
                if not isinstance(ans.payload.payload.payload.payload, Raw):
                    continue
                leak = ans.payload.payload.payload.payload.load[len(load):]
                if leak not in found:
                    found[leak]=None
                    linehexdump(leak)
            except KeyboardInterrupt:
                if intr:
                    raise KeyboardInterrupt
                intr=1
    except KeyboardInterrupt:
        pass

