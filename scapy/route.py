## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Routing and handling of network interfaces.
"""

import socket
from arch import read_routes,get_if_addr,LOOPBACK_NAME
from utils import atol,ltoa,itom
from config import conf
from error import Scapy_Exception,warning

##############################
## Routing/Interfaces stuff ##
##############################

class Route:
    def __init__(self):
        self.resync()
        self.s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cache = {}

    def invalidate_cache(self):
        self.cache = {}

    def resync(self):
        self.invalidate_cache()
        self.routes = read_routes()

    def __repr__(self):
        rt = "Network         Netmask         Gateway         Iface           Output IP\n"
        for net,msk,gw,iface,addr in self.routes:
            rt += "%-15s %-15s %-15s %-15s %-15s\n" % (ltoa(net),
                                              ltoa(msk),
                                              gw,
                                              iface,
                                              addr)
        return rt

    def make_route(self, host=None, net=None, gw=None, dev=None):
        if host is not None:
            thenet,msk = host,32
        elif net is not None:
            thenet,msk = net.split("/")
            msk = int(msk)
        else:
            raise Scapy_Exception("make_route: Incorrect parameters. You should specify a host or a net")
        if gw is None:
            gw="0.0.0.0"
        if dev is None:
            if gw:
                nhop = gw
            else:
                nhop = thenet
            dev,ifaddr,x = self.route(nhop)
        else:
            ifaddr = get_if_addr(dev)
        return (atol(thenet), itom(msk), gw, dev, ifaddr)

    def add(self, *args, **kargs):
        """Ex:
        add(net="192.168.1.0/24",gw="1.2.3.4")
        """
        self.invalidate_cache()
        self.routes.append(self.make_route(*args,**kargs))

        
    def delt(self,  *args, **kargs):
        """delt(host|net, gw|dev)"""
        self.invalidate_cache()
        route = self.make_route(*args,**kargs)
        try:
            i=self.routes.index(route)
            del(self.routes[i])
        except ValueError:
            warning("no matching route found")
             
    def ifchange(self, iff, addr):
        self.invalidate_cache()
        the_addr,the_msk = (addr.split("/")+["32"])[:2]
        the_msk = itom(int(the_msk))
        the_rawaddr = atol(the_addr)
        the_net = the_rawaddr & the_msk
        
        
        for i in range(len(self.routes)):
            net,msk,gw,iface,addr = self.routes[i]
            if iface != iff:
                continue
            if gw == '0.0.0.0':
                self.routes[i] = (the_net,the_msk,gw,iface,the_addr)
            else:
                self.routes[i] = (net,msk,gw,iface,the_addr)
        conf.netcache.flush()
        
                

    def ifdel(self, iff):
        self.invalidate_cache()
        new_routes=[]
        for rt in self.routes:
            if rt[3] != iff:
                new_routes.append(rt)
        self.routes=new_routes
        
    def ifadd(self, iff, addr):
        self.invalidate_cache()
        the_addr,the_msk = (addr.split("/")+["32"])[:2]
        the_msk = itom(int(the_msk))
        the_rawaddr = atol(the_addr)
        the_net = the_rawaddr & the_msk
        self.routes.append((the_net,the_msk,'0.0.0.0',iff,the_addr))


    def route(self,dest,verbose=None):
        if type(dest) is list and dest:
            dest = dest[0]
        if dest in self.cache:
            return self.cache[dest]
        if verbose is None:
            verbose=conf.verb
        # Transform "192.168.*.1-5" to one IP of the set
        dst = dest.split("/")[0]
        dst = dst.replace("*","0") 
        while 1:
            l = dst.find("-")
            if l < 0:
                break
            m = (dst[l:]+".").find(".")
            dst = dst[:l]+dst[l+m:]

            
        dst = atol(dst)
        pathes=[]
        for d,m,gw,i,a in self.routes:
            aa = atol(a)
            if aa == dst:
                pathes.append((0xffffffffL,(LOOPBACK_NAME,a,"0.0.0.0")))
            if (dst & m) == (d & m):
                pathes.append((m,(i,a,gw)))
        if not pathes:
            if verbose:
                warning("No route found (no default route?)")
            return LOOPBACK_NAME,"0.0.0.0","0.0.0.0" #XXX linux specific!
        # Choose the more specific route (greatest netmask).
        # XXX: we don't care about metrics
        pathes.sort()
        ret = pathes[-1][1]
        self.cache[dest] = ret
        return ret
            
    def get_if_bcast(self, iff):
        for net, msk, gw, iface, addr in self.routes:
            if (iff == iface and net != 0L):
                bcast = atol(addr)|(~msk&0xffffffffL); # FIXME: check error in atol()
                return ltoa(bcast);
        warning("No broadcast address found for iface %s\n" % iff);

conf.route=Route()

#XXX use "with"
_betteriface = conf.route.route("0.0.0.0", verbose=0)[0]
if _betteriface != LOOPBACK_NAME:
    conf.iface = _betteriface
del(_betteriface)
