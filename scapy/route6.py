## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## Copyright (C) 2005  Guillaume Valadon <guedou@hongo.wide.ad.jp>
##                     Arnaud Ebalard <arnaud.ebalard@eads.net>

"""
Routing and network interface handling for IPv6.
"""

#############################################################################
#############################################################################
###                      Routing/Interfaces stuff                         ###
#############################################################################
#############################################################################

import socket
from scapy.config import conf
from scapy.utils6 import *
from scapy.arch import *
from scapy.pton_ntop import *
from scapy.error import warning, log_loading


class Route6:

    def __init__(self):
        self.invalidate_cache()
        self.resync()

    def invalidate_cache(self):
        self.cache = {}

    def flush(self):
        self.invalidate_cache()
        self.routes = []

    def resync(self):
        # TODO : At the moment, resync will drop existing Teredo routes
        #        if any. Change that ...
        self.invalidate_cache()
	self.routes = read_routes6()
	if self.routes == []:
	     log_loading.info("No IPv6 support in kernel")
        
    def __repr__(self):
        rtlst = [('Destination', 'Next Hop', "iface", "src candidates")]

        for net,msk,gw,iface,cset in self.routes:
	    rtlst.append(('%s/%i'% (net,msk), gw, (iface if isinstance(iface, basestring) else iface.name), ", ".join(cset)))

        colwidth = map(lambda x: max(map(lambda y: len(y), x)), apply(zip, rtlst))
        fmt = "  ".join(map(lambda x: "%%-%ds"%x, colwidth))
        rt = "\n".join(map(lambda x: fmt % x, rtlst))

        return rt


    # Unlike Scapy's Route.make_route() function, we do not have 'host' and 'net'
    # parameters. We only have a 'dst' parameter that accepts 'prefix' and 
    # 'prefix/prefixlen' values.
    # WARNING: Providing a specific device will at the moment not work correctly.
    def make_route(self, dst, gw=None, dev=None):
        """Internal function : create a route for 'dst' via 'gw'.
        """
        prefix, plen = (dst.split("/")+["128"])[:2]
        plen = int(plen)

        if gw is None:
            gw = "::"
        if dev is None:
            dev, ifaddr, x = self.route(gw)
        else:
            # TODO: do better than that
            # replace that unique address by the list of all addresses
            lifaddr = in6_getifaddr()             
            devaddrs = filter(lambda x: x[2] == dev, lifaddr)
            ifaddr = construct_source_candidate_set(prefix, plen, devaddrs, LOOPBACK_NAME)

        return (prefix, plen, gw, dev, ifaddr)

    
    def add(self, *args, **kargs):
        """Ex:
        add(dst="2001:db8:cafe:f000::/56")
        add(dst="2001:db8:cafe:f000::/56", gw="2001:db8:cafe::1")
        add(dst="2001:db8:cafe:f000::/64", gw="2001:db8:cafe::1", dev="eth0")
        """
        self.invalidate_cache()
        self.routes.append(self.make_route(*args, **kargs))


    def delt(self, dst, gw=None):
        """ Ex: 
        delt(dst="::/0") 
        delt(dst="2001:db8:cafe:f000::/56") 
        delt(dst="2001:db8:cafe:f000::/56", gw="2001:db8:deca::1") 
        """
        tmp = dst+"/128"
        dst, plen = tmp.split('/')[:2]
        dst = in6_ptop(dst)
        plen = int(plen)
        l = filter(lambda x: in6_ptop(x[0]) == dst and x[1] == plen, self.routes)
        if gw:
            gw = in6_ptop(gw)
            l = [x for x in self.routes if in6_ptop(x[2]) == gw]
        if len(l) == 0:
            warning("No matching route found")
        elif len(l) > 1:
            warning("Found more than one match. Aborting.")
        else:
            i=self.routes.index(l[0])
            self.invalidate_cache()
            del(self.routes[i])
        
    def ifchange(self, iff, addr):
        the_addr, the_plen = (addr.split("/")+["128"])[:2]
        the_plen = int(the_plen)

        naddr = inet_pton(socket.AF_INET6, the_addr)
        nmask = in6_cidr2mask(the_plen)
        the_net = inet_ntop(socket.AF_INET6, in6_and(nmask,naddr))
        
        for i, route in enumerate(self.routes):
            net,plen,gw,iface,addr = route
            if iface != iff:
                continue
            if gw == '::':
                self.routes[i] = (the_net,the_plen,gw,iface,[the_addr])
            else:
                self.routes[i] = (net,plen,gw,iface,[the_addr])
        self.invalidate_cache()
        conf.netcache.in6_neighbor.flush()

    def ifdel(self, iff):
        """ removes all route entries that uses 'iff' interface. """
        new_routes=[]
        for rt in self.routes:
            if rt[3] != iff:
                new_routes.append(rt)
        self.invalidate_cache()
        self.routes = new_routes


    def ifadd(self, iff, addr):
        """
        Add an interface 'iff' with provided address into routing table.
        
        Ex: ifadd('eth0', '2001:bd8:cafe:1::1/64') will add following entry into 
            Scapy6 internal routing table:

            Destination           Next Hop  iface  Def src @
            2001:bd8:cafe:1::/64  ::        eth0   2001:bd8:cafe:1::1

            prefix length value can be omitted. In that case, a value of 128
            will be used.
        """
        addr, plen = (addr.split("/")+["128"])[:2]
        addr = in6_ptop(addr)
        plen = int(plen)
        naddr = inet_pton(socket.AF_INET6, addr)
        nmask = in6_cidr2mask(plen)
        prefix = inet_ntop(socket.AF_INET6, in6_and(nmask,naddr))
        self.invalidate_cache()
        self.routes.append((prefix,plen,'::',iff,[addr]))

    def route(self, dst, dev=None):
        """
        Provide best route to IPv6 destination address, based on Scapy6 
        internal routing table content.

        When a set of address is passed (e.g. 2001:db8:cafe:*::1-5) an address
        of the set is used. Be aware of that behavior when using wildcards in
        upper parts of addresses !

        If 'dst' parameter is a FQDN, name resolution is performed and result
        is used.

        if optional 'dev' parameter is provided a specific interface, filtering
        is performed to limit search to route associated to that interface.
        """
        # Transform "2001:db8:cafe:*::1-5:0/120" to one IPv6 address of the set
        dst = dst.split("/")[0]
        savedst = dst # In case following inet_pton() fails 
        dst = dst.replace("*","0")
        l = dst.find("-")
        while l >= 0:
            m = (dst[l:]+":").find(":")
            dst = dst[:l]+dst[l+m:]
            l = dst.find("-")
            
        try:
            inet_pton(socket.AF_INET6, dst)
        except socket.error:
            dst = socket.getaddrinfo(savedst, None, socket.AF_INET6)[0][-1][0]
            # TODO : Check if name resolution went well

        # Deal with dev-specific request for cache search
        k = dst
        if dev is not None:
            k = dst + "%%" + (dev if isinstance(dev, basestring) else dev.pcap_name)
        if k in self.cache:
            return self.cache[k]

        pathes = []

        # TODO : review all kinds of addresses (scope and *cast) to see
        #        if we are able to cope with everything possible. I'm convinced 
        #        it's not the case.
        # -- arnaud
        for p, plen, gw, iface, cset in self.routes:
            if dev is not None and iface != dev:
                continue
            if in6_isincluded(dst, p, plen):
                pathes.append((plen, (iface, cset, gw)))
            elif (in6_ismlladdr(dst) and in6_islladdr(p) and in6_islladdr(cset[0])):
                pathes.append((plen, (iface, cset, gw)))
                
        if not pathes:
            warning("No route found for IPv6 destination %s (no default route?)" % dst)
            return (LOOPBACK_NAME, "::", "::") # XXX Linux specific

        # Sort with longest prefix first
        pathes.sort(reverse=True)

        best_plen = pathes[0][0]
        pathes = filter(lambda x: x[0] == best_plen, pathes)

        res = []
        for p in pathes: # Here we select best source address for every route
            tmp = p[1]
            srcaddr = get_source_addr_from_candidate_set(dst, p[1][1])
            if srcaddr is not None:
                res.append((p[0], (tmp[0], srcaddr, tmp[2])))

        if res == []:
            warning("Found a route for IPv6 destination '%s', but no possible source address." % dst)
            return (LOOPBACK_NAME, "::", "::") # XXX Linux specific

        # Symptom  : 2 routes with same weight (our weight is plen)
        # Solution : 
        #  - dst is unicast global. Check if it is 6to4 and we have a source 
        #    6to4 address in those available
        #  - dst is link local (unicast or multicast) and multiple output
        #    interfaces are available. Take main one (conf.iface6)
        #  - if none of the previous or ambiguity persists, be lazy and keep
        #    first one
        #  XXX TODO : in a _near_ future, include metric in the game

        if len(res) > 1:
            tmp = []
            if in6_isgladdr(dst) and in6_isaddr6to4(dst):
                # TODO : see if taking the longest match between dst and
                #        every source addresses would provide better results
                tmp = filter(lambda x: in6_isaddr6to4(x[1][1]), res)
            elif in6_ismaddr(dst) or in6_islladdr(dst):
                # TODO : I'm sure we are not covering all addresses. Check that
                tmp = filter(lambda x: x[1][0] == conf.iface6, res)

            if tmp:
                res = tmp
                
        # Fill the cache (including dev-specific request)
        k = dst
        if dev is not None:
            k = dst + "%%" + (dev if isinstance(dev, basestring) else dev.pcap_name)
        self.cache[k] = res[0][1]

        return res[0][1]

conf.route6 = Route6()

_res = conf.route6.route("::/0")
if _res:
    iff, gw, addr = _res
    conf.iface6 = iff
del(_res)

