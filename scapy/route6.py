# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

# Copyright (C) 2005  Guillaume Valadon <guedou@hongo.wide.ad.jp>
#                     Arnaud Ebalard <arnaud.ebalard@eads.net>

"""
Routing and network interface handling for IPv6.
"""

#############################################################################
#                        Routing/Interfaces stuff                           #
#############################################################################

from __future__ import absolute_import
import socket
import scapy.consts
from scapy.config import conf
from scapy.utils6 import in6_ptop, in6_cidr2mask, in6_and, \
    in6_islladdr, in6_ismlladdr, in6_isincluded, in6_isgladdr, \
    in6_isaddr6to4, in6_ismaddr, construct_source_candidate_set, \
    get_source_addr_from_candidate_set
from scapy.arch import read_routes6, in6_getifaddr
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.error import warning, log_loading
import scapy.modules.six as six
from scapy.utils import pretty_list


class Route6:

    def __init__(self):
        self.resync()
        self.invalidate_cache()

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
        rtlst = []

        for net, msk, gw, iface, cset, metric in self.routes:
            rtlst.append(('%s/%i' % (net, msk),
                          gw,
                          (iface if isinstance(iface, six.string_types)
                           else iface.description),
                          ", ".join(cset) if len(cset) > 0 else "",
                          str(metric)))

        return pretty_list(rtlst,
                           [('Destination', 'Next Hop', "Iface", "Src candidates", "Metric")],  # noqa: E501
                           sortBy=1)

    # Unlike Scapy's Route.make_route() function, we do not have 'host' and 'net'  # noqa: E501
    # parameters. We only have a 'dst' parameter that accepts 'prefix' and
    # 'prefix/prefixlen' values.
    # WARNING: Providing a specific device will at the moment not work correctly.  # noqa: E501
    def make_route(self, dst, gw=None, dev=None):
        """Internal function : create a route for 'dst' via 'gw'.
        """
        prefix, plen = (dst.split("/") + ["128"])[:2]
        plen = int(plen)

        if gw is None:
            gw = "::"
        if dev is None:
            dev, ifaddr, x = self.route(gw)
        else:
            # TODO: do better than that
            # replace that unique address by the list of all addresses
            lifaddr = in6_getifaddr()
            devaddrs = [x for x in lifaddr if x[2] == dev]
            ifaddr = construct_source_candidate_set(prefix, plen, devaddrs)

        return (prefix, plen, gw, dev, ifaddr, 1)

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
        tmp = dst + "/128"
        dst, plen = tmp.split('/')[:2]
        dst = in6_ptop(dst)
        plen = int(plen)
        to_del = [x for x in self.routes
                  if in6_ptop(x[0]) == dst and x[1] == plen]
        if gw:
            gw = in6_ptop(gw)
            to_del = [x for x in self.routes if in6_ptop(x[2]) == gw]
        if len(to_del) == 0:
            warning("No matching route found")
        elif len(to_del) > 1:
            warning("Found more than one match. Aborting.")
        else:
            i = self.routes.index(to_del[0])
            self.invalidate_cache()
            del(self.routes[i])

    def ifchange(self, iff, addr):
        the_addr, the_plen = (addr.split("/") + ["128"])[:2]
        the_plen = int(the_plen)

        naddr = inet_pton(socket.AF_INET6, the_addr)
        nmask = in6_cidr2mask(the_plen)
        the_net = inet_ntop(socket.AF_INET6, in6_and(nmask, naddr))

        for i, route in enumerate(self.routes):
            net, plen, gw, iface, addr, metric = route
            if iface != iff:
                continue
            if gw == '::':
                self.routes[i] = (the_net, the_plen, gw, iface, [the_addr], metric)  # noqa: E501
            else:
                self.routes[i] = (net, plen, gw, iface, [the_addr], metric)
        self.invalidate_cache()
        conf.netcache.in6_neighbor.flush()

    def ifdel(self, iff):
        """ removes all route entries that uses 'iff' interface. """
        new_routes = []
        for rt in self.routes:
            if rt[3] != iff:
                new_routes.append(rt)
        self.invalidate_cache()
        self.routes = new_routes

    def ifadd(self, iff, addr):
        """
        Add an interface 'iff' with provided address into routing table.

        Ex: ifadd('eth0', '2001:bd8:cafe:1::1/64') will add following entry into  # noqa: E501
            Scapy6 internal routing table:

            Destination           Next Hop  iface  Def src @           Metric
            2001:bd8:cafe:1::/64  ::        eth0   2001:bd8:cafe:1::1  1

            prefix length value can be omitted. In that case, a value of 128
            will be used.
        """
        addr, plen = (addr.split("/") + ["128"])[:2]
        addr = in6_ptop(addr)
        plen = int(plen)
        naddr = inet_pton(socket.AF_INET6, addr)
        nmask = in6_cidr2mask(plen)
        prefix = inet_ntop(socket.AF_INET6, in6_and(nmask, naddr))
        self.invalidate_cache()
        self.routes.append((prefix, plen, '::', iff, [addr], 1))

    def route(self, dst=None, dev=None, verbose=conf.verb):
        """
        Provide best route to IPv6 destination address, based on Scapy
        internal routing table content.

        When a set of address is passed (e.g. 2001:db8:cafe:*::1-5) an address
        of the set is used. Be aware of that behavior when using wildcards in
        upper parts of addresses !

        If 'dst' parameter is a FQDN, name resolution is performed and result
        is used.

        if optional 'dev' parameter is provided a specific interface, filtering
        is performed to limit search to route associated to that interface.
        """
        dst = dst or "::/0"  # Enable route(None) to return default route
        # Transform "2001:db8:cafe:*::1-5:0/120" to one IPv6 address of the set
        dst = dst.split("/")[0]
        savedst = dst  # In case following inet_pton() fails
        dst = dst.replace("*", "0")
        idx = dst.find("-")
        while idx >= 0:
            m = (dst[idx:] + ":").find(":")
            dst = dst[:idx] + dst[idx + m:]
            idx = dst.find("-")

        try:
            inet_pton(socket.AF_INET6, dst)
        except socket.error:
            dst = socket.getaddrinfo(savedst, None, socket.AF_INET6)[0][-1][0]
            # TODO : Check if name resolution went well

        # Use the default interface while dealing with link-local addresses
        if dev is None and (in6_islladdr(dst) or in6_ismlladdr(dst)):
            dev = conf.iface

        # Deal with dev-specific request for cache search
        k = dst
        if dev is not None:
            k = dst + "%%" + (dev if isinstance(dev, six.string_types) else dev.pcap_name)  # noqa: E501
        if k in self.cache:
            return self.cache[k]

        paths = []

        # TODO : review all kinds of addresses (scope and *cast) to see
        #        if we are able to cope with everything possible. I'm convinced
        #        it's not the case.
        # -- arnaud
        for p, plen, gw, iface, cset, me in self.routes:
            if dev is not None and iface != dev:
                continue
            if in6_isincluded(dst, p, plen):
                paths.append((plen, me, (iface, cset, gw)))
            elif (in6_ismlladdr(dst) and in6_islladdr(p) and in6_islladdr(cset[0])):  # noqa: E501
                paths.append((plen, me, (iface, cset, gw)))

        if not paths:
            if verbose:
                warning("No route found for IPv6 destination %s "
                        "(no default route?)", dst)
            return (scapy.consts.LOOPBACK_INTERFACE, "::", "::")

        # Sort with longest prefix first then use metrics as a tie-breaker
        paths.sort(key=lambda x: (-x[0], x[1]))

        best_plen = (paths[0][0], paths[0][1])
        paths = [x for x in paths if (x[0], x[1]) == best_plen]

        res = []
        for p in paths:  # Here we select best source address for every route
            tmp = p[2]
            srcaddr = get_source_addr_from_candidate_set(dst, tmp[1])
            if srcaddr is not None:
                res.append((p[0], p[1], (tmp[0], srcaddr, tmp[2])))

        if res == []:
            warning("Found a route for IPv6 destination '%s', but no possible source address.", dst)  # noqa: E501
            return (scapy.consts.LOOPBACK_INTERFACE, "::", "::")

        # Symptom  : 2 routes with same weight (our weight is plen)
        # Solution :
        #  - dst is unicast global. Check if it is 6to4 and we have a source
        #    6to4 address in those available
        #  - dst is link local (unicast or multicast) and multiple output
        #    interfaces are available. Take main one (conf.iface6)
        #  - if none of the previous or ambiguity persists, be lazy and keep
        #    first one

        if len(res) > 1:
            tmp = []
            if in6_isgladdr(dst) and in6_isaddr6to4(dst):
                # TODO : see if taking the longest match between dst and
                #        every source addresses would provide better results
                tmp = [x for x in res if in6_isaddr6to4(x[2][1])]
            elif in6_ismaddr(dst) or in6_islladdr(dst):
                # TODO : I'm sure we are not covering all addresses. Check that
                tmp = [x for x in res if x[2][0] == conf.iface6]

            if tmp:
                res = tmp

        # Fill the cache (including dev-specific request)
        k = dst
        if dev is not None:
            k = dst + "%%" + (dev if isinstance(dev, six.string_types) else dev.pcap_name)  # noqa: E501
        self.cache[k] = res[0][2]

        return res[0][2]


conf.route6 = Route6()
try:
    conf.iface6 = conf.route6.route(None)[0]
except Exception:
    pass
