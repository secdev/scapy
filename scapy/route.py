# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Routing and handling of network interfaces.
"""


from scapy.compat import plain_str
from scapy.config import conf
from scapy.error import Scapy_Exception, warning
from scapy.interfaces import resolve_iface
from scapy.utils import atol, ltoa, itom, pretty_list

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)


##############################
#  Routing/Interfaces stuff  #
##############################

class Route:
    def __init__(self):
        # type: () -> None
        self.routes = []  # type: List[Tuple[int, int, str, str, str, int]]
        self.invalidate_cache()
        if conf.route_autoload:
            self.resync()

    def invalidate_cache(self):
        # type: () -> None
        self.cache = {}  # type: Dict[Tuple[str, Optional[str]], Tuple[str, str, str]]

    def resync(self):
        # type: () -> None
        from scapy.arch import read_routes
        self.invalidate_cache()
        self.routes = read_routes()

    def __repr__(self):
        # type: () -> str
        rtlst = []  # type: List[Tuple[Union[str, List[str]], ...]]
        for net, msk, gw, iface, addr, metric in self.routes:
            if_repr = resolve_iface(iface).description
            rtlst.append((ltoa(net),
                          ltoa(msk),
                          gw,
                          if_repr,
                          addr,
                          str(metric)))

        return pretty_list(rtlst,
                           [("Network", "Netmask", "Gateway", "Iface", "Output IP", "Metric")])  # noqa: E501

    def make_route(self,
                   host=None,  # type: Optional[str]
                   net=None,  # type: Optional[str]
                   gw=None,  # type: Optional[str]
                   dev=None,  # type: Optional[str]
                   metric=1,  # type: int
                   ):
        # type: (...) -> Tuple[int, int, str, str, str, int]
        if host is not None:
            thenet, msk = host, 32
        elif net is not None:
            thenet, msk_b = net.split("/")
            msk = int(msk_b)
        else:
            raise Scapy_Exception("make_route: Incorrect parameters. You should specify a host or a net")  # noqa: E501
        if gw is None:
            gw = "0.0.0.0"
        if dev is None:
            if gw:
                nhop = gw
            else:
                nhop = thenet
            dev, ifaddr, _ = self.route(nhop)
        else:
            ifaddr = "0.0.0.0"  # acts as a 'via' in `ip addr add`
        return (atol(thenet), itom(msk), gw, dev, ifaddr, metric)

    def add(self, *args, **kargs):
        # type: (*Any, **Any) -> None
        """Add a route to Scapy's IPv4 routing table.
        add(host|net, gw|dev)

        :param host: single IP to consider (/32)
        :param net: range to consider
        :param gw: gateway
        :param dev: force the interface to use
        :param metric: route metric

        Examples:

        - `ip route add 192.168.1.0/24 via 192.168.0.254`::
            >>> conf.route.add(net="192.168.1.0/24", gw="192.168.0.254")

        - `ip route add 192.168.1.0/24 dev eth0`::
            >>> conf.route.add(net="192.168.1.0/24", dev="eth0")

        - `ip route add 192.168.1.0/24 via 192.168.0.254 metric 1`::
            >>> conf.route.add(net="192.168.1.0/24", gw="192.168.0.254", metric=1)
        """
        self.invalidate_cache()
        self.routes.append(self.make_route(*args, **kargs))

    def delt(self, *args, **kargs):
        # type: (*Any, **Any) -> None
        """Remove a route from Scapy's IPv4 routing table.
        delt(host|net, gw|dev)

        Same syntax as add()
        """
        self.invalidate_cache()
        route = self.make_route(*args, **kargs)
        try:
            i = self.routes.index(route)
            del self.routes[i]
        except ValueError:
            raise ValueError("No matching route found!")

    def ifchange(self, iff, addr):
        # type: (str, str) -> None
        self.invalidate_cache()
        the_addr, the_msk_b = (addr.split("/") + ["32"])[:2]
        the_msk = itom(int(the_msk_b))
        the_rawaddr = atol(the_addr)
        the_net = the_rawaddr & the_msk

        for i, route in enumerate(self.routes):
            net, msk, gw, iface, addr, metric = route
            if iff != iface:
                continue
            if gw == '0.0.0.0':
                self.routes[i] = (the_net, the_msk, gw, iface, the_addr, metric)  # noqa: E501
            else:
                self.routes[i] = (net, msk, gw, iface, the_addr, metric)
        conf.netcache.flush()

    def ifdel(self, iff):
        # type: (str) -> None
        self.invalidate_cache()
        new_routes = []
        for rt in self.routes:
            if iff == rt[3]:
                continue
            new_routes.append(rt)
        self.routes = new_routes

    def ifadd(self, iff, addr):
        # type: (str, str) -> None
        self.invalidate_cache()
        the_addr, the_msk_b = (addr.split("/") + ["32"])[:2]
        the_msk = itom(int(the_msk_b))
        the_rawaddr = atol(the_addr)
        the_net = the_rawaddr & the_msk
        self.routes.append((the_net, the_msk, '0.0.0.0', iff, the_addr, 1))

    def route(self, dst=None, dev=None, verbose=conf.verb, _internal=False):
        # type: (Optional[str], Optional[str], int, bool) -> Tuple[str, str, str]
        """Returns the IPv4 routes to a host.

        :param dst: the IPv4 of the destination host
        :param dev: (optional) filtering is performed to limit search to route
                    associated to that interface.

        :returns: tuple (iface, output_ip, gateway_ip) where
            - ``iface``: the interface used to connect to the host
            - ``output_ip``: the outgoing IP that will be used
            - ``gateway_ip``: the gateway IP that will be used
        """
        dst = dst or "0.0.0.0"  # Enable route(None) to return default route
        if isinstance(dst, bytes):
            try:
                dst = plain_str(dst)
            except UnicodeDecodeError:
                raise TypeError("Unknown IP address input (bytes)")
        if (dst, dev) in self.cache:
            return self.cache[(dst, dev)]
        # Transform "192.168.*.1-5" to one IP of the set
        _dst = dst.split("/")[0].replace("*", "0")
        while True:
            idx = _dst.find("-")
            if idx < 0:
                break
            m = (_dst[idx:] + ".").find(".")
            _dst = _dst[:idx] + _dst[idx + m:]

        atol_dst = atol(_dst)
        paths = []
        for d, m, gw, i, a, me in self.routes:
            if not a:  # some interfaces may not currently be connected
                continue
            if dev is not None and i != dev:
                continue
            aa = atol(a)
            if aa == atol_dst:
                paths.append(
                    (0xffffffff, 1, (conf.loopback_name, a, "0.0.0.0"))  # noqa: E501
                )
            if (atol_dst & m) == (d & m):
                paths.append((m, me, (i, a, gw)))

        if not paths:
            if verbose:
                warning("No route found for IPv4 destination %s "
                        "(no default route?)", dst)
            return (dev or conf.loopback_name, "0.0.0.0", "0.0.0.0")
        # Choose the more specific route
        # Sort by greatest netmask and use metrics as a tie-breaker
        paths.sort(key=lambda x: (-x[0], x[1]))
        # Return interface
        ret = paths[0][2]
        # Check if source is 0.0.0.0. This is a 'via' route with no src.
        if ret[1] == "0.0.0.0" and not _internal:
            # Then get the source from route(gw)
            ret = (ret[0], self.route(ret[2], _internal=True)[1], ret[2])
        self.cache[(dst, dev)] = ret
        return ret

    def get_if_bcast(self, iff):
        # type: (str) -> List[str]
        bcast_list = []
        for net, msk, gw, iface, addr, metric in self.routes:
            if net == 0:
                continue    # Ignore default route "0.0.0.0"
            elif msk == 0xffffffff:
                continue    # Ignore host-specific routes
            if iff != iface:
                continue
            bcast = net | (~msk & 0xffffffff)
            bcast_list.append(ltoa(bcast))
        if not bcast_list:
            warning("No broadcast address found for iface %s\n", iff)
        return bcast_list


conf.route = Route()

# Update conf.iface
conf.ifaces.load_confiface()
