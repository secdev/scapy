# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Routing and handling of network interfaces.
"""


from __future__ import absolute_import

from scapy.compat import plain_str
from scapy.config import conf
from scapy.error import Scapy_Exception, warning
from scapy.interfaces import resolve_iface
from scapy.utils import atol, ltoa, itom, pretty_list

from scapy.compat import (
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
        self.resync()

    def invalidate_cache(self):
        # type: () -> None
        self.cache = {}  # type: Dict[str, Tuple[str, str, str]]

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
        from scapy.arch import get_if_addr
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
            ifaddr = get_if_addr(dev)
        return (atol(thenet), itom(msk), gw, dev, ifaddr, metric)

    def add(self, *args, **kargs):
        # type: (*Any, **Any) -> None
        """Ex:
        add(net="192.168.1.0/24",gw="1.2.3.4")
        """
        self.invalidate_cache()
        self.routes.append(self.make_route(*args, **kargs))

    def delt(self, *args, **kargs):
        # type: (*Any, **Any) -> None
        """delt(host|net, gw|dev)"""
        self.invalidate_cache()
        route = self.make_route(*args, **kargs)
        try:
            i = self.routes.index(route)
            del(self.routes[i])
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

    def route(self, dst=None, verbose=conf.verb):
        # type: (Optional[str], int) -> Tuple[str, str, str]
        """Returns the IPv4 routes to a host.
        parameters:
         - dst: the IPv4 of the destination host

        returns: (iface, output_ip, gateway_ip)
         - iface: the interface used to connect to the host
         - output_ip: the outgoing IP that will be used
         - gateway_ip: the gateway IP that will be used
        """
        dst = dst or "0.0.0.0"  # Enable route(None) to return default route
        if isinstance(dst, bytes):
            try:
                dst = plain_str(dst)
            except UnicodeDecodeError:
                raise TypeError("Unknown IP address input (bytes)")
        if dst in self.cache:
            return self.cache[dst]
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
            aa = atol(a)
            if aa == atol_dst:
                paths.append(
                    (0xffffffff, 1, (conf.loopback_name, a, "0.0.0.0"))  # noqa: E501
                )
            if (atol_dst & m) == (d & m):
                paths.append((m, me, (i, a, gw)))

        if not paths:
            if verbose:
                warning("No route found (no default route?)")
            return conf.loopback_name, "0.0.0.0", "0.0.0.0"
        # Choose the more specific route
        # Sort by greatest netmask and use metrics as a tie-breaker
        paths.sort(key=lambda x: (-x[0], x[1]))
        # Return interface
        ret = paths[0][2]
        self.cache[dst] = ret
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

# Load everything, update conf.iface
conf.ifaces.reload()
