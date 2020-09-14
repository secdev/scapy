# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Interfaces management
"""

import itertools
import uuid
from collections import defaultdict

from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.utils import pretty_list
from scapy.utils6 import in6_isvalid

from scapy.modules.six.moves import UserDict
import scapy.modules.six as six


class InterfaceProvider(object):
    name = "Unknown"
    headers = ("Index", "Name", "MAC", "IPv4", "IPv6")
    header_sort = 4
    libpcap = False

    def load(self):
        """Returns a dictionary of the loaded interfaces, by their
        name."""
        raise NotImplementedError

    def reload(self):
        """Same than load() but for reloads. By default calls load"""
        return self.load()

    def l2socket(self):
        """Return L2 socket used by interfaces of this provider"""
        return conf.L2socket

    def l2listen(self):
        """Return L2listen socket used by interfaces of this provider"""
        return conf.L2listen

    def l3socket(self):
        """Return L3 socket used by interfaces of this provider"""
        return conf.L3socket

    def _is_valid(self, dev):
        """Returns whether an interface is valid or not"""
        return bool((self.ip or self.ip6) and self.mac)

    def _format(self, dev, **kwargs):
        """Returns the elements used by show()

        If a tuple is returned, this consist of the strings that will be
        inlined along with the interface.
        If a list of tuples is returned, they will be appended one above the
        other and should all be part of a single interface.
        """
        mac = dev.mac
        resolve_mac = kwargs.get("resolve_mac", True)
        if resolve_mac and conf.manufdb:
            mac = conf.manufdb._resolve_MAC(mac)
        index = str(dev.index)
        return (index, dev.description, mac, dev.ips[4], dev.ips[6])


class NetworkInterface(object):
    def __init__(self, provider, data=None):
        self.provider = provider
        self.name = ""
        self.description = ""
        self.network_name = ""
        self.index = -1
        self.ip = None
        self.ip6 = None
        self.ips = defaultdict(list)
        self.mac = None
        self.dummy = False
        if data is not None:
            self.update(data)

    def update(self, data):
        """Update info about a network interface according
        to a given dictionary. Such data is provided by providers
        """
        self.name = data.get('name', "")
        self.description = data.get('description', "")
        self.network_name = data.get('network_name', "")
        self.index = data.get('index', 0)
        self.ip = data.get('ip', "")
        self.ip6 = data.get('ip6', "")
        self.mac = data.get('mac', "")
        self.flags = data.get('flags', 0)
        self.dummy = data.get('dummy', False)

        for ip in data.get('ips', []):
            if in6_isvalid(ip):
                self.ips[6].append(ip)
            else:
                self.ips[4].append(ip)

        # An interface may have multiple IPv4 or IPv6
        # "ip" and "ip6" should contain the "main" one
        if self.ips[4] and not self.ip:
            self.ip = self.ips[4][0]
        if self.ips[6] and not self.ip6:
            # TODO XXX
            # What should we consider the main IPv6 ? @guedou
            self.ip6 = self.ips[6][0]

    def __eq__(self, other):
        if isinstance(other, str):
            return other in [self.name, self.network_name, self.description]
        if isinstance(other, NetworkInterface):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.network_name)

    def is_valid(self):
        if self.dummy:
            return False
        return self.provider._is_valid(self)

    def l2socket(self):
        return self.provider.l2socket()

    def l2listen(self):
        return self.provider.l2listen()

    def l3socket(self):
        return self.provider.l3socket()

    def __repr__(self):
        return "<%s %s [%s]>" % (self.__class__.__name__,
                                 self.description,
                                 self.dummy and "dummy" or (self.flags or ""))

    def __str__(self):
        return self.network_name

    def __add__(self, other):
        return self.network_name + other

    def __radd__(self, other):
        return other + self.network_name


class NetworkInterfaceDict(UserDict):
    """Store information about network interfaces and convert between names"""

    def __init__(self):
        self.providers = {}
        UserDict.__init__(self)

    def _load(self, dat, prov):
        for ifname, iface in six.iteritems(dat):
            if ifname in self.data:
                # Handle priorities: keep except if libpcap
                if prov.libpcap:
                    self.data[ifname] = iface
            else:
                self.data[ifname] = iface

    def register_provider(self, provider):
        prov = provider()
        self.providers[provider] = prov

    def load_confiface(self):
        """
        Reload conf.iface
        """
        # Can only be called after conf.route is populated
        if not conf.route:
            raise ValueError("Error: conf.route isn't populated !")
        iface = conf.route.route(verbose=0)[0]
        if iface == conf.loopback_name:
            conf.iface = get_working_if()
        else:
            conf.iface = resolve_iface(iface)
            if not conf.iface.is_valid():
                conf.iface = get_working_if()

    def _reload_provs(self):
        self.clear()
        for prov in self.providers.values():
            self._load(prov.reload(), prov)

    def reload(self):
        self._reload_provs()
        if conf.route:
            self.load_confiface()

    def dev_from_name(self, name):
        """Return the first network device name for a given
        device name.
        """
        try:
            return next(iface for iface in six.itervalues(self)
                        if (iface.name == name or iface.description == name))
        except (StopIteration, RuntimeError):
            raise ValueError("Unknown network interface %r" % name)

    def dev_from_networkname(self, network_name):
        """Return interface for a given network device name."""
        try:
            return next(iface for iface in six.itervalues(self)
                        if iface.network_name == network_name)
        except (StopIteration, RuntimeError):
            raise ValueError(
                "Unknown network interface %r" %
                network_name)

    def dev_from_index(self, if_index):
        """Return interface name from interface index"""
        try:
            if_index = int(if_index)  # Backward compatibility
            return next(iface for iface in six.itervalues(self)
                        if iface.index == if_index)
        except (StopIteration, RuntimeError):
            if str(if_index) == "1":
                # Test if the loopback interface is set up
                return self.dev_from_networkname(conf.loopback_name)
            raise ValueError("Unknown network interface index %r" % if_index)

    def _add_fake_iface(self, ifname):
        """Internal function used for a testing purpose"""
        data = {
            'name': ifname,
            'description': ifname,
            'network_name': ifname,
            'index': -1000,
            'dummy': True,
            'mac': '00:00:00:00:00:00',
            'flags': 0,
            'ips': ["127.0.0.1", "::"],
            # Windows only
            'guid': "{%s}" % uuid.uuid1(),
            'ipv4_metric': 0,
            'ipv6_metric': 0,
        }
        if WINDOWS:
            from scapy.arch.windows import NetworkInterface_Win, \
                WindowsInterfacesProvider

            class FakeProv(WindowsInterfacesProvider):
                name = "fake"

            self.data[ifname] = NetworkInterface_Win(
                FakeProv(),
                data
            )
        else:
            self.data[ifname] = NetworkInterface(InterfaceProvider(), data)

    def show(self, print_result=True, **kwargs):
        """
        Print list of available network interfaces in human readable form
        """
        res = defaultdict(list)
        for iface_name in sorted(self.data):
            dev = self.data[iface_name]
            prov = dev.provider
            res[prov].append(
                (prov.name,) + prov._format(dev, **kwargs)
            )
        output = ""
        for provider in res:
            output += pretty_list(
                res[provider],
                [("Source",) + provider.headers],
                sortBy=provider.header_sort
            ) + "\n"
        output = output[:-1]
        if print_result:
            print(output)
        else:
            return output

    def __repr__(self):
        return self.show(print_result=False)


conf.ifaces = IFACES = ifaces = NetworkInterfaceDict()


def get_if_list():
    """Return a list of interface names"""
    return list(conf.ifaces.keys())


def get_working_if():
    """Return an interface that works"""
    # return the interface associated with the route with smallest
    # mask (route by default if it exists)
    routes = conf.route.routes[:]
    routes.sort(key=lambda x: x[1])
    ifaces = (x[3] for x in routes)
    # First check the routing ifaces from best to worse,
    # then check all the available ifaces as backup.
    for iface in itertools.chain(ifaces, conf.ifaces.values()):
        iface = resolve_iface(iface)
        if iface and iface.is_valid():
            return iface
    # There is no hope left
    return conf.loopback_name


def dev_from_networkname(network_name):
    """Return Scapy device name for given network device name"""
    return conf.ifaces.dev_from_networkname(network_name)


def dev_from_index(if_index):
    """Return interface for a given interface index"""
    return conf.ifaces.dev_from_index(if_index)


def resolve_iface(dev):
    """
    Resolve an interface name into the interface
    """
    if isinstance(dev, NetworkInterface):
        return dev
    try:
        return conf.ifaces.dev_from_name(dev)
    except ValueError:
        try:
            return dev_from_networkname(dev)
        except ValueError:
            pass
    # Return a dummy interface
    return NetworkInterface(
        InterfaceProvider(),
        data={
            "name": dev,
            "description": dev,
            "network_name": dev,
            "dummy": True
        }
    )


def network_name(dev):
    """
    Resolves the device network name of a device or Scapy NetworkInterface
    """
    iface = resolve_iface(dev)
    if iface:
        return iface.network_name
    return dev


def show_interfaces(resolve_mac=True):
    """Print list of available network interfaces"""
    return conf.ifaces.show(resolve_mac)
