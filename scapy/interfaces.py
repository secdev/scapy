# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Interfaces management
"""

import uuid
from collections import defaultdict

from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.utils import pretty_list

from scapy.modules.six.moves import UserDict
import scapy.modules.six as six


class InterfaceProvider(object):
    name = "Unknown"
    headers = ("INDEX", "IFACE", "IPv4", "IPv6", "MAC")

    def load(self):
        """Returns a dictionary of the loaded interfaces, by their
        name."""
        raise Exception("load() should be implemented !")

    def reload(self):
        """Same than load() but for reloads"""
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
        return dev.valid

    def _format(self, dev, **kwargs):
        """Returns a tuple of the elements used by show()"""
        mac = dev.mac
        resolve_mac = kwargs.get("resolve_mac", True)
        if resolve_mac and conf.manufdb:
            mac = conf.manufdb._resolve_MAC(mac)
        index = str(dev.index)
        return (index, dev.description, str(dev.ip), str(dev.ip6), mac)


class NetworkInterface(object):
    def __init__(self, provider, data=None):
        self.provider = provider
        self.name = ""
        self.description = ""
        self.network_name = ""
        self.index = -1
        self.ip = None
        self.ip6 = None
        self.ips = []
        self.mac = None
        self.valid = True
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
        self.ips = data.get('ips', [])
        self.mac = data.get('mac', "")
        self.flags = data.get('flags', 0)
        self.valid = data.get('valid', True)

        # Backup to chose main IPs
        if self.ips:
            try:
                self.ip = next(x for x in self.ips if ":" not in x)
            except StopIteration:
                pass
            try:
                self.ip6 = next(x for x in self.ips if ":" in x)
            except StopIteration:
                pass
            if not self.ip and not self.ip6:
                self.valid = False

    def __eq__(self, other):
        if isinstance(other, str):
            return self.name == other or self.network_name == other
        if isinstance(other, NetworkInterface):
            return self.__dict__ == other.__dict__
        return object.__eq__(self, other)

    def __hash__(self):
        return hash(self.network_name)

    def is_valid(self):
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
                                 self.flags or "")

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

    def _load(self, dat):
        self.data.update(dat)

    def register_provider(self, provider):
        prov = provider()
        self.providers[provider] = prov
        self._load(prov.load())

    def reload(self):
        self.clear()
        for prov in self.providers.values():
            self._load(prov.load())
        # Reload conf.iface
        conf.iface = get_working_if()

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
                return conf.loopback_name
            raise ValueError("Unknown network interface index %r" % if_index)

    def _add_fake_iface(self, ifname):
        """Internal function used for a testing purpose"""
        data = {
            'name': ifname,
            'description': ifname,
            'network_name': ifname,
            'index': -1,
            'valid': False,
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
            self.data[ifname] = NetworkInterface_Win(
                WindowsInterfacesProvider(),
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
            output = pretty_list(
                res[provider],
                [("SRC",) + provider.headers],
                sortBy=3
            )
        if print_result:
            print(output)
        else:
            return output

    def __repr__(self):
        return self.show(print_result=False)


conf.ifaces = IFACES = ifaces = NetworkInterfaceDict()


def get_working_if():
    """Return an interface that works"""
    try:
        # return the interface associated with the route with smallest
        # mask (route by default if it exists)
        routes = conf.route.routes[:]
        routes.sort(key=lambda x: x[1])
        ifaces = (x[3] for x in routes)
    except ValueError:
        # no route
        ifaces = [conf.loopback_name]
    for iface in ifaces:
        iface = resolve_iface(iface)
        if iface and iface.is_valid():
            return iface
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
        data={"name": dev, "network_name": dev}
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
