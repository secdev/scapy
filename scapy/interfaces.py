# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Interfaces management
"""

from collections import defaultdict

import scapy
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.utils import pretty_list

from scapy.modules.six.moves import UserDict
import scapy.modules.six as six


class InterfaceProvider(object):
    name = "Unknown"

    def load(self):
        """Returns a dictionary of the loaded interfaces, by their
        name."""
        raise Exception("load() should be implemented !")

    def l2socket(self):
        """Return L2 socket used by interfaces of this provider"""
        return conf.L2socket

    def l2listen(self):
        """Return L2listen socket used by interfaces of this provider"""
        return conf.L2listen

    def l3socket(self):
        """Return L3 socket used by interfaces of this provider"""
        return conf.L3socket


class NetworkInterface(object):
    def __init__(self, provider, data=None):
        self.provider = provider
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
        self.ip = data.get('ip', None) or ""
        self.mac = data.get('mac', None) or ""
        self.invalid = data.get('invalid', False)

    def is_invalid(self):
        return self.invalid

    def l2socket(self):
        return self.provider.l2socket()

    def l2listen(self):
        return self.provider.l2listen()

    def l3socket(self):
        return self.provider.l3socket()

    def __repr__(self):
        return "<%s [%s] %s>" % (self.__class__.__name__,
                                 self.description,
                                 self.network_name)


class NetworkInterfaceDict(UserDict):
    """Store information about network interfaces and convert between names"""

    def __init__(self):
        self.providers = {}
        UserDict.__init__(self)

    def _load(self, dat):
        self.data.update(dat)

    def _reload_loopback(self):
        # Replace LOOPBACK_INTERFACE
        try:
            scapy.consts.LOOPBACK_INTERFACE = self.dev_from_name(
                scapy.consts.LOOPBACK_NAME,
            )
        except ValueError:
            pass

    def register_provider(self, provider):
        prov = provider()
        self.providers[provider] = prov
        self._load(prov.load())
        self._reload_loopback()

    def reload(self):
        self.clear()
        for prov in self.providers.values():
            self._load(prov.load())
        # Reload conf.iface
        conf.iface = get_working_if()
        self._reload_loopback()

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
                if isinstance(scapy.consts.LOOPBACK_INTERFACE, NetworkInterface):  # noqa: E501
                    return scapy.consts.LOOPBACK_INTERFACE
            raise ValueError("Unknown network interface index %r" % if_index)

    def _add_fake_iface(self, ifname):
        """Internal function used for a testing purpose"""
        data = {
            'name': ifname,
            'description': ifname,
            'network_name': ifname,
            'index': -1,
            'invalid': True,
            'mac': '00:00:00:00:00:00',
            # Windows only
            'guid': "{0XX00000-X000-0X0X-X00X-00XXXX000XXX}",
            'ipv4_metric': 0,
            'ipv6_metric': 0,
            'ips': ["127.0.0.1", "::"]
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

    def show(self, resolve_mac=True, print_result=True):
        """Print list of available network interfaces in human readable form"""
        res = defaultdict(list)
        for iface_name in sorted(self.data):
            dev = self.data[iface_name]
            mac = dev.mac
            if resolve_mac and conf.manufdb:
                mac = conf.manufdb._resolve_MAC(mac)
            validity_color = lambda x: conf.color_theme.red if x else \
                conf.color_theme.green
            description = validity_color(dev.is_invalid())(
                str(dev.description)
            )
            index = str(dev.index)
            res[dev.provider].append((index, description, str(dev.ip), mac))

        output = ""
        for provider in res:
            output += "\n### %s ###\n" % provider.name
            output += pretty_list(res[provider],
                                  [("INDEX", "IFACE", "IP", "MAC")], sortBy=2)
        output = output[1:]
        if print_result:
            print(output)
        else:
            return output

    def __repr__(self):
        return self.show(print_result=False)


IFACES = ifaces = NetworkInterfaceDict()


def get_working_if():
    """Return an interface that works"""
    try:
        # return the interface associated with the route with smallest
        # mask (route by default if it exists)
        iface = min(conf.route.routes, key=lambda x: x[1])[3]
    except ValueError:
        # no route
        iface = scapy.consts.LOOPBACK_INTERFACE
    iface = resolve_iface(iface)
    if iface and iface.is_invalid():
        # Backup mode: try them all
        for iface in six.itervalues(IFACES):
            if not iface.is_invalid():
                return iface
        return None
    return iface


def dev_from_networkname(network_name):
    """Return Scapy device name for given network device name"""
    return IFACES.dev_from_networkname(network_name)


def dev_from_index(if_index):
    """Return interface for a given interface index"""
    return IFACES.dev_from_index(if_index)


def resolve_iface(dev, _internal=False):
    """Resolve an interface name into the interface"""
    if isinstance(dev, NetworkInterface):
        return dev
    try:
        return IFACES.dev_from_name(dev)
    except ValueError:
        try:
            return IFACES.dev_from_networkname(dev)
        except ValueError:
            if _internal:
                raise
            IFACES.reload()
            return resolve_iface(dev, _internal=True)


def network_name(dev):
    """Get the device network name of a device or Scapy NetworkInterface
    """
    dev = resolve_iface(dev)
    if dev:
        return dev.network_name


def show_interfaces(resolve_mac=True):
    """Print list of available network interfaces"""
    return IFACES.show(resolve_mac)
