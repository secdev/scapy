*******************
Scapy network stack
*******************

Scapy maintains its own network stack, which is independent from the one of your operating system.
It possesses its own *interfaces list*, *routing table*, *ARP cache*, *IPv6 neighbour* cache, *nameservers* config... and so on, all of which is configurable.

Here are a few examples of where this is used::

- When you use ``sr()/send()``, Scapy will use internally its own routing table (``conf.route``) in order to find which interface to use, and eventually send an ARP request.
- When using ``dns_resolve()``, Scapy uses its own nameservers list (``conf.nameservers``) to perform the request
- etc.

.. note::
    What's important to note is that Scapy initializes its own tables by querying the OS-specific ones.
    It has therefore implemented bindings for Linux/Windows/BSD.. in order to retrieve such data, which may also be used as a high-level API, documented below.


Interfaces list
---------------

Scapy stores its interfaces list in the :py:attr:`conf.ifaces <scapy.interfaces.NetworkInterfaceDict>` object.
It provides a few utility functions such as :py:attr:`dev_from_networkname() <scapy.interfaces.NetworkInterfaceDict.dev_from_networkname>`, :py:attr:`dev_from_name() <scapy.interfaces.NetworkInterfaceDict.dev_from_name>` or :py:attr:`dev_from_index() <scapy.interfaces.NetworkInterfaceDict.dev_from_index>` in order to access those.

.. code-block:: pycon

    >>> conf.ifaces
    Source  Index  Name  MAC                IPv4          IPv6
    sys     1      lo    00:00:00:00:00:00  127.0.0.1     ::1
    sys     2      eth0  Microsof:12:cb:ef  10.0.0.5  fe80::10a:2bef:dc12:afae
    >>> conf.ifaces.dev_from_index(2)
    <NetworkInterface eth0 [UP+BROADCAST+RUNNING+SLAVE]>

You can also use the older ``get_if_list()`` function in order to only get the interface names.

.. code-block:: pycon

    >>> get_if_list()
    ['lo', 'eth0']

Extcap interfaces
~~~~~~~~~~~~~~~~~

Scapy supports sniffing on `Wireshark's extcap <https://www.wireshark.org/docs/man-pages/extcap.html>`_ interfaces. You can simply enable it using ``load_extcap()`` (from ``scapy.libs.extcap``).

.. code-block:: pycon

    >>> load_extcap()
    >>> conf.ifaces
    Source       Index  Name                                     Address
    ciscodump    100    Cisco remote capture                     ciscodump
    dpauxmon     100    DisplayPort AUX channel monitor capture  dpauxmon
    randpktdump  100    Random packet generator                  randpkt
    sdjournal    100    systemd Journal Export                   sdjournal
    sshdump      100    SSH remote capture                       sshdump
    udpdump      100    UDP Listener remote capture              udpdump
    wifidump     100    Wi-Fi remote capture                     wifidump
    Source  Index  Name  MAC                IPv4          IPv6
    sys     1      lo    00:00:00:00:00:00  127.0.0.1     ::1
    sys     2      eth0  Microsof:12:cb:ef  10.0.0.5  fe80::10a:2bef:dc12:afae


Here's an example of how to use `sshdump <https://www.wireshark.org/docs/man-pages/sshdump.html>`_. As you can see you can pass arguments that are properly converted:

.. code-block:: pycon

    >>> load_extcap()
    >>> sniff(
    ...     iface="sshdump",
    ...     prn=lambda x: x.summary(),
    ...     remote_host="192.168.0.1",
    ...     remote_username="root",
    ...     remote_password="SCAPY",
    ... )


You can check the available options by using the following.

.. code-block:: python

    >>> conf.ifaces.dev_from_networkname("sshdump").get_extcap_config()

.. todo:: The sections below can be greatly improved.

IPv4 routes
-----------

.. note::
    If you want to change or edit the routes, have a look at `the "Routing" section in Usage <usage.html#routing>`_

The routes are stores in :py:attr:`conf.route <scapy.route.Route>`. You can use it to display the routes, or get specific routing

.. code-block:: pycon

    >>> conf.route

    Network          Netmask          Gateway   Iface  Output IP  Metric
    0.0.0.0          0.0.0.0          10.0.0.1  eth0   10.0.0.5   100
    10.0.0.0         255.255.255.0    0.0.0.0   eth0   10.0.0.5   0
    127.0.0.0        255.0.0.0        0.0.0.0   lo     127.0.0.1  1
    168.63.129.16    255.255.255.255  10.0.0.1  eth0   10.0.0.5   100
    169.254.169.254  255.255.255.255  10.0.0.1  eth0   10.0.0.5   100

Get the route for a specific IP:  :py:func:`conf.route.route() <scapy.route.Route.route>` will return ``(interface, outgoing_ip, gateway)``

.. code-block:: pycon

    >>> conf.route.route("127.0.0.1")
    ('lo', '127.0.0.1', '0.0.0.0')

IPv6 routes
-----------

Same as IPv4 but with :py:attr:`conf.route6 <scapy.route6.Route6>`

Get default gateway IP address
------------------------------

.. code-block:: pycon

    >>> gw = conf.route.route("0.0.0.0")[2]
    >>> gw
    '10.0.0.1'

Get the IP of an interface
--------------------------

Use ``conf.iface``

.. code-block:: pycon

    >>> ip = get_if_addr(conf.iface)  # default interface
    >>> ip = get_if_addr("eth0")
    >>> ip
    '10.0.0.5'

Get the MAC of an interface
---------------------------

.. code-block:: pycon

    >>> mac = get_if_hwaddr(conf.iface)  # default interface
    >>> mac = get_if_hwaddr("eth0")
    >>> mac
    '54:3f:19:c9:38:6d'

Get MAC address of the next hop to reach an IP
----------------------------------------------

This basically performs a cached ARP who-has when the IP is on the same local link,
returns the MAC of the gateway when it's not, and handle special cases like multicast.

.. code-block:: pycon

    >>> mac = getmacbyip("10.0.0.1")
    >>> mac
    'f3:ae:5e:76:31:9b'

