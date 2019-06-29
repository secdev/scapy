*************
Scapy routing
*************

Scapy needs to know many things related to the network configuration of your machine, to be able to route packets properly. For instance, the interface list, the IPv4 and IPv6 routes...

This means that Scapy has implemented bindings to get this information. Those bindings are OS specific. This will show you how to use it for a different usage.

.. note::
    Scapy will have OS-specific functions underlying some high level functions. This page ONLY presents the cross platform ones


List interfaces
---------------

Use ``get_if_list()`` to get the interface list

.. code-block:: pycon

    >>> get_if_list()
    ['lo', 'eth0']

You can also use the :py:attr:`conf.ifaces <scapy.interfaces.NetworkInterfaceDict>` object to get interfaces.
In this example, the object is first displayed as as column. Then, the :py:attr:`dev_from_index() <scapy.interfaces.NetworkInterfaceDict.dev_from_index>` is used to access the interface at index 2.

.. code-block:: pycon

    >>> conf.ifaces
    SRC  INDEX  IFACE  IPv4       IPv6                      MAC
    sys  2      eth0   10.0.0.5   fe80::10a:2bef:dc12:afae  Microsof:12:cb:ef
    sys  1      lo     127.0.0.1  ::1                       00:00:00:00:00:00
    >>> conf.ifaces.dev_from_index(2)
    <NetworkInterface eth0 [UP+BROADCAST+RUNNING+SLAVE]>

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

Same than IPv4 but with :py:attr:`conf.route6 <scapy.route6.Route6>`

Get router IP address
---------------------

.. code-block:: pycon

    >>> gw = conf.route.route("0.0.0.0")[2]
    >>> gw
    '10.0.0.1'

Get local IP / IP of an interface
---------------------------------

Use ``conf.iface``

.. code-block:: pycon

    >>> ip = get_if_addr(conf.iface)  # default interface
    >>> ip = get_if_addr("eth0")
    >>> ip
    '10.0.0.5'

Get local MAC / MAC of an interface
-----------------------------------

.. code-block:: pycon

    >>> mac = get_if_hwaddr(conf.iface)  # default interface
    >>> mac = get_if_hwaddr("eth0")
    >>> mac
    '54:3f:19:c9:38:6d'

Get MAC by IP
-------------

.. code-block:: pycon

    >>> mac = getmacbyip("10.0.0.1")
    >>> mac
    'f3:ae:5e:76:31:9b'

