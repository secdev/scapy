********************
TUN / TAP Interfaces
********************

.. note::

    This module only works on BSD, Linux and macOS.

TUN/TAP lets you create virtual network interfaces from userspace. There are two
types of devices:

TUN devices
    Operates at Layer 3 (:py:class:`IP`), and is generally limited to one
    protocol.

TAP devices
    Operates at Layer 2 (:py:class:`Ether`), and allows you to use any Layer 3
    protocol (:py:class:`IP`, :py:class:`IPv6`, IPX, etc.)

Requirements
============

FreeBSD
    Requires the ``if_tap`` and ``if_tun`` kernel modules.

    See `tap(4)`__ and `tun(4)`__ manual pages for more information.

Linux
    Load the ``tun`` kernel module:

    .. code-block:: console

        # modprobe tun

    ``udev`` normally handles the creation of device nodes.

    See `networking/tuntap.txt`__ in the Linux kernel documentation for more
    information.

macOS
    On macOS 10.14 and earlier, you need to install `tuntaposx`__. macOS
    10.14.5 and later will warn about the ``tuntaposx`` kexts not being
    `notarised`__, but this works because it was built before 2019-04-07.

    On macOS 10.15 and later, you need to use a `notarized build`__ of
    ``tuntaposx``. `Tunnelblick`__ (OpenVPN client) contains a notarized build
    of ``tuntaposx`` `which can be extracted`__.

    .. note::

        On macOS 10.13 and later, you need to `explicitly approve loading
        each third-party kext for the first time`__.

__ https://www.freebsd.org/cgi/man.cgi?query=tap&sektion=4
__ https://www.freebsd.org/cgi/man.cgi?query=tun&sektion=4
__ https://www.kernel.org/doc/Documentation/networking/tuntap.txt
__ http://tuntaposx.sourceforge.net/
__ https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution?language=objc
__ https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution?language=objc
__ https://tunnelblick.net/downloads.html
__ https://sourceforge.net/p/tuntaposx/bugs/28/#ac64
__ https://developer.apple.com/library/archive/technotes/tn2459/_index.html


Using TUN/TAP in Scapy
======================

.. tip::

    Using TUN/TAP generally requires running Scapy (and these utilities) as
    ``root``.

:py:class:`TunTapInterface` lets you easily create a new device:

.. code-block:: pycon3

    >>> t = TunTapInterface('tun0')

You'll then need to bring the interface up, and assign an IP address in another
terminal.

Because TUN is a layer 3 connection, it acts as a point-to-point link.  We'll
assign these parameters:

* local address (for your machine): 192.0.2.1
* remote address (for Scapy): 192.0.2.2

On Linux, you would use:

.. code-block:: shell

    sudo ip link set tun0 up
    sudo ip addr add 192.0.2.1 peer 192.0.2.2 dev tun0

On BSD and macOS, use:

.. code-block:: shell

    sudo ifconfig tun0 up
    sudo ifconfig tun0 192.0.2.1 192.0.2.2

Now, nothing will happen when you ping those addresses -- you'll need to make
Scapy respond to that traffic.

:py:class:`TunTapInterface` works the same as a :py:class:`SuperSocket`, so lets
setup an :py:class:`AnsweringMachine` to respond to :py:class:`ICMP`
``echo-request``:

.. code-block:: pycon3

    >>> am = t.am(ICMPEcho_am)
    >>> am()

Now, you can ping Scapy in another terminal:

.. code-block: console:

    $ ping -c 3 192.0.2.2
    PING 192.0.2.2 (192.0.2.2): 56 data bytes
    64 bytes from 192.0.2.2: icmp_seq=0 ttl=64 time=2.414 ms
    64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=3.927 ms
    64 bytes from 192.0.2.2: icmp_seq=2 ttl=64 time=5.740 ms

    --- 192.0.2.2 ping statistics ---
    3 packets transmitted, 3 packets received, 0.0% packet loss
    round-trip min/avg/max/stddev = 2.414/4.027/5.740/1.360 ms

You should see those packets show up in Scapy:

.. code-block:: pycon3

    >>> am()
    Replying 192.0.2.1 to 192.0.2.2
    Replying 192.0.2.1 to 192.0.2.2
    Replying 192.0.2.1 to 192.0.2.2

You might have noticed that didn't configure Scapy with any IP address... and
there's a trick to this: :py:class:`ICMPEcho_am` swaps the ``source`` and
``destination`` fields of any :py:class:`Ether` and :py:class:`IP` headers on
the :py:class:`ICMP` packet that it receives. As a result, it actually responds
to *any* IP address.

You can stop the :py:class:`ICMPEcho_am` AnsweringMachine with :kbd:`^C`.

When you close Scapy, the ``tun0`` interface will automatically disappear.

TunTapInterface reference
=========================

.. py:class:: TunTapInterface(SimpleSocket)

    A socket to act as the remote side of a TUN/TAP interface.

    .. py:method:: __init__(iface: Text, [mode_tun], [strip_packet_info = True], [default_read_size = MTU])

        :param Text iface:
            The name of the interface to use, eg: ``tun0``.

            On BSD and macOS, this must start with either ``tun`` or ``tap``,
            and have a corresponding :file:`/dev/` node (eg: :file:`/dev/tun0`).

            On Linux, this will be truncated to 16 bytes.

        :param bool mode_tun:
            If True, create as TUN interface (layer 3). If False, creates a TAP
            interface (layer 2).

            If not supplied, attempts to detect from the ``iface`` parameter.

        :param bool strip_packet_info:
            If True (default), any :py:class:`TunPacketInfo` will be stripped
            from the packet (so you get :py:class:`Ether` or :py:class:`IP`).

            Only Linux TUN interfaces have :py:class:`TunPacketInfo` available.

            This has no effect for interfaces that do not have
            :py:class:`TunPacketInfo` available.

        :param int default_read_size:
            Sets the default size that is read by
            :py:meth:`SuperSocket.raw_recv` and :py:meth:`SuperSocket.recv`.
            This defaults to :py:data:`scapy.data.MTU`.

            :py:class:`TunTapInterface` always adds overhead for
            :py:class:`TunPacketInfo` headers, if required.

.. py:class:: TunPacketInfo(Packet)

    Abstract class used to stack layer 3 protocols on a platform-specific
    header.

    See :py:class:`LinuxTunPacketInfo` for an example.

    .. py:method:: guess_payload_class(payload)

        The default implementation expects the field ``proto`` to be declared,
        with a value from :py:data:`scapy.data.ETHER_TYPES`.

Linux-specific structures
-------------------------

.. py:class:: LinuxTunPacketInfo(TunPacketInfo)

    Packet header used for Linux TUN packets.

    This is ``struct tun_pi``, declared in :file:`linux/if_tun.h`.

    .. py:attribute:: flags

        Flags to set on the packet. Only ``TUN_VNET_HDR`` is supported.

    .. py:attribute:: proto

        Layer 3 protocol number, per :py:data:`scapy.data.ETHER_TYPES`.

        Used by :py:meth:`TunTapPacketInfo.guess_payload_class`.

.. py:class:: LinuxTunIfReq(Packet)

    Internal "packet" used for ``TUNSETIFF`` requests on Linux.

    This is ``struct ifreq``, declared in :file:`linux/if.h`.
