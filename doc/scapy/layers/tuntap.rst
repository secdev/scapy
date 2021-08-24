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
    macOS includes a ``utun`` driver in macOS 10.6.4 and later, which *only*
    provides a TUN (Layer 3) interface. This is the *only* option for Macs
    with Apple Silicon (M1), and this will eventually be the *only* option for
    *all* Macs in a future version of macOS.

    The ``utun`` driver should work when running Scapy as ``root``, just use
    ``TunTapInterface('utun2')``. This requires Python 3.3 or later.

    Scapy also supports `tuntaposx`__, which is an unmaintained, third-party
    kernel extension (for Intel and PPC only) which provides a TAP and TUN
    interface. On macOS 10.15 and later, you need to install a `notarized`__
    build, which `can be extracted`__ from `Tunnelblick`__ (an OpenVPN client).

    macOS 10.15.4 and later `report that tuntaposx uses deprecated APIs`__, and
    this is expected to break in a future version of macOS.

    .. note::

        On macOS 10.13 and later, you need to `explicitly approve loading
        each third-party kext for the first time`__.

__ https://www.freebsd.org/cgi/man.cgi?query=tap&sektion=4
__ https://www.freebsd.org/cgi/man.cgi?query=tun&sektion=4
__ https://www.kernel.org/doc/Documentation/networking/tuntap.txt
__ http://tuntaposx.sourceforge.net/
__ https://developer.apple.com/documentation/security/notarizing_your_app_before_distribution?language=objc
__ https://sourceforge.net/p/tuntaposx/bugs/28/#ac64
__ https://tunnelblick.net/downloads.html
__ https://developer.apple.com/support/kernel-extensions/
__ https://developer.apple.com/library/archive/technotes/tn2459/_index.html


Using TUN/TAP in Scapy
======================

.. tip::

    Using TUN/TAP generally requires running Scapy (and these utilities) as
    ``root``.

:py:class:`TunTapInterface` lets you easily create a new device. On BSD and Linux, use:

.. code-block:: pycon3

    >>> t = TunTapInterface('tun0')

Or on macOS:

.. code-block:: pycon3

    >>> t = TunTapInterface('utun2')

.. note::

    You might need to pick a higher interface number (like ``tun1``) if you
    have other software on your computer using ``tun0``, such as a VPN.

    On macOS, ``utun0`` and ``utun1`` are normally already in use by other
    system software.

    The remainder of this tutorial presumes you're using ``tun0`` or ``utun2``.

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

On BSD, use:

.. code-block:: shell

    sudo ifconfig tun0 up
    sudo ifconfig tun0 192.0.2.1 192.0.2.2

On macOS, use:

.. code-block:: shell

    sudo ifconfig utun2 up
    sudo ifconfig utun2 192.0.2.1 192.0.2.2

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

When you close Scapy, the ``tun0`` / ``utun2`` interface will automatically
disappear.

TunTapInterface reference
=========================

.. py:class:: TunTapInterface(SimpleSocket)

    A socket to act as the remote side of a TUN/TAP interface.

    .. py:method:: __init__(iface: Text, [mode_tun], [strip_packet_info = True], [default_read_size = MTU])

        :param Text iface:
            The name of the interface to use, eg: ``tun0``, ``tap0``, ``utun2``.

            On BSD and macOS (with ``tuntaposx``), this must start with either
            ``tun`` or ``tap``, and have a corresponding :file:`/dev/` node
            (eg: :file:`/dev/tun0`).

            macOS 10.6.4 and later also provide a ``utun`` interface, with no
            additional driver required. This acts as the same as a TUN device.

            On Linux, this will be truncated to 16 bytes.

        :param bool mode_tun:
            If True, create as TUN interface (layer 3). If False, creates a TAP
            interface (layer 2).

            If not supplied, attempts to detect from the ``iface`` parameter.

        :param bool strip_packet_info:
            If True (default), any :py:class:`TunPacketInfo` will be stripped
            from the packet (so you get :py:class:`Ether` or :py:class:`IP`).

            Only Linux TUN and macOS ``utun`` interfaces have
            :py:class:`TunPacketInfo` available.

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
