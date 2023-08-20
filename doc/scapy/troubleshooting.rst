***************
Troubleshooting
***************

FAQ
===

I can't sniff/inject packets in monitor mode.
---------------------------------------------

The use monitor mode varies greatly depending on the platform, reasons are explained on the `Wireshark wiki <https://wiki.wireshark.org/CaptureSetup/WLAN>`_:

    *Unfortunately, changing the 802.11 capture modes is very platform/network adapter/driver/libpcap dependent, and might not be possible at all (Windows is very limited here).*

Here is some guidance on how to properly use monitor mode with Scapy:

- **Using Libpcap (or Npcap)**:
    ``libpcap`` must be called differently by Scapy in order for it to create the sockets in monitor mode. You will need to pass the ``monitor=True`` to any calls that open a socket (``send``, ``sniff``...) or to a Scapy socket that you create yourself (``conf.L2Socket``...)

    **On Windows**, you additionally need to turn on monitor mode on the WiFi card, use::

        # Of course, conf.iface can be replaced by any interfaces accessed through conf.ifaces
        >>> conf.iface.setmonitor(True)

- **Native Linux (with libpcap disabled):**
    You should set the interface in monitor mode on your own. The easiest way to do that is to use ``airmon-ng``::

        $ sudo airmon-ng start wlan0
    
    You can also use::

        $ iw dev wlan0 interface add mon0 type monitor
        $ ifconfig mon0 up

    If you want to enable monitor mode manually, have a look at https://wiki.wireshark.org/CaptureSetup/WLAN#linux

.. warning:: **If you are using Npcap:** please note that Npcap ``npcap-0.9983`` broke the 802.11 support until ``npcap-1.3.0``. Avoid using those versions.

We make our best to make this work, if your adapter works with Wireshark for instance, but not with Scapy, feel free to report an issue.

My TCP connections are reset by Scapy or by my kernel.
------------------------------------------------------
The kernel is not aware of what Scapy is doing behind his back. If Scapy sends a SYN, the target replies with a SYN-ACK and your kernel sees it, it will reply with a RST. To prevent this, use local firewall rules (e.g. NetFilter for Linux). Scapy does not mind about local firewalls.

I can't ping 127.0.0.1 (or ::1). Scapy does not work with 127.0.0.1 (or ::1) on the loopback interface.
-------------------------------------------------------------------------------------------------------

The loopback interface is a very special interface. Packets going through it are not really assembled and disassembled. The kernel routes the packet to its destination while it is still stored an internal structure. What you see with ```tcpdump -i lo``` is only a fake to make you think everything is normal. The kernel is not aware of what Scapy is doing behind his back, so what you see on the loopback interface is also a fake. Except this one did not come from a local structure. Thus the kernel will never receive it.

.. note:: Starting from Scapy > **2.5.0**, Scapy will automatically use ``L3RawSocket`` when necessary when using L3-functions (sr-like) on the loopback interface, when libpcap is not in use.

**On Linux**, in order to speak to local IPv4 applications, you need to build your packets one layer upper, using a PF_INET/SOCK_RAW socket instead of a PF_PACKET/SOCK_RAW (or its equivalent on other systems than Linux)::

    >>> conf.L3socket
    <class __main__.L3PacketSocket at 0xb7bdf5fc>
    >>> conf.L3socket = L3RawSocket
    >>> sr1(IP() / ICMP())
    <IP  version=4L ihl=5L tos=0x0 len=28 id=40953 flags= frag=0L ttl=64 proto=ICMP chksum=0xdce5 src=127.0.0.1 dst=127.0.0.1 options='' |<ICMP  type=echo-reply code=0 chksum=0xffff id=0x0 seq=0x0 |>>

With IPv6, you can simply do::

    # Layer 3
    >>> sr1(IPv6() / ICMPv6EchoRequest())
    <IPv6  version=6 tc=0 fl=866674 plen=8 nh=ICMPv6 hlim=64 src=::1 dst=::1 |<ICMPv6EchoReply  type=Echo Reply code=0 cksum=0x7ebb id=0x0 seq=0x0 |>>

    # Layer 2
    >>> srp1(Ether() / IPv6() / ICMPv6EchoRequest(), iface=conf.loopback_name)
    <Ether  dst=00:00:00:00:00:00 src=00:00:00:00:00:00 type=IPv6 |<IPv6  version=6 tc=0 fl=866674 plen=8 nh=ICMPv6 hlim=64 src=::1 dst=::1 |<ICMPv6EchoReply  type=Echo Reply code=0 cksum=0x7ebb id=0x0 seq=0x0 |>>>

.. warning::
    On Linux, libpcap does not support loopback IPv4 pings:
        >>> conf.use_pcap = True
        >>> sr1(IP() / ICMP())
        Begin emission:
        Finished sending 1 packets.
        .....................................

    You can disable libpcap using ``conf.use_pcap = False`` or bypass it on layer 3 using ``conf.L3socket = L3RawSocket``.

**On Windows, BSD, and macOS**, you must deactivate/configure the local firewall prior to using the following commands::

    # Layer 3
    >>> sr1(IP() / ICMP())
    <IP  version=4L ihl=5L tos=0x0 len=28 id=40953 flags= frag=0L ttl=64 proto=ICMP chksum=0xdce5 src=127.0.0.1 dst=127.0.0.1 options='' |<ICMP  type=echo-reply code=0 chksum=0xffff id=0x0 seq=0x0 |>>
    >>> sr1(IPv6() / ICMPv6EchoRequest())
    <IPv6  version=6 tc=0 fl=866674 plen=8 nh=ICMPv6 hlim=64 src=::1 dst=::1 |<ICMPv6EchoReply  type=Echo Reply code=0 cksum=0x7ebb id=0x0 seq=0x0 |>>

    # Layer 2
    >>> srp1(Loopback() / IP() / ICMP(), iface=conf.loopback_name)
    <Loopback  type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=28 id=56066 flags= frag=0 ttl=64 proto=icmp chksum=0x0 src=127.0.0.1 dst=127.0.0.1 |<ICMP  type=echo-reply code=0 chksum=0xffff id=0x0 seq=0x0 |>>>
    >>> srp1(Loopback() / IPv6() / ICMPv6EchoRequest(), iface=conf.loopback_name)
    <Loopback  type=IPv6 |<IPv6  version=6 tc=0 fl=0 plen=8 nh=ICMPv6 hlim=64 src=::1 dst=::1 |<ICMPv6EchoReply  type=Echo Reply code=0 cksum=0x7ebb id=0x0 seq=0x0 |>>>

Getting 'failed to set hardware filter to promiscuous mode' error
-----------------------------------------------------------------

Disable promiscuous mode::

    conf.sniff_promisc = False

Scapy says there are 'Winpcap/Npcap conflicts'
----------------------------------------------

**On Windows**, as ``Winpcap`` is becoming old, it's recommended to use ``Npcap`` instead. ``Npcap`` is part of the ``Nmap`` project.

.. note::
    This does NOT apply for Windows XP, which isn't supported by ``Npcap``. On XP, uninstall ``Npcap`` and keep ``Winpcap``.

1. If you get the message ``'Winpcap is installed over Npcap.'`` it means that you have installed both Winpcap and Npcap versions, which isn't recommended.

You may first **uninstall winpcap from your Program Files**, then you will need to remove some files that are not deleted by the ``Winpcap`` uninstaller::

    C:/Windows/System32/wpcap.dll
    C:/Windows/System32/Packet.dll

And if you are on an x64 machine, additionally the 32-bit variants::

   C:/Windows/SysWOW64/wpcap.dll
   C:/Windows/SysWOW64/Packet.dll

Once that is done, you'll be able to use ``Npcap`` properly.

2. If you get the message ``'The installed Windump version does not work with Npcap'`` it means that you have probably installed an old version of ``Windump``, made for ``Winpcap``.
Download the one compatible with ``Npcap`` on https://github.com/hsluoyz/WinDump/releases

In some cases, it could also mean that you had installed both ``Npcap`` and ``Winpcap``, and that the Npcap ``Windump`` is using ``Winpcap``. Fully delete ``Winpcap`` using the above method to solve the problem.


BPF filters do not work. I'm on a ppp link
------------------------------------------

This is a known bug. BPF filters must compiled with different offsets on ppp links. It may work if you use libpcap (which will be used to compile the BPF filter) instead of using native linux support (PF_PACKET sockets).

traceroute() does not work. I'm on a ppp link
---------------------------------------------

This is a known bug. See BPF filters do not work. I'm on a ppp link

To work around this, use ``nofilter=1``::

    >>> traceroute("target", nofilter=1)


Graphs are ugly/fonts are too big/image is truncated.
-----------------------------------------------------

Quick fix: use png format::

   >>> x.graph(format="png")
      
Upgrade to latest version of GraphViz.

Try providing different DPI options (50,70,75,96,101,125, for instance)::

   >>> x.graph(options="-Gdpi=70")

If it works, you can make it permanenent::

   >>> conf.prog.dot = "dot -Gdpi=70"

You can also put this line in your ``~/.scapy_startup.py`` file 


Getting help
============

Common problems are answered in the FAQ.

If you need additional help, please check out:

* The `Gitter channel <https://gitter.im/secdev/scapy>`_
* The `GitHub repository <https://github.com/secdev/scapy/>`_

There's also a low traffic mailing list at ``scapy.ml(at)secdev.org``  (`archive <http://news.gmane.org/gmane.comp.security.scapy.general>`_, `RSS, NNTP <http://gmane.org/info.php?group=gmane.comp.security.scapy.general>`_).
Subscribe by sending a mail to ``scapy.ml-subscribe(at)secdev.org``.

You are encouraged to send questions, bug reports, suggestions, ideas, cool usages of Scapy, etc.
