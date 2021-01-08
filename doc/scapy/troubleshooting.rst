***************
Troubleshooting
***************

FAQ
===

I can't sniff/inject packets in monitor mode.
---------------------------------------------

The use monitor mode varies greatly depending on the platform.

- **Windows or *BSD or conf.use_pcap = True**
  ``libpcap`` must be called differently by Scapy in order for it to create the sockets in monitor mode. You will need to pass the ``monitor=True`` to any calls that open a socket (``send``, ``sniff``...) or to a Scapy socket that you create yourself (``conf.L2Socket``...)
- **Native Linux (with pcap disabled):**
  You should set the interface in monitor mode on your own. Scapy provides utilitary functions: ``set_iface_monitor`` and ``get_iface_mode`` (linux only), that may be used (they do system calls to ``iwconfig`` and will restart the adapter).

**If you are using Npcap:** please note that Npcap ``npcap-0.9983`` broke the 802.11 util back in 2019. It has yet to be fixed (as of Npcap 0.9994) so in the meantime, use `npcap-0.9982.exe <https://nmap.org/npcap/dist/npcap-0.9982.exe>`_

.. note:: many adapters do not support monitor mode, especially on Windows, or may incorrectly report the headers. See `the Wireshark doc about this <https://wiki.wireshark.org/CaptureSetup/WLAN>`_

We make our best to make this work, if your adapter works with Wireshark for instance, but not with Scapy, feel free to report an issue.

My TCP connections are reset by Scapy or by my kernel.
------------------------------------------------------
The kernel is not aware of what Scapy is doing behind his back. If Scapy sends a SYN, the target replies with a SYN-ACK and your kernel sees it, it will reply with a RST. To prevent this, use local firewall rules (e.g. NetFilter for Linux). Scapy does not mind about local firewalls.

I can't ping 127.0.0.1. Scapy does not work with 127.0.0.1 or on the loopback interface 
---------------------------------------------------------------------------------------

The loopback interface is a very special interface. Packets going through it are not really assembled and disassembled. The kernel routes the packet to its destination while it is still stored an internal structure. What you see with tcpdump -i lo is only a fake to make you think everything is normal. The kernel is not aware of what Scapy is doing behind his back, so what you see on the loopback interface is also a fake. Except this one did not come from a local structure. Thus the kernel will never receive it.

In order to speak to local applications, you need to build your packets one layer upper, using a PF_INET/SOCK_RAW socket instead of a PF_PACKET/SOCK_RAW (or its equivalent on other systems than Linux)::

    >>> conf.L3socket
    <class __main__.L3PacketSocket at 0xb7bdf5fc>
    >>> conf.L3socket=L3RawSocket
    >>> sr1(IP(dst="127.0.0.1")/ICMP())
    <IP  version=4L ihl=5L tos=0x0 len=28 id=40953 flags= frag=0L ttl=64 proto=ICMP chksum=0xdce5 src=127.0.0.1 dst=127.0.0.1 options='' |<ICMP  type=echo-reply code=0 chksum=0xffff id=0x0 seq=0x0 |>>

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
