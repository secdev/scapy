***************
Troubleshooting
***************

FAQ
===

My TCP connections are reset by Scapy or by my kernel.
------------------------------------------------------
The kernel is not aware of what Scapy is doing behind his back. If Scapy sends a SYN, the target replies with a SYN-ACK and your kernel sees it, it will reply with a RST. To prevent this, use local firewall rules (e.g. NetFilter for Linux). Scapy does not mind about local firewalls.

I can't ping 127.0.0.1. Scapy does not work with 127.0.0.1 or on the loopback interface 
---------------------------------------------------------------------------------------

The loopback interface is a very special interface. Packets going through it are not really assembled and dissassembled. The kernel routes the packet to its destination while it is still stored an internal structure. What you see with tcpdump -i lo is only a fake to make you think everything is normal. The kernel is not aware of what Scapy is doing behind his back, so what you see on the loopback interface is also a fake. Except this one did not come from a local structure. Thus the kernel will never receive it.

In order to speak to local applications, you need to build your packets one layer upper, using a PF_INET/SOCK_RAW socket instead of a PF_PACKET/SOCK_RAW (or its equivalent on other systems that Linux)::

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

To work arround this, use ``nofilter=1``::

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

There's a low traffic mailing list at ``scapy.ml(at)secdev.org``  (`archive <http://news.gmane.org/gmane.comp.security.scapy.general>`_, `RSS, NNTP <http://gmane.org/info.php?group=gmane.comp.security.scapy.general>`_). You are encouraged to send questions, bug reports, suggestions, ideas, cool usages of Scapy, etc. to this list. Subscribe by sending a mail to ``scapy.ml-subscribe(at)secdev.org``.



To avoid spam, you must subscribe to the mailing list to post.