TCP
===

Scapy is based on a stimulus/response model. This model does not work
well for a TCP stack. On the other hand, quite often, the TCP stream is
used as a tube to exchange messages that are stimulus/response-based.

Also, Scapy provides a way to describe network automata that can be
used to create a TCP stack automaton.

There are many ways to use TCP with Scapy

Using the kernel's TCP stack
----------------------------

Scapy provides a ``StreamSocket`` object that can transform a simple
socket into a Scapy supersocket suitable for use with ``sr()`` command
family.

.. code::

   >>> s=socket.socket()
   >>> s.connect(("www.test.com",80))
   >>> ss=StreamSocket(s,Raw)
   >>> ss.sr1(Raw("GET /\r\n"))
   Begin emission:
   Finished to send 1 packets.
   *
   Received 1 packets, got 1 answers, remaining 0 packets
   <Raw  load='<html>\r\n<head> ... >

Using kernel's TCP stack means you'll depend on your local firewall's
rules and the kernel's routing table.

Scapy's TCP client automaton
----------------------------

Scapy provides a simple TCP client automaton (no retransmits, no SAck,
no timestamps, etc.). Automata can provide input and output in the shape
of a supersocket (see `Automata's documentation`_).

Here is how to use Scapy's TCP client automaton (needs at least Scapy v2.1.1).

.. note::
   
   ``TCP_client.tcplink`` is a ``SuperSocket`` subclass, therefore all its functions (``.sniff()``, ...) are available.

.. code::

   >>> s = TCP_client.tcplink(Raw, "www.test.com", 80)
   >>> s.send("GET /\r\n")
   7
   >>> s.recv()
   <Raw  load='<html>\r\n<head> ... >

.. note:: specifically for HTTP, you could pass ``HTTP`` instead of ``Raw``. More information over `HTTP in Scapy <http.html>`_.

Use external projects
---------------------

-  `muXTCP`_ - Writing your own flexible Userland TCP/IP Stack - Ninja Style!!!
-  Integrating `pynids`_

.. _Automata's documentation: ../advanced_usage#automata
.. _muXTCP: http://events.ccc.de/congress/2005/fahrplan/events/529.en.html
.. _pynids: http://jon.oberheide.org/pynids/
