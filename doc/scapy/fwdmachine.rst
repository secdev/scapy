******************
Forwarding Machine
******************

Scapy's ``ForwardingMachine`` is a class utility that allows to very quickly design a server that forwards packets to another server, with the ability
to modify them on-the-fly. This is commonly referred to as a "transparent proxy". The ``ForwardingMachine`` was initially designed to be used with TPROXY,
a linux feature that allows to bind a socket that received *packets to any IP destination*, in which case it properly forwards the packet to the initially
intended destination.

A ``ForwardingMachine`` is expected to be used over a normal Python socket, of any kind, and needs to extended with two
functions: ``xfrmcs`` and ``xfrmsc``. The first one is called whenever data is received from the client side (client-to-server), the other when the data
is received from the server.

Basic usage
___________

Here's an example of a ``ForwardingMachine`` over TPROXY that does nothing. Packets for all destinations are handled, and forwarded to their
initial destinations afterwards. More details on how to setup TPROXY are provided below. Note that a ``ForwardingMachine`` **also works without TPROXY**.

.. code:: python

    from scapy.fwdmachine import ForwardMachine
    from scapy.layers.http import HTTP

    class HTTPEdit(ForwardMachine):
        def xfrmcs(self, pkt, ctx):
            pkt.show()  # we print the client->server packets
            raise self.FORWARD()

        def xfrmsc(self, pkt, ctx):
            pkt.show()  # we print the server->client packets
            raise self.FORWARD()

    # Run it
    HTTPEdit(
        mode=ForwardMachine.MODE.TPROXY,
        port=80,
        cls=HTTP,  # we specify the class of the payload we are receiving
    ).run()

The callback classes use **Operations** to tell the ``ForwardingMachine`` what to do with the incoming data.

.. figure:: ../graphics/fwdmachine.svg
    :align: center

    The main operations available in a Forwarding machine, in this case in ``xfrmcs``.

There are currently 5 operations available:

- **FORWARD**: forward the received payload to the destination intended by the peer;
- **FORWARD_REPLACE**: forward a modified payload to the intended destination;
- **DROP**: drop the received payload;
- **ANSWER**: answer the peer directly with a payload, without forwarding its original payload to the other peer;
- **REDIRECT_TO**: (client-side only) redirects the connection of the client towards a new remote peer.

The ``ctx`` attribute in the callbacks contains context relative to the current client. It can also be use to
store additional data specific to the session.

TLS support
___________

``ForwardingMachine`` has support for TLS through the ``ssl=True`` argument. When TLS is enabled, the SNI (Server Name Indication) is
properly forwarded to the remote peer, and can be accessed through the ``ctx.tls_sni_name`` attribute in the callbacks.

**By default, a ``ForwardingMachine`` generates self-signed certificates** that copy the attributes from the certificate of the remote
server. This behavior can be changed by specifying a certificate (which will be served by the TLS stack).

.. code:: python

    from scapy.fwdmachine import ForwardMachine
    from scapy.layers.http import HTTP

    class HTTPSDump(ForwardMachine):
        def xfrmcs(self, pkt, ctx):
            pkt.show()  # we print the client->server packets
            raise self.FORWARD()

        def xfrmsc(self, pkt, ctx):
            pkt.show()  # we print the server->client packets
            raise self.FORWARD()

    # Run it
    HTTPSDump(
        mode=ForwardMachine.MODE.TPROXY,
        port=443,
        cls=HTTP,
        ssl=True,
    ).run()