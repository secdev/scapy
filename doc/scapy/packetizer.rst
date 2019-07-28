***********
Packetizers
***********

Packetizers are Scapy's interface for taking a stream of bytes, and dividing it
into packets, and also converting packets into a stream of bytes. They
implement at least the `medium access control (MAC)`__ sublayer of the `data
link layer`__.

__ https://en.wikipedia.org/wiki/Medium_access_control
__ https://en.wikipedia.org/wiki/Data_link_layer

In an Ethernet network, your network card's `PHY`__ is the interface between the
analogue domain of Ethernet's line modulation and the digital domain of
link-layer packet signalling used by the MAC. Modern network cards integrate the
functions of the PHY and MAC into a `single package`__. Your operating system
normally only sees packets, and not the analogue electrical signals.

__ https://en.wikipedia.org/wiki/PHY_(chip)
__ https://en.wikipedia.org/wiki/System_in_package

By comparison, serial ports are presented to the operating system as a
bidirectional stream of bytes. Protocols like :abbr:`HDLC (High-level Data Link
Control)` (used by :abbr:`PPP (Point to Point Protocol)`) and :abbr:`SLIP
(Serial Line IP)` define framing semantics for serial links. They enable the
transmission and reception of *packets*, rather than just *bytes*.

These protocols typically define an end-of-frame sequence (to delimit frames),
and an escape sequence (for handling frames that contain end-of-frame
sequences). They might also define a start-of-frame sequence or escapes for
additional reserved characters.

More sophisticated protocols might implement error-correction codes or
checksums, but these should be handled further down the stack as a ``Packet``.

While these sorts of serial links are typically obsolete for the purposes of
providing network access to computers, these protocols have found new life in
embedded electronics.

Additionally, ``libpcap`` files could be called a form of data layer -- the
format defines a mechanism to delimit multiple packets within a single file.

Working with Packetizers
========================

Scapy's Packetizer interface resides in ``scapy/packetizer.py``. It consists of
two classes:

``Packetizer``
  This is an abstract class that all Packetizers inherit from. It buffers
  incoming data, and yields whenever there is a complete frame of data.

  Subclasses implement frame decoding and encoding of frame bytes.

``PacketizerSocket``
  This implements the ``SuperSocket`` interface (via ``SimpleSocket``), wrapping
  ``recv`` and ``send`` calls and handling the interface with ``Packetizer``.

Scapy includes two ``Packetizer`` implementations, ``PPPPacketizer`` (for
PPP) and ``SLIPPacketizer`` (for SLIP).

Packetizer API
--------------

The Packetizer API defines two important fields:

``buffer``
  This is a ``bytearray`` containing incomplete packet bytes. Interactions with
  it must be done with the ``buffer_lock`` (see next), and must only be ever
  done with the class itself to ensure thread safety.

``buffer_lock``
  A ``threading.Lock`` which protects use of ``buffer``. ``Packetizer``
  implementations need not interact with this.

The Packetizer API requires the implementation of three methods:

``find_end``
  Returns an integer with the length of the frame at the start of ``buffer``, or
  ``-1`` if there is no complete packet available.

``decode_frame``
  Decodes a frame at the start of ``buffer`` with a given length (passed from
  ``find_end``).

``encode_frame(packet)``
  Encodes a ``Packet`` into bytes that can be transmitted on the wire. This is
  used directly by ``Packetizer`` callers.

The Packetizer provides three methods for callers:

``clear_buffer``
  Deletes the contents of the ``buffer``, as well as any partial data that
  happens to be inside.

  Blocks on acquiring the ``buffer_lock``.

``data_received(data)``
  Whenever you get new data, call this method. This will yield tuples of
  ``(frame_bytes, time)`` whenever there is a complete frame available.

  Blocks on acquiring the ``buffer_lock``.

``encode_frame(packet)``
  Described above.

``make_socket(fd, packet_class, default_read_size)``
  Wraps this ``Packetizer`` into a ``PacketizerSocket``, consuming the given
  file-like object (``fd``).

  If no ``packet_class`` is specified, this class returns ``Raw`` packets.

If you're defining a protocol that contains simple delimiters and escaping, it
can probably be implemented as a subclass of ``SLIPPacketizer``.

Creating a SLIP connection
==========================

This example sets up a Serial Line IP connection with IPv4, between Scapy and a
remote host.

There are two methods described here, which have different requirements:

using a real serial port
  This requires that you install the `PySerial`__ library, and that you have
  connected two hosts (or the same host on two ports) with a `null modem
  cable`__.

__ https://github.com/pyserial/pyserial
__ https://en.wikipedia.org/wiki/Null_modem

using a virtual PTY
  This requires that you run Scapy on a UNIX-like operating system.

In both cases, your "remote" host will also need a SLIP client:

  * On Linux, you'll need the ``slattach`` tool, which is part of the
    (mostly obsolete) ``net-tools`` package.

  * Mac OS X does not support SLIP natively -- you'll need to use a tool like
    ``slip2tun`` to attach it to a userspace ``tuntap`` device.

  * Windows 95 through to XP support SLIP natively.

  * Windows Vista and later do not support SLIP.

This will be a point-to-point link, with these addresses:

  * Scapy IP address: ``192.0.2.1``
  * Remote IP address: ``192.0.2.2``

To start, we'll create an ICMP Echo Request packet (ping), and add some
fuzzing to the frame in order make sure we get random sequence numbers:

.. code-block:: python3

    echo = (IP(src='192.0.2.1', dst='192.0.2.2')/
            ICMP(type='echo-request')/
            Raw(b'hello!'))

    fuzz(echo[ICMP], 1)

The second parameter to ``fuzz`` causes the operation to be done in-place. This
causes the packet to become volatile -- causing it change every time it is
serialized:

.. code-block:: pycon

    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c00002020800d44551b68e1068656c6c6f21'
    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c000020208b84ab6ffc368da68656c6c6f21'
    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c00002020863d2caeba9f53468656c6c6f21'
    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c00002020812f5faa577188868656c6c6f21'

Now, we can create the SLIP link!

**For a real serial port,** you can use the method ``slip_connect``:

.. code-block:: pycon

    >>> s = slip_connect('/dev/ttyS0', 9600)

This will start a connection at 9600 baud, with the typical ``8N1``
configuration.

**For a virtual serial port,** you can use the method ``slip_pty``. This
automatically opens a new PTY, and reports back the name of it for you to use:

.. code-block:: pycon

    >>> s, child_fn, child_fd = slip_pty()
    >>> child_fn
    /dev/pts/6

This will give you a path to the child PTY on ``child_fn``, and the file
descriptor number in ``child_fd``. The parent is part of the
``PacketizerSocket`` (in ``s``).

**Now that you have a port,** you now need to setup a SLIP client on the other
end of it.

For Linux, these commands will need to be run as root:

.. code-block:: bash

    modprobe -v slip

    # Pick one of these options:
    slattach -s 9600 /dev/ttyS0     # for a physical port
    slattach /dev/pts/6             # for a virtual port

    # Now set an IP and bring it up:
    ip addr change 192.0.2.2/32 peer 192.0.2.1 dev sl0
    ip link set sl0 up

You can then start pinging the remote host with:

.. code-block:: pycon

    >>> scapy.sendrecv.__sr_loop(pty.sr, [echo])
    RECV 1: IP / ICMP 192.0.2.2 > 192.0.2.1 echo-reply 239 / Raw
    RECV 1: IP / ICMP 192.0.2.2 > 192.0.2.1 echo-reply 22 / Raw
    RECV 1: IP / ICMP 192.0.2.2 > 192.0.2.1 echo-reply 36 / Raw

