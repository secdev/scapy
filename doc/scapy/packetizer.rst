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
checksums, but these should be handled further down the stack as a
:py:class:`Packet`.

While these sorts of serial links are typically obsolete for the purposes of
providing network access to computers, these protocols have found new life in
embedded electronics.

Additionally, ``libpcap`` files could be called a form of data layer -- the
format defines a mechanism to delimit multiple packets within a single file.

.. tip::

   For a practical demonstration of Packetizers, see
   :doc:`Serial Line IP <layers/slip>`.

Working with Packetizers
========================

Scapy's Packetizer interface resides in :file:`scapy/packetizer.py`. It
consists of two classes:

:py:class:`Packetizer`

  An abstract class that all Packetizers inherit from. It buffers incoming
  data, and yields whenever there is a complete frame of data.

  Subclasses implement frame decoding and encoding of frame bytes.

:py:class:`PacketizerSocket`

  This implements the :py:class:`SuperSocket` interface (via
  :py:class:`SimpleSocket`), wrapping :py:meth:`SuperSocket.recv` and
  :py:meth:`SuperSocket.send` calls and handling the interface with
  :py:class:`Packetizer`.

Scapy includes two :py:class:`Packetizer` implementations,
:py:class:`PPPPacketizer` (for PPP) and :py:class:`SLIPPacketizer` (for SLIP).

Packetizer API reference
========================

.. tip::

   If you're defining a protocol that contains simple delimiters and escaping,
   it is probably easier to implement a subclass of :py:class:`SLIPPacketizer`.

.. py:class:: Packetizer

   :py:class:`Packetizer` provides three methods for users (in addition to
   :py:meth:`.encode_frame` below):

   .. py:method:: clear_buffer() -> None

      Clears :py:attr:`.buffer`.

      This discards partially processed packet data, which may cause the next
      packet received to be corrupted.

      This method blocks while acquiring :py:attr:`.buffer_lock`.

   .. py:method:: data_received(data: bytes) -> Generator[Tuple[bytes, int]]

      Adds ``data`` to the :py:attr:`.buffer`, and then starts processing it.
      This method blocks while acquiring :py:attr:`.buffer_lock`.

      This will yield a tuple of:

      ``data_bytes`` (bytes)
        The unescaped bytes for a single packet.

      ``time`` (int)
        The time that the bytes were read.

   .. py:method:: make_socket(fd: BytesIO, [packet_class: Type[Packet] = Raw], [default_read_size: int = 256]) -> PacketizerSocket

      Creates a :py:class:`PacketizerSocket` connected to this
      :py:class:`Packetizer`.

   .. py:method:: encode_frame(packet: Union[bytes, Packet]) -> bytes

      Encodes frame bytes (or a :py:class:`Packet`) for transmission on the
      stream.

      This is used by :py:class:`PacketizerSocket`, but can also be used by
      end-users to encode a packet manually.

      If the subclass does not implement it, this calls :py:func:`raw`.

   :py:class:`Packetizer` automatically buffers the incoming data stream. This
   is stored in two protected attributes:

   .. py:attribute:: buffer (bytearray)

      A ``bytearray`` containing incomplete packet bytes. Interactions
      with it must only be done by the holder of :py:attr:`.buffer_lock` (see
      next), and must only be done with the class itself to ensure thread
      safety.

      *Subclasses must not write to this value.*

   .. py:attribute:: buffer_lock (threading.Lock)

      Protects use of :py:attr:`.buffer`. :py:class:`Packetizer` implementations
      should not need to interact with this.

   Subclasses of :py:class:`Packetizer` must implement
   :py:meth:`.encode_frame` (used by :py:class:`PacketizerSocket` and users to
   encode data for transmission), and these two protected methods (used by
   :py:class:`Packetizer` to decode incoming data):

   .. py:method:: find_end() -> int

      Return the length (in bytes) of the first packet in :py:attr:`.buffer`, or
      ``-1`` if there is no complete packet available.

      In the event of desynchronisation (packet unexpectedly terminated), the
      partial packet must be counted.

      The returned value must include the length of any end-of-packet marker.

      This method is "protected", and is not to be called outside of
      :py:class:`Packetizer` or its subclasses.

   .. py:method:: decode_frame(length: int) -> Optional[bytes]

      Gets the bytes for a single frame in :py:attr:`.buffer`.

      Any start or end markets must be removed, and bytes must be unescaped.

      This method is "protected", and is not to be called outside of
      :py:class:`Packetizer` or its subclasses.

      :param int length: The length of the frame, from :py:meth:`.find_end`.
      :returns: Raw bytes from the frame, or None if the frame is invalid.

PacketizerSocket API reference
==============================

.. py:class:: PacketizerSocket(SimpleSocket)

   Wrapper for :py:class:`Packetizer` that turns a file-like stream
   (:py:class:`BytesIO`) into a :py:class:`SuperSocket`.

   Regular :py:class:`SuperSocket` methods such as :py:meth:`SuperSocket.recv`,
   :py:meth:`SuperSocket.send`, :py:meth:`SuperSocket.sniff` and
   :py:meth:`SuperSocket.am` work with it.

   This class processes packets from :py:meth:`Packetizer.data_received` in a
   queue (in addition to :py:attr:`Packetizer.buffer`). This is used if there is
   more than one packet that could fit into ``default_read_size`` (or a custom
   read size specified in ``recv`` or ``raw_recv``).

   .. py:method:: __init__(fd, packetizer, [packet_class = Raw], [default_read_size = 256])

      :param BytesIO fd: Stream (as a file-like object) to wrap. Must support
          reading and writing.

      :param Packetizer packetizer: Used to encode and decode packets.

      :param Type[Packet] packet_class: Reference to :py:class:`Packet` type for
          decoding incoming data packets.

      :param int default_read_size: Number of bytes to read from ``fd`` by
          default in :py:meth:`.recv` or :py:meth:`.raw_recv`.

   :py:class:`PacketizerSocket` attributes:

   .. py:attribute:: packet_class (Type[Packet])

      Reference to :py:class:`Packet` type for decoding incoming data packets.

   .. py:attribute:: packetizer (Packetizer)

      Instance of :py:class:`Packetizer` for encoding and decoding packets.

   .. py:attribute:: promisc (bool)

      Whether the interface should be considered promiscuous (decodes all
      packets seen).  Always true.

   :py:class:`PacketizerSocket` methods:

   .. py:method:: has_packets() -> bool

      Returns True if there are packets ready to be processed in the queue.

   .. py:method:: recv_raw([x: int = default_read_size]) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[int]]

      This implements the same API as :py:meth:`SuperSocket.recv_raw`, so
      everything should "just work".

      There are some conditions that control whether a ``read`` is issued to the
      underlying stream.

      If a Packet is available in the queue, returns it immediately without
      reading from the underlying stream.

      If no Packet is available in the queue, ``x`` bytes are read from the
      underlying stream, and then all of the packets are added to the internal
      queue.

      If a Packet is available in the queue *now*, return it.

      The returned value is always a Tuple with the following layout:

      ``packet_class`` (Type[Packet])
        Reference to the type of the incoming :py:class:`Packet`.

      ``packet`` (bytes)
        The packet data, as bytes.

      ``time`` (int)
        The time that the packet was received.

      If no packet is available, returns ``tuple(None, None, None)``.

   .. py:method:: send(x: Union[Packet, bytes])

      Encodes a packet with :py:meth:`Packetizer.encode_frame` for transmission,
      and writes it to the underlying stream.

      If a :py:class:`Packet` of type :py:attr:`.packet_class` is passed, this
      is encoded and then written to the underlying stream.

      If a :py:class:`Packet` is passed that is not of type
      :py:attr:`.packet_class`, it is appended to a new instance of
      :py:attr:`.packet_class` with default values. This new instance is then
      encoded and written no the underlying stream.

      This is the same behaviour as :py:meth:`L3PacketSocket.send`.

      If bytes are passed, this is presumed to be of :py:attr:`.packet_class`
      type, and they are encoded and written to the stream.

      If the passed value has a ``sent_time`` attribute, this is set to the
      current time (according to :py:func:`time.time()`).
