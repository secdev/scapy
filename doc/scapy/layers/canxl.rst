.. note:: This document is under a `Creative Commons Attribution - Non-Commercial - Share Alike 2.5 <http://creativecommons.org/licenses/by-nc-sa/2.5/>`_ license.

#####
CAN XL
#####

CAN XL (ISO 11898-1:2024) is the newest member of the CAN protocol family,
offering up to 2048 bytes of payload per frame and a priority-based
arbitration field.  The CiA 613-1 specification defines a simple extended
content (SEC) flag and an "add-on services" framework that allows optional
features to be layered on top of plain CAN XL. Two add-on services are
currently standardised in dedicated documents: CANsec for authenticated and
encrypted communication (CiA 613-2) and fragmentation of payloads (CiA 613-3).

Scapy provides the ``CANXL`` packet class in ``scapy.layers.can`` and
supports sending/receiving CAN XL frames through ``NativeCANSocket``
on Linux (kernel 6.2 or later).

Quick start
===========

Setting up a virtual CAN interface
-----------------------------------

CAN XL works over standard Linux virtual CAN (vcan) interfaces.
Make sure your kernel is 6.2 or newer::

    $ sudo modprobe vcan
    $ sudo ip link add dev vcan0 type vcan
    $ sudo ip link set vcan0 up

Building and inspecting frames
-------------------------------

.. code-block:: python

    from scapy.layers.can import CANXL

    # Create a basic CAN XL frame
    pkt = CANXL(priority=0x42, sdt=3, af=0xDEAD) / b'\x01\x02\x03'
    pkt.show()

    # ISO 11898-1 field names (Priority, Format, FTYPE, SDT, SEC, DLC, etc.)
    pkt.show(style="11898-1")

    # Access payload data (same API as classic CAN)
    pkt.data        # b'\x01\x02\x03'

    # ISO properties
    pkt.dlc         # 2 (length - 1)
    pkt.sec         # False
    pkt.xlf         # True
    pkt.fdf         # True
    pkt.ftype       # False
    pkt.frame_format  # 6 (XLF+FDF)

Sending and receiving over a socket
------------------------------------

.. code-block:: python

    from scapy.contrib.cansocket_native import NativeCANSocket
    from scapy.layers.can import CANXL

    # Open a CAN XL socket (xl=True enables CAN_RAW_XL_FRAMES)
    sock = NativeCANSocket(channel="vcan0", xl=True)

    # Send a frame
    sock.send(CANXL(priority=0x42, sdt=3, af=0xDEAD) / b'\x01\x02\x03')

    # Receive a frame (in another terminal or Scapy session)
    pkt = sock.recv()
    pkt.show()
    pkt.show(style="11898-1")

    sock.close()

Kernel requirements:

- CAN XL frames need Linux **kernel >= 6.2** (``CAN_RAW_XL_FRAMES`` socket option).
- VCID pass-through needs Linux **kernel >= 6.11** (``CAN_RAW_XL_VCID_OPTS``).
  Scapy handles older kernels gracefully -- VCID just stays at zero.


Field naming: Linux vs ISO
===========================

CAN XL field names differ between the Linux kernel's ``struct canxl_frame``
(used in Scapy's ``fields_desc``) and the ISO 11898-1:2024 specification.
Use ``pkt.show(style="11898-1")`` to see ISO names, or access via
properties:

+--------------+--------------------+--------------------+
| ISO name     | Linux / Scapy name | Access via         |
+==============+====================+====================+
| Priority     | ``priority``       | ``pkt.priority``   |
+--------------+--------------------+--------------------+
| Format       | ``flags`` bits 7-5 | ``pkt.frame_format``|
+--------------+--------------------+--------------------+
| XLF          | ``flags.xlf``      | ``pkt.xlf``        |
+--------------+--------------------+--------------------+
| FDF          | ``flags.fdf``      | ``pkt.fdf``        |
+--------------+--------------------+--------------------+
| IDE          | ``flags.ide``      | ``pkt.ide``        |
+--------------+--------------------+--------------------+
| SEC          | ``flags.sec``      | ``pkt.sec``        |
+--------------+--------------------+--------------------+
| FTYPE / RRS  | ``flags.rrs``      | ``pkt.ftype``      |
+--------------+--------------------+--------------------+
| SDT          | ``sdt``            | ``pkt.sdt``        |
+--------------+--------------------+--------------------+
| DLC          | ``length`` (len-1) | ``pkt.dlc``        |
+--------------+--------------------+--------------------+
| VCID         | ``vcid``           | ``pkt.vcid``       |
+--------------+--------------------+--------------------+
| AF           | ``af``             | ``pkt.af``         |
+--------------+--------------------+--------------------+
| Data         | (sub-layer payload)| ``pkt.data``       |
+--------------+--------------------+--------------------+


Byte-order handling
====================

CAN XL uses a multi-region byte swap: the Priority word (4 bytes),
Length (2 bytes), and Acceptance Field (4 bytes) are in little-endian
order on the Linux socket but stored as big-endian inside Scapy.
The swap happens automatically in ``pre_dissect`` (receive) and
``post_build`` (send).

Unlike classic CAN and CAN FD, CAN XL **ignores** the
``conf.contribs['CAN']['swap-bytes']`` setting -- the swap always happens
because CAN XL frames only come from PF_CAN sockets which are always LE.
You do *not* need to touch this config for CAN XL.


Interop with can-utils
======================

On Linux you can send and receive CAN XL frames using the ``can-utils``
package (``cansend``, ``candump``, etc.) alongside Scapy.  Start
``candump`` in one terminal and use Scapy to send::

    # Terminal 1:
    $ candump vcan0

    # Terminal 2 (Scapy):
    >>> from scapy.contrib.cansocket_native import NativeCANSocket
    >>> from scapy.layers.can import CANXL
    >>> sock = NativeCANSocket(channel="vcan0", xl=True)
    >>> sock.send(CANXL(priority=0x42, sdt=3, af=0xDEAD) / b'\x01\x02')

The ``candump`` output should show the CAN XL frame with its priority,
SDT, and payload.


Known limitations
==================

- **pcap read/write:** CAN XL frames are part of ``LINKTYPE_CAN_SOCKETCAN``
  (DLT 227) and Wireshark supports them since version 4.2.3.  However, Scapy
  does not yet handle the mixed-endian pcap wire format for CAN XL correctly
  (Priority is big-endian in pcap, while Length and AF are little-endian).
  This will be addressed in a future release.

- **CandumpReader:** The ``rdcandump`` / ``CandumpReader`` utilities do not
  parse CAN XL frames yet.

- **No SDT-based payload dispatch:** The ``guess_payload_class`` override
  currently returns raw bytes.  Sub-dissectors for specific SDT values can
  be added via ``bind_layers`` or by monkey-patching, as the CANsec contrib
  demonstrates.
