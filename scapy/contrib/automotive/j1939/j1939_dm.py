# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) National Motor Freight Traffic Association Inc.
#               <ben.l.gardiner@gmail.com>

# scapy.contrib.description = SAE J1939 Diagnostic Messages (J1939-73)
# scapy.contrib.status = loads

"""
J1939 Diagnostic Messages (DMs) for Scapy.

Implements Scapy packet classes for the most common SAE J1939-73 Diagnostic
Messages:

- ``J1939_DTC``  -- 4-byte Diagnostic Trouble Code (SPN / FMI / CM / OC)
- ``J1939_DM1``  -- Active DTCs, PGN 0xFECA (65226)
- ``J1939_DM13`` -- Stop/Start Broadcast, PGN 0xE000 (57344)
- ``J1939_DM14`` -- Memory Access Request, PGN 0xD900 (55552)

All J1939 payload bytes are in little-endian (LE) byte order.  The
``J1939_DTC`` class uses Scapy's little-endian ``BitField`` support
(``tot_size=-4`` / ``end_tot_size=-4``) to parse and build the LE wire format
transparently.

Usage example::

    >>> load_contrib('automotive.j1939')
    >>> from scapy.contrib.automotive.j1939.j1939_dm import (
    ...     J1939_DTC, J1939_DM1, J1939_DM13, J1939_DM14, PGN_DM1
    ... )
    >>> dtc = J1939_DTC(SPN=100, FMI=2, CM=0, OC=5)
    >>> dm1 = J1939_DM1(mil_status=1, dtcs=[dtc])
    >>> len(bytes(dm1))
    6
"""

# Typing imports
from typing import (  # noqa: F401
    Any,
    Callable,
    List,
    Optional,
    Tuple,
    Union,
)

from scapy.contrib.cansocket import CANSocket

from scapy.contrib.automotive.j1939.j1939_scanner import j1939_decode_can_id
from scapy.contrib.j1939 import (
    J1939,
    J1939SoftSocket,
    J1939_GLOBAL_ADDRESS,
)
from scapy.error import Scapy_Exception
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    PacketListField,
    StrFixedLenField,
    XLEIntField,
    XShortField,
)
from scapy.layers.can import CAN
from scapy.packet import Packet, bind_layers
from scapy.sendrecv import sniff

# ---------------------------------------------------------------------------
# PGN constants for Diagnostic Messages (J1939-73)
# ---------------------------------------------------------------------------

#: PGN for DM1 Active Diagnostic Trouble Codes
J1939_PGN_DM1 = 0xFECA  # 65226

#: PGN for DM13 Stop/Start Broadcast Command
J1939_PGN_DM13 = 0xE000  # 57344

#: PGN for DM14 Memory Access Request
J1939_PGN_DM14 = 0xD900  # 55552

# Lamp status encoding (2-bit values per lamp)
_LAMP_STATUS = {
    0b00: "off",
    0b01: "on",
    0b10: "reserved",
    0b11: "not_available",
}

# DM14 command type encoding
_DM14_COMMAND = {
    0: "erase",
    1: "read",
    2: "write",
    3: "reserved",
}

# DM14 pointer type encoding
_DM14_POINTER_TYPE = {
    0: "direct",
    1: "indirect",
    2: "copy",
    3: "reserved",
}


class J1939_DTC(Packet):
    """J1939-73 Diagnostic Trouble Code (4 bytes, little-endian).

    A DTC is a 32-bit little-endian integer with the following bit layout:

    - bits 18-0:  SPN (Suspect Parameter Number, 19 bits)
    - bits 23-19: FMI (Failure Mode Indicator, 5 bits)
    - bit  24:    CM  (SPN Conversion Method, 1 bit)
    - bits 31-25: OC  (Occurrence Count, 7 bits)

    Wire bytes (LSB first)::

        byte 0: SPN[7:0]
        byte 1: SPN[15:8]
        byte 2: FMI[4:0] | SPN[18:16]   (bits 7-3 = FMI, bits 2-0 = SPN MSBs)
        byte 3: OC[6:0]  | CM             (bits 7-1 = OC,  bit 0  = CM)

    :param SPN: Suspect Parameter Number (0-524287)
    :param FMI: Failure Mode Indicator (0-31)
    :param CM:  SPN Conversion Method (0-1)
    :param OC:  Occurrence Count (0-127)
    """

    name = "J1939_DTC"

    fields_desc = [
        BitField("OC", 0, 7, tot_size=-4),  # bits 31-25 (MSB side)
        BitField("CM", 0, 1),  # bit  24
        BitField("FMI", 0, 5),  # bits 23-19
        BitField("SPN", 0, 19, end_tot_size=-4),  # bits 18-0  (LSB side)
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        """No sub-layer payload; all remaining bytes returned as padding."""
        return b"", s


class J1939_DM1(Packet):
    """DM1 Active Diagnostic Trouble Codes (PGN 0xFECA = 65226).

    Wire format:

    - Bytes 0-1: Lamp Status (4 lamps × 2 bits on/off + 4 lamps × 2 bits
      flash pattern).
    - Bytes 2+:  Variable list of :class:`J1939_DTC` records (4 bytes each).

    Multi-packet messages (>8 bytes) are sent via the J1939-21 Transport
    Protocol, handled automatically by :class:`J1939SoftSocket`.

    :param mil_status: Malfunction Indicator Lamp on/off (0=off, 1=on, 3=N/A)
    :param rsl_status: Red Stop Lamp on/off
    :param awl_status: Amber Warning Lamp on/off
    :param pl_status:  Protect Lamp on/off
    :param mil_flash:  MIL flash pattern
    :param rsl_flash:  RSL flash pattern
    :param awl_flash:  AWL flash pattern
    :param pl_flash:   PL flash pattern
    :param dtcs:       list of :class:`J1939_DTC` objects
    """

    name = "J1939_DM1"

    #: PGN for DM1 Active DTCs (J1939-73)
    PGN = J1939_PGN_DM1

    fields_desc = [
        # Byte 0: Lamp on/off status (bits 7-6 = MIL, 5-4 = RSL, 3-2 = AWL, 1-0 = PL)
        BitEnumField("mil_status", 3, 2, _LAMP_STATUS),
        BitEnumField("rsl_status", 3, 2, _LAMP_STATUS),
        BitEnumField("awl_status", 3, 2, _LAMP_STATUS),
        BitEnumField("pl_status", 3, 2, _LAMP_STATUS),
        # Byte 1: Lamp flash patterns (same 2-bit encoding)
        BitEnumField("mil_flash", 3, 2, _LAMP_STATUS),
        BitEnumField("rsl_flash", 3, 2, _LAMP_STATUS),
        BitEnumField("awl_flash", 3, 2, _LAMP_STATUS),
        BitEnumField("pl_flash", 3, 2, _LAMP_STATUS),
        PacketListField(
            "dtcs",
            [],
            J1939_DTC,
            next_cls_cb=lambda pkt, lst, cur, remain: (
                J1939_DTC if len(remain) >= 4 else None
            ),
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s


class J1939_DM13(Packet):
    """DM13 Stop/Start Broadcast Command (PGN 0xE000 = 57344).

    Broadcast to all ECUs on the bus to start or stop periodic diagnostic
    broadcast.  The ``hold_signal`` byte uses the J1939-73 convention:
    ``0xFE`` = start broadcasting, ``0xFF`` = stop broadcasting.

    :param hold_signal: broadcast control (0xFE=start, 0xFF=stop)
    :param data: remaining 7 bytes (optional override; default all 0xFF)
    """

    name = "J1939_DM13"

    #: PGN for DM13 Stop/Start Broadcast
    PGN = J1939_PGN_DM13

    fields_desc = [
        ByteField("hold_signal", 0xFF),
        StrFixedLenField("data", b"\xff" * 7, 7),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s


class J1939_DM14(Packet):
    """DM14 Memory Access Request (PGN 0xD900 = 55552).

    Peer-to-peer request to read, write, or erase ECU memory.  DM14 must
    always be addressed to a specific ECU (not the global broadcast address
    ``0xFF``).

    Wire format (8 bytes):

    - Byte 0: bits 7-6 = reserved (1), bits 5-4 = command, bits 3-2 =
      pointer type, bits 1-0 = access level
    - Bytes 1-4: memory address (32-bit LE)
    - Byte 5:    data length (number of bytes to read/write)
    - Bytes 6-7: reserved (0xFFFF)

    :param command_type: memory operation (0=erase, 1=read, 2=write)
    :param pointer_type: addressing mode (0=direct, 1=indirect, 2=copy)
    :param access_level: security access level (0-3)
    :param address:      32-bit LE memory address
    :param length:       number of bytes to access
    """

    name = "J1939_DM14"

    #: PGN for DM14 Memory Access Request
    PGN = J1939_PGN_DM14

    fields_desc = [
        # Byte 0: control fields
        BitField("reserved", 0b11, 2),
        BitEnumField("command_type", 1, 2, _DM14_COMMAND),
        BitEnumField("pointer_type", 0, 2, _DM14_POINTER_TYPE),
        BitField("access_level", 0, 2),
        # Bytes 1-4: memory address (little-endian)
        XLEIntField("address", 0),
        # Byte 5: data length
        ByteField("length", 0),
        # Bytes 6-7: reserved
        XShortField("reserved2", 0xFFFF),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s


bind_layers(J1939, J1939_DM1, pgn=J1939_PGN_DM1)
bind_layers(J1939, J1939_DM13, pgn=J1939_PGN_DM13)
bind_layers(J1939, J1939_DM14, pgn=J1939_PGN_DM14)


# ---------------------------------------------------------------------------
# Socket utility functions
# ---------------------------------------------------------------------------


def sniff_dm1(
    sock,  # type: Any
    timeout=10,  # type: float
    reconnect_handler=None,  # type: Optional[Callable[[], Any]]
):
    # type: (...) -> List[J1939_DM1]
    """Sniff DM1 Active DTC messages from the J1939 bus.

    Sniffs for ``timeout`` seconds on *sock* (which may be an already opened
    socket or a per-iteration socket when *reconnect_handler* is provided).
    Each received DM1 payload is dissected into a :class:`J1939_DM1` packet.

    When *reconnect_handler* is provided, a fresh socket is obtained from the factory
    and closed upon exit.  When *reconnect_handler* is ``None``, the provided *sock* is
    reused and left open to save creation and destruction overhead.

    :param sock: CAN or J1939 socket
    :param timeout: sniff duration in seconds
    :param reconnect_handler: optional zero-argument callable returning a newly
                              created CAN/J1939 socket
    :returns: list of :class:`J1939_DM1` packets received
    """
    if reconnect_handler is not None:
        raw_sock = reconnect_handler()
        close_needed = True
    else:
        raw_sock = sock
        close_needed = False

    close_wrapper = False
    if CANSocket is not None and isinstance(raw_sock, CANSocket):
        sniff_sock = J1939SoftSocket(raw_sock, pgn=J1939_PGN_DM1, listen_only=True)
        close_wrapper = True
    else:
        sniff_sock = raw_sock

    try:
        pkts = sniff(opened_socket=sniff_sock, timeout=timeout)
    finally:
        if close_wrapper:
            sniff_sock.close()
        if close_needed:
            raw_sock.close()

    results = []  # type: List[J1939_DM1]
    for p in pkts:
        if isinstance(p, J1939_DM1):
            results.append(p)
        elif isinstance(p, CAN):
            if p.flags & 0x4:  # extended
                _, pf, ps, _ = j1939_decode_can_id(p.identifier)
                pgn = (pf << 8) if pf < 0xF0 else ((pf << 8) | ps)
                if pgn == J1939_PGN_DM1:
                    results.append(J1939_DM1(bytes(p.data)))
        elif hasattr(p, "data"):
            if getattr(p, "pgn", J1939_PGN_DM1) == J1939_PGN_DM1:
                results.append(J1939_DM1(p.data))
    return results


def send_dm14_request(
    sock_or_interface,  # type: Any
    dest_addr,  # type: int
    memory_address,  # type: int
    length=1,  # type: int
):
    # type: (...) -> None
    """Send a DM14 Memory Access Request to a specific ECU.

    :param sock_or_interface: CAN/J1939 socket or CAN interface name string
                              (e.g. ``"can0"``)
    :param dest_addr: destination ECU address (must not be
                      :data:`J1939_GLOBAL_ADDRESS`)
    :param memory_address: 32-bit memory address to access
    :param length: number of bytes to read
    :raises Scapy_Exception: if *dest_addr* equals
                             :data:`J1939_GLOBAL_ADDRESS`
    """
    if dest_addr == J1939_GLOBAL_ADDRESS:
        raise Scapy_Exception(
            "DM14 is a peer-to-peer message; "
            "dst_addr must not be the broadcast address (0xFF)"
        )

    dm14 = J1939_DM14(address=memory_address, length=length)
    pkt = J1939(data=bytes(dm14), pgn=J1939_PGN_DM14, dst=dest_addr)

    if isinstance(sock_or_interface, str):
        from scapy.contrib.automotive.j1939 import (  # type: ignore[attr-defined]
            J1939Socket,
        )
        with J1939Socket(sock_or_interface, src_addr=0xFA, pgn=J1939_PGN_DM14) as s:
            s.send(pkt)
    else:
        sock_or_interface.send(pkt)


__all__ = [
    "J1939_DM1",
    "J1939_DM13",
    "J1939_DM14",
    "J1939_DTC",
    "J1939_PGN_DM1",
    "J1939_PGN_DM13",
    "J1939_PGN_DM14",
    "send_dm14_request",
    "sniff_dm1",
]
