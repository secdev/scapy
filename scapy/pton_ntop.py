# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Convert IPv6 addresses between textual representation and binary.

These functions are missing when python is compiled
without IPv6 support, on Windows for instance.
"""

from __future__ import absolute_import
import socket
import re
import binascii
from scapy.modules.six.moves import range
from scapy.compat import plain_str, hex_bytes, bytes_encode, bytes_hex

_IP6_ZEROS = re.compile('(?::|^)(0(?::0)+)(?::|$)')
_INET6_PTON_EXC = socket.error("illegal IP address string passed to inet_pton")


def _inet6_pton(addr):
    """Convert an IPv6 address from text representation into binary form,
used when socket.inet_pton is not available.

    """
    joker_pos = None
    result = b""
    addr = plain_str(addr)
    if addr == '::':
        return b'\x00' * 16
    if addr.startswith('::'):
        addr = addr[1:]
    if addr.endswith('::'):
        addr = addr[:-1]
    parts = addr.split(":")
    nparts = len(parts)
    for i, part in enumerate(parts):
        if not part:
            # "::" indicates one or more groups of 2 null bytes
            if joker_pos is None:
                joker_pos = len(result)
            else:
                # Wildcard is only allowed once
                raise _INET6_PTON_EXC
        elif i + 1 == nparts and '.' in part:
            # The last part of an IPv6 address can be an IPv4 address
            if part.count('.') != 3:
                # we have to do this since socket.inet_aton('1.2') ==
                # b'\x01\x00\x00\x02'
                raise _INET6_PTON_EXC
            try:
                result += socket.inet_aton(part)
            except socket.error:
                raise _INET6_PTON_EXC
        else:
            # Each part must be 16bit. Add missing zeroes before decoding.
            try:
                result += hex_bytes(part.rjust(4, "0"))
            except (binascii.Error, TypeError):
                raise _INET6_PTON_EXC
    # If there's a wildcard, fill up with zeros to reach 128bit (16 bytes)
    if joker_pos is not None:
        if len(result) == 16:
            raise _INET6_PTON_EXC
        result = (result[:joker_pos] + b"\x00" * (16 - len(result)) +
                  result[joker_pos:])
    if len(result) != 16:
        raise _INET6_PTON_EXC
    return result


_INET_PTON = {
    socket.AF_INET: socket.inet_aton,
    socket.AF_INET6: _inet6_pton,
}


def inet_pton(af, addr):
    """Convert an IP address from text representation into binary form."""
    # Will replace Net/Net6 objects
    addr = plain_str(addr)
    # Use inet_pton if available
    try:
        return socket.inet_pton(af, addr)
    except AttributeError:
        try:
            return _INET_PTON[af](addr)
        except KeyError:
            raise socket.error("Address family not supported by protocol")


def _inet6_ntop(addr):
    """Convert an IPv6 address from binary form into text representation,
used when socket.inet_pton is not available.

    """
    # IPv6 addresses have 128bits (16 bytes)
    if len(addr) != 16:
        raise ValueError("invalid length of packed IP address string")

    # Decode to hex representation
    address = ":".join(plain_str(bytes_hex(addr[idx:idx + 2])).lstrip('0') or '0'  # noqa: E501
                       for idx in range(0, 16, 2))

    try:
        # Get the longest set of zero blocks. We need to take a look
        # at group 1 regarding the length, as 0:0:1:0:0:2:3:4 would
        # have two matches: 0:0: and :0:0: where the latter is longer,
        # though the first one should be taken. Group 1 is in both
        # cases 0:0.
        match = max(_IP6_ZEROS.finditer(address),
                    key=lambda m: m.end(1) - m.start(1))
        return '{}::{}'.format(address[:match.start()], address[match.end():])
    except ValueError:
        return address


_INET_NTOP = {
    socket.AF_INET: socket.inet_ntoa,
    socket.AF_INET6: _inet6_ntop,
}


def inet_ntop(af, addr):
    """Convert an IP address from binary form into text representation."""
    # Use inet_ntop if available
    addr = bytes_encode(addr)
    try:
        return socket.inet_ntop(af, addr)
    except AttributeError:
        try:
            return _INET_NTOP[af](addr)
        except KeyError:
            raise ValueError("unknown address family %d" % af)
