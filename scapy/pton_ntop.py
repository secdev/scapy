## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Convert IPv6 addresses between textual representation and binary.

These functions are missing when python is compiled
without IPv6 support, on Windows for instance.
"""

import socket
import re

_IP6_ZEROS = re.compile('(?::|^)(0(?::0)+)(?::|$)')

def inet_pton(af, addr):
    """Convert an IP address from text representation into binary form"""
    if af == socket.AF_INET:
        return socket.inet_aton(addr)
    elif af == socket.AF_INET6:
        # Use inet_pton if available
        try:
            return socket.inet_pton(af, addr)
        except AttributeError:
            pass

        # IPv6: The use of "::" indicates one or more groups of 16 bits of zeros.
        # We deal with this form of wildcard using a special marker. 
        JOKER = "*"
        while "::" in addr:
            addr = addr.replace("::", ":" + JOKER + ":")
        joker_pos = None 
        
        # The last part of an IPv6 address can be an IPv4 address
        ipv4_addr = None
        if "." in addr:
            ipv4_addr = addr.split(":")[-1]
           
        result = ""
        parts = addr.split(":")
        for part in parts:
            if part == JOKER:
                # Wildcard is only allowed once
                if joker_pos is None:
                   joker_pos = len(result)
                else:
                   raise Exception("Illegal syntax for IP address")
            elif part == ipv4_addr: # FIXME: Make sure IPv4 can only be last part
                # FIXME: inet_aton allows IPv4 addresses with less than 4 octets 
                result += socket.inet_aton(ipv4_addr)
            else:
                # Each part must be 16bit. Add missing zeroes before decoding. 
                try:
                    result += part.rjust(4, "0").decode("hex")
                except TypeError:
                    raise Exception("Illegal syntax for IP address")
                    
        # If there's a wildcard, fill up with zeros to reach 128bit (16 bytes) 
        if JOKER in addr:
            result = (result[:joker_pos] + "\x00" * (16 - len(result))
                      + result[joker_pos:])
    
        if len(result) != 16:
            raise Exception("Illegal syntax for IP address")
        return result 
    else:
        raise Exception("Address family not supported")


def inet_ntop(af, addr):
    """Convert an IP address from binary form into text representation"""
    if af == socket.AF_INET:
        return socket.inet_ntoa(addr)
    elif af == socket.AF_INET6:
        # Use inet_ntop if available
        try:
            return socket.inet_ntop(af, addr)
        except AttributeError:
            return _ipv6_bin_to_str(addr)
    else:
        raise Exception("Address family not supported yet")


def _ipv6_bin_to_str(addr):
    # IPv6 addresses have 128bits (16 bytes)
    if len(addr) != 16:
        raise ValueError("invalid length of packed IP address string")

    # Decode to hex representation
    address = ":".join(addr[idx:idx + 2].encode('hex').lstrip('0') or '0' for idx in xrange(0, 16, 2))

    try:
        # Get the longest set of zero blocks
        # Actually we need to take a look at group 1 regarding the length as 0:0:1:0:0:2:3:4 would have two matches:
        # 0:0: and :0:0: where the latter is longer, though the first one should be taken. Group 1 is in both cases 0:0.
        match = max(_IP6_ZEROS.finditer(address), key=lambda m: m.end(1) - m.start(1))
        return '{}::{}'.format(address[:match.start()], address[match.end():])
    except ValueError:
        return address
