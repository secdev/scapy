# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

# Copyright (C) 2005  Guillaume Valadon <guedou@hongo.wide.ad.jp>
#                     Arnaud Ebalard <arnaud.ebalard@eads.net>

"""
Utility functions for IPv6.
"""
from __future__ import absolute_import
import operator
import random
import socket
import struct
import time
import re

from scapy.config import conf
import scapy.consts
from scapy.base_classes import Gen
from scapy.data import IPV6_ADDR_GLOBAL, IPV6_ADDR_LINKLOCAL, \
    IPV6_ADDR_SITELOCAL, IPV6_ADDR_LOOPBACK, IPV6_ADDR_UNICAST,\
    IPV6_ADDR_MULTICAST, IPV6_ADDR_6TO4, IPV6_ADDR_UNSPECIFIED
from scapy.utils import strxor
from scapy.compat import orb, chb
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.volatile import RandMAC
from scapy.error import warning, Scapy_Exception
from functools import reduce, cmp_to_key
from scapy.modules.six.moves import range, zip


def construct_source_candidate_set(addr, plen, laddr):
    """
    Given all addresses assigned to a specific interface ('laddr' parameter),
    this function returns the "candidate set" associated with 'addr/plen'.

    Basically, the function filters all interface addresses to keep only those
    that have the same scope as provided prefix.

    This is on this list of addresses that the source selection mechanism
    will then be performed to select the best source address associated
    with some specific destination that uses this prefix.
    """
    def cset_sort(x, y):
        x_global = 0
        if in6_isgladdr(x):
            x_global = 1
        y_global = 0
        if in6_isgladdr(y):
            y_global = 1
        res = y_global - x_global
        if res != 0 or y_global != 1:
            return res
        # two global addresses: if one is native, it wins.
        if not in6_isaddr6to4(x):
            return -1
        return -res

    cset = []
    if in6_isgladdr(addr) or in6_isuladdr(addr):
        cset = (x for x in laddr if x[1] == IPV6_ADDR_GLOBAL)
    elif in6_islladdr(addr):
        cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
    elif in6_issladdr(addr):
        cset = (x for x in laddr if x[1] == IPV6_ADDR_SITELOCAL)
    elif in6_ismaddr(addr):
        if in6_ismnladdr(addr):
            cset = [('::1', 16, scapy.consts.LOOPBACK_INTERFACE)]
        elif in6_ismgladdr(addr):
            cset = (x for x in laddr if x[1] == IPV6_ADDR_GLOBAL)
        elif in6_ismlladdr(addr):
            cset = (x for x in laddr if x[1] == IPV6_ADDR_LINKLOCAL)
        elif in6_ismsladdr(addr):
            cset = (x for x in laddr if x[1] == IPV6_ADDR_SITELOCAL)
    elif addr == '::' and plen == 0:
        cset = (x for x in laddr if x[1] == IPV6_ADDR_GLOBAL)
    cset = [x[0] for x in cset]
    # TODO convert the cmd use into a key
    cset.sort(key=cmp_to_key(cset_sort))  # Sort with global addresses first
    return cset


def get_source_addr_from_candidate_set(dst, candidate_set):
    """
    This function implement a limited version of source address selection
    algorithm defined in section 5 of RFC 3484. The format is very different
    from that described in the document because it operates on a set
    of candidate source address for some specific route.
    """

    def scope_cmp(a, b):
        """
        Given two addresses, returns -1, 0 or 1 based on comparison of
        their scope
        """
        scope_mapper = {IPV6_ADDR_GLOBAL: 4,
                        IPV6_ADDR_SITELOCAL: 3,
                        IPV6_ADDR_LINKLOCAL: 2,
                        IPV6_ADDR_LOOPBACK: 1}
        sa = in6_getscope(a)
        if sa == -1:
            sa = IPV6_ADDR_LOOPBACK
        sb = in6_getscope(b)
        if sb == -1:
            sb = IPV6_ADDR_LOOPBACK

        sa = scope_mapper[sa]
        sb = scope_mapper[sb]

        if sa == sb:
            return 0
        if sa > sb:
            return 1
        return -1

    def rfc3484_cmp(source_a, source_b):
        """
        The function implements a limited version of the rules from Source
        Address selection algorithm defined section of RFC 3484.
        """

        # Rule 1: Prefer same address
        if source_a == dst:
            return 1
        if source_b == dst:
            return 1

        # Rule 2: Prefer appropriate scope
        tmp = scope_cmp(source_a, source_b)
        if tmp == -1:
            if scope_cmp(source_a, dst) == -1:
                return 1
            else:
                return -1
        elif tmp == 1:
            if scope_cmp(source_b, dst) == -1:
                return 1
            else:
                return -1

        # Rule 3: cannot be easily implemented
        # Rule 4: cannot be easily implemented
        # Rule 5: does not make sense here
        # Rule 6: cannot be implemented
        # Rule 7: cannot be implemented

        # Rule 8: Longest prefix match
        tmp1 = in6_get_common_plen(source_a, dst)
        tmp2 = in6_get_common_plen(source_b, dst)
        if tmp1 > tmp2:
            return 1
        elif tmp2 > tmp1:
            return -1
        return 0

    if not candidate_set:
        # Should not happen
        return None

    candidate_set.sort(key=cmp_to_key(rfc3484_cmp), reverse=True)

    return candidate_set[0]


# Think before modify it : for instance, FE::1 does exist and is unicast
# there are many others like that.
# TODO : integrate Unique Local Addresses
def in6_getAddrType(addr):
    naddr = inet_pton(socket.AF_INET6, addr)
    paddr = inet_ntop(socket.AF_INET6, naddr)  # normalize
    addrType = 0
    # _Assignable_ Global Unicast Address space
    # is defined in RFC 3513 as those in 2000::/3
    if ((orb(naddr[0]) & 0xE0) == 0x20):
        addrType = (IPV6_ADDR_UNICAST | IPV6_ADDR_GLOBAL)
        if naddr[:2] == b' \x02':  # Mark 6to4 @
            addrType |= IPV6_ADDR_6TO4
    elif orb(naddr[0]) == 0xff:  # multicast
        addrScope = paddr[3]
        if addrScope == '2':
            addrType = (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_MULTICAST)
        elif addrScope == 'e':
            addrType = (IPV6_ADDR_GLOBAL | IPV6_ADDR_MULTICAST)
        else:
            addrType = (IPV6_ADDR_GLOBAL | IPV6_ADDR_MULTICAST)
    elif ((orb(naddr[0]) == 0xfe) and ((int(paddr[2], 16) & 0xC) == 0x8)):
        addrType = (IPV6_ADDR_UNICAST | IPV6_ADDR_LINKLOCAL)
    elif paddr == "::1":
        addrType = IPV6_ADDR_LOOPBACK
    elif paddr == "::":
        addrType = IPV6_ADDR_UNSPECIFIED
    else:
        # Everything else is global unicast (RFC 3513)
        # Even old deprecated (RFC3879) Site-Local addresses
        addrType = (IPV6_ADDR_GLOBAL | IPV6_ADDR_UNICAST)

    return addrType


def in6_mactoifaceid(mac, ulbit=None):
    """
    Compute the interface ID in modified EUI-64 format associated
    to the Ethernet address provided as input.
    value taken by U/L bit in the interface identifier is basically
    the reversed value of that in given MAC address it can be forced
    to a specific value by using optional 'ulbit' parameter.
    """
    if len(mac) != 17:
        return None
    m = "".join(mac.split(':'))
    if len(m) != 12:
        return None
    first = int(m[0:2], 16)
    if ulbit is None or not (ulbit == 0 or ulbit == 1):
        ulbit = [1, '-', 0][first & 0x02]
    ulbit *= 2
    first = "%.02x" % ((first & 0xFD) | ulbit)
    eui64 = first + m[2:4] + ":" + m[4:6] + "FF:FE" + m[6:8] + ":" + m[8:12]
    return eui64.upper()


def in6_ifaceidtomac(ifaceid):
    """
    Extract the mac address from provided iface ID. Iface ID is provided
    in printable format ("XXXX:XXFF:FEXX:XXXX", eventually compressed). None
    is returned on error.
    """
    try:
        # Set ifaceid to a binary form
        ifaceid = inet_pton(socket.AF_INET6, "::" + ifaceid)[8:16]
    except Exception:
        return None
    if ifaceid[3:5] != b'\xff\xfe':  # Check for burned-in MAC address
        return None

    # Unpacking and converting first byte of faceid to MAC address equivalent
    first = struct.unpack("B", ifaceid[:1])[0]
    ulbit = 2 * [1, '-', 0][first & 0x02]
    first = struct.pack("B", ((first & 0xFD) | ulbit))
    # Split into two vars to remove the \xff\xfe bytes
    oui = first + ifaceid[1:3]
    end = ifaceid[5:]
    # Convert and reconstruct into a MAC Address
    mac_bytes = ["%.02x" % orb(x) for x in list(oui + end)]
    return ":".join(mac_bytes)


def in6_addrtomac(addr):
    """
    Extract the mac address from provided address. None is returned
    on error.
    """
    mask = inet_pton(socket.AF_INET6, "::ffff:ffff:ffff:ffff")
    x = in6_and(mask, inet_pton(socket.AF_INET6, addr))
    ifaceid = inet_ntop(socket.AF_INET6, x)[2:]
    return in6_ifaceidtomac(ifaceid)


def in6_addrtovendor(addr):
    """
    Extract the MAC address from a modified EUI-64 constructed IPv6
    address provided and use the IANA oui.txt file to get the vendor.
    The database used for the conversion is the one loaded by Scapy
    from a Wireshark installation if discovered in a well-known
    location. None is returned on error, "UNKNOWN" if the vendor is
    unknown.
    """
    mac = in6_addrtomac(addr)
    if mac is None or not conf.manufdb:
        return None

    res = conf.manufdb._get_manuf(mac)
    if len(res) == 17 and res.count(':') != 5:  # Mac address, i.e. unknown
        res = "UNKNOWN"

    return res


def in6_getLinkScopedMcastAddr(addr, grpid=None, scope=2):
    """
    Generate a Link-Scoped Multicast Address as described in RFC 4489.
    Returned value is in printable notation.

    'addr' parameter specifies the link-local address to use for generating
    Link-scoped multicast address IID.

    By default, the function returns a ::/96 prefix (aka last 32 bits of
    returned address are null). If a group id is provided through 'grpid'
    parameter, last 32 bits of the address are set to that value (accepted
    formats : b'\x12\x34\x56\x78' or '12345678' or 0x12345678 or 305419896).

    By default, generated address scope is Link-Local (2). That value can
    be modified by passing a specific 'scope' value as an argument of the
    function. RFC 4489 only authorizes scope values <= 2. Enforcement
    is performed by the function (None will be returned).

    If no link-local address can be used to generate the Link-Scoped IPv6
    Multicast address, or if another error occurs, None is returned.
    """
    if scope not in [0, 1, 2]:
        return None
    try:
        if not in6_islladdr(addr):
            return None
        addr = inet_pton(socket.AF_INET6, addr)
    except Exception:
        warning("in6_getLinkScopedMcastPrefix(): Invalid address provided")
        return None

    iid = addr[8:]

    if grpid is None:
        grpid = b'\x00\x00\x00\x00'
    else:
        if isinstance(grpid, (bytes, str)):
            if len(grpid) == 8:
                try:
                    grpid = int(grpid, 16) & 0xffffffff
                except Exception:
                    warning("in6_getLinkScopedMcastPrefix(): Invalid group id provided")  # noqa: E501
                    return None
            elif len(grpid) == 4:
                try:
                    grpid = struct.unpack("!I", grpid)[0]
                except Exception:
                    warning("in6_getLinkScopedMcastPrefix(): Invalid group id provided")  # noqa: E501
                    return None
        grpid = struct.pack("!I", grpid)

    flgscope = struct.pack("B", 0xff & ((0x3 << 4) | scope))
    plen = b'\xff'
    res = b'\x00'
    a = b'\xff' + flgscope + res + plen + iid + grpid

    return inet_ntop(socket.AF_INET6, a)


def in6_get6to4Prefix(addr):
    """
    Returns the /48 6to4 prefix associated with provided IPv4 address
    On error, None is returned. No check is performed on public/private
    status of the address
    """
    try:
        addr = inet_pton(socket.AF_INET, addr)
        addr = inet_ntop(socket.AF_INET6, b'\x20\x02' + addr + b'\x00' * 10)
    except Exception:
        return None
    return addr


def in6_6to4ExtractAddr(addr):
    """
    Extract IPv4 address embedded in 6to4 address. Passed address must be
    a 6to4 address. None is returned on error.
    """
    try:
        addr = inet_pton(socket.AF_INET6, addr)
    except Exception:
        return None
    if addr[:2] != b" \x02":
        return None
    return inet_ntop(socket.AF_INET, addr[2:6])


def in6_getLocalUniquePrefix():
    """
    Returns a pseudo-randomly generated Local Unique prefix. Function
    follows recommendation of Section 3.2.2 of RFC 4193 for prefix
    generation.
    """
    # Extracted from RFC 1305 (NTP) :
    # NTP timestamps are represented as a 64-bit unsigned fixed-point number,
    # in seconds relative to 0h on 1 January 1900. The integer part is in the
    # first 32 bits and the fraction part in the last 32 bits.

    # epoch = (1900, 1, 1, 0, 0, 0, 5, 1, 0)
    # x = time.time()
    # from time import gmtime, strftime, gmtime, mktime
    # delta = mktime(gmtime(0)) - mktime(self.epoch)
    # x = x-delta

    tod = time.time()  # time of day. Will bother with epoch later
    i = int(tod)
    j = int((tod - i) * (2**32))
    tod = struct.pack("!II", i, j)
    mac = RandMAC()
    # construct modified EUI-64 ID
    eui64 = inet_pton(socket.AF_INET6, '::' + in6_mactoifaceid(mac))[8:]
    import hashlib
    globalid = hashlib.sha1(tod + eui64).digest()[:5]
    return inet_ntop(socket.AF_INET6, b'\xfd' + globalid + b'\x00' * 10)


def in6_getRandomizedIfaceId(ifaceid, previous=None):
    """
    Implements the interface ID generation algorithm described in RFC 3041.
    The function takes the Modified EUI-64 interface identifier generated
    as described in RFC 4291 and an optional previous history value (the
    first element of the output of this function). If no previous interface
    identifier is provided, a random one is generated. The function returns
    a tuple containing the randomized interface identifier and the history
    value (for possible future use). Input and output values are provided in
    a "printable" format as depicted below.

    ex::
        >>> in6_getRandomizedIfaceId('20b:93ff:feeb:2d3')
        ('4c61:76ff:f46a:a5f3', 'd006:d540:db11:b092')
        >>> in6_getRandomizedIfaceId('20b:93ff:feeb:2d3',
                                     previous='d006:d540:db11:b092')
        ('fe97:46fe:9871:bd38', 'eeed:d79c:2e3f:62e')
    """

    s = b""
    if previous is None:
        d = b"".join(chb(x) for x in range(256))
        for _ in range(8):
            s += chb(random.choice(d))
        previous = s
    s = inet_pton(socket.AF_INET6, "::" + ifaceid)[8:] + previous
    import hashlib
    s = hashlib.md5(s).digest()
    s1, s2 = s[:8], s[8:]
    s1 = chb(orb(s1[0]) | 0x04) + s1[1:]
    s1 = inet_ntop(socket.AF_INET6, b"\xff" * 8 + s1)[20:]
    s2 = inet_ntop(socket.AF_INET6, b"\xff" * 8 + s2)[20:]
    return (s1, s2)


_rfc1924map = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',  # noqa: E501
               'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',  # noqa: E501
               'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',  # noqa: E501
               'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',  # noqa: E501
               'y', 'z', '!', '#', '$', '%', '&', '(', ')', '*', '+', '-', ';', '<', '=',  # noqa: E501
               '>', '?', '@', '^', '_', '`', '{', '|', '}', '~']


def in6_ctop(addr):
    """
    Convert an IPv6 address in Compact Representation Notation
    (RFC 1924) to printable representation ;-)
    Returns None on error.
    """
    if len(addr) != 20 or not reduce(lambda x, y: x and y,
                                     [x in _rfc1924map for x in addr]):
        return None
    i = 0
    for c in addr:
        j = _rfc1924map.index(c)
        i = 85 * i + j
    res = []
    for j in range(4):
        res.append(struct.pack("!I", i % 2**32))
        i = i // (2**32)
    res.reverse()
    return inet_ntop(socket.AF_INET6, b"".join(res))


def in6_ptoc(addr):
    """
    Converts an IPv6 address in printable representation to RFC
    1924 Compact Representation ;-)
    Returns None on error.
    """
    try:
        d = struct.unpack("!IIII", inet_pton(socket.AF_INET6, addr))
    except Exception:
        return None
    res = 0
    m = [2**96, 2**64, 2**32, 1]
    for i in range(4):
        res += d[i] * m[i]
    rem = res
    res = []
    while rem:
        res.append(_rfc1924map[rem % 85])
        rem = rem // 85
    res.reverse()
    return "".join(res)


def in6_isaddr6to4(x):
    """
    Return True if provided address (in printable format) is a 6to4
    address (being in 2002::/16).
    """
    x = inet_pton(socket.AF_INET6, x)
    return x[:2] == b' \x02'


conf.teredoPrefix = "2001::"  # old one was 3ffe:831f (it is a /32)
conf.teredoServerPort = 3544


def in6_isaddrTeredo(x):
    """
    Return True if provided address is a Teredo, meaning it is under
    the /32 conf.teredoPrefix prefix value (by default, 2001::).
    Otherwise, False is returned. Address must be passed in printable
    format.
    """
    our = inet_pton(socket.AF_INET6, x)[0:4]
    teredoPrefix = inet_pton(socket.AF_INET6, conf.teredoPrefix)[0:4]
    return teredoPrefix == our


def teredoAddrExtractInfo(x):
    """
    Extract information from a Teredo address. Return value is
    a 4-tuple made of IPv4 address of Teredo server, flag value (int),
    mapped address (non obfuscated) and mapped port (non obfuscated).
    No specific checks are performed on passed address.
    """
    addr = inet_pton(socket.AF_INET6, x)
    server = inet_ntop(socket.AF_INET, addr[4:8])
    flag = struct.unpack("!H", addr[8:10])[0]
    mappedport = struct.unpack("!H", strxor(addr[10:12], b'\xff' * 2))[0]
    mappedaddr = inet_ntop(socket.AF_INET, strxor(addr[12:16], b'\xff' * 4))
    return server, flag, mappedaddr, mappedport


def in6_iseui64(x):
    """
    Return True if provided address has an interface identifier part
    created in modified EUI-64 format (meaning it matches ``*::*:*ff:fe*:*``).
    Otherwise, False is returned. Address must be passed in printable
    format.
    """
    eui64 = inet_pton(socket.AF_INET6, '::ff:fe00:0')
    x = in6_and(inet_pton(socket.AF_INET6, x), eui64)
    return x == eui64


def in6_isanycast(x):  # RFC 2526
    if in6_iseui64(x):
        s = '::fdff:ffff:ffff:ff80'
        packed_x = inet_pton(socket.AF_INET6, x)
        packed_s = inet_pton(socket.AF_INET6, s)
        x_and_s = in6_and(packed_x, packed_s)
        return x_and_s == packed_s
    else:
        # not EUI-64
        # |              n bits             |    121-n bits    |   7 bits   |
        # +---------------------------------+------------------+------------+
        # |           subnet prefix         | 1111111...111111 | anycast ID |
        # +---------------------------------+------------------+------------+
        #                                   |   interface identifier field  |
        warning('in6_isanycast(): TODO not EUI-64')
        return 0


def _in6_bitops(a1, a2, operator=0):
    a1 = struct.unpack('4I', a1)
    a2 = struct.unpack('4I', a2)
    fop = [lambda x, y: x | y,
           lambda x, y: x & y,
           lambda x, y: x ^ y
           ]
    ret = map(fop[operator % len(fop)], a1, a2)
    return b"".join(struct.pack('I', x) for x in ret)


def in6_or(a1, a2):
    """
    Provides a bit to bit OR of provided addresses. They must be
    passed in network format. Return value is also an IPv6 address
    in network format.
    """
    return _in6_bitops(a1, a2, 0)


def in6_and(a1, a2):
    """
    Provides a bit to bit AND of provided addresses. They must be
    passed in network format. Return value is also an IPv6 address
    in network format.
    """
    return _in6_bitops(a1, a2, 1)


def in6_xor(a1, a2):
    """
    Provides a bit to bit XOR of provided addresses. They must be
    passed in network format. Return value is also an IPv6 address
    in network format.
    """
    return _in6_bitops(a1, a2, 2)


def in6_cidr2mask(m):
    """
    Return the mask (bitstring) associated with provided length
    value. For instance if function is called on 48, return value is
    b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'.

    """
    if m > 128 or m < 0:
        raise Scapy_Exception("value provided to in6_cidr2mask outside [0, 128] domain (%d)" % m)  # noqa: E501

    t = []
    for i in range(0, 4):
        t.append(max(0, 2**32 - 2**(32 - min(32, m))))
        m -= 32

    return b"".join(struct.pack('!I', x) for x in t)


def in6_getnsma(a):
    """
    Return link-local solicited-node multicast address for given
    address. Passed address must be provided in network format.
    Returned value is also in network format.
    """

    r = in6_and(a, inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)
    return r


def in6_getnsmac(a):  # return multicast Ethernet address associated with multicast v6 destination  # noqa: E501
    """
    Return the multicast mac address associated with provided
    IPv6 address. Passed address must be in network format.
    """

    a = struct.unpack('16B', a)[-4:]
    mac = '33:33:'
    mac += ':'.join("%.2x" % x for x in a)
    return mac


def in6_getha(prefix):
    """
    Return the anycast address associated with all home agents on a given
    subnet.
    """
    r = in6_and(inet_pton(socket.AF_INET6, prefix), in6_cidr2mask(64))
    r = in6_or(r, inet_pton(socket.AF_INET6, '::fdff:ffff:ffff:fffe'))
    return inet_ntop(socket.AF_INET6, r)


def in6_ptop(str):
    """
    Normalizes IPv6 addresses provided in printable format, returning the
    same address in printable format. (2001:0db8:0:0::1 -> 2001:db8::1)
    """
    return inet_ntop(socket.AF_INET6, inet_pton(socket.AF_INET6, str))


def in6_isincluded(addr, prefix, plen):
    """
    Returns True when 'addr' belongs to prefix/plen. False otherwise.
    """
    temp = inet_pton(socket.AF_INET6, addr)
    pref = in6_cidr2mask(plen)
    zero = inet_pton(socket.AF_INET6, prefix)
    return zero == in6_and(temp, pref)


def in6_isllsnmaddr(str):
    """
    Return True if provided address is a link-local solicited node
    multicast address, i.e. belongs to ff02::1:ff00:0/104. False is
    returned otherwise.
    """
    temp = in6_and(b"\xff" * 13 + b"\x00" * 3, inet_pton(socket.AF_INET6, str))
    temp2 = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00'
    return temp == temp2


def in6_isdocaddr(str):
    """
    Returns True if provided address in printable format belongs to
    2001:db8::/32 address space reserved for documentation (as defined
    in RFC 3849).
    """
    return in6_isincluded(str, '2001:db8::', 32)


def in6_islladdr(str):
    """
    Returns True if provided address in printable format belongs to
    _allocated_ link-local unicast address space (fe80::/10)
    """
    return in6_isincluded(str, 'fe80::', 10)


def in6_issladdr(str):
    """
    Returns True if provided address in printable format belongs to
    _allocated_ site-local address space (fec0::/10). This prefix has
    been deprecated, address being now reserved by IANA. Function
    will remain for historic reasons.
    """
    return in6_isincluded(str, 'fec0::', 10)


def in6_isuladdr(str):
    """
    Returns True if provided address in printable format belongs to
    Unique local address space (fc00::/7).
    """
    return in6_isincluded(str, 'fc00::', 7)

# TODO : we should see the status of Unique Local addresses against
#        global address space.
#        Up-to-date information is available through RFC 3587.
#        We should review function behavior based on its content.


def in6_isgladdr(str):
    """
    Returns True if provided address in printable format belongs to
    _allocated_ global address space (2000::/3). Please note that,
    Unique Local addresses (FC00::/7) are not part of global address
    space, and won't match.
    """
    return in6_isincluded(str, '2000::', 3)


def in6_ismaddr(str):
    """
    Returns True if provided address in printable format belongs to
    allocated Multicast address space (ff00::/8).
    """
    return in6_isincluded(str, 'ff00::', 8)


def in6_ismnladdr(str):
    """
    Returns True if address belongs to node-local multicast address
    space (ff01::/16) as defined in RFC
    """
    return in6_isincluded(str, 'ff01::', 16)


def in6_ismgladdr(str):
    """
    Returns True if address belongs to global multicast address
    space (ff0e::/16).
    """
    return in6_isincluded(str, 'ff0e::', 16)


def in6_ismlladdr(str):
    """
    Returns True if address belongs to link-local multicast address
    space (ff02::/16)
    """
    return in6_isincluded(str, 'ff02::', 16)


def in6_ismsladdr(str):
    """
    Returns True if address belongs to site-local multicast address
    space (ff05::/16). Site local address space has been deprecated.
    Function remains for historic reasons.
    """
    return in6_isincluded(str, 'ff05::', 16)


def in6_isaddrllallnodes(str):
    """
    Returns True if address is the link-local all-nodes multicast
    address (ff02::1).
    """
    return (inet_pton(socket.AF_INET6, "ff02::1") ==
            inet_pton(socket.AF_INET6, str))


def in6_isaddrllallservers(str):
    """
    Returns True if address is the link-local all-servers multicast
    address (ff02::2).
    """
    return (inet_pton(socket.AF_INET6, "ff02::2") ==
            inet_pton(socket.AF_INET6, str))


def in6_getscope(addr):
    """
    Returns the scope of the address.
    """
    if in6_isgladdr(addr) or in6_isuladdr(addr):
        scope = IPV6_ADDR_GLOBAL
    elif in6_islladdr(addr):
        scope = IPV6_ADDR_LINKLOCAL
    elif in6_issladdr(addr):
        scope = IPV6_ADDR_SITELOCAL
    elif in6_ismaddr(addr):
        if in6_ismgladdr(addr):
            scope = IPV6_ADDR_GLOBAL
        elif in6_ismlladdr(addr):
            scope = IPV6_ADDR_LINKLOCAL
        elif in6_ismsladdr(addr):
            scope = IPV6_ADDR_SITELOCAL
        elif in6_ismnladdr(addr):
            scope = IPV6_ADDR_LOOPBACK
        else:
            scope = -1
    elif addr == '::1':
        scope = IPV6_ADDR_LOOPBACK
    else:
        scope = -1
    return scope


def in6_get_common_plen(a, b):
    """
    Return common prefix length of IPv6 addresses a and b.
    """
    def matching_bits(byte1, byte2):
        for i in range(8):
            cur_mask = 0x80 >> i
            if (byte1 & cur_mask) != (byte2 & cur_mask):
                return i
        return 8

    tmpA = inet_pton(socket.AF_INET6, a)
    tmpB = inet_pton(socket.AF_INET6, b)
    for i in range(16):
        mbits = matching_bits(orb(tmpA[i]), orb(tmpB[i]))
        if mbits != 8:
            return 8 * i + mbits
    return 128


def in6_isvalid(address):
    """Return True if 'address' is a valid IPv6 address string, False
       otherwise."""

    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except Exception:
        return False


class Net6(Gen):  # syntax ex. fec0::/126
    """Generate a list of IPv6s from a network address or a name"""
    name = "ipv6"
    ip_regex = re.compile(r"^([a-fA-F0-9:]+)(/[1]?[0-3]?[0-9])?$")

    def __init__(self, net):
        self.repr = net

        tmp = net.split('/') + ["128"]
        if not self.ip_regex.match(net):
            tmp[0] = socket.getaddrinfo(tmp[0], None, socket.AF_INET6)[0][-1][0]  # noqa: E501

        netmask = int(tmp[1])
        self.net = inet_pton(socket.AF_INET6, tmp[0])
        self.mask = in6_cidr2mask(netmask)
        self.plen = netmask

    def _parse(self):
        def parse_digit(value, netmask):
            netmask = min(8, max(netmask, 0))
            value = int(value)
            return (value & (0xff << netmask),
                    (value | (0xff >> (8 - netmask))) + 1)

        self.parsed = [
            parse_digit(x, y) for x, y in zip(
                struct.unpack("16B", in6_and(self.net, self.mask)),
                (x - self.plen for x in range(8, 129, 8)),
            )
        ]

    def __iter__(self):
        self._parse()

        def rec(n, l):
            sep = ':' if n and n % 2 == 0 else ''
            if n == 16:
                return l
            return rec(n + 1, [y + sep + '%.2x' % i
                               # faster than '%s%s%.2x' % (y, sep, i)
                               for i in range(*self.parsed[n])
                               for y in l])

        return (in6_ptop(addr) for addr in iter(rec(0, [''])))

    def __iterlen__(self):
        self._parse()
        return reduce(operator.mul, ((y - x) for (x, y) in self.parsed), 1)

    def __str__(self):
        try:
            return next(self.__iter__())
        except (StopIteration, RuntimeError):
            return None

    def __eq__(self, other):
        return str(other) == str(self)

    def __ne__(self, other):
        return not self == other

    __hash__ = None

    def __repr__(self):
        return "Net6(%r)" % self.repr
