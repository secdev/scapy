# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
DNS: Domain Name System

This implements:
- RFC1035: Domain Names
- RFC6762: Multicast DNS
- RFC6763: DNS-Based Service Discovery
"""

import abc
import collections
import operator
import itertools
import socket
import struct
import time
import warnings

from scapy.arch import (
    get_if_addr,
    get_if_addr6,
    read_nameservers,
)
from scapy.ansmachine import AnsweringMachine
from scapy.base_classes import Net, ScopedIP
from scapy.config import conf
from scapy.compat import orb, raw, chb, bytes_encode, plain_str
from scapy.error import log_runtime, warning, Scapy_Exception
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FieldListField,
    FlagsField,
    I,
    IP6Field,
    IntField,
    MACField,
    MultipleTypeField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrField,
    StrLenField,
    UTCTimeField,
    XStrFixedLenField,
    XStrLenField,
)
from scapy.interfaces import resolve_iface
from scapy.sendrecv import sr1, sr
from scapy.supersocket import StreamSocket
from scapy.plist import SndRcvList, _PacketList, QueryAnswer
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.utils import pretty_list
from scapy.volatile import RandShort

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, DestIPField, IPField, UDP, TCP
from scapy.layers.inet6 import IPv6

from typing import (
    Any,
    List,
    Optional,
    Tuple,
    Type,
    Union,
)


# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
dnstypes = {
    0: "RESERVED",
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
    9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN",
    21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
    27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC",
    33: "SRV", 34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6",
    39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP",
    45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
    50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
    56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 60: "CDNSKEY",
    61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 100: "UINFO", 101: "UID", 102: "GID", 103: "UNSPEC", 104: "NID",
    105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64", 249: "TKEY",
    250: "TSIG", 256: "URI", 257: "CAA", 258: "AVC", 259: "DOA",
    260: "AMTRELAY", 32768: "TA", 32769: "DLV", 65535: "RESERVED"
}


dnsqtypes = {251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "ALL"}
dnsqtypes.update(dnstypes)
dnsclasses = {1: 'IN', 2: 'CS', 3: 'CH', 4: 'HS', 255: 'ANY'}


# 12/2023 from https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml  # noqa: E501
dnssecalgotypes = {0: "Reserved", 1: "RSA/MD5", 2: "Diffie-Hellman", 3: "DSA/SHA-1",  # noqa: E501
                   4: "Reserved", 5: "RSA/SHA-1", 6: "DSA-NSEC3-SHA1",
                   7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 9: "Reserved",
                   10: "RSA/SHA-512", 11: "Reserved", 12: "GOST R 34.10-2001",
                   13: "ECDSA Curve P-256 with SHA-256", 14: "ECDSA Curve P-384 with SHA-384",  # noqa: E501
                   15: "Ed25519", 16: "Ed448",
                   252: "Reserved for Indirect Keys", 253: "Private algorithms - domain name",  # noqa: E501
                   254: "Private algorithms - OID", 255: "Reserved"}

# 12/2023 from https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
dnssecdigesttypes = {0: "Reserved", 1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384"}  # noqa: E501

# 12/2023 from https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml  # noqa: E501
dnssecnsec3algotypes = {0: "Reserved", 1: "SHA-1"}


def dns_get_str(s, full=None, _ignore_compression=False):
    """This function decompresses a string s, starting
    from the given pointer.

    :param s: the string to decompress
    :param full: (optional) the full packet (used for decompression)

    :returns: (decoded_string, end_index, left_string)
    """
    # _ignore_compression is for internal use only
    max_length = len(s)
    # The result = the extracted name
    name = b""
    # Will contain the index after the pointer, to be returned
    after_pointer = None
    processed_pointers = []  # Used to check for decompression loops
    bytes_left = None
    _fullpacket = False  # s = full packet
    pointer = 0
    while True:
        if abs(pointer) >= max_length:
            log_runtime.info(
                "DNS RR prematured end (ofs=%i, len=%i)", pointer, len(s)
            )
            break
        cur = s[pointer]  # get pointer value
        pointer += 1  # make pointer go forward
        if cur & 0xc0:  # Label pointer
            if after_pointer is None:
                # after_pointer points to where the remaining bytes start,
                # as pointer will follow the jump token
                after_pointer = pointer + 1
            if _ignore_compression:
                # skip
                pointer += 1
                continue
            if pointer >= max_length:
                log_runtime.info(
                    "DNS incomplete jump token at (ofs=%i)", pointer
                )
                break
            if not full:
                raise Scapy_Exception("DNS message can't be compressed " +
                                      "at this point!")
            # Follow the pointer
            pointer = ((cur & ~0xc0) << 8) + s[pointer]
            if pointer in processed_pointers:
                warning("DNS decompression loop detected")
                break
            if len(processed_pointers) >= 20:
                warning("More than 20 jumps in a single DNS decompression ! "
                        "Dropping (evil packet)")
                break
            if not _fullpacket:
                # We switch our s buffer to full, so we need to remember
                # the previous context
                bytes_left = s[after_pointer:]
                s = full
                max_length = len(s)
                _fullpacket = True
            processed_pointers.append(pointer)
            continue
        elif cur > 0:  # Label
            # cur = length of the string
            name += s[pointer:pointer + cur] + b"."
            pointer += cur
        else:  # End
            break
    if after_pointer is not None:
        # Return the real end index (not the one we followed)
        pointer = after_pointer
    if bytes_left is None:
        bytes_left = s[pointer:]
    # name, remaining
    return name or b".", bytes_left


def _is_ptr(x):
    return b"." not in x and (
        (x and orb(x[-1]) == 0) or
        (len(x) >= 2 and (orb(x[-2]) & 0xc0) == 0xc0)
    )


def dns_encode(x, check_built=False):
    """Encodes a bytes string into the DNS format

    :param x: the string
    :param check_built: detect already-built strings and ignore them
    :returns: the encoded bytes string
    """
    if not x or x == b".":
        return b"\x00"

    if check_built and _is_ptr(x):
        # The value has already been processed. Do not process it again
        return x

    # Truncate chunks that cannot be encoded (more than 63 bytes..)
    x = b"".join(chb(len(y)) + y for y in (k[:63] for k in x.split(b".")))
    if x[-1:] != b"\x00":
        x += b"\x00"
    return x


def DNSgetstr(*args, **kwargs):
    """Legacy function. Deprecated"""
    warnings.warn(
        "DNSgetstr is deprecated. Use dns_get_str instead.",
        DeprecationWarning
    )
    return dns_get_str(*args, **kwargs)[:-1]


def dns_compress(pkt):
    """This function compresses a DNS packet according to compression rules.
    """
    if DNS not in pkt:
        raise Scapy_Exception("Can only compress DNS layers")
    pkt = pkt.copy()
    dns_pkt = pkt.getlayer(DNS)
    dns_pkt.clear_cache()
    build_pkt = raw(dns_pkt)

    def field_gen(dns_pkt):
        """Iterates through all DNS strings that can be compressed"""
        for lay in [dns_pkt.qd, dns_pkt.an, dns_pkt.ns, dns_pkt.ar]:
            if not lay:
                continue
            for current in lay:
                for field in current.fields_desc:
                    if isinstance(field, DNSStrField) or \
                        (isinstance(field, MultipleTypeField) and
                         current.type in [2, 3, 4, 5, 12, 15, 39, 47]):
                        # Get the associated data and store it accordingly  # noqa: E501
                        dat = current.getfieldval(field.name)
                        yield current, field.name, dat

    def possible_shortens(dat):
        """Iterates through all possible compression parts in a DNS string"""
        if dat == b".":  # we'd lose by compressing it
            return
        yield dat
        for x in range(1, dat.count(b".")):
            yield dat.split(b".", x)[x]
    data = {}
    for current, name, dat in field_gen(dns_pkt):
        for part in possible_shortens(dat):
            # Encode the data
            encoded = dns_encode(part, check_built=True)
            if part not in data:
                # We have no occurrence of such data, let's store it as a
                # possible pointer for future strings.
                # We get the index of the encoded data
                index = build_pkt.index(encoded)
                # The following is used to build correctly the pointer
                fb_index = ((index >> 8) | 0xc0)
                sb_index = index - (256 * (fb_index - 0xc0))
                pointer = chb(fb_index) + chb(sb_index)
                data[part] = [(current, name, pointer, index + 1)]
            else:
                # This string already exists, let's mark the current field
                # with it, so that it gets compressed
                data[part].append((current, name))
                _in = data[part][0][3]
                build_pkt = build_pkt[:_in] + build_pkt[_in:].replace(
                    encoded,
                    b"\0\0",
                    1
                )
                break
    # Apply compression rules
    for ck in data:
        # compression_key is a DNS string
        replacements = data[ck]
        # replacements is the list of all tuples (layer, field name)
        # where this string was found
        replace_pointer = replacements.pop(0)[2]
        # replace_pointer is the packed pointer that should replace
        # those strings. Note that pop remove it from the list
        for rep in replacements:
            # setfieldval edits the value of the field in the layer
            val = rep[0].getfieldval(rep[1])
            assert val.endswith(ck)
            kept_string = dns_encode(val[:-len(ck)], check_built=True)[:-1]
            new_val = kept_string + replace_pointer
            rep[0].setfieldval(rep[1], new_val)
            try:
                del rep[0].rdlen
            except AttributeError:
                pass
    # End of the compression algorithm
    # Destroy the previous DNS layer if needed
    if not isinstance(pkt, DNS) and pkt.getlayer(DNS).underlayer:
        pkt.getlayer(DNS).underlayer.remove_payload()
        return pkt / dns_pkt
    return dns_pkt


class DNSCompressedPacket(Packet):
    """
    Class to mark that a packet contains DNSStrField and supports compression
    """
    @abc.abstractmethod
    def get_full(self):
        pass


class DNSStrField(StrLenField):
    """
    Special StrField that handles DNS encoding/decoding.
    It will also handle DNS decompression.
    (may be StrLenField if a length_from is passed),
    """
    def any2i(self, pkt, x):
        if x and isinstance(x, list):
            return [self.h2i(pkt, y) for y in x]
        return super(DNSStrField, self).any2i(pkt, x)

    def h2i(self, pkt, x):
        # Setting a DNSStrField manually (h2i) means any current compression will break
        if (
            pkt and
            isinstance(pkt.parent, DNSCompressedPacket) and
            pkt.parent.raw_packet_cache
        ):
            pkt.parent.clear_cache()
        if not x:
            return b"."
        x = bytes_encode(x)
        if x[-1:] != b"." and not _is_ptr(x):
            return x + b"."
        return x

    def i2m(self, pkt, x):
        return dns_encode(x, check_built=True)

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def get_full(self, pkt):
        while pkt and not isinstance(pkt, DNSCompressedPacket):
            pkt = pkt.parent or pkt.underlayer
        if not pkt:
            return None
        return pkt.get_full()

    def getfield(self, pkt, s):
        remain = b""
        if self.length_from:
            remain, s = super(DNSStrField, self).getfield(pkt, s)
        # Decode the compressed DNS message
        decoded, left = dns_get_str(s, full=self.get_full(pkt))
        # returns (remaining, decoded)
        return left + remain, decoded


class DNSTextField(StrLenField):
    """
    Special StrLenField that handles DNS TEXT data (16)
    """

    islist = 1

    def i2h(self, pkt, x):
        if not x:
            return []
        return x

    def m2i(self, pkt, s):
        ret_s = list()
        tmp_s = s
        # RDATA contains a list of strings, each are prepended with
        # a byte containing the size of the following string.
        while tmp_s:
            tmp_len = orb(tmp_s[0]) + 1
            if tmp_len > len(tmp_s):
                log_runtime.info(
                    "DNS RR TXT prematured end of character-string "
                    "(size=%i, remaining bytes=%i)", tmp_len, len(tmp_s)
                )
            ret_s.append(tmp_s[1:tmp_len])
            tmp_s = tmp_s[tmp_len:]
        return ret_s

    def any2i(self, pkt, x):
        if isinstance(x, (str, bytes)):
            return [x]
        return x

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def i2m(self, pkt, s):
        ret_s = b""
        for text in s:
            if not text:
                ret_s += b"\x00"
                continue
            text = bytes_encode(text)
            # The initial string must be split into a list of strings
            # prepended with theirs sizes.
            while len(text) >= 255:
                ret_s += b"\xff" + text[:255]
                text = text[255:]
            # The remaining string is less than 255 bytes long
            if len(text):
                ret_s += struct.pack("!B", len(text)) + text
        return ret_s


# RFC 2671 - Extension Mechanisms for DNS (EDNS0)

edns0types = {0: "Reserved", 1: "LLQ", 2: "UL", 3: "NSID", 4: "Owner",
              5: "DAU", 6: "DHU", 7: "N3U", 8: "edns-client-subnet", 10: "COOKIE",
              15: "Extended DNS Error"}


class _EDNS0Dummy(Packet):
    name = "Dummy class that implements extract_padding()"

    def extract_padding(self, p):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return "", p


class EDNS0TLV(_EDNS0Dummy):
    name = "DNS EDNS0 TLV"
    fields_desc = [ShortEnumField("optcode", 0, edns0types),
                   FieldLenField("optlen", None, "optdata", fmt="H"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Type[Packet]
        if _pkt is None:
            return EDNS0TLV
        if len(_pkt) < 2:
            return Raw
        edns0type = struct.unpack("!H", _pkt[:2])[0]
        return EDNS0OPT_DISPATCHER.get(edns0type, EDNS0TLV)


class DNSRROPT(Packet):
    name = "DNS OPT Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 41, dnstypes),
                   ShortEnumField("rclass", 4096, dnsclasses),
                   ByteField("extrcode", 0),
                   ByteField("version", 0),
                   # version 0 means EDNS0
                   BitEnumField("z", 32768, 16, {32768: "D0"}),
                   # D0 means DNSSEC OK from RFC 3225
                   FieldLenField("rdlen", None, length_of="rdata", fmt="H"),
                   PacketListField("rdata", [], EDNS0TLV,
                                   length_from=lambda pkt: pkt.rdlen)]


# draft-cheshire-edns0-owner-option-01 - EDNS0 OWNER Option

class EDNS0OWN(_EDNS0Dummy):
    name = "EDNS0 Owner (OWN)"
    fields_desc = [ShortEnumField("optcode", 4, edns0types),
                   FieldLenField("optlen", None, count_of="primary_mac", fmt="H"),
                   ByteField("v", 0),
                   ByteField("s", 0),
                   MACField("primary_mac", "00:00:00:00:00:00"),
                   ConditionalField(
                       MACField("wakeup_mac", "00:00:00:00:00:00"),
                       lambda pkt: (pkt.optlen or 0) >= 18),
                   ConditionalField(
                       StrLenField("password", "",
                                   length_from=lambda pkt: pkt.optlen - 18),
                       lambda pkt: (pkt.optlen or 0) >= 22)]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.optlen is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt) - 4) + pkt[4:]
        return pkt


# RFC 6975 - Signaling Cryptographic Algorithm Understanding in
# DNS Security Extensions (DNSSEC)

class EDNS0DAU(_EDNS0Dummy):
    name = "DNSSEC Algorithm Understood (DAU)"
    fields_desc = [ShortEnumField("optcode", 5, edns0types),
                   FieldLenField("optlen", None, count_of="alg_code", fmt="H"),
                   FieldListField("alg_code", None,
                                  ByteEnumField("", 0, dnssecalgotypes),
                                  count_from=lambda pkt:pkt.optlen)]


class EDNS0DHU(_EDNS0Dummy):
    name = "DS Hash Understood (DHU)"
    fields_desc = [ShortEnumField("optcode", 6, edns0types),
                   FieldLenField("optlen", None, count_of="alg_code", fmt="H"),
                   FieldListField("alg_code", None,
                                  ByteEnumField("", 0, dnssecdigesttypes),
                                  count_from=lambda pkt:pkt.optlen)]


class EDNS0N3U(_EDNS0Dummy):
    name = "NSEC3 Hash Understood (N3U)"
    fields_desc = [ShortEnumField("optcode", 7, edns0types),
                   FieldLenField("optlen", None, count_of="alg_code", fmt="H"),
                   FieldListField("alg_code", None,
                                  ByteEnumField("", 0, dnssecnsec3algotypes),
                                  count_from=lambda pkt:pkt.optlen)]


# RFC 7871 - Client Subnet in DNS Queries

class ClientSubnetv4(StrLenField):
    af_familly = socket.AF_INET
    af_length = 32
    af_default = b"\xc0"  # 192.0.0.0

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, I]
        sz = operator.floordiv(self.length_from(pkt), 8)
        sz = min(sz, operator.floordiv(self.af_length, 8))
        return s[sz:], self.m2i(pkt, s[:sz])

    def m2i(self, pkt, x):
        # type: (Optional[Packet], bytes) -> str
        padding = self.af_length - self.length_from(pkt)
        if padding:
            x += b"\x00" * operator.floordiv(padding, 8)
        x = x[: operator.floordiv(self.af_length, 8)]
        return inet_ntop(self.af_familly, x)

    def _pack_subnet(self, subnet):
        # type: (bytes) -> bytes
        packed_subnet = inet_pton(self.af_familly, plain_str(subnet))
        for i in list(range(operator.floordiv(self.af_length, 8)))[::-1]:
            if orb(packed_subnet[i]) != 0:
                i += 1
                break
        return packed_subnet[:i]

    def i2m(self, pkt, x):
        # type: (Optional[Packet], Optional[Union[str, Net]]) -> bytes
        if x is None:
            return self.af_default
        try:
            return self._pack_subnet(x)
        except (OSError, socket.error):
            pkt.family = 2
            return ClientSubnetv6("", "")._pack_subnet(x)

    def i2len(self, pkt, x):
        # type: (Packet, Any) -> int
        if x is None:
            return 1
        try:
            return len(self._pack_subnet(x))
        except (OSError, socket.error):
            pkt.family = 2
            return len(ClientSubnetv6("", "")._pack_subnet(x))


class ClientSubnetv6(ClientSubnetv4):
    af_familly = socket.AF_INET6
    af_length = 128
    af_default = b"\x20"  # 2000::


class EDNS0ClientSubnet(_EDNS0Dummy):
    name = "DNS EDNS0 Client Subnet"
    fields_desc = [ShortEnumField("optcode", 8, edns0types),
                   FieldLenField("optlen", None, "address", fmt="H",
                                 adjust=lambda pkt, x: x + 4),
                   ShortField("family", 1),
                   FieldLenField("source_plen", None,
                                 length_of="address",
                                 fmt="B",
                                 adjust=lambda pkt, x: x * 8),
                   ByteField("scope_plen", 0),
                   MultipleTypeField(
                       [(ClientSubnetv4("address", "192.168.0.0",
                         length_from=lambda p: p.source_plen),
                         lambda pkt: pkt.family == 1),
                        (ClientSubnetv6("address", "2001:db8::",
                         length_from=lambda p: p.source_plen),
                         lambda pkt: pkt.family == 2)],
                       ClientSubnetv4("address", "192.168.0.0",
                                      length_from=lambda p: p.source_plen))]


class EDNS0COOKIE(_EDNS0Dummy):
    name = "DNS EDNS0 COOKIE"
    fields_desc = [ShortEnumField("optcode", 10, edns0types),
                   FieldLenField("optlen", None, length_of="server_cookie", fmt="!H",
                                 adjust=lambda pkt, x: x + 8),
                   XStrFixedLenField("client_cookie", b"\x00" * 8, length=8),
                   XStrLenField("server_cookie", "",
                                length_from=lambda pkt: max(0, pkt.optlen - 8))]


# RFC 8914 - Extended DNS Errors

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes
extended_dns_error_codes = {
    0: "Other",
    1: "Unsupported DNSKEY Algorithm",
    2: "Unsupported DS Digest Type",
    3: "Stale Answer",
    4: "Forged Answer",
    5: "DNSSEC Indeterminate",
    6: "DNSSEC Bogus",
    7: "Signature Expired",
    8: "Signature Not Yet Valid",
    9: "DNSKEY Missing",
    10: "RRSIGs Missing",
    11: "No Zone Key Bit Set",
    12: "NSEC Missing",
    13: "Cached Error",
    14: "Not Ready",
    15: "Blocked",
    16: "Censored",
    17: "Filtered",
    18: "Prohibited",
    19: "Stale NXDOMAIN Answer",
    20: "Not Authoritative",
    21: "Not Supported",
    22: "No Reachable Authority",
    23: "Network Error",
    24: "Invalid Data",
    25: "Signature Expired before Valid",
    26: "Too Early",
    27: "Unsupported NSEC3 Iterations Value",
    28: "Unable to conform to policy",
    29: "Synthesized",
}


# https://www.rfc-editor.org/rfc/rfc8914.html
class EDNS0ExtendedDNSError(_EDNS0Dummy):
    name = "DNS EDNS0 Extended DNS Error"
    fields_desc = [ShortEnumField("optcode", 15, edns0types),
                   FieldLenField("optlen", None, length_of="extra_text", fmt="!H",
                                 adjust=lambda pkt, x: x + 2),
                   ShortEnumField("info_code", 0, extended_dns_error_codes),
                   StrLenField("extra_text", "",
                               length_from=lambda pkt: pkt.optlen - 2)]


EDNS0OPT_DISPATCHER = {
    4: EDNS0OWN,
    5: EDNS0DAU,
    6: EDNS0DHU,
    7: EDNS0N3U,
    8: EDNS0ClientSubnet,
    10: EDNS0COOKIE,
    15: EDNS0ExtendedDNSError,
}


# RFC 4034 - Resource Records for the DNS Security Extensions

def bitmap2RRlist(bitmap):
    """
    Decode the 'Type Bit Maps' field of the NSEC Resource Record into an
    integer list.
    """
    # RFC 4034, 4.1.2. The Type Bit Maps Field

    RRlist = []

    while bitmap:

        if len(bitmap) < 2:
            log_runtime.info("bitmap too short (%i)", len(bitmap))
            return

        window_block = orb(bitmap[0])  # window number
        offset = 256 * window_block  # offset of the Resource Record
        bitmap_len = orb(bitmap[1])  # length of the bitmap in bytes

        if bitmap_len <= 0 or bitmap_len > 32:
            log_runtime.info("bitmap length is no valid (%i)", bitmap_len)
            return

        tmp_bitmap = bitmap[2:2 + bitmap_len]

        # Let's compare each bit of tmp_bitmap and compute the real RR value
        for b in range(len(tmp_bitmap)):
            v = 128
            for i in range(8):
                if orb(tmp_bitmap[b]) & v:
                    # each of the RR is encoded as a bit
                    RRlist += [offset + b * 8 + i]
                v = v >> 1

        # Next block if any
        bitmap = bitmap[2 + bitmap_len:]

    return RRlist


def RRlist2bitmap(lst):
    """
    Encode a list of integers representing Resource Records to a bitmap field
    used in the NSEC Resource Record.
    """
    # RFC 4034, 4.1.2. The Type Bit Maps Field

    import math

    bitmap = b""
    lst = [abs(x) for x in sorted(set(lst)) if x <= 65535]

    # number of window blocks
    max_window_blocks = int(math.ceil(lst[-1] / 256.))
    min_window_blocks = int(math.floor(lst[0] / 256.))
    if min_window_blocks == max_window_blocks:
        max_window_blocks += 1

    for wb in range(min_window_blocks, max_window_blocks + 1):
        # First, filter out RR not encoded in the current window block
        # i.e. keep everything between 256*wb <= 256*(wb+1)
        rrlist = sorted(x for x in lst if 256 * wb <= x < 256 * (wb + 1))
        if not rrlist:
            continue

        # Compute the number of bytes used to store the bitmap
        if rrlist[-1] == 0:  # only one element in the list
            bytes_count = 1
        else:
            max = rrlist[-1] - 256 * wb
            bytes_count = int(math.ceil(max // 8)) + 1  # use at least 1 byte
        if bytes_count > 32:  # Don't encode more than 256 bits / values
            bytes_count = 32

        bitmap += struct.pack("BB", wb, bytes_count)

        # Generate the bitmap
        # The idea is to remove out of range Resource Records with these steps
        # 1. rescale to fit into 8 bits
        # 2. x gives the bit position ; compute the corresponding value
        # 3. sum everything
        bitmap += b"".join(
            struct.pack(
                b"B",
                sum(2 ** (7 - (x - 256 * wb) + (tmp * 8)) for x in rrlist
                    if 256 * wb + 8 * tmp <= x < 256 * wb + 8 * tmp + 8),
            ) for tmp in range(bytes_count)
        )

    return bitmap


class RRlistField(StrField):
    islist = 1

    def h2i(self, pkt, x):
        if x and isinstance(x, list):
            return RRlist2bitmap(x)
        return x

    def i2repr(self, pkt, x):
        if not x:
            return "[]"
        x = self.i2h(pkt, x)
        rrlist = bitmap2RRlist(x)
        return [dnstypes.get(rr, rr) for rr in rrlist] if rrlist else repr(x)


class _DNSRRdummy(Packet):
    name = "Dummy class that implements post_build() for Resource Records"

    def post_build(self, pkt, pay):
        if self.rdlen is not None:
            return pkt + pay

        lrrname = len(self.fields_desc[0].i2m("", self.getfieldval("rrname")))
        tmp_len = len(pkt) - lrrname - 10
        tmp_pkt = pkt[:lrrname + 8]
        pkt = struct.pack("!H", tmp_len) + pkt[lrrname + 8 + 2:]

        return tmp_pkt + pkt + pay

    def default_payload_class(self, payload):
        return conf.padding_layer


class DNSRRHINFO(_DNSRRdummy):
    name = "DNS HINFO Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 13, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   FieldLenField("cpulen", None, fmt="!B", length_of="cpu"),
                   StrLenField("cpu", "", length_from=lambda x: x.cpulen),
                   FieldLenField("oslen", None, fmt="!B", length_of="os"),
                   StrLenField("os", "", length_from=lambda x: x.oslen)]


class DNSRRMX(_DNSRRdummy):
    name = "DNS MX Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 15, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("preference", 0),
                   DNSStrField("exchange", ""),
                   ]


class DNSRRSOA(_DNSRRdummy):
    name = "DNS SOA Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 6, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   DNSStrField("mname", ""),
                   DNSStrField("rname", ""),
                   IntField("serial", 0),
                   IntField("refresh", 0),
                   IntField("retry", 0),
                   IntField("expire", 0),
                   IntField("minimum", 0)
                   ]


class DNSRRRSIG(_DNSRRdummy):
    name = "DNS RRSIG Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 46, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortEnumField("typecovered", 1, dnstypes),
                   ByteEnumField("algorithm", 5, dnssecalgotypes),
                   ByteField("labels", 0),
                   IntField("originalttl", 0),
                   UTCTimeField("expiration", 0),
                   UTCTimeField("inception", 0),
                   ShortField("keytag", 0),
                   DNSStrField("signersname", ""),
                   StrField("signature", "")
                   ]


class DNSRRNSEC(_DNSRRdummy):
    name = "DNS NSEC Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 47, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   DNSStrField("nextname", ""),
                   RRlistField("typebitmaps", [])
                   ]


class DNSRRDNSKEY(_DNSRRdummy):
    name = "DNS DNSKEY Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 48, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   FlagsField("flags", 256, 16, "S???????Z???????"),
                   # S: Secure Entry Point
                   # Z: Zone Key
                   ByteField("protocol", 3),
                   ByteEnumField("algorithm", 5, dnssecalgotypes),
                   StrField("publickey", "")
                   ]


class DNSRRDS(_DNSRRdummy):
    name = "DNS DS Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 43, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("keytag", 0),
                   ByteEnumField("algorithm", 5, dnssecalgotypes),
                   ByteEnumField("digesttype", 5, dnssecdigesttypes),
                   StrField("digest", "")
                   ]


# RFC 5074 - DNSSEC Lookaside Validation (DLV)
class DNSRRDLV(DNSRRDS):
    name = "DNS DLV Resource Record"

    def __init__(self, *args, **kargs):
        DNSRRDS.__init__(self, *args, **kargs)
        if not kargs.get('type', 0):
            self.type = 32769

# RFC 5155 - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence


class DNSRRNSEC3(_DNSRRdummy):
    name = "DNS NSEC3 Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 50, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ByteField("hashalg", 0),
                   BitEnumField("flags", 0, 8, {1: "Opt-Out"}),
                   ShortField("iterations", 0),
                   FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
                   StrLenField("salt", "", length_from=lambda x: x.saltlength),
                   FieldLenField("hashlength", 0, fmt="!B", length_of="nexthashedownername"),  # noqa: E501
                   StrLenField("nexthashedownername", "", length_from=lambda x: x.hashlength),  # noqa: E501
                   RRlistField("typebitmaps", [])
                   ]


class DNSRRNSEC3PARAM(_DNSRRdummy):
    name = "DNS NSEC3PARAM Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 51, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ByteField("hashalg", 0),
                   ByteField("flags", 0),
                   ShortField("iterations", 0),
                   FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
                   StrLenField("salt", "", length_from=lambda pkt: pkt.saltlength)  # noqa: E501
                   ]


# RFC 9460 Service Binding and Parameter Specification via the DNS
# https://www.rfc-editor.org/rfc/rfc9460.html


# https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
svc_param_keys = {
    0: "mandatory",
    1: "alpn",
    2: "no-default-alpn",
    3: "port",
    4: "ipv4hint",
    5: "ech",
    6: "ipv6hint",
    7: "dohpath",
    8: "ohttp",
}


class SvcParam(Packet):
    name = "SvcParam"
    fields_desc = [ShortEnumField("key", 0, svc_param_keys),
                   FieldLenField("len", None, length_of="value", fmt="H"),
                   MultipleTypeField(
                       [
                           # mandatory
                           (FieldListField("value", [],
                                           ShortEnumField("", 0, svc_param_keys),
                                           length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key == 0),
                           # alpn, no-default-alpn
                           (DNSTextField("value", [],
                                         length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key in (1, 2)),
                           # port
                           (ShortField("value", 0),
                               lambda pkt: pkt.key == 3),
                           # ipv4hint
                           (FieldListField("value", [],
                                           IPField("", "0.0.0.0"),
                                           length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key == 4),
                           # ipv6hint
                           (FieldListField("value", [],
                                           IP6Field("", "::"),
                                           length_from=lambda pkt: pkt.len),
                               lambda pkt: pkt.key == 6),
                       ],
                       StrLenField("value", "",
                                   length_from=lambda pkt:pkt.len))]

    def extract_padding(self, p):
        return "", p


class DNSRRSVCB(_DNSRRdummy):
    name = "DNS SVCB Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 64, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("svc_priority", 0),
                   DNSStrField("target_name", ""),
                   PacketListField("svc_params", [], SvcParam)]


class DNSRRHTTPS(_DNSRRdummy):
    name = "DNS HTTPS Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 65, dnstypes)
                   ] + DNSRRSVCB.fields_desc[2:]


# RFC 2782 - A DNS RR for specifying the location of services (DNS SRV)


class DNSRRSRV(_DNSRRdummy):
    name = "DNS SRV Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 33, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("priority", 0),
                   ShortField("weight", 0),
                   ShortField("port", 0),
                   DNSStrField("target", ""), ]


# RFC 2845 - Secret Key Transaction Authentication for DNS (TSIG)
tsig_algo_sizes = {"HMAC-MD5.SIG-ALG.REG.INT": 16,
                   "hmac-sha1": 20}


class TimeSignedField(Field[int, bytes]):
    def __init__(self, name, default):
        Field.__init__(self, name, default, fmt="6s")

    def _convert_seconds(self, packed_seconds):
        """Unpack the internal representation."""
        seconds = struct.unpack("!H", packed_seconds[:2])[0]
        seconds += struct.unpack("!I", packed_seconds[2:])[0]
        return seconds

    def i2m(self, pkt, seconds):
        """Convert the number of seconds since 1-Jan-70 UTC to the packed
           representation."""

        if seconds is None:
            seconds = 0

        tmp_short = (seconds >> 32) & 0xFFFF
        tmp_int = seconds & 0xFFFFFFFF

        return struct.pack("!HI", tmp_short, tmp_int)

    def m2i(self, pkt, packed_seconds):
        """Convert the internal representation to the number of seconds
           since 1-Jan-70 UTC."""

        if packed_seconds is None:
            return None

        return self._convert_seconds(packed_seconds)

    def i2repr(self, pkt, packed_seconds):
        """Convert the internal representation to a nice one using the RFC
           format."""
        time_struct = time.gmtime(packed_seconds)
        return time.strftime("%a %b %d %H:%M:%S %Y", time_struct)


class DNSRRTSIG(_DNSRRdummy):
    name = "DNS TSIG Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 250, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   DNSStrField("algo_name", "hmac-sha1"),
                   TimeSignedField("time_signed", 0),
                   ShortField("fudge", 0),
                   FieldLenField("mac_len", 20, fmt="!H", length_of="mac_data"),  # noqa: E501
                   StrLenField("mac_data", "", length_from=lambda pkt: pkt.mac_len),  # noqa: E501
                   ShortField("original_id", 0),
                   ShortField("error", 0),
                   FieldLenField("other_len", 0, fmt="!H", length_of="other_data"),  # noqa: E501
                   StrLenField("other_data", "", length_from=lambda pkt: pkt.other_len)  # noqa: E501
                   ]


class DNSRRNAPTR(_DNSRRdummy):
    name = "DNS NAPTR Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 35, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ShortField("order", 0),
                   ShortField("preference", 0),
                   FieldLenField("flags_len", None, fmt="!B", length_of="flags"),
                   StrLenField("flags", "", length_from=lambda pkt: pkt.flags_len),
                   FieldLenField("services_len", None, fmt="!B", length_of="services"),
                   StrLenField("services", "",
                               length_from=lambda pkt: pkt.services_len),
                   FieldLenField("regexp_len", None, fmt="!B", length_of="regexp"),
                   StrLenField("regexp", "", length_from=lambda pkt: pkt.regexp_len),
                   DNSStrField("replacement", ""),
                   ]


DNSRR_DISPATCHER = {
    6: DNSRRSOA,         # RFC 1035
    13: DNSRRHINFO,      # RFC 1035
    15: DNSRRMX,         # RFC 1035
    33: DNSRRSRV,        # RFC 2782
    35: DNSRRNAPTR,      # RFC 2915
    41: DNSRROPT,        # RFC 1671
    43: DNSRRDS,         # RFC 4034
    46: DNSRRRSIG,       # RFC 4034
    47: DNSRRNSEC,       # RFC 4034
    48: DNSRRDNSKEY,     # RFC 4034
    50: DNSRRNSEC3,      # RFC 5155
    51: DNSRRNSEC3PARAM,  # RFC 5155
    64: DNSRRSVCB,       # RFC 9460
    65: DNSRRHTTPS,      # RFC 9460
    250: DNSRRTSIG,      # RFC 2845
    32769: DNSRRDLV,     # RFC 4431
}


class DNSRR(Packet):
    name = "DNS Resource Record"
    show_indent = 0
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 1, dnstypes),
                   BitField("cacheflush", 0, 1),  # mDNS RFC 6762
                   BitEnumField("rclass", 1, 15, dnsclasses),
                   IntField("ttl", 0),
                   FieldLenField("rdlen", None, length_of="rdata", fmt="H"),
                   MultipleTypeField(
                       [
                           # A
                           (IPField("rdata", "0.0.0.0"),
                               lambda pkt: pkt.type == 1),
                           # AAAA
                           (IP6Field("rdata", "::"),
                               lambda pkt: pkt.type == 28),
                           # NS, MD, MF, CNAME, PTR, DNAME
                           (DNSStrField("rdata", "",
                                        length_from=lambda pkt: pkt.rdlen),
                               lambda pkt: pkt.type in [2, 3, 4, 5, 12, 39]),
                           # TEXT
                           (DNSTextField("rdata", [""],
                                         length_from=lambda pkt: pkt.rdlen),
                               lambda pkt: pkt.type == 16),
                       ],
                       StrLenField("rdata", "",
                                   length_from=lambda pkt:pkt.rdlen)
    )]

    def default_payload_class(self, payload):
        return conf.padding_layer


def _DNSRR(s, **kwargs):
    """
    DNSRR dispatcher func
    """
    if s:
        # Try to find the type of the RR using the dispatcher
        _, remain = dns_get_str(s, _ignore_compression=True)
        cls = DNSRR_DISPATCHER.get(
            struct.unpack("!H", remain[:2])[0],
            DNSRR,
        )
        rrlen = (
            len(s) - len(remain) +  # rrname len
            10 +
            struct.unpack("!H", remain[8:10])[0]
        )
        pkt = cls(s[:rrlen], **kwargs) / conf.padding_layer(s[rrlen:])
        # drop rdlen because if rdata was compressed, it will break everything
        # when rebuilding
        del pkt.fields["rdlen"]
        return pkt
    return None


class DNSQR(Packet):
    name = "DNS Question Record"
    show_indent = 0
    fields_desc = [DNSStrField("qname", "www.example.com"),
                   ShortEnumField("qtype", 1, dnsqtypes),
                   BitField("unicastresponse", 0, 1),  # mDNS RFC 6762
                   BitEnumField("qclass", 1, 15, dnsclasses)]

    def default_payload_class(self, payload):
        return conf.padding_layer


class _DNSPacketListField(PacketListField):
    # A normal PacketListField with backward-compatible hacks
    def any2i(self, pkt, x):
        # type: (Optional[Packet], List[Any]) -> List[Any]
        if x is None:
            warnings.warn(
                ("The DNS fields 'qd', 'an', 'ns' and 'ar' are now "
                 "PacketListField(s) ! "
                 "Setting a null default should be [] instead of None"),
                DeprecationWarning
            )
            x = []
        return super(_DNSPacketListField, self).any2i(pkt, x)

    def i2h(self, pkt, x):
        # type: (Optional[Packet], List[Packet]) -> Any
        class _list(list):
            """
            Fake list object to provide compatibility with older DNS fields
            """
            def __getattr__(self, attr):
                try:
                    ret = getattr(self[0], attr)
                    warnings.warn(
                        ("The DNS fields 'qd', 'an', 'ns' and 'ar' are now "
                         "PacketListField(s) ! "
                         "To access the first element, use pkt.an[0] instead of "
                         "pkt.an"),
                        DeprecationWarning
                    )
                    return ret
                except AttributeError:
                    raise
        return _list(x)


class DNS(DNSCompressedPacket):
    name = "DNS"
    fields_desc = [
        ConditionalField(ShortField("length", None),
                         lambda p: isinstance(p.underlayer, TCP)),
        ShortField("id", 0),
        BitField("qr", 0, 1),
        BitEnumField("opcode", 0, 4, {0: "QUERY", 1: "IQUERY", 2: "STATUS"}),
        BitField("aa", 0, 1),
        BitField("tc", 0, 1),
        BitField("rd", 1, 1),
        BitField("ra", 0, 1),
        BitField("z", 0, 1),
        # AD and CD bits are defined in RFC 2535
        BitField("ad", 0, 1),  # Authentic Data
        BitField("cd", 0, 1),  # Checking Disabled
        BitEnumField("rcode", 0, 4, {0: "ok", 1: "format-error",
                                     2: "server-failure", 3: "name-error",
                                     4: "not-implemented", 5: "refused"}),
        FieldLenField("qdcount", None, count_of="qd"),
        FieldLenField("ancount", None, count_of="an"),
        FieldLenField("nscount", None, count_of="ns"),
        FieldLenField("arcount", None, count_of="ar"),
        _DNSPacketListField("qd", [DNSQR()], DNSQR, count_from=lambda pkt: pkt.qdcount),
        _DNSPacketListField("an", [], _DNSRR, count_from=lambda pkt: pkt.ancount),
        _DNSPacketListField("ns", [], _DNSRR, count_from=lambda pkt: pkt.nscount),
        _DNSPacketListField("ar", [], _DNSRR, count_from=lambda pkt: pkt.arcount),
    ]

    def get_full(self):
        # Required for DNSCompressedPacket
        if isinstance(self.underlayer, TCP):
            return self.original[2:]
        else:
            return self.original

    def answers(self, other):
        return (isinstance(other, DNS) and
                self.id == other.id and
                self.qr == 1 and
                other.qr == 0)

    def mysummary(self):
        name = ""
        if self.qr:
            type = "Ans"
            if self.an and isinstance(self.an[0], DNSRR):
                name = ' %s' % self.an[0].rdata
            elif self.rcode != 0:
                name = self.sprintf(' %rcode%')
        else:
            type = "Qry"
            if self.qd and isinstance(self.qd[0], DNSQR):
                name = ' %s' % self.qd[0].qname
        return "%sDNS %s%s" % (
            "m"
            if isinstance(self.underlayer, UDP) and self.underlayer.dport == 5353
            else "",
            type,
            name,
        )

    def post_build(self, pkt, pay):
        if isinstance(self.underlayer, TCP) and self.length is None:
            pkt = struct.pack("!H", len(pkt) - 2) + pkt[2:]
        return pkt + pay

    def compress(self):
        """Return the compressed DNS packet (using `dns_compress()`)"""
        return dns_compress(self)

    def pre_dissect(self, s):
        """
        Check that a valid DNS over TCP message can be decoded
        """
        if isinstance(self.underlayer, TCP):

            # Compute the length of the DNS packet
            if len(s) >= 2:
                dns_len = struct.unpack("!H", s[:2])[0]
            else:
                message = "Malformed DNS message: too small!"
                log_runtime.info(message)
                raise Scapy_Exception(message)

            # Check if the length is valid
            if dns_len < 14 or len(s) < dns_len:
                message = "Malformed DNS message: invalid length!"
                log_runtime.info(message)
                raise Scapy_Exception(message)

        return s


bind_layers(UDP, DNS, dport=5353)
bind_layers(UDP, DNS, sport=5353)
bind_layers(UDP, DNS, dport=53)
bind_layers(UDP, DNS, sport=53)
DestIPField.bind_addr(UDP, "224.0.0.251", dport=5353)
if conf.ipv6_enabled:
    from scapy.layers.inet6 import DestIP6Field
    DestIP6Field.bind_addr(UDP, "ff02::fb", dport=5353)
bind_layers(TCP, DNS, dport=53)
bind_layers(TCP, DNS, sport=53)

# Nameserver config
conf.nameservers = read_nameservers()
_dns_cache = conf.netcache.new_cache("dns_cache", 300)


@conf.commands.register
def dns_resolve(qname, qtype="A", raw=False, verbose=1, timeout=3, **kwargs):
    """
    Perform a simple DNS resolution using conf.nameservers with caching

    :param qname: the name to query
    :param qtype: the type to query (default A)
    :param raw: return the whole DNS packet (default False)
    :param verbose: show verbose errors
    :param timeout: seconds until timeout (per server)
    :raise TimeoutError: if no DNS servers were reached in time.
    """
    # Unify types
    qtype = DNSQR.qtype.any2i_one(None, qtype)
    qname = DNSQR.qname.any2i(None, qname)
    # Check cache
    cache_ident = b";".join(
        [qname, struct.pack("!B", qtype)] +
        ([b"raw"] if raw else [])
    )
    result = _dns_cache.get(cache_ident)
    if result:
        return result

    kwargs.setdefault("timeout", timeout)
    kwargs.setdefault("verbose", 0)
    res = None
    for nameserver in conf.nameservers:
        # Try all nameservers
        try:
            # Spawn a UDP socket, connect to the nameserver on port 53
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(kwargs["timeout"])
            sock.connect((nameserver, 53))
            # Connected. Wrap it with DNS
            sock = StreamSocket(sock, DNS)
            # I/O
            res = sock.sr1(
                DNS(qd=[DNSQR(qname=qname, qtype=qtype)], id=RandShort()),
                **kwargs,
            )
        except IOError as ex:
            if verbose:
                log_runtime.warning(str(ex))
            continue
        finally:
            sock.close()
        if res:
            # We have a response ! Check for failure
            if res[DNS].rcode == 2:  # server failure
                res = None
                if verbose:
                    log_runtime.info(
                        "DNS: %s answered with failure for %s" % (
                            nameserver,
                            qname,
                        )
                    )
            else:
                break
    if res is not None:
        if raw:
            # Raw
            result = res
        else:
            # Find answers
            result = [
                x
                for x in itertools.chain(res.an, res.ns, res.ar)
                if x.type == qtype
            ]
        if result:
            # Cache it
            _dns_cache[cache_ident] = result
        return result
    else:
        raise TimeoutError


@conf.commands.register
def dyndns_add(nameserver, name, rdata, type="A", ttl=10):
    """Send a DNS add message to a nameserver for "name" to have a new "rdata"
dyndns_add(nameserver, name, rdata, type="A", ttl=10) -> result code (0=ok)

example: dyndns_add("ns1.toto.com", "dyn.toto.com", "127.0.0.1")
RFC2136
"""
    zone = name[name.find(".") + 1:]
    r = sr1(IP(dst=nameserver) / UDP() / DNS(opcode=5,
                                             qd=[DNSQR(qname=zone, qtype="SOA")],  # noqa: E501
                                             ns=[DNSRR(rrname=name, type="A",
                                                       ttl=ttl, rdata=rdata)]),
            verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1


@conf.commands.register
def dyndns_del(nameserver, name, type="ALL", ttl=10):
    """Send a DNS delete message to a nameserver for "name"
dyndns_del(nameserver, name, type="ANY", ttl=10) -> result code (0=ok)

example: dyndns_del("ns1.toto.com", "dyn.toto.com")
RFC2136
"""
    zone = name[name.find(".") + 1:]
    r = sr1(IP(dst=nameserver) / UDP() / DNS(opcode=5,
                                             qd=[DNSQR(qname=zone, qtype="SOA")],  # noqa: E501
                                             ns=[DNSRR(rrname=name, type=type,
                                                       rclass="ANY", ttl=0, rdata="")]),  # noqa: E501
            verbose=0, timeout=5)
    if r and r.haslayer(DNS):
        return r.getlayer(DNS).rcode
    else:
        return -1


class DNS_am(AnsweringMachine):
    function_name = "dnsd"
    filter = "udp port 53"
    cls = DNS  # We also use this automaton for llmnrd / mdnsd

    def parse_options(self, joker=None,
                      match=None,
                      srvmatch=None,
                      joker6=False,
                      send_error=False,
                      relay=False,
                      from_ip=True,
                      from_ip6=False,
                      src_ip=None,
                      src_ip6=None,
                      ttl=10,
                      jokerarpa=False):
        """
        Simple DNS answering machine.

        :param joker: default IPv4 for unresolved domains.
                      Set to False to disable, None to mirror the interface's IP.
                      Defaults to None, unless 'match' is used, then it defaults to
                      False.
        :param joker6: default IPv6 for unresolved domains.
                       Set to False to disable, None to mirror the interface's IPv6.
                       Defaults to False.
        :param match: queries to match.
                      This can be a dictionary of {name: val} where name is a string
                      representing a domain name (A, AAAA) and val is a tuple of 2
                      elements, each representing an IP or a list of IPs. If val is
                      a single element, (A, None) is assumed.
                      This can also be a list or names, in which case joker(6) are
                      used as a response.
        :param jokerarpa: answer for .in-addr.arpa PTR requests. (Default: False)
        :param relay: relay unresolved domains to conf.nameservers (Default: False).
        :param send_error: send an error message when this server can't answer
                           (Default: False)
        :param srvmatch: a dictionary of {name: (port, target)} used for SRV
        :param from_ip: an source IP to filter. Can contain a netmask. True for all,
                        False for none. Default True
        :param from_ip6: an source IPv6 to filter. Can contain a netmask. True for all,
                        False for none. Default False
        :param ttl: the DNS time to live (in seconds)
        :param src_ip: override the source IP
        :param src_ip6:

        Examples:

        - Answer all 'A' and 'AAAA' requests::

            $ sudo iptables -I OUTPUT -p icmp --icmp-type 3/3 -j DROP
            >>> dnsd(joker="192.168.0.2", joker6="fe80::260:8ff:fe52:f9d8",
            ...      iface="eth0")

        - Answer only 'A' query for google.com with 192.168.0.2::

            >>> dnsd(match={"google.com": "192.168.0.2"}, iface="eth0")

        - Answer DNS for a Windows domain controller ('SRV', 'A' and 'AAAA')::

            >>> dnsd(
            ...     srvmatch={
            ...         "_ldap._tcp.dc._msdcs.DOMAIN.LOCAL.": (389,
            ...                                                "srv1.domain.local"),
            ...     },
            ...     match={"src1.domain.local": ("192.168.0.102",
            ...                                  "fe80::260:8ff:fe52:f9d8")},
            ... )

        - Relay all queries to another DNS server, except some::

            >>> conf.nameservers = ["1.1.1.1"]  # server to relay to
            >>> dnsd(
            ...     match={"test.com": "1.1.1.1"},
            ...     relay=True,
            ... )
        """
        from scapy.layers.inet6 import Net6

        self.mDNS = isinstance(self, mDNS_am)
        self.llmnr = self.cls != DNS

        # Add some checks (to help)
        if not isinstance(joker, (str, bool)) and joker is not None:
            raise ValueError("Bad 'joker': should be an IPv4 (str) or False !")
        if not isinstance(joker6, (str, bool)) and joker6 is not None:
            raise ValueError("Bad 'joker6': should be an IPv6 (str) or False !")
        if not isinstance(jokerarpa, (str, bool)):
            raise ValueError("Bad 'jokerarpa': should be a hostname or False !")
        if not isinstance(from_ip, (str, Net, bool)):
            raise ValueError("Bad 'from_ip': should be an IPv4 (str), Net or False !")
        if not isinstance(from_ip6, (str, Net6, bool)):
            raise ValueError("Bad 'from_ip6': should be an IPv6 (str), Net or False !")
        if self.mDNS and src_ip:
            raise ValueError("Cannot use 'src_ip' in mDNS !")
        if self.mDNS and src_ip6:
            raise ValueError("Cannot use 'src_ip6' in mDNS !")

        if joker is None and match is not None:
            joker = False
        self.joker = joker
        self.joker6 = joker6
        self.jokerarpa = jokerarpa

        def normv(v):
            if isinstance(v, (tuple, list)) and len(v) == 2:
                return tuple(v)
            elif isinstance(v, str):
                return (v, joker6)
            else:
                raise ValueError("Bad match value: '%s'" % repr(v))

        def normk(k):
            k = bytes_encode(k).lower()
            if not k.endswith(b"."):
                k += b"."
            return k

        self.match = collections.defaultdict(lambda: (joker, joker6))
        if match:
            if isinstance(match, (list, set)):
                self.match.update({normk(k): (None, None) for k in match})
            else:
                self.match.update({normk(k): normv(v) for k, v in match.items()})
        if srvmatch is None:
            self.srvmatch = {}
        else:
            self.srvmatch = {normk(k): normv(v) for k, v in srvmatch.items()}

        self.send_error = send_error
        self.relay = relay
        if isinstance(from_ip, str):
            self.from_ip = Net(from_ip)
        else:
            self.from_ip = from_ip
        if isinstance(from_ip6, str):
            self.from_ip6 = Net6(from_ip6)
        else:
            self.from_ip6 = from_ip6
        self.src_ip = src_ip
        self.src_ip6 = src_ip6
        self.ttl = ttl

    def is_request(self, req):
        from scapy.layers.inet6 import IPv6
        return (
            req.haslayer(self.cls) and
            req.getlayer(self.cls).qr == 0 and (
                (
                    self.from_ip6 is True or
                    (self.from_ip6 and req[IPv6].src in self.from_ip6)
                )
                if IPv6 in req else
                (
                    self.from_ip is True or
                    (self.from_ip and req[IP].src in self.from_ip)
                )
            )
        )

    def make_reply(self, req):
        # Build reply from the request
        resp = req.copy()
        if Ether in req:
            if self.mDNS:
                resp[Ether].src, resp[Ether].dst = None, None
            elif self.llmnr:
                resp[Ether].src, resp[Ether].dst = None, req[Ether].src
            else:
                resp[Ether].src, resp[Ether].dst = (
                    None if req[Ether].dst == "ff:ff:ff:ff:ff:ff" else req[Ether].dst,
                    req[Ether].src,
                )
        from scapy.layers.inet6 import IPv6
        if IPv6 in req:
            resp[IPv6].underlayer.remove_payload()
            if self.mDNS:
                # "All Multicast DNS responses (including responses sent via unicast)
                # SHOULD be sent with IP TTL set to 255."
                resp /= IPv6(dst="ff02::fb", src=self.src_ip6,
                             fl=req[IPv6].fl, hlim=255)
            elif self.llmnr:
                resp /= IPv6(dst=req[IPv6].src, src=self.src_ip6,
                             fl=req[IPv6].fl, hlim=req[IPv6].hlim)
            else:
                resp /= IPv6(dst=req[IPv6].src, src=self.src_ip6 or req[IPv6].dst,
                             fl=req[IPv6].fl, hlim=req[IPv6].hlim)
        elif IP in req:
            resp[IP].underlayer.remove_payload()
            if self.mDNS:
                # "All Multicast DNS responses (including responses sent via unicast)
                # SHOULD be sent with IP TTL set to 255."
                resp /= IP(dst="224.0.0.251", src=self.src_ip,
                           id=req[IP].id, ttl=255)
            elif self.llmnr:
                resp /= IP(dst=req[IP].src, src=self.src_ip,
                           id=req[IP].id, ttl=req[IP].ttl)
            else:
                resp /= IP(dst=req[IP].src, src=self.src_ip or req[IP].dst,
                           id=req[IP].id, ttl=req[IP].ttl)
        else:
            warning("No IP or IPv6 layer in %s", req.command())
            return
        try:
            resp /= UDP(sport=req[UDP].dport, dport=req[UDP].sport)
        except IndexError:
            warning("No UDP layer in %s", req.command(), exc_info=True)
            return
        try:
            req = req[self.cls]
        except IndexError:
            warning(
                "No %s layer in %s",
                self.cls.__name__,
                req.command(),
                exc_info=True,
            )
            return
        try:
            queries = req.qd
        except AttributeError:
            warning("No qd attribute in %s", req.command(), exc_info=True)
            return
        # Special case: alias 'ALL' query as 'A' + 'AAAA'
        try:
            allquery = next(
                (x for x in queries if getattr(x, "qtype", None) == 255)
            )
            queries.remove(allquery)
            queries.extend([
                DNSQR(
                    qtype=x,
                    qname=allquery.qname,
                    unicastresponse=allquery.unicastresponse,
                    qclass=allquery.qclass,
                )
                for x in [1, 28]
            ])
        except StopIteration:
            pass
        # Process each query
        ans = []
        ars = []
        for rq in queries:
            if isinstance(rq, Raw):
                warning("Cannot parse qd element %s", rq.command(), exc_info=True)
                continue
            rqname = rq.qname.lower()
            if rq.qtype in [1, 28]:
                # A or AAAA
                if rq.qtype == 28:
                    # AAAA
                    rdata = self.match[rqname][1]
                    if rdata is None and not self.relay:
                        # 'None' resolves to the default IPv6
                        iface = resolve_iface(self.optsniff.get("iface", conf.iface))
                        if self.mDNS:
                            # All IPs, as per mDNS.
                            rdata = iface.ips[6]
                        else:
                            rdata = get_if_addr6(
                                iface
                            )
                    if self.mDNS and rdata and IPv6 in resp:
                        # For mDNS, we must replace the IPv6 src
                        resp[IPv6].src = rdata
                elif rq.qtype == 1:
                    # A
                    rdata = self.match[rqname][0]
                    if rdata is None and not self.relay:
                        # 'None' resolves to the default IPv4
                        iface = resolve_iface(self.optsniff.get("iface", conf.iface))
                        if self.mDNS:
                            # All IPs, as per mDNS.
                            rdata = iface.ips[4]
                        else:
                            rdata = get_if_addr(
                                iface
                            )
                    if self.mDNS and rdata and IP in resp:
                        # For mDNS, we must replace the IP src
                        resp[IP].src = rdata
                if rdata:
                    # Common A and AAAA
                    if not isinstance(rdata, list):
                        rdata = [rdata]
                    ans.extend([
                        DNSRR(
                            rrname=rq.qname,
                            ttl=self.ttl,
                            rdata=x,
                            type=rq.qtype,
                            cacheflush=self.mDNS and rq.qtype == rq.qtype,
                        )
                        for x in rdata
                    ])
                    continue  # next
            elif rq.qtype == 33:
                # SRV
                try:
                    port, target = self.srvmatch[rqname]
                    ans.append(DNSRRSRV(
                        rrname=rq.qname,
                        port=port,
                        target=target,
                        weight=100,
                        ttl=self.ttl
                    ))
                    continue  # next
                except KeyError:
                    # No result
                    pass
            elif rq.qtype == 12:
                # PTR
                if rq.qname[-14:] == b".in-addr.arpa." and self.jokerarpa:
                    ans.append(DNSRR(
                        rrname=rq.qname,
                        type=rq.qtype,
                        ttl=self.ttl,
                        rdata=self.jokerarpa,
                    ))
                    continue
            # It it arrives here, there is currently no answer
            if self.relay:
                # Relay mode ?
                try:
                    _rslv = dns_resolve(rq.qname, qtype=rq.qtype)
                    if _rslv:
                        ans.extend(_rslv)
                        continue  # next
                except TimeoutError:
                    pass
            # Still no answer.
            if self.mDNS:
                # "Any time a responder receives a query for a name for which it
                # has verified exclusive ownership, for a type for which that name
                # has no records, the responder MUST respond asserting the
                # nonexistence of that record using a DNS NSEC record [RFC4034]."
                ans.append(DNSRRNSEC(
                    # RFC6762 sect 6.1 - Negative Response
                    ttl=self.ttl,
                    rrname=rq.qname,
                    nextname=rq.qname,
                    typebitmaps=RRlist2bitmap([rq.qtype]),
                ))
        if self.mDNS and all(x.type == 47 for x in ans):
            # If mDNS answers with only NSEC, discard.
            return
        if not ans:
            # No answer is available.
            if self.send_error:
                resp /= self.cls(id=req.id, qr=1, qd=req.qd, rcode=3)
                return resp
            log_runtime.info("No answer could be provided to: %s" % req.summary())
            return
        # Handle Additional Records
        if self.mDNS:
            # Windows specific extension
            ars.append(DNSRROPT(
                z=0x1194,
                rdata=[
                    EDNS0OWN(
                        primary_mac=resp[Ether].src,
                    ),
                ],
            ))
        # All rq were answered
        if self.mDNS:
            # in mDNS mode, don't repeat the question, set aa=1, rd=0
            dns = self.cls(id=req.id, aa=1, rd=0, qr=1, qd=[], ar=ars, an=ans)
        else:
            dns = self.cls(id=req.id, qr=1, qd=req.qd, ar=ars, an=ans)
        # Compress DNS and mDNS
        if not self.llmnr:
            resp /= dns_compress(dns)
        else:
            resp /= dns
        return resp


class mDNS_am(DNS_am):
    """
    mDNS answering machine.

    This has the same arguments as DNS_am. See help(DNS_am)

    Example::

        - Answer for 'TEST.local' with local IPv4::

            >>> mdnsd(match=["TEST.local"])

        - Answer all requests with other IP::

            >>> mdnsd(joker="192.168.0.2", joker6="fe80::260:8ff:fe52:f9d8",
            ...       iface="eth0")

        - Answer for multiple different mDNS names::

            >>> mdnsd(match={"TEST.local": "192.168.0.100",
            ...              "BOB.local": "192.168.0.101"})

        - Answer with both A and AAAA records::

            >>> mdnsd(match={"TEST.local": ("192.168.0.100",
            ...                             "fe80::260:8ff:fe52:f9d8")})
    """
    function_name = "mdnsd"
    filter = "udp port 5353"


# DNS-SD (RFC 6763)


class DNSSDResult(SndRcvList):
    def __init__(self,
                 res=None,  # type: Optional[Union[_PacketList[QueryAnswer], List[QueryAnswer]]]  # noqa: E501
                 name="DNS-SD",  # type: str
                 stats=None  # type: Optional[List[Type[Packet]]]
                 ):
        SndRcvList.__init__(self, res, name, stats)

    def show(self, types=['PTR', 'SRV'], alltypes=False):
        # type: (List[str], bool) -> None
        """
        Print the list of discovered services.

        :param types: types to show. Default ['PTR', 'SRV']
        :param alltypes: show all types. Default False
        """
        if alltypes:
            types = None
        data = list()  # type: List[Tuple[str | List[str], ...]]

        resolve_mac = (
            self.res and isinstance(self.res[0][1].underlayer, Ether) and
            conf.manufdb
        )

        header = ("IP", "Service")
        if resolve_mac:
            header = ("Mac",) + header

        for _, r in self.res:
            attrs = []
            for attr in itertools.chain(r[DNS].an, r[DNS].ar):
                if types and dnstypes.get(attr.type) not in types:
                    continue
                if isinstance(attr, DNSRRNSEC):
                    attrs.append(attr.sprintf("%type%=%nextname%"))
                elif isinstance(attr, DNSRRSRV):
                    attrs.append(attr.sprintf("%type%=(%target%,%port%)"))
                else:
                    attrs.append(attr.sprintf("%type%=%rdata%"))
            ans = (r.src, attrs)
            if resolve_mac:
                mac = conf.manufdb._resolve_MAC(r.underlayer.src)
                data.append((mac,) + ans)
            else:
                data.append(ans)

        print(
            pretty_list(
                data,
                [header],
            )
        )


@conf.commands.register
def dnssd(service="_services._dns-sd._udp.local",
          af=socket.AF_INET,
          qtype="PTR",
          iface=None,
          verbose=2,
          timeout=3):
    """
    Performs a DNS-SD (RFC6763) request

    :param service: the service name to query (e.g. _spotify-connect._tcp.local)
    :param af: the transport to use. socket.AF_INET or socket.AF_INET6
    :param qtype: the type to use in the mDNS. Either TXT, PTR or SRV.
    :param iface: the interface to do this discovery on.
    """
    if af == socket.AF_INET:
        pkt = IP(dst=ScopedIP("224.0.0.251", iface), ttl=255)
    elif af == socket.AF_INET6:
        pkt = IPv6(dst=ScopedIP("ff02::fb", iface))
    else:
        return
    pkt /= UDP(sport=5353, dport=5353)
    pkt /= DNS(rd=0, qd=[DNSQR(qname=service, qtype=qtype)])
    ans, _ = sr(pkt, multi=True, timeout=timeout, verbose=verbose)
    return DNSSDResult(ans.res)
