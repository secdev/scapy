# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
DNS: Domain Name System.
"""

from __future__ import absolute_import
import operator
import socket
import struct
import time
import warnings

from scapy.arch import get_if_addr, get_if_addr6
from scapy.ansmachine import AnsweringMachine
from scapy.base_classes import Net
from scapy.config import conf
from scapy.compat import orb, raw, chb, bytes_encode, plain_str
from scapy.error import log_runtime, warning, Scapy_Exception
from scapy.packet import Packet, bind_layers, NoPayload, Raw
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    ConditionalField, Field, FieldLenField, FlagsField, IntField, \
    PacketListField, ShortEnumField, ShortField, StrField, \
    StrLenField, MultipleTypeField, UTCTimeField, I
from scapy.sendrecv import sr1
from scapy.pton_ntop import inet_ntop, inet_pton

from scapy.layers.inet import IP, DestIPField, IPField, UDP, TCP
from scapy.layers.inet6 import IPv6, DestIP6Field, IP6Field
import scapy.libs.six as six


from scapy.compat import (
    Any,
    Optional,
    Tuple,
    Type,
    Union,
)


# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
dnstypes = {
    0: "ANY",
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


def dns_get_str(s, pointer=0, pkt=None, _fullpacket=False):
    """This function decompresses a string s, starting
    from the given pointer.

    :param s: the string to decompress
    :param pointer: first pointer on the string (default: 0)
    :param pkt: (optional) an InheritOriginDNSStrPacket packet

    :returns: (decoded_string, end_index, left_string)
    """
    # The _fullpacket parameter is reserved for scapy. It indicates
    # that the string provided is the full dns packet, and thus
    # will be the same than pkt._orig_str. The "Cannot decompress"
    # error will not be prompted if True.
    max_length = len(s)
    # The result = the extracted name
    name = b""
    # Will contain the index after the pointer, to be returned
    after_pointer = None
    processed_pointers = []  # Used to check for decompression loops
    # Analyse given pkt
    if pkt and hasattr(pkt, "_orig_s") and pkt._orig_s:
        s_full = pkt._orig_s
    else:
        s_full = None
    bytes_left = None
    while True:
        if abs(pointer) >= max_length:
            log_runtime.info(
                "DNS RR prematured end (ofs=%i, len=%i)", pointer, len(s)
            )
            break
        cur = orb(s[pointer])  # get pointer value
        pointer += 1  # make pointer go forward
        if cur & 0xc0:  # Label pointer
            if after_pointer is None:
                # after_pointer points to where the remaining bytes start,
                # as pointer will follow the jump token
                after_pointer = pointer + 1
            if pointer >= max_length:
                log_runtime.info(
                    "DNS incomplete jump token at (ofs=%i)", pointer
                )
                break
            # Follow the pointer
            pointer = ((cur & ~0xc0) << 8) + orb(s[pointer]) - 12
            if pointer in processed_pointers:
                warning("DNS decompression loop detected")
                break
            if not _fullpacket:
                # Do we have access to the whole packet ?
                if s_full:
                    # Yes -> use it to continue
                    bytes_left = s[after_pointer:]
                    s = s_full
                    max_length = len(s)
                    _fullpacket = True
                else:
                    # No -> abort
                    raise Scapy_Exception("DNS message can't be compressed " +
                                          "at this point!")
            processed_pointers.append(pointer)
            continue
        elif cur > 0:  # Label
            # cur = length of the string
            name += s[pointer:pointer + cur] + b"."
            pointer += cur
        else:
            break
    if after_pointer is not None:
        # Return the real end index (not the one we followed)
        pointer = after_pointer
    if bytes_left is None:
        bytes_left = s[pointer:]
    # name, end_index, remaining
    return name, pointer, bytes_left, len(processed_pointers) != 0


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
            if lay is None:
                continue
            current = lay
            while not isinstance(current, NoPayload):
                if isinstance(current, InheritOriginDNSStrPacket):
                    for field in current.fields_desc:
                        if isinstance(field, DNSStrField) or \
                           (isinstance(field, MultipleTypeField) and
                           current.type in [2, 3, 4, 5, 12, 15]):
                            # Get the associated data and store it accordingly  # noqa: E501
                            dat = current.getfieldval(field.name)
                            yield current, field.name, dat
                current = current.payload

    def possible_shortens(dat):
        """Iterates through all possible compression parts in a DNS string"""
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


class InheritOriginDNSStrPacket(Packet):
    __slots__ = Packet.__slots__ + ["_orig_s", "_orig_p"]

    def __init__(self, _pkt=None, _orig_s=None, _orig_p=None, *args, **kwargs):
        self._orig_s = _orig_s
        self._orig_p = _orig_p
        Packet.__init__(self, _pkt=_pkt, *args, **kwargs)


class DNSStrField(StrLenField):
    """
    Special StrField that handles DNS encoding/decoding.
    It will also handle DNS decompression.
    (may be StrLenField if a length_from is passed),
    """
    __slots__ = ["compressed"]

    def h2i(self, pkt, x):
        if not x:
            return b"."
        if x[-1:] != b"." and not _is_ptr(x):
            return x + b"."
        return x

    def i2m(self, pkt, x):
        return dns_encode(x, check_built=True)

    def i2len(self, pkt, x):
        return len(self.i2m(pkt, x))

    def getfield(self, pkt, s):
        remain = b""
        if self.length_from:
            remain, s = super(DNSStrField, self).getfield(pkt, s)
        # Decode the compressed DNS message
        decoded, _, left, self.compressed = dns_get_str(s, 0, pkt)
        # returns (remaining, decoded)
        return left + remain, decoded


class DNSRRCountField(ShortField):
    __slots__ = ["rr"]

    def __init__(self, name, default, rr):
        ShortField.__init__(self, name, default)
        self.rr = rr

    def _countRR(self, pkt):
        x = getattr(pkt, self.rr)
        i = 0
        while isinstance(x, (DNSRR, DNSQR)) or isdnssecRR(x):
            x = x.payload
            i += 1
        return i

    def i2m(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x

    def i2h(self, pkt, x):
        if x is None:
            x = self._countRR(pkt)
        return x


class DNSRRField(StrField):
    __slots__ = ["countfld", "passon", "rr"]
    holds_packets = 1

    def __init__(self, name, countfld, default, passon=1):
        StrField.__init__(self, name, None)
        self.countfld = countfld
        # Notes:
        # - self.rr: used by DNSRRCountField() to compute the records count
        # - self.default: used to set the default record
        self.rr = self.default = default
        self.passon = passon

    def i2m(self, pkt, x):
        if x is None:
            return b""
        return bytes_encode(x)

    def decodeRR(self, name, s, p):
        ret = s[p:p + 10]
        # type, cls, ttl, rdlen
        typ, cls, _, rdlen = struct.unpack("!HHIH", ret)
        p += 10
        cls = DNSRR_DISPATCHER.get(typ, DNSRR)
        rr = cls(b"\x00" + ret + s[p:p + rdlen], _orig_s=s, _orig_p=p)

        # Reset rdlen if DNS compression was used
        for fname in rr.fieldtype.keys():
            rdata_obj = rr.fieldtype[fname]
            if fname == "rdata" and isinstance(rdata_obj, MultipleTypeField):
                rdata_obj = rdata_obj._find_fld_pkt_val(rr, rr.type)[0]
            if isinstance(rdata_obj, DNSStrField) and rdata_obj.compressed:
                del rr.rdlen
                break
        rr.rrname = name

        p += rdlen
        return rr, p

    def getfield(self, pkt, s):
        if isinstance(s, tuple):
            s, p = s
        else:
            p = 0
        ret = None
        c = getattr(pkt, self.countfld)
        if c > len(s):
            log_runtime.info("DNS wrong value: DNS.%s=%i", self.countfld, c)
            return s, b""
        while c:
            c -= 1
            name, p, _, _ = dns_get_str(s, p, _fullpacket=True)
            rr, p = self.decodeRR(name, s, p)
            if ret is None:
                ret = rr
            else:
                ret.add_payload(rr)
        if self.passon:
            return (s, p), ret
        else:
            return s[p:], ret


class DNSQRField(DNSRRField):
    def decodeRR(self, name, s, p):
        ret = s[p:p + 4]
        p += 4
        rr = DNSQR(b"\x00" + ret, _orig_s=s, _orig_p=p)
        rr.qname = name
        return rr, p


class DNSTextField(StrLenField):
    """
    Special StrLenField that handles DNS TEXT data (16)
    """

    islist = 1

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


class DNSQR(InheritOriginDNSStrPacket):
    name = "DNS Question Record"
    show_indent = 0
    fields_desc = [DNSStrField("qname", "www.example.com"),
                   ShortEnumField("qtype", 1, dnsqtypes),
                   ShortEnumField("qclass", 1, dnsclasses)]


class DNS(Packet):
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
        DNSRRCountField("qdcount", None, "qd"),
        DNSRRCountField("ancount", None, "an"),
        DNSRRCountField("nscount", None, "ns"),
        DNSRRCountField("arcount", None, "ar"),
        DNSQRField("qd", "qdcount", DNSQR()),
        DNSRRField("an", "ancount", None),
        DNSRRField("ns", "nscount", None),
        DNSRRField("ar", "arcount", None, 0),
    ]

    def answers(self, other):
        return (isinstance(other, DNS) and
                self.id == other.id and
                self.qr == 1 and
                other.qr == 0)

    def mysummary(self):
        name = ""
        if self.qr:
            type = "Ans"
            if self.ancount > 0 and isinstance(self.an, DNSRR):
                name = ' "%s"' % self.an.rdata
        else:
            type = "Qry"
            if self.qdcount > 0 and isinstance(self.qd, DNSQR):
                name = ' "%s"' % self.qd.qname
        return 'DNS %s%s ' % (type, name)

    def post_build(self, pkt, pay):
        if isinstance(self.underlayer, TCP) and self.length is None:
            pkt = struct.pack("!H", len(pkt) - 2) + pkt[2:]
        return pkt + pay

    def compress(self):
        """Return the compressed DNS packet (using `dns_compress()`"""
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


# RFC 2671 - Extension Mechanisms for DNS (EDNS0)

edns0types = {0: "Reserved", 1: "LLQ", 2: "UL", 3: "NSID", 4: "Reserved",
              5: "PING", 8: "edns-client-subnet"}


class EDNS0TLV(Packet):
    name = "DNS EDNS0 TLV"
    fields_desc = [ShortEnumField("optcode", 0, edns0types),
                   FieldLenField("optlen", None, "optdata", fmt="H"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]

    def extract_padding(self, p):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        return "", p

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Type[Packet]
        if _pkt is None:
            return EDNS0TLV
        if len(_pkt) < 2:
            return Raw
        edns0type = struct.unpack("!H", _pkt[:2])[0]
        if edns0type == 8:
            return EDNS0ClientSubnet
        return EDNS0TLV


class DNSRROPT(InheritOriginDNSStrPacket):
    name = "DNS OPT Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 41, dnstypes),
                   ShortField("rclass", 4096),
                   ByteField("extrcode", 0),
                   ByteField("version", 0),
                   # version 0 means EDNS0
                   BitEnumField("z", 32768, 16, {32768: "D0"}),
                   # D0 means DNSSEC OK from RFC 3225
                   FieldLenField("rdlen", None, length_of="rdata", fmt="H"),
                   PacketListField("rdata", [], EDNS0TLV,
                                   length_from=lambda pkt: pkt.rdlen)]


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


class EDNS0ClientSubnet(Packet):
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


# RFC 4034 - Resource Records for the DNS Security Extensions


# 09/2013 from http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml  # noqa: E501
dnssecalgotypes = {0: "Reserved", 1: "RSA/MD5", 2: "Diffie-Hellman", 3: "DSA/SHA-1",  # noqa: E501
                   4: "Reserved", 5: "RSA/SHA-1", 6: "DSA-NSEC3-SHA1",
                   7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256", 9: "Reserved",
                   10: "RSA/SHA-512", 11: "Reserved", 12: "GOST R 34.10-2001",
                   13: "ECDSA Curve P-256 with SHA-256", 14: "ECDSA Curve P-384 with SHA-384",  # noqa: E501
                   252: "Reserved for Indirect Keys", 253: "Private algorithms - domain name",  # noqa: E501
                   254: "Private algorithms - OID", 255: "Reserved"}

# 09/2013 from http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
dnssecdigesttypes = {0: "Reserved", 1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384"}  # noqa: E501


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
    def h2i(self, pkt, x):
        if isinstance(x, list):
            return RRlist2bitmap(x)
        return x

    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        rrlist = bitmap2RRlist(x)
        return [dnstypes.get(rr, rr) for rr in rrlist] if rrlist else repr(x)


class _DNSRRdummy(InheritOriginDNSStrPacket):
    name = "Dummy class that implements post_build() for Resource Records"

    def post_build(self, pkt, pay):
        if self.rdlen is not None:
            return pkt + pay

        lrrname = len(self.fields_desc[0].i2m("", self.getfieldval("rrname")))
        tmp_len = len(pkt) - lrrname - 10
        tmp_pkt = pkt[:lrrname + 8]
        pkt = struct.pack("!H", tmp_len) + pkt[lrrname + 8 + 2:]

        return tmp_pkt + pkt + pay


class DNSRRMX(_DNSRRdummy):
    name = "DNS MX Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 6, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
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
                   ShortEnumField("rclass", 1, dnsclasses),
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
                   ShortEnumField("rclass", 1, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   DNSStrField("nextname", ""),
                   RRlistField("typebitmaps", "")
                   ]


class DNSRRDNSKEY(_DNSRRdummy):
    name = "DNS DNSKEY Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 48, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
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
                   ShortEnumField("rclass", 1, dnsclasses),
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
                   ShortEnumField("rclass", 1, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ByteField("hashalg", 0),
                   BitEnumField("flags", 0, 8, {1: "Opt-Out"}),
                   ShortField("iterations", 0),
                   FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
                   StrLenField("salt", "", length_from=lambda x: x.saltlength),
                   FieldLenField("hashlength", 0, fmt="!B", length_of="nexthashedownername"),  # noqa: E501
                   StrLenField("nexthashedownername", "", length_from=lambda x: x.hashlength),  # noqa: E501
                   RRlistField("typebitmaps", "")
                   ]


class DNSRRNSEC3PARAM(_DNSRRdummy):
    name = "DNS NSEC3PARAM Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 51, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
                   IntField("ttl", 0),
                   ShortField("rdlen", None),
                   ByteField("hashalg", 0),
                   ByteField("flags", 0),
                   ShortField("iterations", 0),
                   FieldLenField("saltlength", 0, fmt="!B", length_of="salt"),
                   StrLenField("salt", "", length_from=lambda pkt: pkt.saltlength)  # noqa: E501
                   ]

# RFC 2782 - A DNS RR for specifying the location of services (DNS SRV)


class DNSRRSRV(_DNSRRdummy):
    name = "DNS SRV Resource Record"
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 33, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
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


DNSRR_DISPATCHER = {
    6: DNSRRSOA,         # RFC 1035
    15: DNSRRMX,         # RFC 1035
    33: DNSRRSRV,        # RFC 2782
    41: DNSRROPT,        # RFC 1671
    43: DNSRRDS,         # RFC 4034
    46: DNSRRRSIG,       # RFC 4034
    47: DNSRRNSEC,       # RFC 4034
    48: DNSRRDNSKEY,     # RFC 4034
    50: DNSRRNSEC3,      # RFC 5155
    51: DNSRRNSEC3PARAM,  # RFC 5155
    250: DNSRRTSIG,      # RFC 2845
    32769: DNSRRDLV,     # RFC 4431
}

DNSSEC_CLASSES = tuple(six.itervalues(DNSRR_DISPATCHER))


def isdnssecRR(obj):
    return isinstance(obj, DNSSEC_CLASSES)


class DNSRR(InheritOriginDNSStrPacket):
    name = "DNS Resource Record"
    show_indent = 0
    fields_desc = [DNSStrField("rrname", ""),
                   ShortEnumField("type", 1, dnstypes),
                   ShortEnumField("rclass", 1, dnsclasses),
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
                           # NS, MD, MF, CNAME, PTR
                           (DNSStrField("rdata", "",
                                        length_from=lambda pkt: pkt.rdlen),
                               lambda pkt: pkt.type in [2, 3, 4, 5, 12]),
                           # TEXT
                           (DNSTextField("rdata", [],
                                         length_from=lambda pkt: pkt.rdlen),
                               lambda pkt: pkt.type == 16),
                       ],
                       StrLenField("rdata", "",
                                   length_from=lambda pkt:pkt.rdlen)
    )]


bind_layers(UDP, DNS, dport=5353)
bind_layers(UDP, DNS, sport=5353)
bind_layers(UDP, DNS, dport=53)
bind_layers(UDP, DNS, sport=53)
DestIPField.bind_addr(UDP, "224.0.0.251", dport=5353)
DestIP6Field.bind_addr(UDP, "ff02::fb", dport=5353)
bind_layers(TCP, DNS, dport=53)
bind_layers(TCP, DNS, sport=53)


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
    function_name = "dns_spoof"
    filter = "udp port 53"
    cls = DNS  # We use this automaton for llmnr_spoof

    def parse_options(self, joker=None,
                      match=None, joker6=None, from_ip=None):
        """
        :param joker: default IPv4 for unresolved domains. (Default: None)
                      Set to False to disable, None to mirror the interface's IP.
        :param joker6: default IPv6 for unresolved domains (Default: False)
                       set to False to disable, None to mirror the interface's IPv6.
        :param match: a dictionary of {names: (ip, ipv6)}
        :param from_ip: an source IP to filter. Can contain a netmask
        """
        if match is None:
            self.match = {}
        else:
            self.match = match
        self.joker = joker
        self.joker6 = joker6
        if isinstance(from_ip, str):
            self.from_ip = Net(from_ip)
        else:
            self.from_ip = from_ip

    def is_request(self, req):
        from scapy.layers.inet6 import IPv6
        return (
            req.haslayer(self.cls) and
            req.getlayer(self.cls).qr == 0 and
            (not self.from_ip or (
                req[IPv6].src in req if IPv6 in req else req[IP].src
            ) in self.from_ip)
        )

    def make_reply(self, req):
        IPcls = IPv6 if IPv6 in req else IP
        resp = IPcls(dst=req[IPcls].src) / UDP(sport=req.dport, dport=req.sport)
        dns = req.getlayer(self.cls)
        if req.qd.qtype == 28:
            # AAAA
            if self.joker6 is False:
                return
            rdata = self.match.get(
                dns.qd.qname,
                self.joker or get_if_addr6(self.optsniff.get("iface", conf.iface))
            )
            if isinstance(rdata, (tuple, list)):
                rdata = rdata[1]
            resp /= self.cls(id=dns.id, qr=1, qd=dns.qd,
                             an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=rdata,
                                      type=28))
        else:
            if self.joker is False:
                return
            rdata = self.match.get(
                dns.qd.qname,
                self.joker or get_if_addr(self.optsniff.get("iface", conf.iface))
            )
            if isinstance(rdata, (tuple, list)):
                # Fallback
                rdata = rdata[0]
            resp /= self.cls(id=dns.id, qr=1, qd=dns.qd,
                             an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=rdata))
        return resp
