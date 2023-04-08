# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Clone of p0f v3 passive OS fingerprinting
"""

import re
import struct
import random

from scapy.data import KnowledgeBase, select_path
from scapy.config import conf
from scapy.compat import raw, orb
from scapy.packet import NoPayload
from scapy.layers.inet import IP, TCP, TCPOptions
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet6 import IPv6
from scapy.volatile import RandByte, RandShort, RandString
from scapy.error import warning

_p0fpaths = ["/etc/p0f", "/usr/share/p0f", "/opt/local"]
conf.p0f_base = select_path(_p0fpaths, "p0f.fp")

MIN_TCP4 = 40  # Min size of IPv4/TCP headers
MIN_TCP6 = 60  # Min size of IPv6/TCP headers
MAX_DIST = 35  # Maximum TTL distance for non-fuzzy signature matching

WIN_TYPE_NORMAL = 0  # Literal value
WIN_TYPE_ANY = 1  # Wildcard
WIN_TYPE_MOD = 2  # Modulo check
WIN_TYPE_MSS = 3  # Window size MSS multiplier
WIN_TYPE_MTU = 4  # Window size MTU multiplier

# Convert TCP option num to p0f (nop is handled separately)
tcp_options_p0f = {
    2: "mss",  # maximum segment size
    3: "ws",  # window scaling
    4: "sok",  # selective ACK permitted
    5: "sack",  # selective ACK (should not be seen)
    8: "ts",  # timestamp
}


# Signatures
class TCP_Signature(object):
    __slots__ = ["olayout", "quirks", "ip_opt_len", "ip_ver", "ttl",
                 "mss", "win", "win_type", "wscale", "pay_class", "ts1"]

    def __init__(self, olayout, quirks, ip_opt_len, ip_ver, ttl,
                 mss, win, win_type, wscale, pay_class, ts1):
        self.olayout = olayout
        self.quirks = quirks
        self.ip_opt_len = ip_opt_len
        self.ip_ver = ip_ver
        self.ttl = ttl
        self.mss = mss
        self.win = win
        self.win_type = win_type  # None for packet signatures
        self.wscale = wscale
        self.pay_class = pay_class
        self.ts1 = ts1  # None for base signatures

    @classmethod
    def from_packet(cls, pkt):
        """
        Receives a TCP packet (assuming it's valid), and returns
        a TCP_Signature object
        """
        ip_ver = pkt.version
        quirks = set()

        def addq(name):
            quirks.add(name)

        # IPv4/IPv6 parsing
        if ip_ver == 4:
            ttl = pkt.ttl
            ip_opt_len = (pkt.ihl * 4) - 20
            if pkt.tos & (0x01 | 0x02):
                addq("ecn")
            if pkt.flags.evil:
                addq("0+")
            if pkt.flags.DF:
                addq("df")
                if pkt.id:
                    addq("id+")
            elif pkt.id == 0:
                addq("id-")
        else:
            ttl = pkt.hlim
            ip_opt_len = 0
            if pkt.fl:
                addq("flow")
            if pkt.tc & (0x01 | 0x02):
                addq("ecn")

        # TCP parsing
        tcp = pkt[TCP]
        win = tcp.window
        if tcp.flags & (0x40 | 0x80 | 0x01):
            addq("ecn")
        if tcp.seq == 0:
            addq("seq-")
        if tcp.flags.A:
            if tcp.ack == 0:
                addq("ack-")
        elif tcp.ack:
            addq("ack+")
        if tcp.flags.U:
            addq("urgf+")
        elif tcp.urgptr:
            addq("uptr+")
        if tcp.flags.P:
            addq("pushf+")

        pay_class = 1 if tcp.payload else 0

        # Manual TCP options parsing
        mss = 0
        wscale = 0
        ts1 = 0
        olayout = ""
        optlen = (tcp.dataofs << 2) - 20
        x = raw(tcp)[-optlen:]  # raw bytes of TCP options
        while x:
            onum = orb(x[0])
            if onum == 0:
                x = x[1:]
                olayout += "eol+%i," % len(x)
                if x.strip(b"\x00"):  # non-zero past EOL
                    addq("opt+")
                break
            if onum == 1:
                x = x[1:]
                olayout += "nop,"
                continue
            try:
                olen = orb(x[1])
            except IndexError:  # no room for length field
                addq("bad")
                break
            oval = x[2:olen]
            if onum in tcp_options_p0f:
                ofmt = TCPOptions[0][onum][1]
                olayout += "%s," % tcp_options_p0f[onum]
                optsize = 2 + struct.calcsize(ofmt) if ofmt else 2  # total len
                if len(x) < optsize:  # option would end past end of header
                    addq("bad")
                    break

                if onum == 5:
                    if olen < 10 or olen > 34:  # SACK length out of range
                        addq("bad")
                        break
                else:
                    if olen != optsize:  # length field doesn't fit option type
                        addq("bad")
                        break
                    if ofmt:
                        oval = struct.unpack(ofmt, oval)
                        if len(oval) == 1:
                            oval = oval[0]
                    if onum == 2:
                        mss = oval
                    elif onum == 3:
                        wscale = oval
                        if wscale > 14:
                            addq("exws")
                    elif onum == 8:
                        ts1 = oval[0]
                        if not ts1:
                            addq("ts1-")
                        if oval[1] and (tcp.flags.S and not tcp.flags.A):
                            addq("ts2+")
            else:  # Unknown option, presumably with specified size
                if olen < 2 or olen > 40 or olen > len(x):
                    addq("bad")
                    break
            x = x[olen:]
        olayout = olayout[:-1]

        return cls(olayout, quirks, ip_opt_len, ip_ver, ttl, mss, win, None, wscale, pay_class, ts1)  # noqa: E501

    @classmethod
    def from_raw_sig(cls, sig_line):
        """
        Parses a TCP sig line and returns a tuple consisting of a
        TCP_Signature object and bad_ttl as bool
        """
        ver, ttl, olen, mss, wsize, olayout, quirks, pclass = lparse(sig_line, 8)  # noqa: E501
        wsize, _, scale = wsize.partition(",")

        ip_ver = -1 if ver == "*" else int(ver)
        ttl, bad_ttl = (int(ttl[:-1]), True) if ttl[-1] == "-" else (int(ttl), False)  # noqa: E501
        ip_opt_len = int(olen)
        mss = -1 if mss == "*" else int(mss)
        if wsize == "*":
            win, win_type = (0, WIN_TYPE_ANY)
        elif wsize[:3] == "mss":
            win, win_type = (int(wsize[4:]), WIN_TYPE_MSS)
        elif wsize[0] == "%":
            win, win_type = (int(wsize[1:]), WIN_TYPE_MOD)
        elif wsize[:3] == "mtu":
            win, win_type = (int(wsize[4:]), WIN_TYPE_MTU)
        else:
            win, win_type = (int(wsize), WIN_TYPE_NORMAL)
        wscale = -1 if scale == "*" else int(scale)
        if quirks:
            quirks = frozenset(q for q in quirks.split(","))
        else:
            quirks = frozenset()
        pay_class = -1 if pclass == "*" else int(pclass == "+")

        sig = cls(olayout, quirks, ip_opt_len, ip_ver, ttl, mss, win, win_type, wscale, pay_class, None)  # noqa: E501
        return sig, bad_ttl

    def __str__(self):
        quirks = ",".join(q for q in self.quirks)
        fmt = "%i:%i+%i:%i:%i:%i,%i:%s:%s:%i"
        s = fmt % (self.ip_ver, self.ttl, guess_dist(self.ttl),
                   self.ip_opt_len, self.mss, self.win, self.wscale,
                   self.olayout, quirks, self.pay_class)
        return s


class HTTP_Signature(object):
    __slots__ = ["http_ver", "hdr", "hdr_set", "habsent", "sw"]

    def __init__(self, http_ver, hdr, hdr_set, habsent, sw):
        self.http_ver = http_ver
        self.hdr = hdr
        self.hdr_set = hdr_set
        self.habsent = habsent  # None for packet signatures
        self.sw = sw

    @classmethod
    def from_packet(cls, pkt):
        """
        Receives an HTTP packet (assuming it's valid), and returns
        a HTTP_Signature object
        """
        http_payload = raw(pkt[TCP].payload)

        crlfcrlf = b"\r\n\r\n"
        crlfcrlfIndex = http_payload.find(crlfcrlf)
        if crlfcrlfIndex != -1:
            headers = http_payload[:crlfcrlfIndex + len(crlfcrlf)]
        else:
            headers = http_payload
        headers = headers.decode()  # XXX: Check if this could fail
        first_line, headers = headers.split("\r\n", 1)

        if "1.0" in first_line:
            http_ver = 0
        elif "1.1" in first_line:
            http_ver = 1
        else:
            raise ValueError("HTTP version is not 1.0/1.1")

        sw = ""
        headers_found = []
        hdr_set = set()
        for header_line in headers.split("\r\n"):
            name, _, value = header_line.partition(":")
            if value:
                value = value.strip()
                headers_found.append((name, value))
                hdr_set.add(name)
                if name in ("User-Agent", "Server"):
                    sw = value
        hdr = tuple(headers_found)
        return cls(http_ver, hdr, hdr_set, None, sw)

    @classmethod
    def from_raw_sig(cls, sig_line):
        """
        Parses an HTTP sig line and returns a HTTP_Signature object
        """
        ver, horder, habsent, expsw = lparse(sig_line, 4)
        http_ver = -1 if ver == "*" else int(ver)

        # horder parsing - split by commas that aren't in []
        new_horder = []
        for header in re.split(r",(?![^\[]*\])", horder):
            name, _, value = header.partition("=")
            if name[0] == "?":  # Optional header
                new_horder.append((name[1:], value[1:-1], True))
            else:
                new_horder.append((name, value[1:-1], False))
        hdr = tuple(new_horder)
        hdr_set = frozenset(header[0] for header in hdr if not header[2])
        habsent = frozenset(habsent.split(","))
        return cls(http_ver, hdr, hdr_set, habsent, expsw)

    def __str__(self):
        # values that depend on the context are not included in the string
        skipval = ("Host", "User-Agent", "Date", "Content-Type", "Server")
        hdr = ",".join(n if n in skipval else "%s=[%s]" % (n, v) for n, v in self.hdr)  # noqa: E501
        fmt = "%i:%s::%s"
        s = fmt % (self.http_ver, hdr, self.sw)
        return s


# Records
class MTU_Record(object):
    __slots__ = ["label_id", "mtu"]

    def __init__(self, label_id, sig_line):
        self.label_id = label_id
        self.mtu = int(sig_line)


class TCP_Record(object):
    __slots__ = ["label_id", "bad_ttl", "sig"]

    def __init__(self, label_id, sig_line):
        self.label_id = label_id
        sig, bad_ttl = TCP_Signature.from_raw_sig(sig_line)
        self.bad_ttl = bad_ttl
        self.sig = sig


class HTTP_Record(object):
    __slots__ = ["label_id", "sig"]

    def __init__(self, label_id, sig_line):
        self.label_id = label_id
        self.sig = HTTP_Signature.from_raw_sig(sig_line)


class p0fKnowledgeBase(KnowledgeBase):
    """
    self.base = {
        "mtu" (str): [sig(tuple), ...]
        "tcp"/"http" (str): {
            direction (str): [sig(tuple), ...]
            }
    }
    self.labels = (label(tuple), ...)
    """
    def lazy_init(self):
        try:
            f = open(self.filename)
        except Exception:
            warning("Can't open base %s", self.filename)
            return

        self.base = {}
        self.labels = []
        self._parse_file(f)
        self.labels = tuple(self.labels)
        f.close()

    def _parse_file(self, file):
        """
        Parses p0f.fp file and stores the data with described structures.
        """
        label_id = -1

        for line in file:
            if line[0] in (";", "\n"):
                continue
            line = line.strip()

            if line[0] == "[":
                section, direction = lparse(line[1:-1], 2)
                if section == "mtu":
                    self.base[section] = []
                    curr_records = self.base[section]
                else:
                    if section not in self.base:
                        self.base[section] = {direction: []}
                    elif direction not in self.base[section]:
                        self.base[section][direction] = []
                    curr_records = self.base[section][direction]
            else:
                param, _, val = line.partition(" = ")
                param = param.strip()

                if param == "sig":
                    if section == "mtu":
                        record_class = MTU_Record
                    elif section == "tcp":
                        record_class = TCP_Record
                    elif section == "http":
                        record_class = HTTP_Record
                    curr_records.append(record_class(label_id, val))

                elif param == "label":
                    label_id += 1
                    if section == "mtu":
                        self.labels.append(val)
                        continue
                    # label = type:class:name:flavor
                    t, c, name, flavor = lparse(val, 4)
                    self.labels.append((t, c, name, flavor))

                elif param == "sys":
                    sys_names = tuple(name for name in val.split(","))
                    self.labels[label_id] += (sys_names,)

    def get_sigs_by_os(self, direction, osgenre, osdetails=None):
        """Get TCP signatures that match an OS genre and details (if specified).
        If osdetails isn't specified, then we pick all signatures
        that match osgenre.

        Examples:
            >>> p0fdb.get_sigs_by_os("request", "Linux", "2.6")
            >>> p0fdb.get_sigs_by_os("response", "Windows", "8")
            >>> p0fdb.get_sigs_by_os("request", "FreeBSD")
        """
        sigs = []
        for tcp_record in self.base["tcp"][direction]:
            label = self.labels[tcp_record.label_id]
            name, flavor = label[2], label[3]
            if osgenre and osgenre == name:
                if osdetails:
                    if osdetails in flavor:
                        sigs.append(tcp_record.sig)
                else:
                    sigs.append(tcp_record.sig)
        return sigs

    def tcp_find_match(self, ts, direction):
        """
        Finds the best match for the given signature and direction.
        If a match is found, returns a tuple consisting of:
        - label: the matched label
        - dist: guessed distance from the packet source
        - fuzzy: whether the match is fuzzy
        Returns None if no match was found
        """
        win_multi, use_mtu = detect_win_multi(ts)

        gmatch = None  # generic match
        fmatch = None  # fuzzy match
        for tcp_record in self.base["tcp"][direction]:
            rs = tcp_record.sig

            fuzzy = False
            ref_quirks = rs.quirks

            if rs.olayout != ts.olayout:
                continue

            if rs.ip_ver == -1:
                ref_quirks -= {"flow"} if ts.ip_ver == 4 else {"df", "id+", "id-"}  # noqa: E501

            if ref_quirks != ts.quirks:
                deleted = (ref_quirks ^ ts.quirks) & ref_quirks
                added = (ref_quirks ^ ts.quirks) & ts.quirks

                if (fmatch or (deleted - {"df", "id+"}) or (added - {"id-", "ecn"})):  # noqa: E501
                    continue
                fuzzy = True

            if rs.ip_opt_len != ts.ip_opt_len:
                continue
            if tcp_record.bad_ttl:
                if rs.ttl < ts.ttl:
                    continue
            else:
                if rs.ttl < ts.ttl or rs.ttl - ts.ttl > MAX_DIST:
                    fuzzy = True

            if ((rs.mss != -1 and rs.mss != ts.mss) or
               (rs.wscale != -1 and rs.wscale != ts.wscale) or
               (rs.pay_class != -1 and rs.pay_class != ts.pay_class)):
                continue

            if rs.win_type == WIN_TYPE_NORMAL:
                if rs.win != ts.win:
                    continue
            elif rs.win_type == WIN_TYPE_MOD:
                if ts.win % rs.win:
                    continue
            elif rs.win_type == WIN_TYPE_MSS:
                if (use_mtu or rs.win != win_multi):
                    continue
            elif rs.win_type == WIN_TYPE_MTU:
                if (not use_mtu or rs.win != win_multi):
                    continue

            # Got a match? If not fuzzy, return. If fuzzy, keep looking.
            label = self.labels[tcp_record.label_id]
            match = (label, rs.ttl - ts.ttl, fuzzy)
            if not fuzzy:
                if label[0] == "s":
                    return match
                elif not gmatch:
                    gmatch = match
            elif not fmatch:
                fmatch = match

        if gmatch:
            return gmatch
        if fmatch:
            return fmatch
        return None

    def http_find_match(self, ts, direction):
        """
        Finds the best match for the given signature and direction.
        If a match is found, returns a tuple consisting of:
        - label: the matched label
        - dishonest: whether the software was detected as dishonest
        Returns None if no match was found
        """
        gmatch = None  # generic match
        for http_record in self.base["http"][direction]:
            rs = http_record.sig

            if rs.http_ver != -1 and rs.http_ver != ts.http_ver:
                continue

            # Check that all non-optional headers appear in the packet
            if not (ts.hdr_set & rs.hdr_set) == rs.hdr_set:
                continue

            # Check that no forbidden headers appear in the packet.
            if len(rs.habsent & ts.hdr_set) > 0:
                continue

            def headers_correl():
                phi = 0  # Packet HTTP header index
                hdr_len = len(ts.hdr)

                # Confirm the ordering and values of headers
                # (this is relatively slow, hence the if statements above).
                # The algorithm is derived from the original p0f/fp_http.c
                for kh in rs.hdr:
                    orig_phi = phi
                    while (phi < hdr_len and
                           kh[0] != ts.hdr[phi][0]):
                        phi += 1

                    if phi == hdr_len:
                        if not kh[2]:
                            return False

                        for ph in ts.hdr:
                            if kh[0] == ph[0]:
                                return False

                        phi = orig_phi
                        continue

                    if kh[1] not in ts.hdr[phi][1]:
                        return False
                    phi += 1
                return True

            if not headers_correl():
                continue

            # Got a match
            label = self.labels[http_record.label_id]
            dishonest = rs.sw and ts.sw and rs.sw not in ts.sw
            match = (label, dishonest)
            if label[0] == "s":
                return match
            elif not gmatch:
                gmatch = match
        return gmatch if gmatch else None

    def mtu_find_match(self, mtu):
        """
        Finds a match for the given MTU.
        If a match is found, returns the label string.
        Returns None if no match was found
        """
        for mtu_record in self.base["mtu"]:
            if mtu == mtu_record.mtu:
                return self.labels[mtu_record.label_id]
        return None


p0fdb = p0fKnowledgeBase(conf.p0f_base)


def guess_dist(ttl):
    for ottl in (32, 64, 128, 255):
        if ttl <= ottl:
            return ottl - ttl


def lparse(line, n, delimiter=":", default=""):
    """
    Parsing of 'a:b:c:d:e' lines
    """
    a = line.split(delimiter)[:n]
    for elt in a:
        yield elt
    for _ in range(n - len(a)):
        yield default


def validate_packet(pkt):
    """
    Validate that the packet is an IPv4/IPv6 and TCP packet.
    If the packet is valid, a copy is returned. If not, TypeError is raised.
    """
    pkt = pkt.copy()
    valid = pkt.haslayer(TCP) and (pkt.haslayer(IP) or pkt.haslayer(IPv6))
    if not valid:
        raise TypeError("Not a TCP/IP packet")
    return pkt


def detect_win_multi(ts):
    """
    Figure out if window size is a multiplier of MSS or MTU.
    Receives a TCP signature and returns the multiplier and
    whether mtu should be used
    """
    mss = ts.mss
    win = ts.win
    if not win or mss < 100:
        return -1, False

    options = [
        (mss, False),
        (1500 - MIN_TCP4, False),
        (1500 - MIN_TCP4 - 12, False),
        (mss + MIN_TCP4, True),
        (1500, True)
    ]
    if ts.ts1:
        options.append((mss - 12, False))
    if ts.ip_ver == 6:
        options.append((1500 - MIN_TCP6, False))
        options.append((1500 - MIN_TCP6 - 12, False))
        options.append((mss + MIN_TCP6, True))

    for div, use_mtu in options:
        if not win % div:
            return win / div, use_mtu
    return -1, False


def packet2p0f(pkt):
    """
    Returns a p0f signature of the packet, and the direction.
    Raises TypeError if the packet isn't valid for p0f
    """
    pkt = validate_packet(pkt)
    pkt = pkt.__class__(raw(pkt))

    if pkt[TCP].flags.S:
        if pkt[TCP].flags.A:
            direction = "response"
        else:
            direction = "request"
        sig = TCP_Signature.from_packet(pkt)

    elif pkt[TCP].payload:
        # XXX: guess_payload_class doesn't use any class related attributes
        pclass = HTTP().guess_payload_class(raw(pkt[TCP].payload))
        if pclass == HTTPRequest:
            direction = "request"
        elif pclass == HTTPResponse:
            direction = "response"
        else:
            raise TypeError("Not an HTTP payload")
        sig = HTTP_Signature.from_packet(pkt)
    else:
        raise TypeError("Not a SYN, SYN/ACK, or HTTP packet")
    return sig, direction


def fingerprint_mtu(pkt):
    """
    Fingerprints the MTU based on the maximum segment size specified
    in TCP options.
    If a match was found, returns the label. If not returns None
    """
    pkt = validate_packet(pkt)
    mss = 0
    for name, value in pkt.payload.options:
        if name == "MSS":
            mss = value

    if not mss:
        return None

    mtu = (mss + MIN_TCP4) if pkt.version == 4 else (mss + MIN_TCP6)

    if not p0fdb.get_base():
        warning("p0f base empty.")
        return None

    return p0fdb.mtu_find_match(mtu)


def p0f(pkt):
    sig, direction = packet2p0f(pkt)
    if not p0fdb.get_base():
        warning("p0f base empty.")
        return None

    if isinstance(sig, TCP_Signature):
        return p0fdb.tcp_find_match(sig, direction)
    else:
        return p0fdb.http_find_match(sig, direction)


def prnp0f(pkt):
    """Calls p0f and prints a user-friendly output"""
    try:
        r = p0f(pkt)
    except Exception:
        return

    sig, direction = packet2p0f(pkt)
    is_tcp_sig = isinstance(sig, TCP_Signature)
    to_server = direction == "request"

    if is_tcp_sig:
        pkt_type = "SYN" if to_server else "SYN+ACK"
    else:
        pkt_type = "HTTP Request" if to_server else "HTTP Response"

    res = pkt.sprintf(".-[ %IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport% (" + pkt_type + ") ]-\n|\n")  # noqa: E501
    fields = []

    def add_field(name, value):
        fields.append("| %-8s = %s\n" % (name, value))

    cli_or_svr = "Client" if to_server else "Server"
    add_field(cli_or_svr, pkt.sprintf("%IP.src%:%TCP.sport%"))

    if r:
        label = r[0]
        app_or_os = "App" if label[1] == "!" else "OS"
        add_field(app_or_os, label[2] + " " + label[3])
        if len(label) == 5:  # label includes sys
            add_field("Sys", ", ".join(name for name in label[4]))
        if is_tcp_sig:
            add_field("Distance", r[1])
    else:
        app_or_os = "OS" if is_tcp_sig else "App"
        add_field(app_or_os, "UNKNOWN")

    add_field("Raw sig", str(sig))

    res += "".join(fields)
    res += "`____\n"
    print(res)


def p0f_impersonate(pkt, osgenre=None, osdetails=None, signature=None,
                    extrahops=0, mtu=1500, uptime=None):
    """Modifies pkt so that p0f will think it has been sent by a
    specific OS. Either osgenre or signature is required to impersonate.
    If signature is specified (as a raw string), we use the signature.
    signature format:
        "ip_ver:ttl:ip_opt_len:mss:window,wscale:opt_layout:quirks:pay_class"

    If osgenre is specified, we randomly pick a signature with a label
    that matches osgenre (and osdetails, if specified).
    Note: osgenre is case sensitive ("linux" -> "Linux" etc.), and osdetails
    is a substring of a label flavor ("7", "8" and "7 or 8" will
    all match the label "s:win:Windows:7 or 8")

    For now, only TCP SYN/SYN+ACK packets are supported."""
    pkt = validate_packet(pkt)

    if not osgenre and not signature:
        raise ValueError("osgenre or signature is required to impersonate!")

    tcp = pkt[TCP]
    tcp_type = tcp.flags & (0x02 | 0x10)  # SYN / SYN+ACK

    if signature:
        if isinstance(signature, str):
            sig, _ = TCP_Signature.from_raw_sig(signature)
        else:
            raise TypeError("Unsupported signature type")
    else:
        if not p0fdb.get_base():
            sigs = []
        else:
            direction = "request" if tcp_type == 0x02 else "response"
            sigs = p0fdb.get_sigs_by_os(direction, osgenre, osdetails)

        # If IPv6 packet, remove IPv4-only signatures and vice versa
        sigs = [s for s in sigs if s.ip_ver == -1 or s.ip_ver == pkt.version]
        if not sigs:
            raise ValueError("No match in the p0f database")
        sig = random.choice(sigs)

    if sig.ip_ver != -1 and pkt.version != sig.ip_ver:
        raise ValueError("Can't convert between IPv4 and IPv6")

    quirks = sig.quirks

    if pkt.version == 4:
        pkt.ttl = sig.ttl - extrahops
        if sig.ip_opt_len != 0:
            # FIXME: Non-zero IPv4 options not handled
            warning("Unhandled IPv4 option field")
        else:
            pkt.options = []

        if "df" in quirks:
            pkt.flags |= 0x02  # set DF flag
            if "id+" in quirks:
                if pkt.id == 0:
                    pkt.id = random.randint(1, 2**16 - 1)
            else:
                pkt.id = 0
        else:
            pkt.flags &= ~(0x02)  # DF flag not set
            if "id-" in quirks:
                pkt.id = 0
            elif pkt.id == 0:
                pkt.id = random.randint(1, 2**16 - 1)
        if "ecn" in quirks:
            pkt.tos |= random.randint(0x01, 0x03)
        pkt.flags = pkt.flags | 0x04 if "0+" in quirks else pkt.flags & ~(0x04)
    else:
        pkt.hlim = sig.ttl - extrahops
        if "flow" in quirks:
            pkt.fl = random.randint(1, 2**20 - 1)
        if "ecn" in quirks:
            pkt.tc |= random.randint(0x01, 0x03)

    # Take the options already set as "hints" to use in the new packet if we
    # can. we'll use the already-set values if they're valid integers.
    def int_only(val):
        return val if isinstance(val, int) else None
    orig_opts = dict(tcp.options)
    mss_hint = int_only(orig_opts.get("MSS"))
    ws_hint = int_only(orig_opts.get("WScale"))
    ts_hint = [int_only(o) for o in orig_opts.get("Timestamp", (None, None))]

    options = []
    for opt in sig.olayout.split(","):
        if opt == "mss":
            # MSS might have a maximum size because of WIN_TYPE_MSS
            if sig.win_type == WIN_TYPE_MSS:
                maxmss = (2**16 - 1) // sig.win
            else:
                maxmss = (2**16 - 1)

            if sig.mss == -1:  # wildcard mss
                if mss_hint and 0 <= mss_hint <= maxmss:
                    options.append(("MSS", mss_hint))
                else:  # invalid hint, generate new value
                    options.append(("MSS", random.randint(100, maxmss)))
            else:
                options.append(("MSS", sig.mss))

        elif opt == "ws":
            if sig.wscale == -1:  # wildcard wscale
                maxws = 2**8
                if "exws" in quirks:  # wscale > 14
                    if ws_hint and 14 < ws_hint < maxws:
                        options.append(("WScale", ws_hint))
                    else:  # invalid hint, generate new value > 14
                        options.append(("WScale", random.randint(15, maxws - 1)))  # noqa: E501
                else:
                    if ws_hint and 0 <= ws_hint < maxws:
                        options.append(("WScale", ws_hint))
                    else:  # invalid hint, generate new value
                        options.append(("WScale", RandByte()))
            else:
                options.append(("WScale", sig.wscale))

        elif opt == "ts":
            ts1, ts2 = ts_hint

            if "ts1-" in quirks:  # own timestamp specified as zero
                ts1 = 0
            elif uptime is not None:  # if specified uptime, override
                ts1 = uptime
            elif ts1 is None or not (0 < ts1 < 2**32):  # invalid hint
                ts1 = random.randint(120, 100 * 60 * 60 * 24 * 365)

            # non-zero peer timestamp on initial SYN
            if "ts2+" in quirks and tcp_type == 0x02:
                if ts2 is None or not (0 < ts2 < 2**32):  # invalid hint
                    ts2 = random.randint(1, 2**32 - 1)
            else:
                ts2 = 0
            options.append(("Timestamp", (ts1, ts2)))

        elif opt == "nop":
            options.append(("NOP", None))
        elif opt == "sok":
            options.append(("SAckOK", ""))
        elif opt[:3] == "eol":
            options.append(("EOL", None))
            # FIXME: opt+ quirk not handled
            if "opt+" in quirks:
                warning("Unhandled opt+ quirk")
        elif opt == "sack":
            # Randomize SAck value in range of 10 <= val <= 34
            sack_len = random.choice([10, 18, 26, 34]) - 2
            optstruct = "!%iI" % (sack_len // 4)
            rand_val = RandString(struct.calcsize(optstruct))._fix()
            options.append(("SAck", struct.unpack(optstruct, rand_val)))
        else:
            warning("Unhandled TCP option %s", opt)
        tcp.options = options

    if sig.win_type == WIN_TYPE_NORMAL:
        tcp.window = sig.win
    elif sig.win_type == WIN_TYPE_MSS:
        mss = [x for x in options if x[0] == "MSS"]
        if not mss:
            raise ValueError("TCP window value requires MSS, and MSS option not set")  # noqa: E501
        tcp.window = mss[0][1] * sig.win
    elif sig.win_type == WIN_TYPE_MOD:
        tcp.window = sig.win * random.randint(1, (2**16 - 1) // sig.win)
    elif sig.win_type == WIN_TYPE_MTU:
        tcp.window = mtu * sig.win
    elif sig.win_type == WIN_TYPE_ANY:
        tcp.window = RandShort()
    else:
        warning("Unhandled window size specification")

    if "seq-" in quirks:
        tcp.seq = 0
    elif tcp.seq == 0:
        tcp.seq = random.randint(1, 2**32 - 1)

    if "ack+" in quirks:
        tcp.flags &= ~(0x10)  # ACK flag not set
        if tcp.ack == 0:
            tcp.ack = random.randint(1, 2**32 - 1)
    elif "ack-" in quirks:
        tcp.flags |= 0x10  # ACK flag set
        tcp.ack = 0

    if "uptr+" in quirks:
        tcp.flags &= ~(0x020)  # URG flag not set
        if tcp.urgptr == 0:
            tcp.urgptr = random.randint(1, 2**16 - 1)
    elif "urgf+" in quirks:
        tcp.flags |= 0x020  # URG flag used

    tcp.flags = tcp.flags | 0x08 if "pushf+" in quirks else tcp.flags & ~(0x08)

    if sig.pay_class:  # signature has payload
        if not tcp.payload:
            pkt /= conf.raw_layer(load=RandString(random.randint(1, 10)))
    else:
        tcp.payload = NoPayload()

    return pkt
