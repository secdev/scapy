from __future__ import absolute_import
from __future__ import print_function
import re
import struct

from scapy.data import KnowledgeBase, select_path
from scapy.config import conf
from scapy.compat import raw, orb
from scapy.layers.inet import IP, TCP, TCPOptions
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet6 import IPv6
from scapy.error import warning
from scapy.modules.six.moves import range

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

quirks_p0f = {
    "df": 0,  # don't fragment flag
    "id+": 1,  # df set but IPID non-zero
    "id-": 2,  # df not set but IPID zero
    "ecn": 3,  # explicit confestion notification support
    "0+": 4,  # 'must be zero' field not zero
    "flow": 5,  # non-zero IPv6 flow ID
    "seq-": 6,  # sequence number is zero
    "ack+": 7,  # ACK number is non-zero but ACK flag is not set
    "ack-": 8,  # ACK number is zero but ACK flag is set
    "uptr+": 9,  # URG pointer is non-zero but URG flag not set
    "urgf+": 10,  # URG flag used
    "pushf+": 11,  # PUSH flag used
    "ts1-": 12,  # own timestamp specified as zero
    "ts2+": 13,  # non-zero peer timestamp on initial SYN
    "opt+": 14,  # trailing non-zero data in options segment
    "exws": 15,  # excessive window scaling factor ( > 14)
    "bad": 16  # malformed tcp options
}

options_p0f = {
    1: "nop",  # no-op option
    2: "mss",  # maximum segment size
    3: "ws",  # window scaling
    4: "sok",  # selective ACK permitted
    5: "sack",  # selective ACK (should not be seen)
    8: "ts",  # timestamp
}


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
                        curr_records.append((label_id, int(val)))
                    elif section == "tcp":
                        sig = self.tcp_register_sig(val)
                        curr_records.append((label_id, sig))
                    elif section == "http":
                        sig = self.http_register_sig(val)
                        curr_records.append((label_id, sig))

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

    def tcp_register_sig(self, line):
        """
        Parses a TCP sig line and returns the signature as a tuple
        """
        ver, ttl, olen, mss, wsize, olayout, quirks, pclass = lparse(line, 8)
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
            quirks = frozenset(quirks_p0f[q] for q in quirks.split(","))
        else:
            quirks = frozenset()
        pay_class = -1 if pclass == "*" else int(pclass == "+")

        sig = (ip_ver, ttl, bad_ttl, ip_opt_len, mss, win, win_type, wscale, olayout, quirks, pay_class)  # noqa: E501
        return sig

    def http_register_sig(self, val):
        """
        Parses an HTTP sig line and returns the signature as a tuple
        """
        ver, horder, habsent, expsw = lparse(val, 4)
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

        return (http_ver, hdr, hdr_set, habsent, expsw)

    def tcp_find_match(self, tcpsig, direction):
        """
        Finds the best match for the given signature and direction.
        If a match is found, returns a tuple consisting of:
        - label: the matched label
        - dist: guessed distance from the packet source
        - fuzzy: whether the match is fuzzy
        Returns None if no match was found
        """
        ver, ttl, olen, mss, win, wscale, olayout, quirks, pclass = tcpsig
        win_multi, use_mtu = detect_win_multi(tcpsig)

        gmatch = None  # generic match
        fmatch = None  # fuzzy match
        for label_id, sig in self.base["tcp"][direction]:
            ver2, ttl2, bad_ttl, olen2, mss2, win2, win_type, wscale2, olayout2, quirks2, pclass2 = sig  # noqa: E501

            fuzzy = False
            if olayout2 != olayout:
                continue

            if ver2 == -1:
                if ver == 4:
                    quirks2 -= {quirks_p0f["flow"]}
                else:
                    quirks2 -= {quirks_p0f[q] for q in ("df", "id+", "id-")}
            if quirks2 != quirks:
                deleted = (quirks2 ^ quirks) & quirks2
                added = (quirks2 ^ quirks) & quirks

                if (fmatch or (deleted - {quirks_p0f["df"], quirks_p0f["id+"]}) or  # noqa:E501
                   (added - {quirks_p0f["id-"], quirks_p0f["ecn"]})):
                    continue
                fuzzy = True

            if olen2 != olen:
                continue
            if bad_ttl:
                if ttl2 < ttl:
                    continue
            else:
                if ttl2 < ttl or ttl2 - ttl > MAX_DIST:
                    fuzzy = True

            if ((mss2 != -1 and mss2 != mss) or
               (wscale2 != -1 and wscale2 != wscale) or
               (pclass2 != -1 and pclass2 != pclass)):
                continue

            if win_type == WIN_TYPE_NORMAL:
                if win2 != win:
                    continue
            elif win_type == WIN_TYPE_MOD:
                if win % win2:
                    continue
            elif win_type == WIN_TYPE_MSS:
                if (use_mtu or win2 != win_multi):
                    continue
            elif win_type == WIN_TYPE_MTU:
                if (not use_mtu or win2 != win_multi):
                    continue

            label = self.labels[label_id]
            if not fuzzy:
                if label[0] == "s":
                    return (label, ttl2 - ttl, fuzzy)
                elif not gmatch:
                    gmatch = (label, ttl2 - ttl, fuzzy)
            elif not fmatch:
                fmatch = (label, ttl2 - ttl, fuzzy)

        if gmatch:
            return gmatch
        if fmatch:
            return fmatch
        return None

    def http_find_match(self, httpsig, direction):
        """
        Finds the best match for the given signature and direction.
        If a match is found, returns a tuple consisting of:
        - label: the matched label
        - dishonest: whether the software was detected as dishonest
        Returns None if no match was found
        """
        ver, hdr, hdr_set, sw = httpsig

        gmatch = None  # generic match
        for label_id, sig in self.base["http"][direction]:
            ver2, hdr2, hdr_set2, habsent, expsw = sig

            if ver2 != -1 and ver2 != ver:
                continue

            # Check that all non-optional headers appear in the packet
            if not (hdr_set & hdr_set2) == hdr_set2:
                continue

            # Check that no forbidden headers appear in the packet.
            if len(habsent & hdr_set) > 0:
                continue

            def headers_correl():
                phi = 0  # Packet HTTP header index
                hdr_len = len(hdr)

                # Confirm the ordering and values of headers
                # (this is relatively slow, hence the if statements above).
                # The algorithm is derived from the original p0f/fp_http.c
                for kh in hdr2:  # kh - KnowledgeBase HTTP header
                    orig_phi = phi
                    while (phi < hdr_len and
                           kh[0] != hdr[phi][0]):
                        phi += 1

                    if phi == hdr_len:
                        if not kh[2]:
                            return False

                        for ph in hdr:
                            if kh[0] == ph[0]:
                                return False

                        phi = orig_phi
                        continue

                    if kh[1] not in hdr[phi][1]:
                        return False
                    phi += 1
                return True

            if not headers_correl():
                continue

            label = self.labels[label_id]
            dishonest = expsw and sw and expsw not in sw

            if label[0] == "s":
                return label, dishonest
            elif not gmatch:
                gmatch = (label, dishonest)
        return gmatch if gmatch else None

    def mtu_find_match(self, mtu):
        """
        Finds a match for the given MTU.
        If a match is found, returns the label string.
        Returns None if no match was found
        """
        for label_id, mtu_record in self.base["mtu"]:
            if mtu == mtu_record:
                return self.labels[label_id]
        return None


p0fdb = p0fKnowledgeBase(conf.p0f_base)


def lparse(line, n, delimiter=":", default=""):
    """
    Parsing of 'a:b:c:d:e' lines
    """
    a = line.split(delimiter)[:n]
    for elt in a:
        yield elt
    for _ in range(n - len(a)):
        yield default


def preprocess_packet(pkt):
    """
    Creates a copy of the packet and checks if the packet has
    IPv4/IPv6 and TCP layers. If the packet is valid, the copy is returned.
    If not, TypeError is raised.
    """
    pkt = pkt.copy()
    pkt = pkt.__class__(raw(pkt))
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    if ((not isinstance(pkt, IPv6) and not isinstance(pkt, IP)) or
       not isinstance(pkt.payload, TCP)):
        raise TypeError("Not a TCP/IP packet")
    return pkt


def detect_win_multi(tcpsig):
    """
    Figure out if window size is a multiplier of MSS or MTU.
    Returns the multiplier and whether mtu should be used
    """
    mss, win = tcpsig[3], tcpsig[4]
    if not win or mss < 100:
        return -1, False

    ip_ver, olayout, quirks = tcpsig[0], tcpsig[6], tcpsig[7]
    ts1 = "ts" in olayout and quirks_p0f["ts1-"] not in quirks
    options = [
        (mss, False),
        (1500 - MIN_TCP4, False),
        (1500 - MIN_TCP4 - 12, False),
        (mss + MIN_TCP4, True),
        (1500, True)
    ]
    if ts1:
        options.append((mss - 12, False))
    if ip_ver == 6:
        options.append((1500 - MIN_TCP6, False))
        options.append((1500 - MIN_TCP6 - 12, False))
        options.append((mss + MIN_TCP6, True))

    for div, use_mtu in options:
        if not (win % div):
            return win / div, use_mtu
    return -1, False


def packet2p0f(pkt):
    """
    Returns a p0f signature of the packet, and the direction.
    Raises TypeError if the packet isn't valid for p0f
    """
    pkt = preprocess_packet(pkt)

    if pkt[TCP].flags.S:
        if pkt[TCP].flags.A:
            direction = "response"
        else:
            direction = "request"
        sig = packet2tcpsig(pkt)

    elif pkt[TCP].payload:
        # XXX: guess_payload_class doesn't use any class related attributes
        pclass = HTTP().guess_payload_class(raw(pkt[TCP].payload))
        if pclass == HTTPRequest:
            direction = "request"
        elif pclass == HTTPResponse:
            direction = "response"
        else:
            raise TypeError("Not an HTTP payload")
        sig = packet2httpsig(pkt)
    else:
        raise TypeError("Not a SYN, SYN/ACK, or HTTP packet")
    return sig, direction


def packet2tcpsig(pkt):
    """
    Receives a TCP packet (assuming it's valid), and returns
    a TCP signature as a tuple containing:
    (ip_ver, ttl, ip_opt_len, mss, win, wscale, opt_layout, quirks, pay_class)
    """
    ip_ver = pkt.version
    quirks = set()

    def addq(name):
        quirks.add(quirks_p0f[name])

    # IPv4/IPv6 parsing
    if ip_ver == 4:
        ttl = pkt.ttl
        ip_opt_len = (pkt.ihl * 4) - 20
        if (pkt.tos & 0x3) in (0x1, 0x2, 0x3):
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
        if (pkt.tc & 0x3) in (0x1, 0x2, 0x3):
            addq("ecn")

    # TCP parsing
    tcp = pkt[TCP]
    win = tcp.window
    if tcp.flags.C or tcp.flags.E:
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
        if onum in options_p0f:
            ofmt = TCPOptions[0][onum][1]
            olayout += "%s," % options_p0f[onum]
            optsize = 2 + struct.calcsize(ofmt) if ofmt else 2  # total size
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
                    if not oval[0]:
                        addq("ts1-")
                    if oval[1] and (tcp.flags.S and not tcp.flags.A):
                        addq("ts2+")
        else:  # Unknown option, presumably with specified size
            if olen < 2 or olen > 40 or olen > len(x):
                addq("bad")
                break
        x = x[olen:]
    olayout = olayout[:-1]

    return (ip_ver, ttl, ip_opt_len, mss, win, wscale, olayout, quirks, pay_class)  # noqa: E501


def packet2httpsig(pkt):
    """
    Receives an HTTP packet (assuming it's valid), and returns
    an HTTP signature as a tuple containing:
    (http_ver, hdr, hdr_set, sw)
    """
    http_payload = raw(pkt[TCP].payload)

    crlfcrlf = b"\r\n\r\n"
    crlfcrlfIndex = http_payload.find(crlfcrlf)
    if crlfcrlfIndex != -1:
        headers = http_payload[:crlfcrlfIndex + len(crlfcrlf)]
    else:
        headers = http_payload
    headers = headers.decode()
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
    return (http_ver, hdr, hdr_set, sw)


def sig2str(sig):
    """
    Receives a packet TCP/HTTP signature as a tuple and returns
    a string representation of it
    """
    s = ""
    if len(sig) == 9:  # TCP signature
        def guess_dist(ttl):
            for opt in (32, 64, 128):
                if ttl <= opt:
                    return opt - ttl
            return 255 - ttl

        fmt = "%i:%i+%i:%i:%i:%i,%i:%s:%s:%i"
        s += fmt % (sig[0], sig[1], guess_dist(sig[1]), sig[2],
                    sig[3], sig[4], sig[5], sig[6], sig[7], sig[8])
    else:
        # values that depend on the context are not included in the string
        skipval = ("Host", "User-Agent", "Date", "Content-Type", "Server")
        fmt = "%i:%s::%s"
        hdr = ",".join(n if n in skipval else "%s=[%s]" % (n, v) for n, v in sig[1])  # noqa: E501
        s += fmt % (sig[0], hdr, sig[3])
    return s


def fingerprint_mtu(pkt):
    """
    Fingerprints the MTU based on the maximum segment size specified
    in TCP options.
    If a match was found, returns the label. If not returns None
    """
    pkt = preprocess_packet(pkt)
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

    if len(sig) == 9:  # TCP signature
        return p0fdb.tcp_find_match(sig, direction)
    else:
        return p0fdb.http_find_match(sig, direction)


def prnp0f(pkt):
    """Calls p0f and returns a user-friendly output"""
    try:
        r = p0f(pkt)
    except Exception:
        return

    sig, direction = packet2p0f(pkt)
    tcp_sig = len(sig) == 9
    if tcp_sig:
        pkt_type = "SYN" if direction == "request" else "SYN+ACK"
    else:
        pkt_type = "HTTP Request" if direction == "request" else "HTTP Response"  # noqa: E501

    res = pkt.sprintf(".-[ %IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport% (" + pkt_type + ") ]-\n|\n")  # noqa: E501
    fields = []

    def add_field(name, value):
        fields.append("| %-8s = %s\n" % (name, value))

    cli_or_svr = "Client" if direction == "request" else "Server"
    add_field(cli_or_svr, pkt.sprintf("%IP.src%:%TCP.sport%"))

    if r:
        label = r[0]
        app_or_os = "App" if label[1] == "!" else "OS"
        add_field(app_or_os, label[2] + " " + label[3])
        if len(label) == 5:  # label includes sys
            add_field("Sys", ", ".join(name for name in label[4]))
        if tcp_sig:
            add_field("Distance", r[1])
    else:
        app_or_os = "OS" if tcp_sig else "App"
        add_field(app_or_os, "UNKNOWN")

    add_field("Raw sig", sig2str(sig))

    res += "".join(fields)
    res += "`____\n"
    print(res)
