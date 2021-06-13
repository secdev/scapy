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
        "mtu" (str): { sig (int): labelnum (int) }

        "tcp"/"http" (str): {
            direction (str): { sig (tuple): labelnum (int) }
            }
    }

    # TODO: parse "sys" lines with labels
    self.labels = ((generic(str), class(str), name(str), flavor(str), ...)
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

        # Parse mtu, tcp, and http bases
        self.base["mtu"] = {int(s): l for s, l in self.base["mtu"].items()}
        self._parse_tcp_base()
        self._parse_http_base()
        f.close()

    def _parse_file(self, file):
        """
        Does actual parsing of the file and stores the data with described
        structures.
        TODO: parse "sys" lines to associate labels with user applications
        """
        label_id = -1

        for line in file:
            line = line.strip()

            if not line or line[0] == ";":
                continue
            if line[0] == "[":
                section, direction = lparse(line[1:-1], 2)
                if section == "mtu":
                    self.base[section] = {}
                    currsec = self.base[section]
                else:
                    if section not in self.base:
                        self.base[section] = {direction: {}}
                    elif direction not in self.base[section]:
                        self.base[section][direction] = {}
                    currsec = self.base[section][direction]
            else:
                param, _, value = line.partition(" = ")
                param = param.strip()

                if param == "sig":
                    currsec[value] = label_id

                elif param == "label":
                    label_id += 1
                    if section == "mtu":
                        self.labels.append(value)
                    else:
                        # label = type:class:name:flavor
                        t, c, name, flavor = lparse(value, 4)
                        self.labels.append((t, c, name, flavor))

    def _parse_tcp_base(self):
        """
        TCP database signature is a tuple containing:
        - ver: 4, 6, or -1 (any)
        - tuple(ttl, bad_ttl(bool))
        - olen: length of IP options
        - mss: Maximum segment size (-1 = any)
        - window: tuple(wsize, wtype)
        - scale: window scale (-1 = any)
        - olayout(str): TCP option layout
        - quirks(frozenset): quirks
        - pclass: -1 = any, 0 = zero, 1 = non-zero
        """
        for direction in "request", "response":
            newsigs = {}
            for sig, labelnum in self.base["tcp"][direction].items():
                ver, ttl, olen, mss, wsize, olayout, quirks, pclass = lparse(sig, 8)  # noqa: E501
                wsize, _, scale = wsize.partition(",")

                ver = -1 if ver == "*" else int(ver)
                ttl = (int(ttl[:-1]), True) if ttl[-1] == "-" else (int(ttl), False)  # noqa: E501
                olen = int(olen)
                mss = -1 if mss == "*" else int(mss)
                if wsize == "*":
                    window = (0, WIN_TYPE_ANY)
                elif wsize[:3] == "mss":
                    window = (int(wsize[4:]), WIN_TYPE_MSS)
                elif wsize[0] == "%":
                    window = (int(wsize[1:]), WIN_TYPE_MOD)
                elif wsize[:3] == "mtu":
                    window = (int(wsize[4:]), WIN_TYPE_MTU)
                else:
                    window = (int(wsize), WIN_TYPE_NORMAL)
                scale = -1 if scale == "*" else int(scale)
                if quirks:
                    quirks = frozenset(quirks_p0f[q] for q in quirks.split(","))  # noqa: E501
                else:
                    quirks = frozenset()

                pclass = -1 if pclass == "*" else int(pclass == "+")

                newsigs[(ver, ttl, olen, mss, window,
                         scale, olayout, quirks, pclass)] = labelnum

            self.base["tcp"][direction] = newsigs

    def _parse_http_base(self):
        """
        HTTP database signature is a tuple containing:
        - ver: 0 (1.0), 1 (1.1), or -1 (any)
        - horder: tuple((name, value(str), optional(bool)), ...)
        - headers_set(frozenset): all non-optional header names
        - habsent(frozenset)
        - expsw(str)
        """
        for direction in "request", "response":
            newsigs = {}
            for sig, labelnum in self.base["http"][direction].items():
                ver, horder, habsent, expsw = lparse(sig, 4)

                ver = -1 if ver == "*" else int(ver)

                # horder parsing - split by commas that aren't in []
                new_horder = []
                for header in re.split(r",(?![^\[]*\])", horder):
                    name, _, value = header.partition("=")
                    if name[0] == "?":  # Optional header
                        new_horder.append((name[1:], value[1:-1], True))
                    else:
                        new_horder.append((name, value[1:-1], False))
                horder = tuple(new_horder)
                headers_set = frozenset(hdr[0] for hdr in horder if not hdr[2])
                habsent = frozenset(habsent.split(","))

                newsigs[(ver, horder, headers_set, habsent, expsw)] = labelnum

            self.base["http"][direction] = newsigs

    def tcp_find_match(self, tcpsig, direction):
        """
        Finds the best match for the given signature and direction.
        Returns a tuple consisting of:
        - label: the matched label
        - dist: guessed distance from the packet source
        - fuzzy: whether the match is fuzzy
        """
        ver, ittl, olen, mss, wsize, scale, olayout, quirks, pclass = tcpsig
        win_multi, use_mtu = detect_win_multi(wsize, mss)

        gmatch = None  # generic match
        fmatch = None  # fuzzy match
        for sig, labelnum in self.base["tcp"][direction].items():
            sver, sittl, solen, smss, swsize, sscale, solayout, squirks, spclass = sig  # noqa: E501

            fuzzy = False
            if solayout != olayout:
                continue

            if sver == -1:
                if ver == 4:
                    squirks -= {quirks_p0f["flow"]}
                else:
                    squirks -= {quirks_p0f[q] for q in ("df", "id+", "id-")}
            if squirks != quirks:
                deleted = (squirks ^ quirks) & squirks
                added = (squirks ^ quirks) & quirks

                if (fmatch or (deleted - {quirks_p0f["df"], quirks_p0f["id+"]})
                   or (added - {quirks_p0f["id-"], quirks_p0f["ecn"]})):
                    continue
                fuzzy = True

            if solen != olen:
                continue
            if sittl[1]:
                if sittl[0] < ittl:
                    continue
            else:
                if sittl[0] < ittl or sittl[0] - ittl > MAX_DIST:
                    fuzzy = True

            if ((smss != -1 and smss != mss) or
               (sscale != -1 and sscale != scale) or
               (spclass != -1 and spclass != pclass)):
                continue

            if swsize[1] == WIN_TYPE_NORMAL:
                if swsize[0] != wsize:
                    continue
            elif swsize[1] == WIN_TYPE_MOD:
                if wsize % swsize[0]:
                    continue
            elif swsize[1] == WIN_TYPE_MSS:
                if (use_mtu or swsize[0] != win_multi):
                    continue
            elif swsize[1] == WIN_TYPE_MTU:
                if (not use_mtu or swsize[0] != win_multi):
                    continue

            label = self.labels[labelnum]
            if not fuzzy:
                if label[0] == "s":
                    return (label, sittl[0] - ittl, fuzzy)
                elif not gmatch:
                    gmatch = (label, sittl[0] - ittl, fuzzy)
            elif not fmatch:
                fmatch = (label, sittl[0] - ittl, fuzzy)

        if gmatch:
            return gmatch
        if fmatch:
            return fmatch
        return None

    def http_find_match(self, httpsig, direction):
        """
        Finds the best match for the given signature and direction.
        Returns the matched label.
        """
        ver, headers, headers_set = httpsig

        gmatch = None  # generic match
        for sig, labelnum in self.base["http"][direction].items():
            sver, sheaders, sheaders_set, habsent, expsw = sig

            if sver != -1 and sver != ver:
                continue

            # Check that all non-optional headers appear in the packet
            if not (headers_set & sheaders_set) == sheaders_set:
                continue

            # Check that no forbidden headers appear in the packet.
            if len(habsent & headers_set) > 0:
                continue

            def headers_correl():
                d_hdr = 0  # Database hdr index
                p_hdr = 0  # Packet hdr index

                # Confirm the ordering and values of headers
                # (this is relatively slow, hence the if statements above).
                # The algorithm is taken from the original p0f/fp_http.c
                for d_hdr in range(len(sheaders)):
                    orig_p = p_hdr
                    while (p_hdr < len(headers) and
                           sheaders[d_hdr][0] != headers[p_hdr][0]):
                        p_hdr += 1

                    if p_hdr == len(headers):
                        if not sheaders[d_hdr][2]:
                            return False

                        for p_hdr in range(len(headers)):
                            if sheaders[d_hdr][0] == headers[p_hdr][0]:
                                return False

                        p_hdr = orig_p
                        continue

                    if sheaders[d_hdr][1] not in headers[p_hdr][1]:
                        return False
                    p_hdr += 1
                return True

            if not headers_correl():
                continue

            label = self.labels[labelnum]
            # TODO: check dishonest software
            if label[0] == "s":
                return label
            elif not gmatch:
                gmatch = label

        return gmatch if gmatch else None


p0fdb = p0fKnowledgeBase(conf.p0f_base)


def lparse(line, n, default="", splitchar=":"):
    """
    Parsing of 'a:b:c:d:e' lines
    """
    a = line.split(splitchar)[:n]
    for elt in a:
        yield elt
    for _ in range(n - len(a)):
        yield default


def preprocess_packet(pkt):
    """
    Makes sure the packet is an IPv4/IPv6 and TCP packet
    """
    pkt = pkt.copy()
    pkt = pkt.__class__(raw(pkt))
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    if ((not isinstance(pkt, IPv6) and not isinstance(pkt, IP))
       or not isinstance(pkt.payload, TCP)):
        raise TypeError("Not a TCP/IP packet")
    return pkt


def detect_win_multi(win, mss):
    """
    Figure out if window size is a multiplier of MSS or MTU.
    """
    default_mtu = False
    default_multi = -1
    if win or mss > 100:
        options = (
            (mss, False),  # MSS
            (mss - 12, False),  # MSS - 12
            (1500 - MIN_TCP4, False),  # MSS (MTU = 1500, IPv4)
            (1500 - MIN_TCP4 - 12, False),  # MSS (MTU = 1500, IPv4 - 12)
            (1500 - MIN_TCP6, False),  # MSS (MTU = 1500, IPv6)
            (1500 - MIN_TCP6 - 12, False),  # MSS (MTU = 1500, IPv6 - 12)
            (mss + MIN_TCP4, True),  # MTU (IPv4)
            (mss + MIN_TCP6, True),  # MTU (IPv6)
            (1500, True)  # MTU (1500)
        )
        for div, use_mtu in options:
            if not (win % div):
                return win / div, use_mtu
    return default_multi, default_mtu


def packet2p0f(pkt):
    """
    Returns a p0f signature of the packet, and the direction
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
    TCP packet signature is a tuple containing:
    (ver(int), ttl(int), ip_opt_len(int), mss(int), wsize(int),
     scale(int), olayout(str), quirks(set), pclass(int))
    """
    ver = pkt.version
    quirks = set()

    def addq(name):
        quirks.add(quirks_p0f[name])

    # IPv4/IPv6 parsing
    if ver == 4:
        ittl = pkt.ttl
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
        ittl = pkt.hlim
        ip_opt_len = 0
        if pkt.fl:
            addq("flow")
        if (pkt.tc & 0x3) in (0x1, 0x2, 0x3):
            addq("ecn")

    # TCP parsing
    tcp = pkt[TCP]
    wsize = tcp.window
    if tcp.flags.C or tcp.flags.E:
        addq("ecn")
    if tcp.seq == 0:
        addq("seq-")
    if tcp.flags.A:
        if tcp.ack == 0:
            addq("ack-")
    else:
        if tcp.ack:
            addq("ack+")
    if tcp.flags.U:
        addq("urgf+")
    else:
        if tcp.urgptr:
            addq("uptr+")
    if tcp.flags.P:
        addq("pushf+")

    pclass = 1 if tcp.payload else 0

    # Manual TCP options parsing
    mss = 0
    scale = 0
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
        if onum in (2, 3, 4, 5, 8):
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
                    scale = oval
                    if scale > 14:
                        addq("exws")
                elif onum == 8:
                    if not oval[0]:
                        addq("ts1-")
                    if oval[1] and (tcp.flags.S and not tcp.flags.A):
                        addq("ts2+")
        else:  # Unknown option, presumably with specified size
            if (olen < 2 or olen > 40) or (olen > len(x)):
                addq("bad")
                break
        x = x[olen:]
    olayout = olayout[:-1]

    return (ver, ittl, ip_opt_len, mss, wsize, scale, olayout, quirks, pclass)


def packet2httpsig(pkt):
    """
    HTTP packet signature is a tuple containing:
    (ver(int), headers(name, value(str), headers_set(set))
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
        ver = 0
    elif "1.1" in first_line:
        ver = 1
    else:
        raise ValueError("HTTP version is not 1.0/1.1")

    headers_found = []
    for header_line in headers.split("\r\n"):
        name, _, value = header_line.partition(": ")
        if value:
            headers_found.append((name, value))
    headers = tuple(headers_found)
    headers_set = {hdr[0] for hdr in headers}
    return (ver, headers, headers_set)

def fingerprint_mtu(pkt):
    """
    Fingerprints the MTU based on the maximum segment size specified
    in TCP options.
    """
    pkt = preprocess_packet(pkt)
    mss = 0
    for name, value in pkt.payload.options:
        if name == "MSS":
            mss = value

    if not mss:
        return None

    mtu = (mss + MIN_TCP4) if pkt.version == 4 else (mss + MIN_TCP6)

    db = p0fdb.get_base()
    if db and mtu in db["mtu"]:
        labelnum = db["mtu"][mtu]
        return p0fdb.labels[labelnum]
    return None

def p0f(pkt):
    sig, direction = packet2p0f(pkt)
    if not p0fdb.get_base():
        warning("p0f base empty.")
        return None

    match = None
    if len(sig) == 9:  # TCP signature
        match = p0fdb.tcp_find_match(sig, direction)
    else:
        match = p0fdb.http_find_match(sig, direction)
    return match
