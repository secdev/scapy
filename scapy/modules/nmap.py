# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""Clone of Nmap's first generation OS fingerprinting.

This code works with the first-generation OS detection and
nmap-os-fingerprints, which has been removed from Nmap on November 3,
2007 (https://github.com/nmap/nmap/commit/50c49819), which means it is
outdated.

To get the last published version of this outdated fingerprint
database, you can fetch it from
<https://raw.githubusercontent.com/nmap/nmap/9efe1892/nmap-os-fingerprints>.

"""

import os
import re

from scapy.data import KnowledgeBase
from scapy.config import conf
from scapy.arch import WINDOWS
from scapy.error import warning
from scapy.layers.inet import IP, TCP, UDP, ICMP, UDPerror, IPerror
from scapy.packet import NoPayload, Packet
from scapy.sendrecv import sr
from scapy.compat import plain_str, raw
from scapy.plist import SndRcvList, PacketList

# Typing imports
from typing import (
    Dict,
    List,
    Tuple,
    Optional,
    cast,
    Union,
)

if WINDOWS:
    conf.nmap_base = os.environ["ProgramFiles"] + "\\nmap\\nmap-os-fingerprints"  # noqa: E501
else:
    conf.nmap_base = "/usr/share/nmap/nmap-os-fingerprints"


######################
#  nmap OS fp stuff  #
######################


_NMAP_LINE = re.compile('^([^\\(]*)\\(([^\\)]*)\\)$')


class NmapKnowledgeBase(KnowledgeBase):
    """A KnowledgeBase specialized in Nmap first-generation OS
fingerprints database. Loads from conf.nmap_base when self.filename is
None.

    """

    def lazy_init(self):
        # type: () -> None
        try:
            fdesc = open(conf.nmap_base
                         if self.filename is None else
                         self.filename, "rb")
        except (IOError, TypeError):
            warning("Cannot open nmap database [%s]", self.filename)
            self.filename = None
            return

        self.base = []
        self.base = cast(List[Tuple[str, Dict[str, Dict[str, str]]]], self.base)
        name = None
        sig = {}  # type: Dict[str,Dict[str,str]]
        for line in fdesc:
            str_line = plain_str(line)
            str_line = str_line.split('#', 1)[0].strip()
            if not str_line:
                continue
            if str_line.startswith("Fingerprint "):
                if name is not None:
                    self.base.append((name, sig))
                name = str_line[12:].strip()
                sig = {}
                continue
            if str_line.startswith("Class "):
                continue
            match_line = _NMAP_LINE.search(str_line)
            if match_line is None:
                continue
            test, values = match_line.groups()
            sig[test] = dict(val.split('=', 1) for val in
                             (values.split('%') if values else []))
        if name is not None:
            self.base.append((name, sig))
        fdesc.close()

    def get_base(self):
        # type: () -> List[Tuple[str, Dict]]
        return cast(List[Tuple[str, Dict]], super(NmapKnowledgeBase, self).get_base())


conf.nmap_kdb = NmapKnowledgeBase(None)
conf.nmap_kdb = cast(NmapKnowledgeBase, conf.nmap_kdb)


def nmap_tcppacket_sig(pkt):
    # type: (Optional[Packet]) -> Dict
    res = {}
    if pkt is not None:
        res["DF"] = "Y" if pkt.flags.DF else "N"
        res["W"] = "%X" % pkt.window
        res["ACK"] = "S++" if pkt.ack == 2 else "S" if pkt.ack == 1 else "O"
        res["Flags"] = str(pkt[TCP].flags)[::-1]
        res["Ops"] = "".join(x[0][0] for x in pkt[TCP].options)
    else:
        res["Resp"] = "N"
    return res


def nmap_udppacket_sig(snd, rcv):
    # type: (SndRcvList, PacketList) -> Dict
    res = {}
    if rcv is None:
        res["Resp"] = "N"
    else:
        res["DF"] = "Y" if rcv.flags.DF else "N"
        res["TOS"] = "%X" % rcv.tos
        res["IPLEN"] = "%X" % rcv.len
        res["RIPTL"] = "%X" % rcv.payload.payload.len
        res["RID"] = "E" if snd.id == rcv[IPerror].id else "F"
        res["RIPCK"] = "E" if snd.chksum == rcv[IPerror].chksum else (
            "0" if rcv[IPerror].chksum == 0 else "F"
        )
        res["UCK"] = "E" if snd.payload.chksum == rcv[UDPerror].chksum else (
            "0" if rcv[UDPerror].chksum == 0 else "F"
        )
        res["ULEN"] = "%X" % rcv[UDPerror].len
        res["DAT"] = "E" if (
            isinstance(rcv[UDPerror].payload, NoPayload) or
            raw(rcv[UDPerror].payload) == raw(snd[UDP].payload)
        ) else "F"
    return res


def nmap_match_one_sig(seen, ref):
    # type: (Dict, Dict) -> float
    cnt = sum(val in ref.get(key, "").split("|") for key, val in seen.items())
    if cnt == 0 and seen.get("Resp") == "N":
        return 0.7
    return float(cnt) / len(seen)


def nmap_sig(target, oport=80, cport=81, ucport=1):
    # type: (str, int, int, int) -> Dict
    res = {}

    tcpopt = [("WScale", 10),
              ("NOP", None),
              ("MSS", 256),
              ("Timestamp", (123, 0))]
    tests = [
        IP(dst=target, id=1) /
        TCP(seq=1, sport=5001 + i, dport=oport if i < 4 else cport,
            options=tcpopt, flags=flags)
        for i, flags in enumerate(["CS", "", "SFUP", "A", "S", "A", "FPU"])
    ]
    tests.append(IP(dst=target) / UDP(sport=5008, dport=ucport) / (300 * "i"))

    ans, unans = sr(tests, timeout=2)
    ans.extend((x, None) for x in unans)

    for snd, rcv in ans:
        if snd.sport == 5008:
            res["PU"] = (snd, rcv)
        else:
            test = "T%i" % (snd.sport - 5000)
            if rcv is not None and ICMP in rcv:
                warning("Test %s answered by an ICMP", test)
                rcv = None  # type: ignore
            res[test] = rcv

    return nmap_probes2sig(res)


def nmap_probes2sig(tests):
    # type: (Dict) -> Dict
    tests = tests.copy()
    res = {}
    if "PU" in tests:
        res["PU"] = nmap_udppacket_sig(*tests["PU"])
        del tests["PU"]
    for k in tests:
        res[k] = nmap_tcppacket_sig(tests[k])
    return res


def nmap_search(sigs):
    # type: (Dict) -> Tuple[Union[int, float], List]
    guess = 0, []  # type: Tuple[Union[int, float], List]
    conf.nmap_kdb = cast(NmapKnowledgeBase, conf.nmap_kdb)
    for osval, fprint in conf.nmap_kdb.get_base():
        score = 0.0
        for test, values in fprint.items():
            if test in sigs:
                score += nmap_match_one_sig(sigs[test], values)
        score /= len(sigs)
        if score > guess[0]:
            guess = score, [osval]
        elif score == guess[0]:
            guess[1].append(osval)
    return guess


@conf.commands.register
def nmap_fp(target, oport=80, cport=81):
    # type: (str, int, int) -> Tuple[Union[int, float], List]
    """nmap fingerprinting
nmap_fp(target, [oport=80,] [cport=81,]) -> list of best guesses with accuracy
"""
    sigs = nmap_sig(target, oport, cport)
    return nmap_search(sigs)


@conf.commands.register
def nmap_sig2txt(sig):
    # type: (Dict) -> str
    torder = ["TSeq", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "PU"]
    korder = ["Class", "gcd", "SI", "IPID", "TS",
              "Resp", "DF", "W", "ACK", "Flags", "Ops",
              "TOS", "IPLEN", "RIPTL", "RID", "RIPCK", "UCK", "ULEN", "DAT"]
    txt = []
    for i in sig:
        if i not in torder:
            torder.append(i)
    for test in torder:
        testsig = sig.get(test)
        if testsig is None:
            continue
        txt.append("%s(%s)" % (test, "%".join(
            "%s=%s" % (key, testsig[key]) for key in korder if key in testsig
        )))
    return "\n".join(txt)
