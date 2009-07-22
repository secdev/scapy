## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import os

from scapy.data import KnowledgeBase
from scapy.config import conf
from scapy.arch import WINDOWS


if WINDOWS:
    conf.nmap_base=os.environ["ProgramFiles"] + "\\nmap\\nmap-os-fingerprints"
else:
    conf.nmap_base ="/usr/share/nmap/nmap-os-fingerprints"


######################
## nmap OS fp stuff ##
######################


class NmapKnowledgeBase(KnowledgeBase):
    def lazy_init(self):
        try:
            f=open(self.filename)
        except IOError:
            return

        self.base = []
        name = None
        try:
            for l in f:
                l = l.strip()
                if not l or l[0] == "#":
                    continue
                if l[:12] == "Fingerprint ":
                    if name is not None:
                        self.base.append((name,sig))
                    name = l[12:].strip()
                    sig={}
                    p = self.base
                    continue
                elif l[:6] == "Class ":
                    continue
                op = l.find("(")
                cl = l.find(")")
                if op < 0 or cl < 0:
                    warning("error reading nmap os fp base file")
                    continue
                test = l[:op]
                s = map(lambda x: x.split("="), l[op+1:cl].split("%"))
                si = {}
                for n,v in s:
                    si[n] = v
                sig[test]=si
            if name is not None:
                self.base.append((name,sig))
        except:
            self.base = None
            warning("Can't read nmap database [%s](new nmap version ?)" % self.filename)
        f.close()

nmap_kdb = NmapKnowledgeBase(conf.nmap_base)

def TCPflags2str(f):
    fl="FSRPAUEC"
    s=""
    for i in range(len(fl)):
        if f & 1:
            s = fl[i]+s
        f >>= 1
    return s

def nmap_tcppacket_sig(pkt):
    r = {}
    if pkt is not None:
#        r["Resp"] = "Y"
        r["DF"] = (pkt.flags & 2) and "Y" or "N"
        r["W"] = "%X" % pkt.window
        r["ACK"] = pkt.ack==2 and "S++" or pkt.ack==1 and "S" or "O"
        r["Flags"] = TCPflags2str(pkt.payload.flags)
        r["Ops"] = "".join(map(lambda x: x[0][0],pkt.payload.options))
    else:
        r["Resp"] = "N"
    return r


def nmap_udppacket_sig(S,T):
    r={}
    if T is None:
        r["Resp"] = "N"
    else:
        r["DF"] = (T.flags & 2) and "Y" or "N"
        r["TOS"] = "%X" % T.tos
        r["IPLEN"] = "%X" % T.len
        r["RIPTL"] = "%X" % T.payload.payload.len
        r["RID"] = S.id == T.payload.payload.id and "E" or "F"
        r["RIPCK"] = S.chksum == T.getlayer(IPerror).chksum and "E" or T.getlayer(IPerror).chksum == 0 and "0" or "F"
        r["UCK"] = S.payload.chksum == T.getlayer(UDPerror).chksum and "E" or T.getlayer(UDPerror).chksum ==0 and "0" or "F"
        r["ULEN"] = "%X" % T.getlayer(UDPerror).len
        r["DAT"] = T.getlayer(Raw) is None and "E" or S.getlayer(Raw).load == T.getlayer(Raw).load and "E" or "F"
    return r
    


def nmap_match_one_sig(seen, ref):
    c = 0
    for k in seen.keys():
        if ref.has_key(k):
            if seen[k] in ref[k].split("|"):
                c += 1
    if c == 0 and seen.get("Resp") == "N":
        return 0.7
    else:
        return 1.0*c/len(seen.keys())
        
        
def nmap_sig(target, oport=80, cport=81, ucport=1):
    res = {}

    tcpopt = [ ("WScale", 10),
               ("NOP",None),
               ("MSS", 256),
               ("Timestamp",(123,0)) ]
    tests = [ IP(dst=target, id=1)/TCP(seq=1, sport=5001, dport=oport, options=tcpopt, flags="CS"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5002, dport=oport, options=tcpopt, flags=0),
              IP(dst=target, id=1)/TCP(seq=1, sport=5003, dport=oport, options=tcpopt, flags="SFUP"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5004, dport=oport, options=tcpopt, flags="A"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5005, dport=cport, options=tcpopt, flags="S"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5006, dport=cport, options=tcpopt, flags="A"),
              IP(dst=target, id=1)/TCP(seq=1, sport=5007, dport=cport, options=tcpopt, flags="FPU"),
              IP(str(IP(dst=target)/UDP(sport=5008,dport=ucport)/(300*"i"))) ]

    ans, unans = sr(tests, timeout=2)
    ans += map(lambda x: (x,None), unans)

    for S,T in ans:
        if S.sport == 5008:
            res["PU"] = nmap_udppacket_sig(S,T)
        else:
            t = "T%i" % (S.sport-5000)
            if T is not None and T.haslayer(ICMP):
                warning("Test %s answered by an ICMP" % t)
                T=None
            res[t] = nmap_tcppacket_sig(T)

    return res

def nmap_probes2sig(tests):
    tests=tests.copy()
    res = {}
    if "PU" in tests:
        res["PU"] = nmap_udppacket_sig(*tests["PU"])
        del(tests["PU"])
    for k in tests:
        res[k] = nmap_tcppacket_sig(tests[k])
    return res
        

def nmap_search(sigs):
    guess = 0,[]
    for os,fp in nmap_kdb.get_base():
        c = 0.0
        for t in sigs.keys():
            if t in fp:
                c += nmap_match_one_sig(sigs[t], fp[t])
        c /= len(sigs.keys())
        if c > guess[0]:
            guess = c,[ os ]
        elif c == guess[0]:
            guess[1].append(os)
    return guess
    
    
@conf.commands.register
def nmap_fp(target, oport=80, cport=81):
    """nmap fingerprinting
nmap_fp(target, [oport=80,] [cport=81,]) -> list of best guesses with accuracy
"""
    sigs = nmap_sig(target, oport, cport)
    return nmap_search(sigs)
        

@conf.commands.register
def nmap_sig2txt(sig):
    torder = ["TSeq","T1","T2","T3","T4","T5","T6","T7","PU"]
    korder = ["Class", "gcd", "SI", "IPID", "TS",
              "Resp", "DF", "W", "ACK", "Flags", "Ops",
              "TOS", "IPLEN", "RIPTL", "RID", "RIPCK", "UCK", "ULEN", "DAT" ]
    txt=[]
    for i in sig.keys():
        if i not in torder:
            torder.append(i)
    for t in torder:
        sl = sig.get(t)
        if sl is None:
            continue
        s = []
        for k in korder:
            v = sl.get(k)
            if v is None:
                continue
            s.append("%s=%s"%(k,v))
        txt.append("%s(%s)" % (t, "%".join(s)))
    return "\n".join(txt)
            
        


