## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Clone of queso OS fingerprinting
"""

from scapy.data import KnowledgeBase
from scapy.config import conf
from scapy.layers.inet import IP,TCP
#from 

conf.queso_base ="/etc/queso.conf"


#################
## Queso stuff ##
#################


def quesoTCPflags(flags):
    if flags == "-":
        return "-"
    flv = "FSRPAUXY"
    v = 0
    for i in flags:
        v |= 2**flv.index(i)
    return "%x" % v

class QuesoKnowledgeBase(KnowledgeBase):
    def lazy_init(self):
        try:
            f = open(self.filename)
        except IOError:
            return
        self.base = {}
        p = None
        try:
            for l in f:
                l = l.strip()
                if not l or l[0] == ';':
                    continue
                if l[0] == '*':
                    if p is not None:
                        p[""] = name
                    name = l[1:].strip()
                    p = self.base
                    continue
                if l[0] not in list("0123456"):
                    continue
                res = l[2:].split()
                res[-1] = quesoTCPflags(res[-1])
                res = " ".join(res)
                if not p.has_key(res):
                    p[res] = {}
                p = p[res]
            if p is not None:
                p[""] = name
        except:
            self.base = None
            warning("Can't load queso base [%s]", self.filename)
        f.close()
            
        
queso_kdb = QuesoKnowledgeBase(conf.queso_base)

    
def queso_sig(target, dport=80, timeout=3):
    p = queso_kdb.get_base()
    ret = []
    for flags in ["S", "SA", "F", "FA", "SF", "P", "SEC"]:
        ans, unans = sr(IP(dst=target)/TCP(dport=dport,flags=flags,seq=RandInt()),
                        timeout=timeout, verbose=0)
        if len(ans) == 0:
            rs = "- - - -"
        else:
            s,r = ans[0]
            rs = "%i" % (r.seq != 0)
            if not r.ack:
                r += " 0"
            elif r.ack-s.seq > 666:
                rs += " R" % 0
            else:
                rs += " +%i" % (r.ack-s.seq)
            rs += " %X" % r.window
            rs += " %x" % r.payload.flags
        ret.append(rs)
    return ret
            
def queso_search(sig):
    p = queso_kdb.get_base()
    sig.reverse()
    ret = []
    try:
        while sig:
            s = sig.pop()
            p = p[s]
            if p.has_key(""):
                ret.append(p[""])
    except KeyError:
        pass
    return ret
        

@conf.commands.register
def queso(*args,**kargs):
    """Queso OS fingerprinting
queso(target, dport=80, timeout=3)"""
    return queso_search(queso_sig(*args, **kargs))


