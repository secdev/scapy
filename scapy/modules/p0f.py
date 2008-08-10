## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.data import KnowledgeBase
from scapy.config import conf

conf.p0f_base ="/etc/p0f/p0f.fp"


###############
## p0f stuff ##
###############

# File format (according to p0f.fp) :
#
# wwww:ttt:D:ss:OOO...:QQ:OS:Details
#
# wwww    - window size
# ttt     - initial TTL
# D       - don't fragment bit  (0=unset, 1=set) 
# ss      - overall SYN packet size
# OOO     - option value and order specification
# QQ      - quirks list
# OS      - OS genre
# details - OS description



class p0fKnowledgeBase(KnowledgeBase):
    def __init__(self, filename):
        KnowledgeBase.__init__(self, filename)
        #self.ttl_range=[255]
    def lazy_init(self):
        try:
            f=open(self.filename)
        except IOError:
            warning("Can't open base %s" % self.filename)
            return
        try:
            self.base = []
            for l in f:
                if l[0] in ["#","\n"]:
                    continue
                l = tuple(l.split(":"))
                if len(l) < 8:
                    continue
                li = map(int,l[1:4])
                #if li[0] not in self.ttl_range:
                #    self.ttl_range.append(li[0])
                #    self.ttl_range.sort()
                self.base.append((l[0], li[0], li[1], li[2], l[4], l[5], l[6], l[7][:-1]))
        except:
            warning("Can't parse p0f database (new p0f version ?)")
            self.base = None
        f.close()

p0f_kdb = p0fKnowledgeBase(conf.p0f_base)


def packet2p0f(pkt):
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    if not isinstance(pkt, IP) or not isinstance(pkt.payload, TCP):
        raise TypeError("Not a TCP/IP packet")
    if pkt.payload.flags & 0x13 != 0x02: #S,!A,!F
        raise TypeError("Not a syn packet")
    
    #t = p0f_kdb.ttl_range[:]
    #t += [pkt.ttl]
    #t.sort()
    #ttl=t[t.index(pkt.ttl)+1]
    ttl = pkt.ttl

    df = (pkt.flags & 2) / 2
    ss = len(pkt)
    # from p0f/config.h : PACKET_BIG = 100
    if ss > 100:
        ss = 0

    ooo = ""
    mss = -1
    qqT = False
    qqP = False
    #qqBroken = False
    ilen = (pkt[TCP].dataofs << 2) - 20 # from p0f.c
    for option in pkt.payload.options:
        ilen -= 1
        if option[0] == "MSS":
            ooo += "M" + str(option[1]) + ","
            mss = option[1]
            # FIXME: qqBroken
            ilen -= 3
        elif option[0] == "WScale":
            ooo += "W" + str(option[1]) + ","
            # FIXME: qqBroken
            ilen -= 2
        elif option[0] == "Timestamp":
            if option[1][0] == 0:
                ooo += "T0,"
            else:
                ooo += "T,"
            if option[1][1] != 0:
                qqT = True
            ilen -= 9
        elif option[0] == "SAckOK":
            ooo += "S,"
            ilen -= 1
        elif option[0] == "NOP":
            ooo += "N,"
        elif option[0] == "EOL":
            ooo += "E,"
            if ilen > 0:
                qqP = True
        else:
            ooo += "?,"
            # FIXME: ilen
    ooo = ooo[:-1]
    if ooo == "": ooo = "."

    win = pkt.payload.window
    if mss != -1:
        if win % mss == 0:
            win = "S" + str(win/mss)
        elif win % (mss + 40) == 0:
            win = "T" + str(win/(mss+40))
        win = str(win)

    qq = ""

    if qqP:
        qq += "P"
    if pkt[IP].id == 0:
        qq += "Z"
    if pkt[IP].options != '':
        qq += "I"
    if pkt[TCP].urgptr != 0:
        qq += "U"
    if pkt[TCP].reserved != 0:
        qq += "X"
    if pkt[TCP].ack != 0:
        qq += "A"
    if qqT:
        qq += "T"
    if pkt[TCP].flags & 40 != 0:
        # U or P
        qq += "F"
    if not isinstance(pkt[TCP].payload, NoPayload):
        qq += "D"
    # FIXME : "!" - broken options segment

    if qq == "":
        qq = "."

    return (win,
            ttl,
            df,
            ss,
            ooo,
            qq)

def p0f_correl(x,y):
    d = 0
    # wwww can be "*" or "%nn"
    d += (x[0] == y[0] or y[0] == "*" or (y[0][0] == "%" and x[0].isdigit() and (int(x[0]) % int(y[0][1:])) == 0))
    # ttl
    d += (y[1] >= x[1] and y[1] - x[1] < 32)
    for i in [2, 3, 5]:
        d += (x[i] == y[i])
    xopt = x[4].split(",")
    yopt = y[4].split(",")
    if len(xopt) == len(yopt):
        same = True
        for i in range(len(xopt)):
            if not (xopt[i] == yopt[i] or
                    (len(yopt[i]) == 2 and len(xopt[i]) > 1 and
                     yopt[i][1] == "*" and xopt[i][0] == yopt[i][0]) or
                    (len(yopt[i]) > 2 and len(xopt[i]) > 1 and
                     yopt[i][1] == "%" and xopt[i][0] == yopt[i][0] and
                     int(xopt[i][1:]) % int(yopt[i][2:]) == 0)):
                same = False
                break
        if same:
            d += len(xopt)
    return d


@conf.commands.register
def p0f(pkt):
    """Passive OS fingerprinting: which OS emitted this TCP SYN ?
p0f(packet) -> accuracy, [list of guesses]
"""
    pb = p0f_kdb.get_base()
    if not pb:
        warning("p0f base empty.")
        return []
    s = len(pb[0][0])
    r = []
    sig = packet2p0f(pkt)
    max = len(sig[4].split(",")) + 5
    for b in pb:
        d = p0f_correl(sig,b)
        if d == max:
            r.append((b[6], b[7], b[1] - pkt[IP].ttl))
    return r
            

def prnp0f(pkt):
    try:
        r = p0f(pkt)
    except:
        return
    if r == []:
        r = ("UNKNOWN", "[" + ":".join(map(str, packet2p0f(pkt))) + ":?:?]", None)
    else:
        r = r[0]
    uptime = None
    try:
        uptime = pkt2uptime(pkt)
    except:
        pass
    if uptime == 0:
        uptime = None
    res = pkt.sprintf("%IP.src%:%TCP.sport% - " + r[0] + " " + r[1])
    if uptime is not None:
        res += pkt.sprintf(" (up: " + str(uptime/3600) + " hrs)\n  -> %IP.dst%:%TCP.dport%")
    else:
        res += pkt.sprintf("\n  -> %IP.dst%:%TCP.dport%")
    if r[2] is not None:
        res += " (distance " + str(r[2]) + ")"
    print res

@conf.commands.register
def pkt2uptime(pkt, HZ=100):
    """Calculate the date the machine which emitted the packet booted using TCP timestamp
pkt2uptime(pkt, [HZ=100])"""
    if not isinstance(pkt, Packet):
        raise TypeError("Not a TCP packet")
    if isinstance(pkt,NoPayload):
        raise TypeError("Not a TCP packet")
    if not isinstance(pkt, TCP):
        return pkt2uptime(pkt.payload)
    for opt in pkt.options:
        if opt[0] == "Timestamp":
            #t = pkt.time - opt[1][0] * 1.0/HZ
            #return time.ctime(t)
            t = opt[1][0] / HZ
            return t
    raise TypeError("No timestamp option")


