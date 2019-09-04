from __future__ import absolute_import
from __future__ import print_function

from scapy.data import KnowledgeBase
from scapy.config import conf
from scapy.layers.inet import IP, TCP, TCPOptions
from scapy.error import warning, Scapy_Exception
from scapy.sendrecv import sniff
from scapy.modules import six
from scapy.modules.six.moves import map, range

conf.p0f_base = '/etc/p0f/p0f.fp'
mtu = float('inf')

# Nice namespace for p0f quirks
Quirks_p0f = {
    'df'     : 0,  # don't fragment flag
    'id+'    : 1,  # df set but IPID non-zero
    'id-'    : 2,  # df not set but IPID zero
    'ecn'    : 3,  # explicit confestion notification support
    'zero+'  : 4,  # 'must be zero' field not zero
    'flow'   : 5,  # non-zero IPv6 flow ID

    'seq-'   : 6,  # sequence number is zero
    'ack+'   : 7,  # ACK number is non-zero but ACK flag is not set
    'ack-'   : 8,  # ACK number is zero but ACK flag is set
    'uptr+'  : 9,  # URG pointer is non-zero but URG flag not set
    'urgf+'  : 10, # URG flag used
    'pushf+' : 11, # PUSH flag used

    'ts1-'   : 12, # own timestamp specified as zero
    'ts2+'   : 13, # non-zero peer timestamp on initial SYN
    'opt+'   : 14, # trailing non-zero data in options segment
    'exws'   : 15, # excessive window scaling factor ( > 14)
    'bad'    : 16 # malformed tcp options
}

Layouts_p0f = {
    'nop'  : 0, # no-op option
    'mss'  : 1, # maximum segment size
    'ws'   : 2, # window scaling
    'sok'  : 3, # selective ACK permitted
    'sack' : 4, # selective ACK (should not be seen)
    'ts'   : 5, # timestamp
    '?n'   : 6, # unknown option ID n
}
# eol+n will be stored as '-n' integer

def lparse(line, n, default='', splitchar=':'):
    """
    Function for nice parcing of 'a:b:c:d:e' lines
    Only Python 3 compatible
    """
    a = line.split(splitchar)[:n]
    yield from a
    yield from [default] * (n - len(a))

class p0fDatabase(KnowledgeBase):
    """
    p0fDatabase structure

    nested dictionary structure
    self.base = {
        'module' (str): {
            'moduledir' (str): {sig (tuple): labelnum (int)}
            }
        }

    self.labels = ['label' (str), ...]
    """

    def lazy_init(self):

        #FIXME I have found out that KnowledgeBase class is used
        # only for p0f and nmap modules which are outdated
        # I think it would be nice to rewrite some of
        # KnowledgeBase class code

        try:
            f = open(self.filename)
        except IOError:
            warning("Can't open base %s", self.filename)
            return

        self.base = {}
        self.labels = []
        self.parse_file(f)
        self.labels = tuple(self.labels)
        self.parse_tcp_base()
        self.parse_http_base()

        f.close()

    def parse_file(self, file):
        """
        Does actual parsing and stores it to self.base with described structure
        """
        
        module = 'classes'
        moduledir = ''
        self.base[module] = {}
        self.base[module][moduledir] = {}
        currdict = self.base[module][moduledir]
        currlabel = 'classes'

        for line in file:
            line = line.partition(';')[0]

            if not line:
                continue

            if line[0] == '[':
                module, moduledir = lparse(line[1:line.rfind(']')], 2)
                try:
                    self.base[module][moduledir] = {}
                except KeyError:
                    self.base[module] = {moduledir: {}}
                currdict = self.base[module][moduledir]
            else:
                param, _, value = line.partition(' = ')
                param = param.strip()
                value = value.strip()

                if param =='label':
                    l = len(self.labels)
                    self.labels.append(value)
                    currlabel = l
    
                elif param == 'sig':
                    currdict[value] = currlabel

                elif param == 'classes':
                    currdict[currlabel] = value

    def parse_tcp_base(self):

        for moduledir in 'response', 'request':
            sigdict = self.base['tcp'][moduledir]
            newsigdict = {}
            for sig, numlabel in sigdict.items():

                ver, ttl, olen, mss, wsize, olayout, quirks, pclass = lparse(sig, 8)
                wsize, _, scale = wsize.partition(',')

                quirks = frozenset(map(Quirks_p0f.get, quirks.split(',')))

                olayout = list(map(lambda x: Layouts_p0f.get(x, x), olayout.split(',')))
                if isinstance(olayout[-1], str):
                    olayout[-1] = - int(olayout[-1][4:])
                olayout = tuple(olayout)

                newsigdict[(ver, ttl, olen, mss, wsize,
                    scale, olayout, quirks, pclass)] = numlabel

            self.base['tcp'][moduledir] = newsigdict

    def parse_http_base(self):
        
        for moduledir in 'response', 'request':
            sigdict = self.base['http'][moduledir]
            newsigdict = {}
            for sig, numlabel in sigdict.items():

                ver, horder, habsent, expsw = lparse(sig, 4)
                horder = tuple(p0fDatabase._parse_horder(horder))
                habsent = frozenset(habsent.split(','))

                newsigdict[(ver, horder, habsent, expsw)] = numlabel

            self.base['http'][moduledir] = newsigdict

    @staticmethod
    def _parse_horder(horder):
        
        for header in horder.split(','):
            header, eq, value = header.partition('=')

            if header[0] == '?':
                yield (header[1:], None)
            else:
                yield (header, value[1:-1])


    def tcp_correl(self, moduledir, tcpsign, olayout, quirks):
        """
        Correlates the tcp-packet with p0f database

        Correlation is done via computing correlation score, 
        which is based on
        1) hits count (TCP signature count)
        2) intersection of found quirks and database's quirks
        3) options layout equality
        """
        
        # prepare values
        ver, ttl, olen, mss, wsize, wscale, pclass = tcpsign
        sigdict = self.base['tcp'][moduledir]

        # 's' stnds for signature
        for (sver, sttl, solen, smss, swsize, sscale,
                solayout, squirks, spclass), numlabel in sigdict.items():

            hits = 0

            # compares main values
            hits += (sver == '*') or (int(sver) == ver)
            hits += (int(sttl[:-1]) >= ttl) if sttl[-1] == '-' else int(sttl) == ttl
            hits += int(solen) == olen
            hits += (smss == '*') or (int(smss) == mss)
            if swsize == '*' or type(eval(swsize) == str):
                hits += 1
            else:
                evaled = eval(swsize)
                if wsize <= evaled:
                    hits += min(1, wsize / evaled)
            hits += (sscale == '*') or (int(sscale) == wscale)
            hits += (spclass == '*') or (spclass == pclass == 0) or \
                    (spclass == '+' and pclass)

            h_correl = hits / 7

            # compares quirks
            q_correl = len(squirks & quirks) / len(quirks)

            # compares layouts
            l_correl = solayout == olayout

            yield (q_correl, h_correl, l_correl), self.labels[numlabel]

    def http_correl(self, moduledir, version, headers):
        """
        Correlates http packet with p0f database
        """
        for (ver, horder, habsent, expsw), numlabel in self.base[moduledir]:

            ver_correl = (ver == '*') or (int(ver) == version)
            exp_correl = False
            abs_correl = True

            ord_correl = True
            ordi = 0

            q_headers = set(map(lambda x: x[0], filter(lambda y: y[1] == None, horder)))

            # Really weird algorithm
            # FIXME

            prevs = set()
            for name, value in headers:

                if not ord_correl:
                    break

                if abs_correl and (name in habsent):
                    abs_correl = False

                if not exp_correl and (name in {'User-Agent', 'Server'}) and value == expsw:
                    exp_correl = True

                if ordi >= len(horder):
                    break

                checked = False
                while not checked:

                    if name == horder[ordi][0] and (horder[ordi][1] in ('', value)):
                        ordi += 1
                        prevs = set()
                        checked = True

                    elif horder[ordi][1] == None:
                        prevs.add(horder[ordi][0])
                        ordi += 1
                            
                    elif name in prevs:
                        checked = True

                    elif name in q_headers:
                        checked = True
                        ord_correl = False
            
            yield (ver_correl, ord_correl, abs_correl, exp_correl), self.labels[numlabel]


p0fdb = p0fDatabase(conf.p0f_base)

def preprocessPacket4p0f(pkt):
    """
    Actually copied it from old p0f.py
    """
    pkt = pkt.copy()
    pkt = pkt.__class__(raw(pkt))
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    if not (isinstance(pkt, IP) and isinstance(pkt.payload, TCP)):
        raise TypeError('Not a TCP/IP packet')
    
    return pkt

def packet2quirks(pkt):
    """
    *requires preprocessed packet
    Returns set of quirks found in packet
    Help required
    """

    quirks = set()
    addq = lambda name: quirks.add(Quirks_p0f[name])
    
    # IPv4 only
    if type(pkt) == scapy.layers.inet.IP:
        
        if pkt.flags == 2:
            addq('df')

            if pkt.id != 0:
                addq('id+')

        elif pkt.id == 0:
            addq('id-')
    
        #if pkt.flags.ECN:
        #    addq('ecn')

        if pkt.seq == 0:
            addq('seq-')

    # IPv6 only
    elif type(pkt) == scapy.layers.inet6.IPv6:
        
        if pky.fl:
            quirks.add(Quirks_p0f['flow'])

    # TCP
    pkt = pkt.payload

    if pkt.flags.A:        
        if pkt.ack == 0:
            addq('ack+')
    else:
        if pkt.ack:
            addq('ack-')

    if pkt.flags.U:
        addq('urgf+')
        
    else:
        if pkt.urgptr:
            addq('uptr+')
        
    if pkt.flags.P:
        addq('pushf+')

    for name, val in pkt.options:
        
        if name == 'Timestamp':
            if val[0] == 0:
                addq('ts1-')
            if val[1] != 0:
                addq('ts2+')

        elif name == 'WScale' and val > 14:
            addq('exws')

    # TODO
    # please help me with '0+' (must be zero field) in p0f
    # and with 'opt+', 'bad', 'ECN' field  

    return quirks

def packet2olayout(pkt):
    """
    *requires preprocessed packet
    Returns list of layout options
    """
        
    # TODO
    # please help me with 'eol+n', 'sok', 'sack', '?n'

    olayout = []
    addl = lambda name: olayout.append(Layouts_p0f[name])

    for name, _ in pkt.payload.options:

        if name == 'NOP':
            addl('nop')

        elif name == 'Timestamp':
            addl('ts')

        elif name == 'MSS':
            addl('mss')
        
        elif name == 'WScale':
            addl('ws')
    
    return tuple(olayout)
   

def packet2tcpsign(pkt):
    """
    *requires preprocessed packet
    Parses TCP packet and returns TCP signature
    """

    #IP  layer - pkt
    #TCP layer - pkt.payload

    ver = pkt.version
    wsize = pkt.payload.window
    pclass = bool(pkt.payload.payload)

    try:
        ttl = pkt.ttl
        olen = len(pkt.options)
    except AttributeError:
        #IPv6 packet
        ttl = 0
        olen = 0

    mss = '*'
    wscale = '*'

    for name, value in pkt.payload.options:
        if name == 'MSS':
            mss = value
        elif name == 'WScale':
            wscale = value

    return (ver, ttl, olen, mss, wsize, wscale, pclass)

def prnp0f(pkt):
    pkt = preprocessPacket4p0f(pkt)
    if pkt['TCP'].flags.S:
        p0f_out = packet2tcpsign(pkt)
        olayout = packet2olayout(pkt)
        quirks  = packet2quirks(pkt)
        if pkt['TCP'].flags.A:
            direction = 'response'
        else:
            direction = 'request'
        gen = p0fdb.tcp_correl(direction, p0f_out, olayout, quirks)
        return max(list(gen), key=lambda x: sum(x[0]))[1]

if __name__ == '__main__':
    # This one is for testing

    pdb = p0fDatabase(conf.p0f_base)
    base = pdb.get_base()
    packet = IP(version=4, ttl=64)/TCP(options=[('WScale', 10)], window=8192, flags='SA')

    from time import time
    to = time()

    print(packet2tcpsign(packet))
    gen = pdb.tcp_correl('request', packet2tcpsign(packet), (1, 3, 5, 0, 2), {0, 1})
    l = sorted(list(gen), key = lambda x: (sum(x[0]) / 3, x[1]))

    for (q, h, l), n in l:
        print(f"{h, l ,q}   : {n}")
    
    print(time() - to) #002 avg time
