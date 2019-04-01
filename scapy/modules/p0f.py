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
mtu = 123231231

def lparse(line, n, default='', splitchar=':'):
    """Function for nice parcing of 'a:b:c:d:e' lines"""
    a = line.split(splitchar)[:n]
    yield from a
    yield from [default] * (n - len(a))

class p0fDatabase(KnowledgeBase):
    """
    p0fDatabase structure

    nested dictionary structure
    self.base = {
        'module' (str): {
            'moduledir' (str): {'sig' (str): labelnum (int)}
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

        #try:
        self.base = {}
        self.labels = []
        self.parse_file(f)
        self.labels = tuple(self.labels)
        #except Exception:
        #    warning("Can't parse p0f database (new p0f version ?)")
        #    self.base = None

        f.close()

    def parse_file(self, file):
        """Does actual parsing and stores it to self.base with described structure"""
        
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

    def p0f_tcp_correl(self, moduledir, pkt2p0f_out, olayout, quirks):
        """corellates the tcp-packet with p0f database"""
        
        # prepare values
        ver, ttl, olen, mss, wsize, wscale, pclass = pkt2p0f_out
        sigdict = self.base['tcp'][moduledir]

        for sig, numlabel in sigdict.items():
            label = self.labels[numlabel]
            hits = 0

            # 's' stands for 'signature_'
            sver, sttl, solen, smss, swsize_sscale, solayout, squirks, spclass = lparse(sig, 8)
            swsize, sscale = swsize_sscale.split(',')

            # compares main values
            hits += (sver == '*') or (int(sver) == ver)
            hits += (int(sttl[:-1]) >= ttl) if sttl[-1] == '-' else int(sttl) == ttl
            hits += int(solen) == olen
            hits += (smss == '*') or (int(smss) == mss)
            hits += (swsize == '*') or (type(eval(swsize)) == str) or (eval(swsize) >= wsize)
            hits += (sscale == '*') or (int(sscale) == wscale)
            hits += (spclass == '*') or (spclass == pclass == 0) or (spclass == '+' and pclass)

            # compares quirks
            squirks = squirks.split(',')
            if squirks[0]:
                qhits = sum(quirks_correl(quirks, squirks))
            else:
                qhits = 0
            # compares layaouts
            # TODO

            q_correl = qhits / len(squirks)
            h_correl = hits / 7
            l_correl = 1

            yield q_correl, h_correl, l_correl, label

p0fdb = p0fDatabase(conf.p0f_base)

def preprocessPacket4p0f(pkt):
    """Actually copied it from old p0f.py"""
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
    'bad'    : 16} # malformed tcp options

Layouts_p0f = {
        
        
}

def quirks_correl(qint, quirks):
    for quirk in quirks:
        yield bool((1 << Quirks_p0f[quirk]) & qint)

def packet2quirks(pkt):
    """
        requires preprocessed packet
        not done yet
    """

    quirks = 0

    #df check
    if pkt.flags == 2:
        quirks += 1 << Quirks_p0f['df']

        if pkt.id != 0:
            quirks += 1 << Quirks_p0f['id+']

    elif pkt.id == 0:
        quirks += 1 << Quirks_p0f['id-']

    if pkt.flags.ECN:
        quircks += 1 << Quirks_p0f['ecn']


def packet2olayout(pkt):
    """requires preprocessed packet"""
    pass


def packet2p0f(pkt):
    """requires preprocessed packet"""

    #IP  layer - pkt
    #TCP layer - pkt.payload

    #Independent IP
    ver = pkt.version

    #Independent TCP
    wsize = pkt.payload.window
    pclass = bool(pkt.payload.payload)

    #IPv-dependent
    try:
        ttl = pkt.ttl
        olen = len(pkt.options)
    except AttributeError:
        #IPv6 packet
        ttl = 0
        olen = 0

    #TCP options presets
    mss = '*'
    wscale = '*'

    #TCP options acquiring
    for option in pkt.payload.options:
        if option[0] == 'MSS':
            mss = option[1]
        if option[0] == 'WScale':
            wscale = option[1]

    return (ver, ttl, olen, mss, wsize, wscale, pclass)

if __name__ == '__main__':
    # This one is for testing

    pdb = p0fDatabase(conf.p0f_base)
    base = pdb.get_base()
    from time import time
    to = time()
    packet = IP(version=4, ttl=64)/TCP(options=[], window=128)
    gen = pdb.p0f_tcp_correl('request', packet2p0f(packet), [], 0)
    l = list(map(lambda x: (sum(x[:2]) / 3, x[3]), gen))
    print(time() - to)
