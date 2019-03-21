from __future__ import absolute_import
from __future__ import print_function

from scapy.data import KnowledgeBase, MTU
from scapy.config import conf
from scapy.layers.inet import IP, TCP, TCPOptions
from scapy.error import warning, Scapy_Exception
from scapy.sendrecv import sniff
from scapy.modules import six
from scapy.modules.six.moves import map, range

conf.p0f_base = '/etc/p0f/p0f.fp'

def lparse(line, n, default='', splitchar=':'):
    """Function for nice parcing of 'a:b:c:d:e' lines"""
    a = line.split(splitchar)
    yield from a
    yield from [default] * (n - len(a))

class p0fDatabase(KnowledgeBase):
    """
    p0fDatabase structure

    nested dictionary structure
    self.base = {
        'module' (str): {
            'moduledir' (str): {'sig' (str): 'label' (str)}
            }
        }
    """

    def lazy_init(self):

        #FIXME I have found out that KnowledgeBase class is used
        # for p0f and nmap modules which are outdated
        # I think it would be nice to rewrite some of
        # KnowledgeBase class code

        try:
            f = open(self.filename)
        except IOError:
            warning("Can't open base %s", self.filename)
            return

        #try:
        self.base = {}
        self.parse_file(f)
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
                    currlabel = value
    
                elif param == 'sig':
                    currdict[value] = currlabel

                elif param == 'classes':
                    currdict[currlabel] = value


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

class Quirks_p0f:
    """Nice namespace for p0f quirks"""
    df      = "don't fragment flag"
    idp     = "df set but IPID non-zero"
    idm     = "df not set but IPID zero"
    ecn     = "explicit confestion notification support"
    zerop   = "'must be zero' field not zero"
    flow    = "non-zero IPv6 flow ID"

    seq     = "sequence number is zero"
    ackp    = "ACK number is non-zero but ACK flag is not set"
    ackm    = "ACK number is zero but ACK flag is set"
    uptrp   = "URG pointer is non-zero but URG flag not set"
    urgfp   = "URG flag used"
    pushfpp = "PSUH flag used"

    ts1m    = "own timestamp specified as zero"
    ts2p    = "non-zero peer timestamp on initial SYN"
    optp    = "trailing non-zero data in options segment"
    exws    = "excessive window scaling factor ( > 14)"
    bad     = "malformed tcp options"

def packet2quirks(pkt):
    """requires preprocessed packet"""

    quirks = []

    #df check
    if pkt.flags == 2:
        quirks.append(Quirks_p0f.df)

        if pkt.id != 0:
            quirks.append(Quirks_p0f.idp)

    elif pkt.id == 0:
        quirks.append(Quirks_p0f.idm)

    if pkt.flags.ECN:
        quircks.append(Quirks_p0f.ecn)


def packet2p0f(pkt):
    """requires preprocessed packet"""

    #IP  layer - pkt
    #TCP layer - pkt.payload

    #Independent TCP
    wsize = pkt.payload.window

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

    olayout = set(map(lambda x: x[0], pkt.payload.options))

    return wsize, ttl, olen, mss, wscale, olayout

if __name__ == '__main__':
    """ This one is for testing"""

    pdb = p0fDatabase(conf.p0f_base)
    base = pdb.get_base()

