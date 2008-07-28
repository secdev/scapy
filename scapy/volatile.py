## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import random,time
from base_classes import Net
from utils import corrupt_bits,corrupt_bytes

####################
## Random numbers ##
####################

def randseq(inf, sup, seed=None, forever=1, renewkeys=0):
    """iterate through a sequence in random order.
       When all the values have been drawn, if forever=1, the drawing is done again.
       If renewkeys=0, the draw will be in the same order, guaranteeing that the same
       number will be drawn in not less than the number of integers of the sequence"""
    rnd = random.Random(seed)
    sbox_size = 256

    top = sup-inf+1
    
    n=0
    while (1<<n) < top:
        n += 1

    fs = min(3,(n+1)/2)
    fsmask = 2**fs-1
    rounds = max(n,3)
    turns = 0

    while 1:
        if turns == 0 or renewkeys:
            sbox = [rnd.randint(0,fsmask) for k in xrange(sbox_size)]
        turns += 1
        i = 0
        while i < 2**n:
            ct = i
            i += 1
            for k in range(rounds): # Unbalanced Feistel Network
                lsb = ct & fsmask
                ct >>= fs
                lsb ^= sbox[ct%sbox_size]
                ct |= lsb << (n-fs)
            
            if ct < top:
                yield inf+ct
        if not forever:
            break


class VolatileValue:
    def __repr__(self):
        return "<%s>" % self.__class__.__name__
    def __getattr__(self, attr):
        if attr == "__setstate__":
            raise AttributeError(attr)
        return getattr(self._fix(),attr)
    def _fix(self):
        return None


class RandField(VolatileValue):
    pass


class RandNum(RandField):
    min = 0
    max = 0
    def __init__(self, min, max):
        self.seq = randseq(min,max)
    def _fix(self):
        return self.seq.next()

class RandNumGamma(RandField):
    def __init__(self, alpha, beta):
        self.alpha = alpha
        self.beta = beta
    def _fix(self):
        return int(round(random.gammavariate(self.alpha, self.beta)))

class RandNumGauss(RandField):
    def __init__(self, mu, sigma):
        self.mu = mu
        self.sigma = sigma
    def _fix(self):
        return int(round(random.gauss(self.mu, self.sigma)))

class RandNumExpo(RandField):
    def __init__(self, lambd):
        self.lambd = lambd
    def _fix(self):
        return int(round(random.expovariate(self.lambd)))

class RandByte(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**8-1)

class RandShort(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**16-1)

class RandInt(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**32-1)

class RandSInt(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2L**31, 2L**31-1)

class RandLong(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**64-1)

class RandSLong(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2L**63, 2L**63-1)

class RandChoice(RandField):
    def __init__(self, *args):
        if not args:
            raise TypeError("RandChoice needs at least one choice")
        self._choice = args
    def _fix(self):
        return random.choice(self._choice)
    
class RandString(RandField):
    def __init__(self, size, chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
        self.chars = chars
        self.size = size
    def _fix(self):
        s = ""
        for i in range(self.size):
            s += random.choice(self.chars)
        return s

class RandBin(RandString):
    def __init__(self, size):
        RandString.__init__(self, size, "".join(map(chr,range(256))))


class RandTermString(RandString):
    def __init__(self, size, term):
        RandString.__init__(self, size, "".join(map(chr,range(1,256))))
        self.term = term
    def _fix(self):
        return RandString._fix(self)+self.term
    
    

class RandIP(RandString):
    def __init__(self, iptemplate="0.0.0.0/0"):
        self.ip = Net(iptemplate)
    def _fix(self):
        return self.ip.choice()

class RandMAC(RandString):
    def __init__(self, template="*"):
        template += ":*:*:*:*:*"
        template = template.split(":")
        self.mac = ()
        for i in range(6):
            if template[i] == "*":
                v = RandByte()
            elif "-" in template[i]:
                x,y = template[i].split("-")
                v = RandNum(int(x,16), int(y,16))
            else:
                v = int(template[i],16)
            self.mac += (v,)
    def _fix(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % self.mac
    

class RandOID(RandString):
    def __init__(self, fmt=None, depth=RandNumExpo(0.1), idnum=RandNumExpo(0.01)):
        self.ori_fmt = fmt
        if fmt is not None:
            fmt = fmt.split(".")
            for i in range(len(fmt)):
                if "-" in fmt[i]:
                    fmt[i] = tuple(map(int, fmt[i].split("-")))
        self.fmt = fmt
        self.depth = depth
        self.idnum = idnum
    def __repr__(self):
        if self.ori_fmt is None:
            return "<%s>" % self.__class__.__name__
        else:
            return "<%s [%s]>" % (self.__class__.__name__, self.ori_fmt)
    def _fix(self):
        if self.fmt is None:
            return ".".join(map(str, [self.idnum for i in xrange(1+self.depth)]))
        else:
            oid = []
            for i in self.fmt:
                if i == "*":
                    oid.append(str(self.idnum))
                elif i == "**":
                    oid += map(str, [self.idnum for i in xrange(1+self.depth)])
                elif type(i) is tuple:
                    oid.append(str(random.randrange(*i)))
                else:
                    oid.append(i)
            return ".".join(oid)
            


class RandDHCPOptions(RandField):
    def __init__(self, size=None, rndstr=None):
        if size is None:
            size = RandNumExpo(0.05)
        self.size = size
        if rndstr is None:
            rndstr = RandBin(RandNum(0,255))
        self.rndstr=rndstr
        self._opts = DHCPOptions.values()
        self._opts.remove("pad")
        self._opts.remove("end")
    def _fix(self):
        op = []
        for k in range(self.size):
            o = random.choice(self._opts)
            if type(o) is str:
                op.append((o,self.rndstr*1))
            else:
                op.append((o.name, o.randval()._fix()))
        return op
            

# Automatic timestamp

class AutoTime(VolatileValue):
    def __init__(self, base=None):
        if base == None:
            self.diff = 0
        else:
            self.diff = time.time()-base
    def _fix(self):
        return time.time()-self.diff
            
class IntAutoTime(AutoTime):
    def _fix(self):
        return int(time.time()-self.diff)


class ZuluTime(AutoTime):
    def __init__(self, diff=None):
        self.diff=diff
    def _fix(self):
        return time.strftime("%y%m%d%H%M%SZ",time.gmtime(time.time()+self.diff))


class DelayedEval(VolatileValue):
    """ Exemple of usage: DelayedEval("time.time()") """
    def __init__(self, expr):
        self.expr = expr
    def _fix(self):
        return eval(self.expr)


class IncrementalValue(VolatileValue):
    def __init__(self, start=0, step=1, restart=-1):
        self.start = self.val = start
        self.step = step
        self.restart = restart
    def _fix(self):
        v = self.val
        if self.val == self.restart :
            self.val = self.start
        else:
            self.val += self.step
        return v

class CorruptedBytes(VolatileValue):
    def __init__(self, s, p=0.01, n=None):
        self.s = s
        self.p = p
        self.n = n
    def _fix(self):
        return corrupt_bytes(self.s, self.p, self.n)

class CorruptedBits(CorruptedBytes):
    def _fix(self):
        return corrupt_bits(self.s, self.p, self.n)

