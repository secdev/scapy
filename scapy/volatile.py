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


class RandomSequence:
    """iterate through a sequence in random order.
       When all the values have been drawn, if forever=1, the drawing is done again.
       If renewkeys=0, the draw will be in the same order, guaranteeing that the same
       number will be drawn in not less than the number of integers of the sequence"""
    def __init__(self, inf, sup, seed=None, forever=1, renewkeys=0):
        self.forever = forever
        self.renewkeys = renewkeys
        self.inf = inf
        self.rnd = random.Random(seed)
        self.sbox_size = 256

        self.top = sup-inf+1
    
        n=0
        while (1<<n) < self.top:
            n += 1
        self.n =n

        self.fs = min(3,(n+1)/2)
        self.fsmask = 2**self.fs-1
        self.rounds = max(self.n,3)
        self.turns = 0
        self.i = 0

    def __iter__(self):
        return self
    def next(self):
        while True:
            if self.turns == 0 or (self.i == 0 and self.renewkeys):
                self.sbox = [self.rnd.randint(0,self.fsmask) for k in xrange(self.sbox_size)]
            self.turns += 1
            while self.i < 2**self.n:
                ct = self.i
                self.i += 1
                for k in range(self.rounds): # Unbalanced Feistel Network
                    lsb = ct & self.fsmask
                    ct >>= self.fs
                    lsb ^= self.sbox[ct%self.sbox_size]
                    ct |= lsb << (self.n-self.fs)
                
                if ct < self.top:
                    return self.inf+ct
            self.i = 0
            if not self.forever:
                raise StopIteration


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
        self.min = min
        self.max = max
    def _fix(self):
        # XXX: replace with sth that guarantee unicity
        return random.randrange(self.min, self.max+1)

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
    def __init__(self, lambd, base=0):
        self.lambd = lambd
        self.base = base
    def _fix(self):
        return self.base+int(round(random.expovariate(self.lambd)))

class RandSeq(RandNum):
    def __init__(self, min, max):
        self.seq = RandomSequence(min,max)
    def _fix(self):
        return self.seq.next()

class RandByte(RandSeq):
    def __init__(self):
        RandSeq.__init__(self, 0, 2L**8-1)

class RandShort(RandSeq):
    def __init__(self):
        RandSeq.__init__(self, 0, 2L**16-1)

class RandInt(RandSeq):
    def __init__(self):
        RandSeq.__init__(self, 0, 2L**32-1)

class RandSInt(RandSeq):
    def __init__(self):
        RandSeq.__init__(self, -2L**31, 2L**31-1)

class RandLong(RandSeq):
    def __init__(self):
        RandSeq.__init__(self, 0, 2L**64-1)

class RandSLong(RandSeq):
    def __init__(self):
        RandSeq.__init__(self, -2L**63, 2L**63-1)

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
                v = RandSeq(int(x,16), int(y,16))
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
            

from pprint import pprint
        
class RandRegExp(RandField):
    def __init__(self, regexp, lambda_=0.3,):
        self._regexp = regexp
        self._lambda = lambda_

    @staticmethod
    def choice_expand(s): #XXX does not support special sets like (ex ':alnum:')
        m = ""
        invert = s and s[0] == "^"
        while True:
            p = s.find("-")
            if p < 0:
                break
            if p == 0 or p == len(s)-1:
                m = "-"
                if p:
                    s = s[:-1]
                else:
                    s = s[1:]
            else:
                c1 = s[p-1]
                c2 = s[p+1]
                rng = "".join(map(chr, range(ord(c1),ord(c2)+1)))
                s = s[:p-1]+rng+s[p+1:]
        res = m+s
        if invert:
            res = "".join([chr(x) for x in xrange(256) if chr(x) not in res])
        return res

    @staticmethod
    def stack_fix(lst, index):
        r = ""
        mul = 1
        for e in lst:
            if type(e) is list:
                if mul != 1:
                    mul = mul-1
                    r += RandRegExp.stack_fix(e[1:]*mul, index)
                # only the last iteration should be kept for back reference
                f = RandRegExp.stack_fix(e[1:], index)
                for i,idx in enumerate(index):
                    if e is idx:
                        index[i] = f
                r += f
                mul = 1
            elif type(e) is tuple:
                kind,val = e
                if kind == "cite":
                    r += index[val-1]
                elif kind == "repeat":
                    mul = val

                elif kind == "choice":
                    if mul == 1:
                        c = random.choice(val)
                        r += RandRegExp.stack_fix(c[1:], index)
                    else:
                        r += RandRegExp.stack_fix([e]*mul, index)
                        mul = 1
            else:
                if mul != 1:
                    r += RandRegExp.stack_fix([e]*mul, index)
                    mul = 1
                else:
                    r += str(e)
        return r

    def _fix(self):
        stack = [None]
        index = []
        current = stack
        i = 0
        ln = len(self._regexp)
        interp = True
        while i < ln:
            c = self._regexp[i]
            i+=1
            
            if c == '(':
                current = [current]
                current[0].append(current)
            elif c == '|':
                p = current[0]
                ch = p[-1]
                if type(ch) is not tuple:
                    ch = ("choice",[current])
                    p[-1] = ch
                else:
                    ch[1].append(current)
                current = [p]
            elif c == ')':
                ch = current[0][-1]
                if type(ch) is tuple:
                    ch[1].append(current)
                index.append(current)
                current = current[0]
            elif c == '[' or c == '{':
                current = [current]
                current[0].append(current)
                interp = False
            elif c == ']':
                current = current[0]
                choice = RandRegExp.choice_expand("".join(current.pop()[1:]))
                current.append(RandChoice(*list(choice)))
                interp = True
            elif c == '}':
                current = current[0]
                num = "".join(current.pop()[1:])
                e = current.pop()
                if "," not in num:
                    n = int(num)
                    current.append([current]+[e]*n)
                else:
                    num_min,num_max = num.split(",")
                    if not num_min:
                        num_min = "0"
                    if num_max:
                        n = RandNum(int(num_min),int(num_max))
                    else:
                        n = RandNumExpo(self._lambda,base=int(num_min))
                    current.append(("repeat",n))
                    current.append(e)
                interp = True
            elif c == '\\':
                c = self._regexp[i]
                if c == "s":
                    c = RandChoice(" ","\t")
                elif c in "0123456789":
                    c = ("cite",ord(c)-0x30)
                current.append(c)
                i += 1
            elif not interp:
                current.append(c)
            elif c == '+':
                e = current.pop()
                current.append([current]+[e]*(int(random.expovariate(self._lambda))+1))
            elif c == '*':
                e = current.pop()
                current.append([current]+[e]*int(random.expovariate(self._lambda)))
            elif c == '?':
                if random.randint(0,1):
                    current.pop()
            elif c == '.':
                current.append(RandChoice(*[chr(x) for x in xrange(256)]))
            elif c == '$' or c == '^':
                pass
            else:
                current.append(c)

        return RandRegExp.stack_fix(stack[1:], index)
    def __repr__(self):
        return "<%s [%r]>" % (self.__class__.__name__, self._regexp)
                
                
        
        

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

