## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Fields that hold random numbers.
"""

import random,time,math
from base_classes import Net
from utils import corrupt_bits,corrupt_bytes

####################
## Random numbers ##
####################


class RandomEnumeration:
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
                self.cnt_key = self.rnd.randint(0,2**self.n-1)
                self.sbox = [self.rnd.randint(0,self.fsmask) for k in xrange(self.sbox_size)]
            self.turns += 1
            while self.i < 2**self.n:
                ct = self.i^self.cnt_key
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
        elif attr == "__cmp__":
            x = self._fix()
            def cmp2(y,x=x):
                if type(x) != type(y):
                    return -1
                return x.__cmp__(y)
            return cmp2
        return getattr(self._fix(),attr)
    def _fix(self):
        return None


class RandField(VolatileValue):
    pass

class RandNum(RandField):
    """Instances evaluate to random integers in selected range"""
    min = 0
    max = 0
    def __init__(self, min, max):
        self.min = min
        self.max = max
    def _fix(self):
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

class RandEnum(RandNum):
    """Instances evaluate to integer sampling without replacement from the given interval"""
    def __init__(self, min, max):
        self.seq = RandomEnumeration(min,max)
    def _fix(self):
        return self.seq.next()

class RandByte(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**8-1)

class RandSByte(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2L**7, 2L**7-1)

class RandShort(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 2L**16-1)

class RandSShort(RandNum):
    def __init__(self):
        RandNum.__init__(self, -2L**15, 2L**15-1)

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

class RandEnumByte(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2L**8-1)

class RandEnumSByte(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2L**7, 2L**7-1)

class RandEnumShort(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2L**16-1)

class RandEnumSShort(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2L**15, 2L**15-1)

class RandEnumInt(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2L**32-1)

class RandEnumSInt(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2L**31, 2L**31-1)

class RandEnumLong(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, 0, 2L**64-1)

class RandEnumSLong(RandEnum):
    def __init__(self):
        RandEnum.__init__(self, -2L**63, 2L**63-1)

class RandChoice(RandField):
    def __init__(self, *args):
        if not args:
            raise TypeError("RandChoice needs at least one choice")
        self._choice = args
    def _fix(self):
        return random.choice(self._choice)
    
class RandString(RandField):
    def __init__(self, size=None, chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
        if size is None:
            size = RandNumExpo(0.01)
        self.size = size
        self.chars = chars
    def _fix(self):
        s = ""
        for i in range(self.size):
            s += random.choice(self.chars)
        return s

class RandBin(RandString):
    def __init__(self, size=None):
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
    
class RandIP6(RandString):
    def __init__(self, ip6template="**"):
        self.tmpl = ip6template
        self.sp = self.tmpl.split(":")
        for i,v in enumerate(self.sp):
            if not v or v == "**":
                continue
            if "-" in v:
                a,b = v.split("-")
            elif v == "*":
                a=b=""
            else:
                a=b=v

            if not a:
                a = "0"
            if not b:
                b = "ffff"
            if a==b:
                self.sp[i] = int(a,16)
            else:
                self.sp[i] = RandNum(int(a,16), int(b,16))
        self.variable = "" in self.sp
        self.multi = self.sp.count("**")
    def _fix(self):
        done = 0
        nbm = self.multi
        ip = []
        for i,n in enumerate(self.sp):
            if n == "**":
                nbm -= 1
                remain = 8-(len(self.sp)-i-1)-len(ip)+nbm
                if "" in self.sp:
                    remain += 1
                if nbm or self.variable:
                    remain = random.randint(0,remain)
                for j in range(remain):
                    ip.append("%04x" % random.randint(0,65535))
            if n == 0:
              ip.append("0")
            elif not n:
                ip.append("")
            else:
                ip.append("%04x" % n)
        if len(ip) == 9:
            ip.remove("")
        if ip[-1] == "":
          ip[-1] = 0
        return ":".join(ip)

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

class RandSingularity(RandChoice):
    pass
                
class RandSingNum(RandSingularity):
    @staticmethod
    def make_power_of_two(end):
        sign = 1
        if end == 0: 
            end = 1
        if end < 0:
            end = -end
            sign = -1
        end_n = int(math.log(end)/math.log(2))+1
        return set([sign*2**i for i in range(end_n)])            
        
    def __init__(self, mn, mx):
        sing = set([0, mn, mx, int((mn+mx)/2)])
        sing |= self.make_power_of_two(mn)
        sing |= self.make_power_of_two(mx)
        for i in sing.copy():
            sing.add(i+1)
            sing.add(i-1)
        for i in sing.copy():
            if not mn <= i <= mx:
                sing.remove(i)
        self._choice = list(sing)
        

class RandSingByte(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2L**8-1)

class RandSingSByte(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2L**7, 2L**7-1)

class RandSingShort(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2L**16-1)

class RandSingSShort(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2L**15, 2L**15-1)

class RandSingInt(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2L**32-1)

class RandSingSInt(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2L**31, 2L**31-1)

class RandSingLong(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, 0, 2L**64-1)

class RandSingSLong(RandSingNum):
    def __init__(self):
        RandSingNum.__init__(self, -2L**63, 2L**63-1)

class RandSingString(RandSingularity):
    def __init__(self):
        self._choice = [ "",
                         "%x",
                         "%%",
                         "%s",
                         "%i",
                         "%n",
                         "%x%x%x%x%x%x%x%x%x",
                         "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                         "%",
                         "%%%",
                         "A"*4096,
                         "\x00"*4096,
                         "\xff"*4096,
                         "\x7f"*4096,
                         "\x80"*4096,
                         " "*4096,
                         "\\"*4096,
                         "("*4096,
                         "../"*1024,
                         "/"*1024,
                         "${HOME}"*512,
                         " or 1=1 --",
                         "' or 1=1 --",
                         '" or 1=1 --',
                         " or 1=1; #",
                         "' or 1=1; #",
                         '" or 1=1; #',
                         ";reboot;",
                         "$(reboot)",
                         "`reboot`",
                         "index.php%00",
                         "\x00",
                         "%00",
                         "\\",
                         "../../../../../../../../../../../../../../../../../etc/passwd",
                         "%2e%2e%2f" * 20 + "etc/passwd",
                         "%252e%252e%252f" * 20 + "boot.ini",
                         "..%c0%af" * 20 + "etc/passwd",
                         "..%c0%af" * 20 + "boot.ini",
                         "//etc/passwd",
                         r"..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\boot.ini",
                         "AUX:",
                         "CLOCK$",
                         "COM:",
                         "CON:",
                         "LPT:",
                         "LST:",
                         "NUL:",
                         "CON:",
                         r"C:\CON\CON",
                         r"C:\boot.ini",
                         r"\\myserver\share",
                         "foo.exe:",
                         "foo.exe\\", ]
                             

class RandPool(RandField):
    def __init__(self, *args):
        """Each parameter is a volatile object or a couple (volatile object, weight)"""
        pool = []
        for p in args:
            w = 1
            if type(p) is tuple:
                p,w = p
            pool += [p]*w
        self._pool = pool
    def _fix(self):
        r = random.choice(self._pool)
        return r._fix()

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

