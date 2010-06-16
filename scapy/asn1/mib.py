## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Management Information Base (MIB) parsing
"""

import re
from glob import glob
from scapy.dadict import DADict,fixname
from scapy.config import conf
from scapy.utils import do_graph

#################
## MIB parsing ##
#################

_mib_re_integer = re.compile("^[0-9]+$")
_mib_re_both = re.compile("^([a-zA-Z_][a-zA-Z0-9_-]*)\(([0-9]+)\)$")
_mib_re_oiddecl = re.compile("$\s*([a-zA-Z0-9_-]+)\s+OBJECT([^:\{\}]|\{[^:]+\})+::=\s*\{([^\}]+)\}",re.M)
_mib_re_strings = re.compile('"[^"]*"')
_mib_re_comments = re.compile('--.*(\r|\n)')

class MIBDict(DADict):
    def _findroot(self, x):
        if x.startswith("."):
            x = x[1:]
        if not x.endswith("."):
            x += "."
        max=0
        root="."
        for k in self.keys():
            if x.startswith(self[k]+"."):
                if max < len(self[k]):
                    max = len(self[k])
                    root = k
        return root, x[max:-1]
    def _oidname(self, x):
        root,remainder = self._findroot(x)
        return root+remainder
    def _oid(self, x):
        xl = x.strip(".").split(".")
        p = len(xl)-1
        while p >= 0 and _mib_re_integer.match(xl[p]):
            p -= 1
        if p != 0 or xl[p] not in self:
            return x
        xl[p] = self[xl[p]] 
        return ".".join(xl[p:])
    def _make_graph(self, other_keys=[], **kargs):
        nodes = [(k,self[k]) for k in self.keys()]
        oids = [self[k] for k in self.keys()]
        for k in other_keys:
            if k not in oids:
                nodes.append(self.oidname(k),k)
        s = 'digraph "mib" {\n\trankdir=LR;\n\n'
        for k,o in nodes:
            s += '\t"%s" [ label="%s"  ];\n' % (o,k)
        s += "\n"
        for k,o in nodes:
            parent,remainder = self._findroot(o[:-1])
            remainder = remainder[1:]+o[-1]
            if parent != ".":
                parent = self[parent]
            s += '\t"%s" -> "%s" [label="%s"];\n' % (parent, o,remainder)
        s += "}\n"
        do_graph(s, **kargs)
    def __len__(self):
        return len(self.keys())


def mib_register(ident, value, the_mib, unresolved):
    if ident in the_mib or ident in unresolved:
        return ident in the_mib
    resval = []
    not_resolved = 0
    for v in value:
        if _mib_re_integer.match(v):
            resval.append(v)
        else:
            v = fixname(v)
            if v not in the_mib:
                not_resolved = 1
            if v in the_mib:
                v = the_mib[v]
            elif v in unresolved:
                v = unresolved[v]
            if type(v) is list:
                resval += v
            else:
                resval.append(v)
    if not_resolved:
        unresolved[ident] = resval
        return False
    else:
        the_mib[ident] = resval
        keys = unresolved.keys()
        i = 0
        while i < len(keys):
            k = keys[i]
            if mib_register(k,unresolved[k], the_mib, {}):
                del(unresolved[k])
                del(keys[i])
                i = 0
            else:
                i += 1
                    
        return True


def load_mib(filenames):
    the_mib = {'iso': ['1']}
    unresolved = {}
    for k in conf.mib.keys():
        mib_register(k, conf.mib[k].split("."), the_mib, unresolved)

    if type(filenames) is str:
        filenames = [filenames]
    for fnames in filenames:
        for fname in glob(fnames):
            f = open(fname)
            text = f.read()
            cleantext = " ".join(_mib_re_strings.split(" ".join(_mib_re_comments.split(text))))
            for m in _mib_re_oiddecl.finditer(cleantext):
                gr = m.groups()
                ident,oid = gr[0],gr[-1]
                ident=fixname(ident)
                oid = oid.split()
                for i in range(len(oid)):
                    m = _mib_re_both.match(oid[i])
                    if m:
                        oid[i] = m.groups()[1]
                mib_register(ident, oid, the_mib, unresolved)

    newmib = MIBDict(_name="MIB")
    for k,o in the_mib.iteritems():
        newmib[k]=".".join(o)
    for k,o in unresolved.iteritems():
        newmib[k]=".".join(o)

    conf.mib=newmib



conf.mib = MIBDict(_name="MIB")
