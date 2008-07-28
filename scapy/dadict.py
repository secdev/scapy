## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from error import Scapy_Exception

###############################
## Direct Access dictionnary ##
###############################

def fixname(x):
    if x and x[0] in "0123456789":
        x = "n_"+x
    return x.translate("________________________________________________0123456789_______ABCDEFGHIJKLMNOPQRSTUVWXYZ______abcdefghijklmnopqrstuvwxyz_____________________________________________________________________________________________________________________________________")


class DADict_Exception(Scapy_Exception):
    pass

class DADict:
    def __init__(self, _name="DADict", **kargs):
        self._name=_name
        self.__dict__.update(kargs)
    def fixname(self,val):
        return fixname(val)
    def __contains__(self, val):
        return val in self.__dict__
    def __getitem__(self, attr):
        return getattr(self, attr)
    def __setitem__(self, attr, val):        
        return setattr(self, self.fixname(attr), val)
    def __iter__(self):
        return iter(map(lambda (x,y):y,filter(lambda (x,y):x and x[0]!="_", self.__dict__.items())))
    def _show(self):
        for k in self.__dict__.keys():
            if k and k[0] != "_":
                print "%10s = %r" % (k,getattr(self,k))
    def __repr__(self):
        return "<%s/ %s>" % (self._name," ".join(filter(lambda x:x and x[0]!="_",self.__dict__.keys())))

    def _branch(self, br, uniq=0):
        if uniq and br._name in self:
            raise DADict_Exception("DADict: [%s] already branched in [%s]" % (br._name, self._name))
        self[br._name] = br

    def _my_find(self, *args, **kargs):
        if args and self._name not in args:
            return False
        for k in kargs:
            if k not in self or self[k] != kargs[k]:
                return False
        return True
    
    def _find(self, *args, **kargs):
         return self._recurs_find((), *args, **kargs)
    def _recurs_find(self, path, *args, **kargs):
        if self in path:
            return None
        if self._my_find(*args, **kargs):
            return self
        for o in self:
            if isinstance(o, DADict):
                p = o._recurs_find(path+(self,), *args, **kargs)
                if p is not None:
                    return p
        return None
    def _find_all(self, *args, **kargs):
        return self._recurs_find_all((), *args, **kargs)
    def _recurs_find_all(self, path, *args, **kargs):
        r = []
        if self in path:
            return r
        if self._my_find(*args, **kargs):
            r.append(self)
        for o in self:
            if isinstance(o, DADict):
                p = o._recurs_find_all(path+(self,), *args, **kargs)
                r += p
        return r
    def keys(self):
        return filter(lambda x:x and x[0]!="_", self.__dict__.keys())
        
