## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Generators and packet meta classes.
"""

###############
## Generators ##
################

import re,random,socket
import types

class Gen(object):
    __slots__ = []
    def __iter__(self):
        return iter([])
    
class SetGen(Gen):
    def __init__(self, values, _iterpacket=1):
        self._iterpacket=_iterpacket
        if isinstance(values, (list, BasePacketList)):
            self.values = list(values)
        elif (type(values) is tuple) and (2 <= len(values) <= 3) and \
             all(type(i) is int for i in values):
            # We use values[1] + 1 as stop value for xrange to maintain
            # the behavior of using tuples as field `values`
            self.values = [xrange(*((values[0], values[1] + 1) + values[2:]))]
        else:
            self.values = [values]
    def transf(self, element):
        return element
    def __iter__(self):
        for i in self.values:
            if (isinstance(i, Gen) and
                (self._iterpacket or not isinstance(i,BasePacket))) or (
                    isinstance(i, (xrange, types.GeneratorType))):
                for j in i:
                    yield j
            else:
                yield i
    def __repr__(self):
        return "<SetGen %r>" % self.values

class Net(Gen):
    """Generate a list of IPs from a network address or a name"""
    name = "ip"
    ipaddress = re.compile(r"^(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)(/[0-3]?[0-9])?$")

    @staticmethod
    def _parse_digit(a,netmask):
        netmask = min(8,max(netmask,0))
        if a == "*":
            a = (0,256)
        elif a.find("-") >= 0:
            x,y = map(int,a.split("-"))
            if x > y:
                y = x
            a = (x &  (0xffL<<netmask) , max(y, (x | (0xffL>>(8-netmask))))+1)
        else:
            a = (int(a) & (0xffL<<netmask),(int(a) | (0xffL>>(8-netmask)))+1)
        return a

    @classmethod
    def _parse_net(cls, net):
        tmp=net.split('/')+["32"]
        if not cls.ipaddress.match(net):
            tmp[0]=socket.gethostbyname(tmp[0])
        netmask = int(tmp[1])
        return map(lambda x,y: cls._parse_digit(x,y), tmp[0].split("."), map(lambda x,nm=netmask: x-nm, (8,16,24,32))),netmask

    def __init__(self, net):
        self.repr=net
        self.parsed,self.netmask = self._parse_net(net)


                                                                                               
    def __iter__(self):
        for d in xrange(*self.parsed[3]):
            for c in xrange(*self.parsed[2]):
                for b in xrange(*self.parsed[1]):
                    for a in xrange(*self.parsed[0]):
                        yield "%i.%i.%i.%i" % (a,b,c,d)
    def choice(self):
        ip = []
        for v in self.parsed:
            ip.append(str(random.randint(v[0],v[1]-1)))
        return ".".join(ip) 
                          
    def __repr__(self):
        return "Net(%r)" % self.repr
    def __eq__(self, other):
        if hasattr(other, "parsed"):
            p2 = other.parsed
        else:
            p2,nm2 = self._parse_net(other)
        return self.parsed == p2
    def __contains__(self, other):
        if hasattr(other, "parsed"):
            p2 = other.parsed
        else:
            p2,nm2 = self._parse_net(other)
        for (a1,b1),(a2,b2) in zip(self.parsed,p2):
            if a1 > a2 or b1 < b2:
                return False
        return True
    def __rcontains__(self, other):        
        return self in self.__class__(other)
        

class OID(Gen):
    name = "OID"
    def __init__(self, oid):
        self.oid = oid        
        self.cmpt = []
        fmt = []        
        for i in oid.split("."):
            if "-" in i:
                fmt.append("%i")
                self.cmpt.append(tuple(map(int, i.split("-"))))
            else:
                fmt.append(i)
        self.fmt = ".".join(fmt)
    def __repr__(self):
        return "OID(%r)" % self.oid
    def __iter__(self):        
        ii = [k[0] for k in self.cmpt]
        while 1:
            yield self.fmt % tuple(ii)
            i = 0
            while 1:
                if i >= len(ii):
                    raise StopIteration
                if ii[i] < self.cmpt[i][1]:
                    ii[i]+=1
                    break
                else:
                    ii[i] = self.cmpt[i][0]
                i += 1


 
######################################
## Packet abstract and base classes ##
######################################

class Packet_metaclass(type):
    def __new__(cls, name, bases, dct):
        if "fields_desc" in dct: # perform resolution of references to other packets
            current_fld = dct["fields_desc"]
            resolved_fld = []
            for f in current_fld:
                if isinstance(f, Packet_metaclass): # reference to another fields_desc
                    for f2 in f.fields_desc:
                        resolved_fld.append(f2)
                else:
                    resolved_fld.append(f)
        else: # look for a field_desc in parent classes
            resolved_fld = None
            for b in bases:
                if hasattr(b,"fields_desc"):
                    resolved_fld = b.fields_desc
                    break

        if resolved_fld: # perform default value replacements
            final_fld = []
            for f in resolved_fld:
                if f.name in dct:
                    f = f.copy()
                    f.default = dct[f.name]
                    del(dct[f.name])
                final_fld.append(f)

            dct["fields_desc"] = final_fld

        if "__slots__" not in dct:
            dct["__slots__"] = []
        for attr in ["name", "overload_fields"]:
            try:
                dct["_%s" % attr] = dct.pop(attr)
            except KeyError:
                pass
        newcls = super(Packet_metaclass, cls).__new__(cls, name, bases, dct)
        newcls.__all_slots__ = set(
            attr
            for cls in newcls.__mro__ if hasattr(cls, "__slots__")
            for attr in cls.__slots__
        )

        if hasattr(newcls, "aliastypes"):
            newcls.aliastypes = [newcls] + newcls.aliastypes
        else:
            newcls.aliastypes = [newcls]

        if hasattr(newcls,"register_variant"):
            newcls.register_variant()
        for f in newcls.fields_desc:
            if hasattr(f, "register_owner"):
                f.register_owner(newcls)
        from scapy import config
        config.conf.layers.register(newcls)
        return newcls

    def __getattr__(self, attr):
        for k in self.fields_desc:
            if k.name == attr:
                return k
        raise AttributeError(attr)

    def __call__(cls, *args, **kargs):
        if "dispatch_hook" in cls.__dict__:
            try:
                cls = cls.dispatch_hook(*args, **kargs)
            except:
                from scapy import config
                if config.conf.debug_dissector:
                    raise
                cls = config.conf.raw_layer
        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        i.__init__(*args, **kargs)
        return i

class Field_metaclass(type):
    def __new__(cls, name, bases, dct):
        if "__slots__" not in dct:
            dct["__slots__"] = []
        newcls = super(Field_metaclass, cls).__new__(cls, name, bases, dct)
        return newcls

class NewDefaultValues(Packet_metaclass):
    """NewDefaultValues is deprecated (not needed anymore)
    
    remove this:
        __metaclass__ = NewDefaultValues
    and it should still work.
    """    
    def __new__(cls, name, bases, dct):
        from scapy.error import log_loading
        import traceback
        try:
            for tb in traceback.extract_stack()+[("??",-1,None,"")]:
                f,l,_,line = tb
                if line.startswith("class"):
                    break
        except:
            f,l="??",-1
            raise
        log_loading.warning("Deprecated (no more needed) use of NewDefaultValues  (%s l. %i)." % (f,l))
        
        return super(NewDefaultValues, cls).__new__(cls, name, bases, dct)

class BasePacket(Gen):
    __slots__ = []


#############################
## Packet list base classe ##
#############################

class BasePacketList(object):
    __slots__ = []
