## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

###############
## Generators ##
################

import re,random,socket
import config
import error

class Gen(object):
    def __iter__(self):
        return iter([])
    
class SetGen(Gen):
    def __init__(self, set, _iterpacket=1):
        self._iterpacket=_iterpacket
        if type(set) is list:
            self.set = set
        elif isinstance(set, BasePacketList):
            self.set = list(set)
        else:
            self.set = [set]
    def transf(self, element):
        return element
    def __iter__(self):
        for i in self.set:
            if (type(i) is tuple) and (len(i) == 2) and type(i[0]) is int and type(i[1]) is int:
                if  (i[0] <= i[1]):
                    j=i[0]
                    while j <= i[1]:
                        yield j
                        j += 1
            elif isinstance(i, Gen) and (self._iterpacket or not isinstance(i,BasePacket)):
                for j in i:
                    yield j
            else:
                yield i
    def __repr__(self):
        return "<SetGen %s>" % self.set.__repr__()

class Net(Gen):
    """Generate a list of IPs from a network address or a name"""
    name = "ip"
    ipaddress = re.compile(r"^(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)\.(\*|[0-2]?[0-9]?[0-9](-[0-2]?[0-9]?[0-9])?)(/[0-3]?[0-9])?$")
    def __init__(self, net):
        self.repr=net

        tmp=net.split('/')+["32"]
        if not self.ipaddress.match(net):
            tmp[0]=socket.gethostbyname(tmp[0])
        netmask = int(tmp[1])

        def parse_digit(a,netmask):
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

        self.parsed = map(lambda x,y: parse_digit(x,y), tmp[0].split("."), map(lambda x,nm=netmask: x-nm, (8,16,24,32)))
                                                                                               
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
        newcls = super(Packet_metaclass, cls).__new__(cls, name, bases, dct)
        for f in newcls.fields_desc:
            f.register_owner(newcls)
        config.conf.layers.register(newcls)
        return newcls
    def __getattr__(self, attr):
        for k in self.fields_desc:
            if k.name == attr:
                return k
        raise AttributeError(attr)

class NewDefaultValues(Packet_metaclass):
    """NewDefaultValues metaclass. Example usage:
    class MyPacket(Packet):
        fields_desc = [ StrField("my_field", "my default value"),  ]
        
    class MyPacket_variant(MyPacket):
        __metaclass__ = NewDefaultValues
        my_field = "my new default value"
    """    
    def __new__(cls, name, bases, dct):
        fields = None
        for b in bases:
            if hasattr(b,"fields_desc"):
                fields = b.fields_desc
                break
        if fields is None:
            raise error.Scapy_Exception("No fields_desc in superclasses")

        new_fields = []
        for f in fields:
            if f.name in dct:
                f = f.copy()
                f.default = dct[f.name]
                del(dct[f.name])
            new_fields.append(f)
        dct["fields_desc"] = new_fields
        return super(NewDefaultValues, cls).__new__(cls, name, bases, dct)

class BasePacket(Gen):
    pass


#############################
## Packet list base classe ##
#############################

class BasePacketList:
    pass



