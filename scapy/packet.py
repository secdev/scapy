## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Packet class. Binding mechanism. fuzz() method.
"""

import re
import time,itertools
import copy
import subprocess

from scapy.fields import StrField, ConditionalField, Emph, PacketListField, BitField, \
    MultiEnumField, EnumField, FlagsField
from scapy.config import conf
from scapy.base_classes import BasePacket, Gen, SetGen, Packet_metaclass
from scapy.volatile import VolatileValue
from scapy.utils import import_hexcap,tex_escape,colgen,get_temp_file
from scapy.error import Scapy_Exception, log_runtime
from scapy.consts import PYX

try:
    import pyx
except ImportError:
    pass


class RawVal:
    def __init__(self, val=""):
        self.val = val
    def __str__(self):
        return str(self.val)
    def __repr__(self):
        return "<RawVal [%r]>" % self.val


class Packet(BasePacket):
    __slots__ = [
        "time", "sent_time", "name", "default_fields",
        "overload_fields", "overloaded_fields", "fields", "fieldtype",
        "packetfields",
        "original", "explicit", "raw_packet_cache",
        "raw_packet_cache_fields", "_pkt", "post_transforms",
        # then payload and underlayer
        "payload", "underlayer",
        "name",
        # used for sr()
        "_answered",
        # used when sniffing
        "direction", "sniffed_on"
    ]
    __metaclass__ = Packet_metaclass
    name = None
    fields_desc = []
    overload_fields = {}
    payload_guess = []
    show_indent = 1
    show_summary = True

    @classmethod
    def from_hexcap(cls):
        return cls(import_hexcap())

    @classmethod
    def upper_bonds(self):
        for fval,upper in self.payload_guess:
            print "%-20s  %s" % (upper.__name__, ", ".join("%-12s" % ("%s=%r"%i) for i in fval.iteritems()))

    @classmethod
    def lower_bonds(self):
        for lower,fval in self._overload_fields.iteritems():
            print "%-20s  %s" % (lower.__name__, ", ".join("%-12s" % ("%s=%r"%i) for i in fval.iteritems()))

    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):
        self.time  = time.time()
        self.sent_time = None
        self.name = (self.__class__.__name__
                     if self._name is None else
                     self._name)
        self.default_fields = {}
        self.overload_fields = self._overload_fields
        self.overloaded_fields = {}
        self.fields = {}
        self.fieldtype = {}
        self.packetfields = []
        self.payload = NoPayload()
        self.init_fields()
        self.underlayer = _underlayer
        self.original = _pkt
        self.explicit = 0
        self.raw_packet_cache = None
        self.raw_packet_cache_fields = None
        if _pkt:
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        for f, v in fields.iteritems():
            self.fields[f] = self.get_field(f).any2i(self, v)
        if type(post_transform) is list:
            self.post_transforms = post_transform
        elif post_transform is None:
            self.post_transforms = []
        else:
            self.post_transforms = [post_transform]

    def init_fields(self):
        self.do_init_fields(self.fields_desc)

    def do_init_fields(self, flist):
        for f in flist:
            self.default_fields[f.name] = copy.deepcopy(f.default)
            self.fieldtype[f.name] = f
            if f.holds_packets:
                self.packetfields.append(f)
            
    def dissection_done(self,pkt):
        """DEV: will be called after a dissection is completed"""
        self.post_dissection(pkt)
        self.payload.dissection_done(pkt)
        
    def post_dissection(self, pkt):
        """DEV: is called after the dissection of the whole packet"""
        pass

    def get_field(self, fld):
        """DEV: returns the field instance from the name of the field"""
        return self.fieldtype[fld]
        
    def add_payload(self, payload):
        if payload is None:
            return
        elif not isinstance(self.payload, NoPayload):
            self.payload.add_payload(payload)
        else:
            if isinstance(payload, Packet):
                self.payload = payload
                payload.add_underlayer(self)
                for t in self.aliastypes:
                    if payload.overload_fields.has_key(t):
                        self.overloaded_fields = payload.overload_fields[t]
                        break
            elif type(payload) is str:
                self.payload = conf.raw_layer(load=payload)
            else:
                raise TypeError("payload must be either 'Packet' or 'str', not [%s]" % repr(payload))
    def remove_payload(self):
        self.payload.remove_underlayer(self)
        self.payload = NoPayload()
        self.overloaded_fields = {}
    def add_underlayer(self, underlayer):
        self.underlayer = underlayer
    def remove_underlayer(self,other):
        self.underlayer = None
    def copy(self):
        """Returns a deep copy of the instance."""
        clone = self.__class__()
        clone.fields = self.copy_fields_dict(self.fields)
        clone.default_fields = self.copy_fields_dict(self.default_fields)
        clone.overloaded_fields = self.overloaded_fields.copy()
        clone.underlayer = self.underlayer
        clone.explicit = self.explicit
        clone.raw_packet_cache = self.raw_packet_cache
        clone.raw_packet_cache_fields = self.copy_fields_dict(
            self.raw_packet_cache_fields
        )
        clone.post_transforms = self.post_transforms[:]
        clone.payload = self.payload.copy()
        clone.payload.add_underlayer(clone)
        clone.time = self.time
        return clone

    def getfieldval(self, attr):
        if attr in self.fields:
            return self.fields[attr]
        if attr in self.overloaded_fields:
            return self.overloaded_fields[attr]
        if attr in self.default_fields:
            return self.default_fields[attr]
        return self.payload.getfieldval(attr)
    
    def getfield_and_val(self, attr):
        if attr in self.fields:
            return self.get_field(attr),self.fields[attr]
        if attr in self.overloaded_fields:
            return self.get_field(attr),self.overloaded_fields[attr]
        if attr in self.default_fields:
            return self.get_field(attr),self.default_fields[attr]

    def __getattr__(self, attr):
        try:
            fld, v = self.getfield_and_val(attr)
        except TypeError:
            return self.payload.__getattr__(attr)
        if fld is not None:
            return fld.i2h(self, v)
        return v

    def setfieldval(self, attr, val):
        if self.default_fields.has_key(attr):
            fld = self.get_field(attr)
            if fld is None:
                any2i = lambda x,y: y
            else:
                any2i = fld.any2i
            self.fields[attr] = any2i(self, val)
            self.explicit = 0
            self.raw_packet_cache = None
            self.raw_packet_cache_fields = None
        elif attr == "payload":
            self.remove_payload()
            self.add_payload(val)
        else:
            self.payload.setfieldval(attr,val)

    def __setattr__(self, attr, val):
        if attr in self.__all_slots__:
            return object.__setattr__(self, attr, val)
        try:
            return self.setfieldval(attr,val)
        except AttributeError:
            pass
        return object.__setattr__(self, attr, val)

    def delfieldval(self, attr):
        if self.fields.has_key(attr):
            del(self.fields[attr])
            self.explicit = 0 # in case a default value must be explicited
            self.raw_packet_cache = None
            self.raw_packet_cache_fields = None
        elif self.default_fields.has_key(attr):
            pass
        elif attr == "payload":
            self.remove_payload()
        else:
            self.payload.delfieldval(attr)

    def __delattr__(self, attr):
        if attr == "payload":
            return self.remove_payload()
        if attr in self.__all_slots__:
            return object.__delattr__(self, attr)
        try:
            return self.delfieldval(attr)
        except AttributeError:
            pass
        return object.__delattr__(self, attr)
            
    def __repr__(self):
        s = ""
        ct = conf.color_theme
        for f in self.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            if f.name in self.fields:
                val = f.i2repr(self, self.fields[f.name])
            elif f.name in self.overloaded_fields:
                val =  f.i2repr(self, self.overloaded_fields[f.name])
            else:
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value

                
            s += " %s%s%s" % (ncol(f.name),
                              ct.punct("="),
                              vcol(val))
        return "%s%s %s %s%s%s"% (ct.punct("<"),
                                  ct.layer_name(self.__class__.__name__),
                                  s,
                                  ct.punct("|"),
                                  repr(self.payload),
                                  ct.punct(">"))
    def __str__(self):
        return self.build()
    def __div__(self, other):
        if isinstance(other, Packet):
            cloneA = self.copy()
            cloneB = other.copy()
            cloneA.add_payload(cloneB)
            return cloneA
        elif type(other) is str:
            return self/conf.raw_layer(load=other)
        else:
            return other.__rdiv__(self)
    __truediv__ = __div__
    def __rdiv__(self, other):
        if type(other) is str:
            return conf.raw_layer(load=other)/self
        else:
            raise TypeError
    __rtruediv__ = __rdiv__
    def __mul__(self, other):
        if type(other) is int:
            return  [self]*other
        else:
            raise TypeError
    def __rmul__(self,other):
        return self.__mul__(other)
    
    def __nonzero__(self):
        return True
    def __len__(self):
        return len(self.__str__())
    def copy_field_value(self, fieldname, value):
        return self.get_field(fieldname).do_copy(value)
    def copy_fields_dict(self, fields):
        if fields is None:
            return None
        return {fname: self.copy_field_value(fname, fval)
                for fname, fval in fields.iteritems()}
    def self_build(self, field_pos_list=None):
        if self.raw_packet_cache is not None:
            for fname, fval in self.raw_packet_cache_fields.iteritems():
                if self.getfieldval(fname) != fval:
                    self.raw_packet_cache = None
                    self.raw_packet_cache_fields = None
                    break
            if self.raw_packet_cache is not None:
                return self.raw_packet_cache
        p=""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            if isinstance(val, RawVal):
                sval = str(val)
                p += sval
                if field_pos_list is not None:
                    field_pos_list.append( (f.name, sval.encode("string_escape"), len(p), len(sval) ) )
            else:
                p = f.addfield(self, p, val)
        return p

    def do_build_payload(self):
        return self.payload.do_build()

    def do_build(self):
        if not self.explicit:
            self = self.__iter__().next()
        pkt = self.self_build()
        for t in self.post_transforms:
            pkt = t(pkt)
        pay = self.do_build_payload()
        if self.raw_packet_cache is None:
            return self.post_build(pkt, pay)
        else:
            return pkt + pay
    
    def build_padding(self):
        return self.payload.build_padding()

    def build(self):
        p = self.do_build()
        p += self.build_padding()
        p = self.build_done(p)
        return p
    
    def post_build(self, pkt, pay):
        """DEV: called right after the current layer is build."""
        return pkt+pay

    def build_done(self, p):
        return self.payload.build_done(p)

    def do_build_ps(self):
        p=""
        pl = []
        q=""
        for f in self.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            p = f.addfield(self, p, self.getfieldval(f.name) )
            if type(p) is str:
                r = p[len(q):]
                q = p
            else:
                r = ""
            pl.append( (f, f.i2repr(self,self.getfieldval(f.name)), r) )
            
        pkt,lst = self.payload.build_ps(internal=1)
        p += pkt
        lst.append( (self, pl) )
        
        return p,lst
    
    def build_ps(self,internal=0):
        p,lst = self.do_build_ps()
#        if not internal:
#            pkt = self
#            while pkt.haslayer(conf.padding_layer):
#                pkt = pkt.getlayer(conf.padding_layer)
#                lst.append( (pkt, [ ("loakjkjd", pkt.load, pkt.load) ] ) )
#                p += pkt.load
#                pkt = pkt.payload
        return p,lst


    def psdump(self, filename=None, **kargs):
        """psdump(filename=None, layer_shift=0, rebuild=1)
Creates an EPS file describing a packet. If filename is not provided a temporary file is created and gs is called."""
        canvas = self.canvas_dump(**kargs)
        if filename is None:
            fname = get_temp_file(autoext=".eps")
            canvas.writeEPSfile(fname)
            subprocess.Popen([conf.prog.psreader, fname+".eps"])
        else:
            canvas.writeEPSfile(filename)

    def pdfdump(self, filename=None, **kargs):
        """pdfdump(filename=None, layer_shift=0, rebuild=1)
        Creates a PDF file describing a packet. If filename is not provided a temporary file is created and xpdf is called."""
        canvas = self.canvas_dump(**kargs)
        if filename is None:
            fname = get_temp_file(autoext=".pdf")
            canvas.writePDFfile(fname)
            subprocess.Popen([conf.prog.pdfreader, fname+".pdf"])
        else:
            canvas.writePDFfile(filename)

        
    def canvas_dump(self, layer_shift=0, rebuild=1):
        if PYX == 0:
            raise ImportError("PyX and its depedencies must be installed")
        canvas = pyx.canvas.canvas()
        if rebuild:
            p,t = self.__class__(str(self)).build_ps()
        else:
            p,t = self.build_ps()
        YTXT=len(t)
        for n,l in t:
            YTXT += len(l)
        YTXT = float(YTXT)
        YDUMP=YTXT

        XSTART = 1
        XDSTART = 10
        y = 0.0
        yd = 0.0
        xd = 0 
        XMUL= 0.55
        YMUL = 0.4
    
        backcolor=colgen(0.6, 0.8, 1.0, trans=pyx.color.rgb)
        forecolor=colgen(0.2, 0.5, 0.8, trans=pyx.color.rgb)
#        backcolor=makecol(0.376, 0.729, 0.525, 1.0)
        
        
        def hexstr(x):
            s = []
            for c in x:
                s.append("%02x" % ord(c))
            return " ".join(s)

                
        def make_dump_txt(x,y,txt):
            return pyx.text.text(XDSTART+x*XMUL, (YDUMP-y)*YMUL, r"\tt{%s}"%hexstr(txt), [pyx.text.size.Large])

        def make_box(o):
            return pyx.box.rect(o.left(), o.bottom(), o.width(), o.height(), relcenter=(0.5,0.5))

        def make_frame(lst):
            if len(lst) == 1:
                b = lst[0].bbox()
                b.enlarge(pyx.unit.u_pt)
                return b.path()
            else:
                fb = lst[0].bbox()
                fb.enlarge(pyx.unit.u_pt)
                lb = lst[-1].bbox()
                lb.enlarge(pyx.unit.u_pt)
                if len(lst) == 2 and fb.left() > lb.right():
                    return pyx.path.path(pyx.path.moveto(fb.right(), fb.top()),
                                         pyx.path.lineto(fb.left(), fb.top()),
                                         pyx.path.lineto(fb.left(), fb.bottom()),
                                         pyx.path.lineto(fb.right(), fb.bottom()),
                                         pyx.path.moveto(lb.left(), lb.top()),
                                         pyx.path.lineto(lb.right(), lb.top()),
                                         pyx.path.lineto(lb.right(), lb.bottom()),
                                         pyx.path.lineto(lb.left(), lb.bottom()))
                else:
                    # XXX
                    gb = lst[1].bbox()
                    if gb != lb:
                        gb.enlarge(pyx.unit.u_pt)
                    kb = lst[-2].bbox()
                    if kb != gb and kb != lb:
                        kb.enlarge(pyx.unit.u_pt)
                    return pyx.path.path(pyx.path.moveto(fb.left(), fb.top()),
                                         pyx.path.lineto(fb.right(), fb.top()),
                                         pyx.path.lineto(fb.right(), kb.bottom()),
                                         pyx.path.lineto(lb.right(), kb.bottom()),
                                         pyx.path.lineto(lb.right(), lb.bottom()),
                                         pyx.path.lineto(lb.left(), lb.bottom()),
                                         pyx.path.lineto(lb.left(), gb.top()),
                                         pyx.path.lineto(fb.left(), gb.top()),
                                         pyx.path.closepath(),)
                                         

        def make_dump(s, shift=0, y=0, col=None, bkcol=None, larg=16):
            c = pyx.canvas.canvas()
            tlist = []
            while s:
                dmp,s = s[:larg-shift],s[larg-shift:]
                txt = make_dump_txt(shift, y, dmp)
                tlist.append(txt)
                shift += len(dmp)
                if shift >= 16:
                    shift = 0
                    y += 1
            if col is None:
                col = pyx.color.rgb.red
            if bkcol is None:
                col = pyx.color.rgb.white
            c.stroke(make_frame(tlist),[col,pyx.deco.filled([bkcol]),pyx.style.linewidth.Thick])
            for txt in tlist:
                c.insert(txt)
            return c, tlist[-1].bbox(), shift, y
                            

        last_shift,last_y=0,0.0
        while t:
            bkcol = backcolor.next()
            proto,fields = t.pop()
            y += 0.5
            pt = pyx.text.text(XSTART, (YTXT-y)*YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % proto.name, [ pyx.text.size.Large])
            y += 1
            ptbb=pt.bbox()
            ptbb.enlarge(pyx.unit.u_pt*2)
            canvas.stroke(ptbb.path(),[pyx.color.rgb.black, pyx.deco.filled([bkcol])])
            canvas.insert(pt)
            for fname, fval, fdump in fields:
                col = forecolor.next()
                ft = pyx.text.text(XSTART, (YTXT-y)*YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % tex_escape(fname.name))
                if isinstance(fval, str):
                    if len(fval) > 18:
                        fval = fval[:18]+"[...]"
                else:
                    fval=""
                vt = pyx.text.text(XSTART+3, (YTXT-y)*YMUL, r"\font\cmssfont=cmss10\cmssfont{%s}" % tex_escape(fval))
                y += 1.0
                if fdump:
                    dt,target,last_shift,last_y = make_dump(fdump, last_shift, last_y, col, bkcol)

                    dtb = dt.bbox()
                    dtb=target
                    vtb = vt.bbox()
                    bxvt = make_box(vtb)
                    bxdt = make_box(dtb)
                    dtb.enlarge(pyx.unit.u_pt)
                    try:
                        if yd < 0:
                            cnx = pyx.connector.curve(bxvt,bxdt,absangle1=0, absangle2=-90)
                        else:
                            cnx = pyx.connector.curve(bxvt,bxdt,absangle1=0, absangle2=90)
                    except:
                        pass
                    else:
                        canvas.stroke(cnx,[pyx.style.linewidth.thin,pyx.deco.earrow.small,col])
                        
                    canvas.insert(dt)
                
                canvas.insert(ft)
                canvas.insert(vt)
            last_y += layer_shift
    
        return canvas



    def extract_padding(self, s):
        """DEV: to be overloaded to extract current layer's padding. Return a couple of strings (actual layer, padding)"""
        return s,None

    def post_dissect(self, s):
        """DEV: is called right after the current layer has been dissected"""
        return s

    def pre_dissect(self, s):
        """DEV: is called right before the current layer is dissected"""
        return s

    def do_dissect(self, s):
        raw = s
        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            if not s:
                break
            s, fval = f.getfield(self, s)
            # We need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
            if f.islist or f.holds_packets or f.ismutable:
                self.raw_packet_cache_fields[f.name] = f.do_copy(fval)
            self.fields[f.name] = fval
        assert(raw.endswith(s))
        self.raw_packet_cache = raw[:-len(s)] if s else raw
        self.explicit = 1
        return s

    def do_dissect_payload(self, s):
        if s:
            cls = self.guess_payload_class(s)
            try:
                p = cls(s, _internal=1, _underlayer=self)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    if isinstance(cls,type) and issubclass(cls,Packet):
                        log_runtime.error("%s dissector failed" % cls.name)
                    else:
                        log_runtime.error("%s.guess_payload_class() returned [%s]" % (self.__class__.__name__,repr(cls)))
                    if cls is not None:
                        raise
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)

    def dissect(self, s):
        s = self.pre_dissect(s)

        s = self.do_dissect(s)

        s = self.post_dissect(s)
            
        payl,pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(conf.padding_layer(pad))


    def guess_payload_class(self, payload):
        """DEV: Guesses the next payload class from layer bonds. Can be overloaded to use a different mechanism."""
        for t in self.aliastypes:
            for fval, cls in t.payload_guess:
                ok = 1
                for k, v in fval.iteritems():
                    if not hasattr(self, k) or v != self.getfieldval(k):
                        ok = 0
                        break
                if ok:
                    return cls
        return self.default_payload_class(payload)
    
    def default_payload_class(self, payload):
        """DEV: Returns the default payload class if nothing has been found by the guess_payload_class() method."""
        return conf.raw_layer

    def hide_defaults(self):
        """Removes fields' values that are the same as default values."""
        for k, v in self.fields.items():  # use .items(): self.fields is modified in the loop
            if k in self.default_fields:
                if self.default_fields[k] == v:
                    del self.fields[k]
        self.payload.hide_defaults()

    def clone_with(self, payload=None, **kargs):
        pkt = self.__class__()
        pkt.explicit = 1
        pkt.fields = kargs
        pkt.default_fields = self.copy_fields_dict(self.default_fields)
        pkt.overloaded_fields = self.overloaded_fields.copy()
        pkt.time = self.time
        pkt.underlayer = self.underlayer
        pkt.post_transforms = self.post_transforms
        pkt.raw_packet_cache = self.raw_packet_cache
        pkt.raw_packet_cache_fields = self.copy_fields_dict(
            self.raw_packet_cache_fields
        )
        if payload is not None:
            pkt.add_payload(payload)
        return pkt

    def __iter__(self):
        def loop(todo, done, self=self):
            if todo:
                eltname = todo.pop()
                elt = self.getfieldval(eltname)
                if not isinstance(elt, Gen):
                    if self.get_field(eltname).islist:
                        elt = SetGen([elt])
                    else:
                        elt = SetGen(elt)
                for e in elt:
                    done[eltname]=e
                    for x in loop(todo[:], done):
                        yield x
            else:
                if isinstance(self.payload,NoPayload):
                    payloads = [None]
                else:
                    payloads = self.payload
                for payl in payloads:
                    done2=done.copy()
                    for k in done2:
                        if isinstance(done2[k], VolatileValue):
                            done2[k] = done2[k]._fix()
                    pkt = self.clone_with(payload=payl, **done2)
                    yield pkt

        if self.explicit or self.raw_packet_cache is not None:
            todo = []
            done = self.fields
        else:
            todo = [k for (k,v) in itertools.chain(self.default_fields.iteritems(),
                                                   self.overloaded_fields.iteritems())
                    if isinstance(v, VolatileValue)] + self.fields.keys()
            done = {}
        return loop(todo, done)

    def __gt__(self, other):
        """True if other is an answer from self (self ==> other)."""
        if isinstance(other, Packet):
            return other < self
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))
    def __lt__(self, other):
        """True if self is an answer from other (other ==> self)."""
        if isinstance(other, Packet):
            return self.answers(other)
        elif type(other) is str:
            return 1
        else:
            raise TypeError((self, other))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        for f in self.fields_desc:
            if f not in other.fields_desc:
                return False
            if self.getfieldval(f.name) != other.getfieldval(f.name):
                return False
        return self.payload == other.payload

    def __ne__(self, other):
        return not self.__eq__(other)

    def hashret(self):
        """DEV: returns a string that has the same value for a request and its answer."""
        return self.payload.hashret()
    def answers(self, other):
        """DEV: true if self is an answer from other"""
        if other.__class__ == self.__class__:
            return self.payload.answers(other.payload)
        return 0

    def haslayer(self, cls):
        """true if self has a layer that is an instance of cls. Superseded by "cls in self" syntax."""
        if self.__class__ == cls or self.__class__.__name__ == cls:
            return 1
        for f in self.packetfields:
            fvalue_gen = self.getfieldval(f.name)
            if fvalue_gen is None:
                continue
            if not f.islist:
                fvalue_gen = SetGen(fvalue_gen,_iterpacket=0)
            for fvalue in fvalue_gen:
                if isinstance(fvalue, Packet):
                    ret = fvalue.haslayer(cls)
                    if ret:
                        return ret
        return self.payload.haslayer(cls)
    def getlayer(self, cls, nb=1, _track=None):
        """Return the nb^th layer that is an instance of cls."""
        if type(cls) is int:
            nb = cls+1
            cls = None
        if type(cls) is str and "." in cls:
            ccls,fld = cls.split(".",1)
        else:
            ccls,fld = cls,None
        if cls is None or self.__class__ == cls or self.__class__.__name__ == ccls:
            if nb == 1:
                if fld is None:
                    return self
                else:
                    return self.getfieldval(fld)
            else:
                nb -=1
        for f in self.packetfields:
            fvalue_gen = self.getfieldval(f.name)
            if fvalue_gen is None:
                continue
            if not f.islist:
                fvalue_gen = SetGen(fvalue_gen,_iterpacket=0)
            for fvalue in fvalue_gen:
                if isinstance(fvalue, Packet):
                    track=[]
                    ret = fvalue.getlayer(cls, nb, _track=track)
                    if ret is not None:
                        return ret
                    nb = track[0]
        return self.payload.getlayer(cls,nb,_track=_track)

    def firstlayer(self):
        q = self
        while q.underlayer is not None:
            q = q.underlayer
        return q

    def __getitem__(self, cls):
        if type(cls) is slice:
            lname = cls.start
            if cls.stop:
                ret = self.getlayer(cls.start, cls.stop)
            else:
                ret = self.getlayer(cls.start)
            if ret is None and cls.step is not None:
                ret = cls.step
        else:
            lname=cls
            ret = self.getlayer(cls)
        if ret is None:
            if type(lname) is Packet_metaclass:
                lname = lname.__name__
            elif type(lname) is not str:
                lname = repr(lname)
            raise IndexError("Layer [%s] not found" % lname)
        return ret

    def __delitem__(self, cls):
        del(self[cls].underlayer.payload)

    def __setitem__(self, cls, val):
        self[cls].underlayer.payload = val
    
    def __contains__(self, cls):
        """"cls in self" returns true if self has a layer which is an instance of cls."""
        return self.haslayer(cls)

    def route(self):
        return (None,None,None)

    def fragment(self, *args, **kargs):
        return self.payload.fragment(*args, **kargs)
    

    def display(self,*args,**kargs):  # Deprecated. Use show()
        """Deprecated. Use show() method."""
        self.show(*args,**kargs)
    
    def _show_or_dump(self, dump=False, indent=3, lvl="", label_lvl="", first_call=True):
        """
        Internal method that shows or dumps a hierarchical view of a packet.
        Called by show.
        """

        if dump:
            from scapy.themes import AnsiColorTheme
            ct = AnsiColorTheme() # No color for dump output
        else:
            ct = conf.color_theme
        s = "%s%s %s %s \n" % (label_lvl,
                              ct.punct("###["),
                              ct.layer_name(self.name),
                              ct.punct("]###"))
        for f in self.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value
            fvalue = self.getfieldval(f.name)
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and type(fvalue) is list):
                s += "%s  \\%-10s\\\n" % (label_lvl+lvl, ncol(f.name))
                fvalue_gen = SetGen(fvalue,_iterpacket=0)
                for fvalue in fvalue_gen:
                    s += fvalue._show_or_dump(dump=dump, indent=indent, label_lvl=label_lvl+lvl+"   |", first_call=False)
            else:
                begn = "%s  %-10s%s " % (label_lvl+lvl,
                                        ncol(f.name),
                                        ct.punct("="),)
                reprval = f.i2repr(self,fvalue)
                if type(reprval) is str:
                    reprval = reprval.replace("\n", "\n"+" "*(len(label_lvl)
                                                              +len(lvl)
                                                              +len(f.name)
                                                              +4))
                s += "%s%s\n" % (begn,vcol(reprval))
        if self.payload:
            s += self.payload._show_or_dump(dump=dump, indent=indent, lvl=lvl+(" "*indent*self.show_indent), label_lvl=label_lvl, first_call=False)

        if first_call and not dump:
            print s
        else:
            return s

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """Prints or returns (when "dump" is true) a hierarchical view of the packet. "indent" gives the size of indentation for each layer."""
	return self._show_or_dump(dump, indent, lvl, label_lvl)

    def show2(self, dump=False, indent=3, lvl="", label_lvl=""):
        """Prints or returns (when "dump" is true) a hierarchical view of an assembled version of the packet, so that automatic fields are calculated (checksums, etc.)"""
        return self.__class__(str(self)).show(dump, indent, lvl, label_lvl)

    def sprintf(self, fmt, relax=1):
        """sprintf(format, [relax=1]) -> str
where format is a string that can include directives. A directive begins and
ends by % and has the following format %[fmt[r],][cls[:nb].]field%.

fmt is a classic printf directive, "r" can be appended for raw substitution
(ex: IP.flags=0x18 instead of SA), nb is the number of the layer we want
(ex: for IP/IP packets, IP:2.src is the src of the upper IP layer).
Special case : "%.time%" is the creation time.
Ex : p.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% "
               "%03xr,IP.proto% %r,TCP.flags%")

Moreover, the format string can include conditional statements. A conditional
statement looks like : {layer:string} where layer is a layer name, and string
is the string to insert in place of the condition if it is true, i.e. if layer
is present. If layer is preceded by a "!", the result is inverted. Conditions
can be imbricated. A valid statement can be :
  p.sprintf("This is a{TCP: TCP}{UDP: UDP}{ICMP:n ICMP} packet")
  p.sprintf("{IP:%IP.dst% {ICMP:%ICMP.type%}{TCP:%TCP.dport%}}")

A side effect is that, to obtain "{" and "}" characters, you must use
"%(" and "%)".
"""

        escape = { "%": "%",
                   "(": "{",
                   ")": "}" }


        # Evaluate conditions 
        while "{" in fmt:
            i = fmt.rindex("{")
            j = fmt[i+1:].index("}")
            cond = fmt[i+1:i+j+1]
            k = cond.find(":")
            if k < 0:
                raise Scapy_Exception("Bad condition in format string: [%s] (read sprintf doc!)"%cond)
            cond,format = cond[:k],cond[k+1:]
            res = False
            if cond[0] == "!":
                res = True
                cond = cond[1:]
            if self.haslayer(cond):
                res = not res
            if not res:
                format = ""
            fmt = fmt[:i]+format+fmt[i+j+2:]

        # Evaluate directives
        s = ""
        while "%" in fmt:
            i = fmt.index("%")
            s += fmt[:i]
            fmt = fmt[i+1:]
            if fmt and fmt[0] in escape:
                s += escape[fmt[0]]
                fmt = fmt[1:]
                continue
            try:
                i = fmt.index("%")
                sfclsfld = fmt[:i]
                fclsfld = sfclsfld.split(",")
                if len(fclsfld) == 1:
                    f = "s"
                    clsfld = fclsfld[0]
                elif len(fclsfld) == 2:
                    f,clsfld = fclsfld
                else:
                    raise Scapy_Exception
                if "." in clsfld:
                    cls,fld = clsfld.split(".")
                else:
                    cls = self.__class__.__name__
                    fld = clsfld
                num = 1
                if ":" in cls:
                    cls,num = cls.split(":")
                    num = int(num)
                fmt = fmt[i+1:]
            except:
                raise Scapy_Exception("Bad format string [%%%s%s]" % (fmt[:25], fmt[25:] and "..."))
            else:
                if fld == "time":
                    val = time.strftime("%H:%M:%S.%%06i", time.localtime(self.time)) % int((self.time-int(self.time))*1000000)
                elif cls == self.__class__.__name__ and hasattr(self, fld):
                    if num > 1:
                        val = self.payload.sprintf("%%%s,%s:%s.%s%%" % (f,cls,num-1,fld), relax)
                        f = "s"
                    elif f[-1] == "r":  # Raw field value
                        val = getattr(self,fld)
                        f = f[:-1]
                        if not f:
                            f = "s"
                    else:
                        val = getattr(self,fld)
                        if fld in self.fieldtype:
                            val = self.fieldtype[fld].i2repr(self,val)
                else:
                    val = self.payload.sprintf("%%%s%%" % sfclsfld, relax)
                    f = "s"
                s += ("%"+f) % val
            
        s += fmt
        return s

    def mysummary(self):
        """DEV: can be overloaded to return a string that summarizes the layer.
           Only one mysummary() is used in a whole packet summary: the one of the upper layer,
           except if a mysummary() also returns (as a couple) a list of layers whose
           mysummary() must be called if they are present."""
        return ""

    def _do_summary(self):
        found, s, needed = self.payload._do_summary()
        ret = ""
        if not found or self.__class__ in needed:
            ret = self.mysummary()
            if type(ret) is tuple:
                ret,n = ret
                needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = self.__class__.__name__ if self.show_summary else ""
        if self.__class__ in conf.emph:
            impf = []
            for f in self.fields_desc:
                if f in conf.emph:
                    impf.append("%s=%s" % (f.name, f.i2repr(self, self.getfieldval(f.name))))
            ret = "%s [%s]" % (ret," ".join(impf))
        if ret and s:
            ret = "%s / %s" % (ret, s)
        else:
            ret = "%s%s" % (ret,s)
        return found,ret,needed

    def summary(self, intern=0):
        """Prints a one line summary of a packet."""
        found,s,needed = self._do_summary()
        return s

    
    def lastlayer(self,layer=None):
        """Returns the uppest layer of the packet"""
        return self.payload.lastlayer(self)

    def decode_payload_as(self,cls):
        """Reassembles the payload and decode it using another packet class"""
        s = str(self.payload)
        self.payload = cls(s, _internal=1, _underlayer=self)
        pp = self
        while pp.underlayer is not None:
            pp = pp.underlayer
        self.payload.dissection_done(pp)

    def libnet(self):
        """Not ready yet. Should give the necessary C code that interfaces with libnet to recreate the packet"""
        print "libnet_build_%s(" % self.__class__.name.lower()
        det = self.__class__(str(self))
        for f in self.fields_desc:
            val = det.getfieldval(f.name)
            if val is None:
                val = 0
            elif type(val) is int:
                val = str(val)
            else:
                val = '"%s"' % str(val)
            print "\t%s, \t\t/* %s */" % (val,f.name)
        print ");"
    def command(self):
        """Returns a string representing the command you have to type to obtain the same packet"""
        f = []
        for fn,fv in self.fields.items():
            fld = self.get_field(fn)
            if isinstance(fv, Packet):
                fv = fv.command()
            elif fld.islist and fld.holds_packets and type(fv) is list:
                fv = "[%s]" % ",".join( map(Packet.command, fv))
            else:
                fv = repr(fv)
            f.append("%s=%s" % (fn, fv))
        c = "%s(%s)" % (self.__class__.__name__, ", ".join(f))
        pc = self.payload.command()
        if pc:
            c += "/"+pc
        return c                    

class NoPayload(Packet):
    def __new__(cls, *args, **kargs):
        singl = cls.__dict__.get("__singl__")
        if singl is None:
            cls.__singl__ = singl = Packet.__new__(cls)
            Packet.__init__(singl)
        return singl
    def __init__(self, *args, **kargs):
        pass
    def dissection_done(self,pkt):
        return
    def add_payload(self, payload):
        raise Scapy_Exception("Can't add payload to NoPayload instance")
    def remove_payload(self):
        pass
    def add_underlayer(self,underlayer):
        pass
    def remove_underlayer(self,other):
        pass
    def copy(self):
        return self
    def __repr__(self):
        return ""
    def __str__(self):
        return ""
    def __nonzero__(self):
        return False
    def do_build(self):
        return ""
    def build(self):
        return ""
    def build_padding(self):
        return ""
    def build_done(self, p):
        return p
    def build_ps(self, internal=0):
        return "",[]
    def getfieldval(self, attr):
        raise AttributeError(attr)
    def getfield_and_val(self, attr):
        raise AttributeError(attr)
    def setfieldval(self, attr, val):
        raise AttributeError(attr)
    def delfieldval(self, attr):
        raise AttributeError(attr)
    def hide_defaults(self):
        pass
    def __iter__(self):
        return iter([])
    def __eq__(self, other):
        if isinstance(other, NoPayload):
            return True
        return False
    def hashret(self):
        return ""
    def answers(self, other):
        return isinstance(other, NoPayload) or isinstance(other, conf.padding_layer)
    def haslayer(self, cls):
        return 0
    def getlayer(self, cls, nb=1, _track=None):
        if _track is not None:
            _track.append(nb)
        return None
    def fragment(self, *args, **kargs):
        raise Scapy_Exception("cannot fragment this packet")        
    def show(self, indent=3, lvl="", label_lvl=""):
        pass
    def sprintf(self, fmt, relax):
        if relax:
            return "??"
        else:
            raise Scapy_Exception("Format not found [%s]"%fmt)
    def _do_summary(self):
        return 0,"",[]
    def lastlayer(self,layer):
        return layer
    def command(self):
        return ""
    
####################
## packet classes ##
####################

            
class Raw(Packet):
    name = "Raw"
    fields_desc = [ StrField("load", "") ]
    def answers(self, other):
        return 1
#        s = str(other)
#        t = self.load
#        l = min(len(s), len(t))
#        return  s[:l] == t[:l]
    def mysummary(self):
        cs = conf.raw_summary
        if cs:
            if callable(cs):
                return "Raw %s" % cs(self.load)
            else:
                return "Raw %r" % self.load
        return Packet.mysummary(self)
        
class Padding(Raw):
    name = "Padding"
    def self_build(self):
        return ""
    def build_padding(self):
        return (self.load if self.raw_packet_cache is None
                else self.raw_packet_cache) + self.payload.build_padding()

conf.raw_layer = Raw
conf.padding_layer = Padding
if conf.default_l2 is None:
    conf.default_l2 = Raw

#################
## Bind layers ##
#################


def bind_bottom_up(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    lower.payload_guess = lower.payload_guess[:]
    lower.payload_guess.append((fval, upper))
    

def bind_top_down(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    upper._overload_fields = upper._overload_fields.copy()
    upper._overload_fields[lower] = fval
    
@conf.commands.register
def bind_layers(lower, upper, __fval=None, **fval):
    """Bind 2 layers on some specific fields' values"""
    if __fval is not None:
        fval.update(__fval)
    bind_top_down(lower, upper, **fval)
    bind_bottom_up(lower, upper, **fval)

def split_bottom_up(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    def do_filter((f,u),upper=upper,fval=fval):
        if u != upper:
            return True
        for k in fval:
            if k not in f or f[k] != fval[k]:
                return True
        return False
    lower.payload_guess = filter(do_filter, lower.payload_guess)
        
def split_top_down(lower, upper, __fval=None, **fval):
    if __fval is not None:
        fval.update(__fval)
    if lower in upper._overload_fields:
        ofval = upper._overload_fields[lower]
        for k in fval:
            if k not in ofval or ofval[k] != fval[k]:
                return
        upper._overload_fields = upper._overload_fields.copy()
        del(upper._overload_fields[lower])

@conf.commands.register
def split_layers(lower, upper, __fval=None, **fval):
    """Split 2 layers previously bound"""
    if __fval is not None:
        fval.update(__fval)
    split_bottom_up(lower, upper, **fval)
    split_top_down(lower, upper, **fval)


@conf.commands.register
def ls(obj=None, case_sensitive=False, verbose=False):
    """List  available layers, or infos on a given layer class or name"""
    is_string = isinstance(obj, basestring)

    if obj is None or is_string:
        if obj is None:
            all_layers = sorted(conf.layers, key=lambda x: x.__name__)
        else:
            pattern = re.compile(obj, 0 if case_sensitive else re.I)
            all_layers = sorted((layer for layer in conf.layers
                                if (pattern.search(layer.__name__ or '')
                                    or pattern.search(layer.name or ''))),
                                key=lambda x: x.__name__)
        for layer in all_layers:
            print "%-10s : %s" % (layer.__name__, layer._name)

    else:
        is_pkt = isinstance(obj, Packet)
        if (isinstance(obj, type) and issubclass(obj, Packet)) or is_pkt:
            for f in obj.fields_desc:
                cur_fld = f
                attrs = []
                long_attrs = []
                while isinstance(cur_fld, (Emph, ConditionalField)):
                    if isinstance(cur_fld, ConditionalField):
                        attrs.append(cur_fld.__class__.__name__[:4])
                    cur_fld = cur_fld.fld
                if verbose and isinstance(cur_fld, EnumField) \
                   and hasattr(cur_fld, "i2s"):
                    if len(cur_fld.i2s) < 50:
                        long_attrs.extend(
                            "%s: %d" % (strval, numval)
                            for numval, strval in
                            sorted(cur_fld.i2s.iteritems())
                        )
                elif isinstance(cur_fld, MultiEnumField):
                    fld_depend = cur_fld.depends_on(obj.__class__
                                                    if is_pkt else obj)
                    attrs.append("Depends on %s" % fld_depend.name)
                    if verbose:
                        cur_i2s = cur_fld.i2s_multi.get(
                            cur_fld.depends_on(obj if is_pkt else obj()), {}
                        )
                        if len(cur_i2s) < 50:
                            long_attrs.extend(
                                "%s: %d" % (strval, numval)
                                for numval, strval in
                                sorted(cur_i2s.iteritems())
                            )
                elif verbose and isinstance(cur_fld, FlagsField):
                    names = cur_fld.names
                    long_attrs.append(", ".join(names))
                class_name = "%s (%s)" % (
                    cur_fld.__class__.__name__,
                    ", ".join(attrs)) if attrs else cur_fld.__class__.__name__
                if isinstance(cur_fld, BitField):
                    class_name += " (%d bit%s)" % (cur_fld.size,
                                                   "s" if cur_fld.size > 1
                                                   else "")
                print "%-10s : %-35s =" % (f.name, class_name),
                if is_pkt:
                    print "%-15r" % (getattr(obj, f.name),),
                print "(%r)" % (f.default,)
                for attr in long_attrs:
                    print "%-15s%s" % ("", attr)
            if is_pkt and not isinstance(obj.payload, NoPayload):
                print "--"
                ls(obj.payload)

        else:
            print "Not a packet class or name. Type 'ls()' to list packet classes."


    
#############
## Fuzzing ##
#############

@conf.commands.register
def fuzz(p, _inplace=0):
    """Transform a layer into a fuzzy layer by replacing some default values by random objects"""
    if not _inplace:
        p = p.copy()
    q = p
    while not isinstance(q, NoPayload):
        for f in q.fields_desc:
            if isinstance(f, PacketListField):
                for r in getattr(q, f.name):
                    print "fuzzing", repr(r)
                    fuzz(r, _inplace=1)
            elif f.default is not None:
                rnd = f.randval()
                if rnd is not None:
                    q.default_fields[f.name] = rnd
        q = q.payload
    return p



