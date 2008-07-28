## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

########################
## Answering machines ##
########################

from sendrecv import send,sendp,sniff
from config import conf
from error import log_interactive

class ReferenceAM(type):
    def __new__(cls, name, bases, dct):
        o = super(ReferenceAM, cls).__new__(cls, name, bases, dct)
        if o.function_name:
            globals()[o.function_name] = lambda o=o,*args,**kargs: o(*args,**kargs)()
        return o


class AnsweringMachine(object):
    __metaclass__ = ReferenceAM
    function_name = ""
    filter = None
    sniff_options = { "store":0 }
    sniff_options_list = [ "store", "iface", "count", "promisc", "filter", "type", "prn" ]
    send_options = { "verbose":0 }
    send_options_list = ["iface", "inter", "loop", "verbose"]
    send_function = staticmethod(send)
    
    
    def __init__(self, **kargs):
        self.mode = 0
        if self.filter:
            kargs.setdefault("filter",self.filter)
        kargs.setdefault("prn", self.reply)
        self.optam1 = {}
        self.optam2 = {}
        self.optam0 = {}
        doptsend,doptsniff = self.parse_all_options(1, kargs)
        self.defoptsend = self.send_options.copy()
        self.defoptsend.update(doptsend)
        self.defoptsniff = self.sniff_options.copy()
        self.defoptsniff.update(doptsniff)
        self.optsend,self.optsniff = [{},{}]

    def __getattr__(self, attr):
        for d in [self.optam2, self.optam1]:
            if attr in d:
                return d[attr]
        raise AttributeError,attr
                
    def __setattr__(self, attr, val):
        mode = self.__dict__.get("mode",0)
        if mode == 0:
            self.__dict__[attr] = val
        else:
            [self.optam1, self.optam2][mode-1][attr] = val

    def parse_options(self):
        pass

    def parse_all_options(self, mode, kargs):
        sniffopt = {}
        sendopt = {}
        for k in kargs.keys():            
            if k in self.sniff_options_list:
                sniffopt[k] = kargs[k]
            if k in self.send_options_list:
                sendopt[k] = kargs[k]
            if k in self.sniff_options_list+self.send_options_list:
                del(kargs[k])
        if mode != 2 or kargs:
            if mode == 1:
                self.optam0 = kargs
            elif mode == 2 and kargs:
                k = self.optam0.copy()
                k.update(kargs)
                self.parse_options(**k)
                kargs = k 
            omode = self.__dict__.get("mode",0)
            self.__dict__["mode"] = mode
            self.parse_options(**kargs)
            self.__dict__["mode"] = omode
        return sendopt,sniffopt

    def is_request(self, req):
        return 1

    def make_reply(self, req):
        return req

    def send_reply(self, reply):
        self.send_function(reply, **self.optsend)

    def print_reply(self, req, reply):
        print "%s ==> %s" % (req.summary(),reply.summary())

    def reply(self, pkt):
        if not self.is_request(pkt):
            return
        reply = self.make_reply(pkt)
        self.send_reply(reply)
        if conf.verb >= 0:
            self.print_reply(pkt, reply)

    def run(self, *args, **kargs):
        log_interactive.warning("run() method deprecated. The intance is now callable")
        self(*args,**kargs)

    def __call__(self, *args, **kargs):
        optsend,optsniff = self.parse_all_options(2,kargs)
        self.optsend=self.defoptsend.copy()
        self.optsend.update(optsend)
        self.optsniff=self.defoptsniff.copy()
        self.optsniff.update(optsniff)

        try:
            self.sniff()
        except KeyboardInterrupt:
            print "Interrupted by user"
        
    def sniff(self):
        sniff(**self.optsniff)

