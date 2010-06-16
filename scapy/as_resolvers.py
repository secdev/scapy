## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Resolve Autonomous Systems (AS).
"""


import socket
from config import conf

class AS_resolver:
    server = None
    options = "-k" 
    def __init__(self, server=None, port=43, options=None):
        if server is not None:
            self.server = server
        self.port = port
        if options is not None:
            self.options = options
        
    def _start(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server,self.port))
        if self.options:
            self.s.send(self.options+"\n")
            self.s.recv(8192)
    def _stop(self):
        self.s.close()
        
    def _parse_whois(self, txt):
        asn,desc = None,""
        for l in txt.splitlines():
            if not asn and l.startswith("origin:"):
                asn = l[7:].strip()
            if l.startswith("descr:"):
                if desc:
                    desc += r"\n"
                desc += l[6:].strip()
            if asn is not None and desc:
                break
        return asn,desc.strip()

    def _resolve_one(self, ip):
        self.s.send("%s\n" % ip)
        x = ""
        while not ("%" in x  or "source" in x):
            x += self.s.recv(8192)
        asn, desc = self._parse_whois(x)
        return ip,asn,desc
    def resolve(self, *ips):
        self._start()
        ret = []
        for ip in ips:
            ip,asn,desc = self._resolve_one(ip)
            if asn is not None:
                ret.append((ip,asn,desc))
        self._stop()
        return ret

class AS_resolver_riswhois(AS_resolver):
    server = "riswhois.ripe.net"
    options = "-k -M -1"


class AS_resolver_radb(AS_resolver):
    server = "whois.ra.net"
    options = "-k -M"
    

class AS_resolver_cymru(AS_resolver):
    server = "whois.cymru.com"
    options = None
    def resolve(self, *ips):
        ASNlist = []
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server,self.port))
        s.send("begin\r\n"+"\r\n".join(ips)+"\r\nend\r\n")
        r = ""
        while 1:
            l = s.recv(8192)
            if l == "":
                break
            r += l
        s.close()
        for l in r.splitlines()[1:]:
            if "|" not in l:
                continue
            asn,ip,desc = map(str.strip, l.split("|"))
            if asn == "NA":
                continue
            asn = int(asn)
            ASNlist.append((ip,asn,desc))
        return ASNlist

class AS_resolver_multi(AS_resolver):
    resolvers_list = ( AS_resolver_cymru(),AS_resolver_riswhois(),AS_resolver_radb() )
    def __init__(self, *reslist):
        if reslist:
            self.resolvers_list = reslist
    def resolve(self, *ips):
        todo = ips
        ret = []
        for ASres in self.resolvers_list:
            res = ASres.resolve(*todo)
            resolved = [ ip for ip,asn,desc in res ]
            todo = [ ip for ip in todo if ip not in resolved ]
            ret += res
        return ret


conf.AS_resolver = AS_resolver_multi()
