## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Resolve Autonomous Systems (AS).
"""


from __future__ import absolute_import
import socket, errno
from scapy.config import conf
from six.moves import map
from scapy.data import str_bytes

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
            self.s.send(str_bytes(self.options+"\n"))
            self.s.recv(8192)
    def _stop(self):
        self.s.close()
        
    def _parse_whois(self, txt):
        asn,desc = None, b""
        for l in txt.splitlines():
            if not asn and l.startswith(b"origin:"):
                asn = l[7:].strip().decode("utf8")
            if l.startswith(b"descr:"):
                if desc:
                    desc += r"\n"
                desc += l[6:].strip().decode("utf8")
            if asn is not None and desc:
                break
        return asn,desc.strip()

    def _resolve_one(self, ip):
        self.s.send(str_bytes("%s\n" % ip))
        x = b""
        while not (b"%" in x or b"source" in x):
            x += self.s.recv(8192)
        asn, desc = self._parse_whois(x)
        return ip,asn,desc
    def resolve(self, *ips):
        self._start()
        ret = []
        for ip in ips:
            ip,asn,desc = self._resolve_one(str_bytes(ip))
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
        s.send(b"begin\r\n"+b"\r\n".join([str_bytes(x) for x in ips])+b"\r\nend\r\n")
        r = b""
        while 1:
            l = s.recv(8192)
            if l == b"":
                break
            r += l
        s.close()
        for l in r.splitlines()[1:]:
            if b"|" not in l:
                continue
            asn,ip,desc = [ str_bytes(i) for i in map(bytes.strip, l.split(b"|")) ]
            if asn == b"NA":
                continue
            asn = b"AS" + asn
            ASNlist.append((ip, asn, desc))
        return ASNlist

class AS_resolver_multi(AS_resolver):
    resolvers_list = ( AS_resolver_riswhois(),AS_resolver_radb(),AS_resolver_cymru() )
    def __init__(self, *reslist):
        if reslist:
            self.resolvers_list = reslist
    def resolve(self, *ips):
        todo = ips
        ret = []
        for ASres in self.resolvers_list:
            try:
                res = ASres.resolve(*todo)
            except socket.error as e:
                if e[0] in [errno.ECONNREFUSED, errno.ETIMEDOUT, errno.ECONNRESET]:
                    continue
            resolved = [ ip for ip,asn,desc in res ]
            todo = [ ip for ip in todo if ip not in resolved ]
            ret += res
            if len(todo) == 0:
                break
        if len(ips) != len(ret):
            raise RuntimeError("Could not contact whois providers")
        return ret


conf.AS_resolver = AS_resolver_multi()
