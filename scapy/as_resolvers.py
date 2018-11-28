# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Resolve Autonomous Systems (AS).
"""


from __future__ import absolute_import
import socket
import errno
from scapy.config import conf
from scapy.compat import plain_str


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
        self.s.connect((self.server, self.port))
        if self.options:
            self.s.send(self.options.encode("utf8") + b"\n")
            self.s.recv(8192)

    def _stop(self):
        self.s.close()

    def _parse_whois(self, txt):
        asn, desc = None, b""
        for line in txt.splitlines():
            if not asn and line.startswith(b"origin:"):
                asn = plain_str(line[7:].strip())
            if line.startswith(b"descr:"):
                if desc:
                    desc += r"\n"
                desc += line[6:].strip()
            if asn is not None and desc:
                break
        return asn, plain_str(desc.strip())

    def _resolve_one(self, ip):
        self.s.send(("%s\n" % ip).encode("utf8"))
        x = b""
        while not (b"%" in x or b"source" in x):
            x += self.s.recv(8192)
        asn, desc = self._parse_whois(x)
        return ip, asn, desc

    def resolve(self, *ips):
        self._start()
        ret = []
        for ip in ips:
            ip, asn, desc = self._resolve_one(ip)
            if asn is not None:
                ret.append((ip, asn, desc))
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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server, self.port))
        s.send(b"begin\r\n" + b"\r\n".join(ip.encode("utf8") for ip in ips) + b"\r\nend\r\n")  # noqa: E501
        r = b""
        while True:
            line = s.recv(8192)
            if line == b"":
                break
            r += line
        s.close()

        return self.parse(r)

    def parse(self, data):
        """Parse bulk cymru data"""

        ASNlist = []
        for line in data.splitlines()[1:]:
            line = plain_str(line)
            if "|" not in line:
                continue
            asn, ip, desc = [elt.strip() for elt in line.split('|')]
            if asn == "NA":
                continue
            asn = "AS%s" % asn
            ASNlist.append((ip, asn, desc))
        return ASNlist


class AS_resolver_multi(AS_resolver):
    resolvers_list = (AS_resolver_riswhois(), AS_resolver_radb(), AS_resolver_cymru())  # noqa: E501

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
                if e.errno in [errno.ECONNREFUSED, errno.ETIMEDOUT,
                   errno.ECONNRESET]:
                    continue
            resolved = [ip for ip, asn, desc in res]
            todo = [ip for ip in todo if ip not in resolved]
            ret += res
            if len(todo) == 0:
                break
        if len(ips) != len(ret):
            raise RuntimeError("Could not contact whois providers")
        return ret


conf.AS_resolver = AS_resolver_multi()
