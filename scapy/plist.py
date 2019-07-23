# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
PacketList: holds several packets and allows to do operations on them.
"""


from __future__ import absolute_import
from __future__ import print_function
import os
from collections import defaultdict

from scapy.compat import lambda_tuple_converter
from scapy.config import conf
from scapy.base_classes import BasePacket, BasePacketList, _CanvasDumpExtended
from scapy.utils import do_graph, hexdump, make_table, make_lined_table, \
    make_tex_table, issubtype
from scapy.extlib import plt, MATPLOTLIB_INLINED, MATPLOTLIB_DEFAULT_PLOT_KARGS
from functools import reduce
import scapy.modules.six as six
from scapy.modules.six.moves import range, zip

#############
#  Results  #
#############


class PacketList(BasePacketList, _CanvasDumpExtended):
    __slots__ = ["stats", "res", "listname"]

    def __init__(self, res=None, name="PacketList", stats=None):
        """create a packet list from a list of packets
           res: the list of packets
           stats: a list of classes that will appear in the stats (defaults to [TCP,UDP,ICMP])"""  # noqa: E501
        if stats is None:
            stats = conf.stats_classic_protocols
        self.stats = stats
        if res is None:
            res = []
        elif isinstance(res, PacketList):
            res = res.res
        self.res = res
        self.listname = name

    def __len__(self):
        return len(self.res)

    def _elt2pkt(self, elt):
        return elt

    def _elt2sum(self, elt):
        return elt.summary()

    def _elt2show(self, elt):
        return self._elt2sum(elt)

    def __repr__(self):
        stats = {x: 0 for x in self.stats}
        other = 0
        for r in self.res:
            f = 0
            for p in stats:
                if self._elt2pkt(r).haslayer(p):
                    stats[p] += 1
                    f = 1
                    break
            if not f:
                other += 1
        s = ""
        ct = conf.color_theme
        for p in self.stats:
            s += " %s%s%s" % (ct.packetlist_proto(p._name),
                              ct.punct(":"),
                              ct.packetlist_value(stats[p]))
        s += " %s%s%s" % (ct.packetlist_proto("Other"),
                          ct.punct(":"),
                          ct.packetlist_value(other))
        return "%s%s%s%s%s" % (ct.punct("<"),
                               ct.packetlist_name(self.listname),
                               ct.punct(":"),
                               s,
                               ct.punct(">"))

    def __getstate__(self):
        """
        create a basic representation of the instance, used in conjunction with __setstate__() e.g. by pickle  # noqa: E501
        :return: dict representing this instance
        """
        state = {
            'res': self.res,
            'stats': self.stats,
            'listname': self.listname
        }
        return state

    def __setstate__(self, state):
        """
        set instance attributes to values given by state, used in conjunction with __getstate__() e.g. by pickle  # noqa: E501
        :param state: dict representing this instance
        """
        self.res = state['res']
        self.stats = state['stats']
        self.listname = state['listname']

    def __getattr__(self, attr):
        return getattr(self.res, attr)

    def __getitem__(self, item):
        if issubtype(item, BasePacket):
            return self.__class__([x for x in self.res if item in self._elt2pkt(x)],  # noqa: E501
                                  name="%s from %s" % (item.__name__, self.listname))  # noqa: E501
        if isinstance(item, slice):
            return self.__class__(self.res.__getitem__(item),
                                  name="mod %s" % self.listname)
        return self.res.__getitem__(item)

    def __getslice__(self, *args, **kargs):
        return self.__class__(self.res.__getslice__(*args, **kargs),
                              name="mod %s" % self.listname)

    def __add__(self, other):
        return self.__class__(self.res + other.res,
                              name="%s+%s" % (self.listname, other.listname))

    def summary(self, prn=None, lfilter=None):
        """prints a summary of each packet
prn:     function to apply to each packet instead of lambda x:x.summary()
lfilter: truth function to apply to each packet to decide whether it will be displayed"""  # noqa: E501
        for r in self.res:
            if lfilter is not None:
                if not lfilter(r):
                    continue
            if prn is None:
                print(self._elt2sum(r))
            else:
                print(prn(r))

    def nsummary(self, prn=None, lfilter=None):
        """prints a summary of each packet with the packet's number
prn:     function to apply to each packet instead of lambda x:x.summary()
lfilter: truth function to apply to each packet to decide whether it will be displayed"""  # noqa: E501
        for i, res in enumerate(self.res):
            if lfilter is not None:
                if not lfilter(res):
                    continue
            print(conf.color_theme.id(i, fmt="%04i"), end=' ')
            if prn is None:
                print(self._elt2sum(res))
            else:
                print(prn(res))

    def display(self):  # Deprecated. Use show()
        """deprecated. is show()"""
        self.show()

    def show(self, *args, **kargs):
        """Best way to display the packet list. Defaults to nsummary() method"""  # noqa: E501
        return self.nsummary(*args, **kargs)

    def filter(self, func):
        """Returns a packet list filtered by a truth function. This truth
        function has to take a packet as the only argument and return a boolean value."""  # noqa: E501
        return self.__class__([x for x in self.res if func(x)],
                              name="filtered %s" % self.listname)

    def make_table(self, *args, **kargs):
        """Prints a table using a function that returns for each packet its head column value, head row value and displayed value  # noqa: E501
        ex: p.make_table(lambda x:(x[IP].dst, x[TCP].dport, x[TCP].sprintf("%flags%")) """  # noqa: E501
        return make_table(self.res, *args, **kargs)

    def make_lined_table(self, *args, **kargs):
        """Same as make_table, but print a table with lines"""
        return make_lined_table(self.res, *args, **kargs)

    def make_tex_table(self, *args, **kargs):
        """Same as make_table, but print a table with LaTeX syntax"""
        return make_tex_table(self.res, *args, **kargs)

    def plot(self, f, lfilter=None, plot_xy=False, **kargs):
        """Applies a function to each packet to get a value that will be plotted
        with matplotlib. A list of matplotlib.lines.Line2D is returned.

        lfilter: a truth function that decides whether a packet must be plotted
        """

        # Python 2 backward compatibility
        f = lambda_tuple_converter(f)
        lfilter = lambda_tuple_converter(lfilter)

        # Get the list of packets
        if lfilter is None:
            lst_pkts = [f(*e) for e in self.res]
        else:
            lst_pkts = [f(*e) for e in self.res if lfilter(*e)]

        # Mimic the default gnuplot output
        if kargs == {}:
            kargs = MATPLOTLIB_DEFAULT_PLOT_KARGS
        if plot_xy:
            lines = plt.plot(*zip(*lst_pkts), **kargs)
        else:
            lines = plt.plot(lst_pkts, **kargs)

        # Call show() if matplotlib is not inlined
        if not MATPLOTLIB_INLINED:
            plt.show()

        return lines

    def diffplot(self, f, delay=1, lfilter=None, **kargs):
        """diffplot(f, delay=1, lfilter=None)
        Applies a function to couples (l[i],l[i+delay])

        A list of matplotlib.lines.Line2D is returned.
        """

        # Get the list of packets
        if lfilter is None:
            lst_pkts = [f(self.res[i], self.res[i + 1])
                        for i in range(len(self.res) - delay)]
        else:
            lst_pkts = [f(self.res[i], self.res[i + 1])
                        for i in range(len(self.res) - delay)
                        if lfilter(self.res[i])]

        # Mimic the default gnuplot output
        if kargs == {}:
            kargs = MATPLOTLIB_DEFAULT_PLOT_KARGS
        lines = plt.plot(lst_pkts, **kargs)

        # Call show() if matplotlib is not inlined
        if not MATPLOTLIB_INLINED:
            plt.show()

        return lines

    def multiplot(self, f, lfilter=None, plot_xy=False, **kargs):
        """Uses a function that returns a label and a value for this label, then
        plots all the values label by label.

        A list of matplotlib.lines.Line2D is returned.
        """

        # Python 2 backward compatibility
        f = lambda_tuple_converter(f)
        lfilter = lambda_tuple_converter(lfilter)

        # Get the list of packets
        if lfilter is None:
            lst_pkts = (f(*e) for e in self.res)
        else:
            lst_pkts = (f(*e) for e in self.res if lfilter(*e))

        # Apply the function f to the packets
        d = {}
        for k, v in lst_pkts:
            d.setdefault(k, []).append(v)

        # Mimic the default gnuplot output
        if not kargs:
            kargs = MATPLOTLIB_DEFAULT_PLOT_KARGS

        if plot_xy:
            lines = [plt.plot(*zip(*pl), **dict(kargs, label=k))
                     for k, pl in six.iteritems(d)]
        else:
            lines = [plt.plot(pl, **dict(kargs, label=k))
                     for k, pl in six.iteritems(d)]
        plt.legend(loc="center right", bbox_to_anchor=(1.5, 0.5))

        # Call show() if matplotlib is not inlined
        if not MATPLOTLIB_INLINED:
            plt.show()

        return lines

    def rawhexdump(self):
        """Prints an hexadecimal dump of each packet in the list"""
        for p in self:
            hexdump(self._elt2pkt(p))

    def hexraw(self, lfilter=None):
        """Same as nsummary(), except that if a packet has a Raw layer, it will be hexdumped  # noqa: E501
        lfilter: a truth function that decides whether a packet must be displayed"""  # noqa: E501
        for i, res in enumerate(self.res):
            p = self._elt2pkt(res)
            if lfilter is not None and not lfilter(p):
                continue
            print("%s %s %s" % (conf.color_theme.id(i, fmt="%04i"),
                                p.sprintf("%.time%"),
                                self._elt2sum(res)))
            if p.haslayer(conf.raw_layer):
                hexdump(p.getlayer(conf.raw_layer).load)

    def hexdump(self, lfilter=None):
        """Same as nsummary(), except that packets are also hexdumped
        lfilter: a truth function that decides whether a packet must be displayed"""  # noqa: E501
        for i, res in enumerate(self.res):
            p = self._elt2pkt(res)
            if lfilter is not None and not lfilter(p):
                continue
            print("%s %s %s" % (conf.color_theme.id(i, fmt="%04i"),
                                p.sprintf("%.time%"),
                                self._elt2sum(res)))
            hexdump(p)

    def padding(self, lfilter=None):
        """Same as hexraw(), for Padding layer"""
        for i, res in enumerate(self.res):
            p = self._elt2pkt(res)
            if p.haslayer(conf.padding_layer):
                if lfilter is None or lfilter(p):
                    print("%s %s %s" % (conf.color_theme.id(i, fmt="%04i"),
                                        p.sprintf("%.time%"),
                                        self._elt2sum(res)))
                    hexdump(p.getlayer(conf.padding_layer).load)

    def nzpadding(self, lfilter=None):
        """Same as padding() but only non null padding"""
        for i, res in enumerate(self.res):
            p = self._elt2pkt(res)
            if p.haslayer(conf.padding_layer):
                pad = p.getlayer(conf.padding_layer).load
                if pad == pad[0] * len(pad):
                    continue
                if lfilter is None or lfilter(p):
                    print("%s %s %s" % (conf.color_theme.id(i, fmt="%04i"),
                                        p.sprintf("%.time%"),
                                        self._elt2sum(res)))
                    hexdump(p.getlayer(conf.padding_layer).load)

    def conversations(self, getsrcdst=None, **kargs):
        """Graphes a conversations between sources and destinations and display it
        (using graphviz and imagemagick)
        getsrcdst: a function that takes an element of the list and
                   returns the source, the destination and optionally
                   a label. By default, returns the IP source and
                   destination from IP and ARP layers
        type: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option  # noqa: E501
        target: filename or redirect. Defaults pipe to Imagemagick's display program  # noqa: E501
        prog: which graphviz program to use"""
        if getsrcdst is None:
            def getsrcdst(pkt):
                """Extract src and dst addresses"""
                if 'IP' in pkt:
                    return (pkt['IP'].src, pkt['IP'].dst)
                if 'IPv6' in pkt:
                    return (pkt['IPv6'].src, pkt['IPv6'].dst)
                if 'ARP' in pkt:
                    return (pkt['ARP'].psrc, pkt['ARP'].pdst)
                raise TypeError()
        conv = {}
        for p in self.res:
            p = self._elt2pkt(p)
            try:
                c = getsrcdst(p)
            except Exception:
                # No warning here: it's OK that getsrcdst() raises an
                # exception, since it might be, for example, a
                # function that expects a specific layer in each
                # packet. The try/except approach is faster and
                # considered more Pythonic than adding tests.
                continue
            if len(c) == 3:
                conv.setdefault(c[:2], set()).add(c[2])
            else:
                conv[c] = conv.get(c, 0) + 1
        gr = 'digraph "conv" {\n'
        for (s, d), l in six.iteritems(conv):
            gr += '\t "%s" -> "%s" [label="%s"]\n' % (
                s, d, ', '.join(str(x) for x in l) if isinstance(l, set) else l
            )
        gr += "}\n"
        return do_graph(gr, **kargs)

    def afterglow(self, src=None, event=None, dst=None, **kargs):
        """Experimental clone attempt of http://sourceforge.net/projects/afterglow
        each datum is reduced as src -> event -> dst and the data are graphed.
        by default we have IP.src -> IP.dport -> IP.dst"""
        if src is None:
            src = lambda x: x['IP'].src
        if event is None:
            event = lambda x: x['IP'].dport
        if dst is None:
            dst = lambda x: x['IP'].dst
        sl = {}
        el = {}
        dl = {}
        for i in self.res:
            try:
                s, e, d = src(i), event(i), dst(i)
                if s in sl:
                    n, lst = sl[s]
                    n += 1
                    if e not in lst:
                        lst.append(e)
                    sl[s] = (n, lst)
                else:
                    sl[s] = (1, [e])
                if e in el:
                    n, lst = el[e]
                    n += 1
                    if d not in lst:
                        lst.append(d)
                    el[e] = (n, lst)
                else:
                    el[e] = (1, [d])
                dl[d] = dl.get(d, 0) + 1
            except Exception:
                continue

        def minmax(x):
            m, M = reduce(lambda a, b: (min(a[0], b[0]), max(a[1], b[1])),
                          ((a, a) for a in x))
            if m == M:
                m = 0
            if M == 0:
                M = 1
            return m, M

        mins, maxs = minmax(x for x, _ in six.itervalues(sl))
        mine, maxe = minmax(x for x, _ in six.itervalues(el))
        mind, maxd = minmax(six.itervalues(dl))

        gr = 'digraph "afterglow" {\n\tedge [len=2.5];\n'

        gr += "# src nodes\n"
        for s in sl:
            n, _ = sl[s]
            n = 1 + float(n - mins) / (maxs - mins)
            gr += '"src.%s" [label = "%s", shape=box, fillcolor="#FF0000", style=filled, fixedsize=1, height=%.2f,width=%.2f];\n' % (repr(s), repr(s), n, n)  # noqa: E501
        gr += "# event nodes\n"
        for e in el:
            n, _ = el[e]
            n = n = 1 + float(n - mine) / (maxe - mine)
            gr += '"evt.%s" [label = "%s", shape=circle, fillcolor="#00FFFF", style=filled, fixedsize=1, height=%.2f, width=%.2f];\n' % (repr(e), repr(e), n, n)  # noqa: E501
        for d in dl:
            n = dl[d]
            n = n = 1 + float(n - mind) / (maxd - mind)
            gr += '"dst.%s" [label = "%s", shape=triangle, fillcolor="#0000ff", style=filled, fixedsize=1, height=%.2f, width=%.2f];\n' % (repr(d), repr(d), n, n)  # noqa: E501

        gr += "###\n"
        for s in sl:
            n, lst = sl[s]
            for e in lst:
                gr += ' "src.%s" -> "evt.%s";\n' % (repr(s), repr(e))
        for e in el:
            n, lst = el[e]
            for d in lst:
                gr += ' "evt.%s" -> "dst.%s";\n' % (repr(e), repr(d))

        gr += "}"
        return do_graph(gr, **kargs)

    def canvas_dump(self, **kargs):
        import pyx
        d = pyx.document.document()
        len_res = len(self.res)
        for i, res in enumerate(self.res):
            c = self._elt2pkt(res).canvas_dump(**kargs)
            cbb = c.bbox()
            c.text(cbb.left(), cbb.top() + 1, r"\font\cmssfont=cmss12\cmssfont{Frame %i/%i}" % (i, len_res), [pyx.text.size.LARGE])  # noqa: E501
            if conf.verb >= 2:
                os.write(1, b".")
            d.append(pyx.document.page(c, paperformat=pyx.document.paperformat.A4,  # noqa: E501
                                       margin=1 * pyx.unit.t_cm,
                                       fittosize=1))
        return d

    def sr(self, multi=0):
        """sr([multi=1]) -> (SndRcvList, PacketList)
        Matches packets in the list and return ( (matched couples), (unmatched packets) )"""  # noqa: E501
        remain = self.res[:]
        sr = []
        i = 0
        while i < len(remain):
            s = remain[i]
            j = i
            while j < len(remain) - 1:
                j += 1
                r = remain[j]
                if r.answers(s):
                    sr.append((s, r))
                    if multi:
                        remain[i]._answered = 1
                        remain[j]._answered = 2
                        continue
                    del(remain[j])
                    del(remain[i])
                    i -= 1
                    break
            i += 1
        if multi:
            remain = [x for x in remain if not hasattr(x, "_answered")]
        return SndRcvList(sr), PacketList(remain)

    def sessions(self, session_extractor=None):
        if session_extractor is None:
            def session_extractor(p):
                """Extract sessions from packets"""
                if 'Ether' in p:
                    if 'IP' in p or 'IPv6' in p:
                        ip_src_fmt = "{IP:%IP.src%}{IPv6:%IPv6.src%}"
                        ip_dst_fmt = "{IP:%IP.dst%}{IPv6:%IPv6.dst%}"
                        addr_fmt = (ip_src_fmt, ip_dst_fmt)
                        if 'TCP' in p:
                            fmt = "TCP {}:%r,TCP.sport% > {}:%r,TCP.dport%"
                        elif 'UDP' in p:
                            fmt = "UDP {}:%r,UDP.sport% > {}:%r,UDP.dport%"
                        elif 'ICMP' in p:
                            fmt = "ICMP {} > {} type=%r,ICMP.type% code=%r," \
                                  "ICMP.code% id=%ICMP.id%"
                        elif 'ICMPv6' in p:
                            fmt = "ICMPv6 {} > {} type=%r,ICMPv6.type% " \
                                  "code=%r,ICMPv6.code%"
                        elif 'IPv6' in p:
                            fmt = "IPv6 {} > {} nh=%IPv6.nh%"
                        else:
                            fmt = "IP {} > {} proto=%IP.proto%"
                        return p.sprintf(fmt.format(*addr_fmt))
                    elif 'ARP' in p:
                        return p.sprintf("ARP %ARP.psrc% > %ARP.pdst%")
                    else:
                        return p.sprintf("Ethernet type=%04xr,Ether.type%")
                return "Other"
        sessions = defaultdict(self.__class__)
        for p in self.res:
            sess = session_extractor(self._elt2pkt(p))
            sessions[sess].append(p)
        return dict(sessions)

    def replace(self, *args, **kargs):
        """
        lst.replace(<field>,[<oldvalue>,]<newvalue>)
        lst.replace( (fld,[ov],nv),(fld,[ov,]nv),...)
          if ov is None, all values are replaced
        ex:
          lst.replace( IP.src, "192.168.1.1", "10.0.0.1" )
          lst.replace( IP.ttl, 64 )
          lst.replace( (IP.ttl, 64), (TCP.sport, 666, 777), )
        """
        delete_checksums = kargs.get("delete_checksums", False)
        x = PacketList(name="Replaced %s" % self.listname)
        if not isinstance(args[0], tuple):
            args = (args,)
        for p in self.res:
            p = self._elt2pkt(p)
            copied = False
            for scheme in args:
                fld = scheme[0]
                old = scheme[1]  # not used if len(scheme) == 2
                new = scheme[-1]
                for o in fld.owners:
                    if o in p:
                        if len(scheme) == 2 or p[o].getfieldval(fld.name) == old:  # noqa: E501
                            if not copied:
                                p = p.copy()
                                if delete_checksums:
                                    p.delete_checksums()
                                copied = True
                            setattr(p[o], fld.name, new)
            x.append(p)
        return x

    def getlayer(self, cls, nb=None, flt=None, name=None, stats=None):
        """Returns the packet list from a given layer.

        See ``Packet.getlayer`` for more info.

        :param cls: search for a layer that is an instance of ``cls``
        :type cls: Type[Packet]

        :param nb: return the nb^th layer that is an instance of ``cls``
        :type nb: Optional[int]

        :param flt: filter parameters for ``Packet.getlayer``
        :type flt: Optional[Dict[str, Any]]

        :param name: optional name for the new PacketList
        :type name: Optional[str]

        :param stats: optional list of protocols to give stats on; if not
                      specified, inherits from this PacketList.
        :type stats: Optional[List[Type[Packet]]]
        :rtype: PacketList
        """
        if name is None:
            name = "{} layer {}".format(self.listname, cls.__name__)
        if stats is None:
            stats = self.stats

        getlayer_arg = {}
        if flt is not None:
            getlayer_arg.update(flt)
        getlayer_arg['cls'] = cls
        if nb is not None:
            getlayer_arg['nb'] = nb

        # Only return non-None getlayer results
        return PacketList([
            pc for pc in (p.getlayer(**getlayer_arg) for p in self.res)
            if pc is not None],
            name, stats
        )

    def convert_to(self, other_cls, name=None, stats=None):
        """Converts all packets to another type.

        See ``Packet.convert_to`` for more info.

        :param other_cls: reference to a Packet class to convert to
        :type other_cls: Type[Packet]

        :param name: optional name for the new PacketList
        :type name: Optional[str]

        :param stats: optional list of protocols to give stats on;
                      if not specified, inherits from this PacketList.
        :type stats: Optional[List[Type[Packet]]]

        :rtype: PacketList
        """
        if name is None:
            name = "{} converted to {}".format(
                self.listname, other_cls.__name__)
        if stats is None:
            stats = self.stats

        return PacketList(
            [p.convert_to(other_cls) for p in self.res],
            name, stats
        )


class SndRcvList(PacketList):
    __slots__ = []

    def __init__(self, res=None, name="Results", stats=None):
        PacketList.__init__(self, res, name, stats)

    def _elt2pkt(self, elt):
        return elt[1]

    def _elt2sum(self, elt):
        return "%s ==> %s" % (elt[0].summary(), elt[1].summary())
