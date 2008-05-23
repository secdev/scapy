import os,socket
from config import conf

#############
## Results ##
#############

class PacketList:
    res = []
    def __init__(self, res=None, name="PacketList", stats=None):
        """create a packet list from a list of packets
           res: the list of packets
           stats: a list of classes that will appear in the stats (defaults to [TCP,UDP,ICMP])"""
        if stats is None:
            stats = [ TCP,UDP,ICMP ]
        self.stats = stats
        if res is None:
            res = []
        if isinstance(res, PacketList):
            res = res.res
        self.res = res
        self.listname = name
    def _elt2pkt(self, elt):
        return elt
    def _elt2sum(self, elt):
        return elt.summary()
    def _elt2show(self, elt):
        return self._elt2sum(elt)
    def __repr__(self):
#        stats=dict.fromkeys(self.stats,0) ## needs python >= 2.3  :(
        stats = dict(map(lambda x: (x,0), self.stats))
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
            s += " %s%s%s" % (ct.packetlist_proto(p.name),
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
    def __getattr__(self, attr):
        return getattr(self.res, attr)
    def __getitem__(self, item):
        if isinstance(item,type) and issubclass(item,Packet):
            return self.__class__(filter(lambda x: item in self._elt2pkt(x),self.res),
                                  name="%s from %s"%(item.__name__,self.listname))
        if type(item) is slice:
            return self.__class__(self.res.__getitem__(item),
                                  name = "mod %s" % self.listname)
        return self.res.__getitem__(item)
    def __getslice__(self, *args, **kargs):
        return self.__class__(self.res.__getslice__(*args, **kargs),
                              name="mod %s"%self.listname)
    def __add__(self, other):
        return self.__class__(self.res+other.res,
                              name="%s+%s"%(self.listname,other.listname))
    def summary(self, prn=None, lfilter=None):
        """prints a summary of each packet
prn:     function to apply to each packet instead of lambda x:x.summary()
lfilter: truth function to apply to each packet to decide whether it will be displayed"""
        for r in self.res:
            if lfilter is not None:
                if not lfilter(r):
                    continue
            if prn is None:
                print self._elt2sum(r)
            else:
                print prn(r)
    def nsummary(self,prn=None, lfilter=None):
        """prints a summary of each packet with the packet's number
prn:     function to apply to each packet instead of lambda x:x.summary()
lfilter: truth function to apply to each packet to decide whether it will be displayed"""
        for i in range(len(self.res)):
            if lfilter is not None:
                if not lfilter(self.res[i]):
                    continue
            print conf.color_theme.id(i,"%04i"),
            if prn is None:
                print self._elt2sum(self.res[i])
            else:
                print prn(self.res[i])
    def display(self): # Deprecated. Use show()
        """deprecated. is show()"""
        self.show()
    def show(self, *args, **kargs):
        """Best way to display the packet list. Defaults to nsummary() method"""
        return self.nsummary(*args, **kargs)
    
    def filter(self, func):
        """Returns a packet list filtered by a truth function"""
        return self.__class__(filter(func,self.res),
                              name="filtered %s"%self.listname)
    def make_table(self, *args, **kargs):
        """Prints a table using a function that returs for each packet its head column value, head row value and displayed value
        ex: p.make_table(lambda x:(x[IP].dst, x[TCP].dport, x[TCP].sprintf("%flags%")) """
        return make_table(self.res, *args, **kargs)
    def make_lined_table(self, *args, **kargs):
        """Same as make_table, but print a table with lines"""
        return make_lined_table(self.res, *args, **kargs)
    def make_tex_table(self, *args, **kargs):
        """Same as make_table, but print a table with LaTeX syntax"""
        return make_tex_table(self.res, *args, **kargs)

    def plot(self, f, lfilter=None,**kargs):
        """Applies a function to each packet to get a value that will be plotted with GnuPlot. A gnuplot object is returned
        lfilter: a truth function that decides whether a packet must be ploted"""
        g=Gnuplot.Gnuplot()
        l = self.res
        if lfilter is not None:
            l = filter(lfilter, l)
        l = map(f,l)
        g.plot(Gnuplot.Data(l, **kargs))
        return g

    def diffplot(self, f, delay=1, lfilter=None, **kargs):
        """diffplot(f, delay=1, lfilter=None)
        Applies a function to couples (l[i],l[i+delay])"""
        g = Gnuplot.Gnuplot()
        l = self.res
        if lfilter is not None:
            l = filter(lfilter, l)
        l = map(f,l[:-delay],l[delay:])
        g.plot(Gnuplot.Data(l, **kargs))
        return g

    def multiplot(self, f, lfilter=None, **kargs):
        """Uses a function that returns a label and a value for this label, then plots all the values label by label"""
        g=Gnuplot.Gnuplot()
        l = self.res
        if lfilter is not None:
            l = filter(lfilter, l)

        d={}
        for e in l:
            k,v = f(e)
            if k in d:
                d[k].append(v)
            else:
                d[k] = [v]
        data=[]
        for k in d:
            data.append(Gnuplot.Data(d[k], title=k, **kargs))

        g.plot(*data)
        return g
        

    def rawhexdump(self):
        """Prints an hexadecimal dump of each packet in the list"""
        for p in self:
            hexdump(self._elt2pkt(p))

    def hexraw(self, lfilter=None):
        """Same as nsummary(), except that if a packet has a Raw layer, it will be hexdumped
        lfilter: a truth function that decides whether a packet must be displayed"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if lfilter is not None and not lfilter(p):
                continue
            print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                p.sprintf("%.time%"),
                                self._elt2sum(self.res[i]))
            if p.haslayer(Raw):
                hexdump(p.getlayer(Raw).load)

    def hexdump(self, lfilter=None):
        """Same as nsummary(), except that packets are also hexdumped
        lfilter: a truth function that decides whether a packet must be displayed"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if lfilter is not None and not lfilter(p):
                continue
            print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                p.sprintf("%.time%"),
                                self._elt2sum(self.res[i]))
            hexdump(p)

    def padding(self, lfilter=None):
        """Same as hexraw(), for Padding layer"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if p.haslayer(Padding):
                if lfilter is None or lfilter(p):
                    print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                        p.sprintf("%.time%"),
                                        self._elt2sum(self.res[i]))
                    hexdump(p.getlayer(Padding).load)

    def nzpadding(self, lfilter=None):
        """Same as padding() but only non null padding"""
        for i in range(len(self.res)):
            p = self._elt2pkt(self.res[i])
            if p.haslayer(Padding):
                pad = p.getlayer(Padding).load
                if pad == pad[0]*len(pad):
                    continue
                if lfilter is None or lfilter(p):
                    print "%s %s %s" % (conf.color_theme.id(i,"%04i"),
                                        p.sprintf("%.time%"),
                                        self._elt2sum(self.res[i]))
                    hexdump(p.getlayer(Padding).load)
        

    def conversations(self, getsrcdst=None,**kargs):
        """Graphes a conversations between sources and destinations and display it
        (using graphviz and imagemagick)
        getsrcdst: a function that takes an element of the list and return the source and dest
                   by defaults, return source and destination IP
        type: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
        target: filename or redirect. Defaults pipe to Imagemagick's display program
        prog: which graphviz program to use"""
        if getsrcdst is None:
            getsrcdst = lambda x:(x[IP].src, x[IP].dst)
        conv = {}
        for p in self.res:
            p = self._elt2pkt(p)
            try:
                c = getsrcdst(p)
            except:
                #XXX warning()
                continue
            conv[c] = conv.get(c,0)+1
        gr = 'digraph "conv" {\n'
        for s,d in conv:
            gr += '\t "%s" -> "%s"\n' % (s,d)
        gr += "}\n"        
        return do_graph(gr, **kargs)

    def afterglow(self, src=None, event=None, dst=None, **kargs):
        """Experimental clone attempt of http://sourceforge.net/projects/afterglow
        each datum is reduced as src -> event -> dst and the data are graphed.
        by default we have IP.src -> IP.dport -> IP.dst"""
        if src is None:
            src = lambda x: x[IP].src
        if event is None:
            event = lambda x: x[IP].dport
        if dst is None:
            dst = lambda x: x[IP].dst
        sl = {}
        el = {}
        dl = {}
        for i in self.res:
            try:
                s,e,d = src(i),event(i),dst(i)
                if s in sl:
                    n,l = sl[s]
                    n += 1
                    if e not in l:
                        l.append(e)
                    sl[s] = (n,l)
                else:
                    sl[s] = (1,[e])
                if e in el:
                    n,l = el[e]
                    n+=1
                    if d not in l:
                        l.append(d)
                    el[e] = (n,l)
                else:
                    el[e] = (1,[d])
                dl[d] = dl.get(d,0)+1
            except:
                continue

        import math
        def normalize(n):
            return 2+math.log(n)/4.0

        def minmax(x):
            m,M = min(x),max(x)
            if m == M:
                m = 0
            if M == 0:
                M = 1
            return m,M

        mins,maxs = minmax(map(lambda (x,y): x, sl.values()))
        mine,maxe = minmax(map(lambda (x,y): x, el.values()))
        mind,maxd = minmax(dl.values())
    
        gr = 'digraph "afterglow" {\n\tedge [len=2.5];\n'

        gr += "# src nodes\n"
        for s in sl:
            n,l = sl[s]; n = 1+float(n-mins)/(maxs-mins)
            gr += '"src.%s" [label = "%s", shape=box, fillcolor="#FF0000", style=filled, fixedsize=1, height=%.2f,width=%.2f];\n' % (`s`,`s`,n,n)
        gr += "# event nodes\n"
        for e in el:
            n,l = el[e]; n = n = 1+float(n-mine)/(maxe-mine)
            gr += '"evt.%s" [label = "%s", shape=circle, fillcolor="#00FFFF", style=filled, fixedsize=1, height=%.2f, width=%.2f];\n' % (`e`,`e`,n,n)
        for d in dl:
            n = dl[d]; n = n = 1+float(n-mind)/(maxd-mind)
            gr += '"dst.%s" [label = "%s", shape=triangle, fillcolor="#0000ff", style=filled, fixedsize=1, height=%.2f, width=%.2f];\n' % (`d`,`d`,n,n)

        gr += "###\n"
        for s in sl:
            n,l = sl[s]
            for e in l:
                gr += ' "src.%s" -> "evt.%s";\n' % (`s`,`e`) 
        for e in el:
            n,l = el[e]
            for d in l:
                gr += ' "evt.%s" -> "dst.%s";\n' % (`e`,`d`) 
            
        gr += "}"
        open("/tmp/aze","w").write(gr)
        return do_graph(gr, **kargs)
        

        
    def timeskew_graph(self, ip, **kargs):
        """Tries to graph the timeskew between the timestamps and real time for a given ip"""
        res = map(lambda x: self._elt2pkt(x), self.res)
        b = filter(lambda x:x.haslayer(IP) and x.getlayer(IP).src == ip and x.haslayer(TCP), res)
        c = []
        for p in b:
            opts = p.getlayer(TCP).options
            for o in opts:
                if o[0] == "Timestamp":
                    c.append((p.time,o[1][0]))
        if not c:
            warning("No timestamps found in packet list")
            return
        d = map(lambda (x,y): (x%2000,((x-c[0][0])-((y-c[0][1])/1000.0))),c)
        g = Gnuplot.Gnuplot()
        g.plot(Gnuplot.Data(d,**kargs))
        return g
        
    def _dump_document(self, **kargs):
        d = pyx.document.document()
        l = len(self.res)
        for i in range(len(self.res)):
            elt = self.res[i]
            c = self._elt2pkt(elt).canvas_dump(**kargs)
            cbb = c.bbox()
            c.text(cbb.left(),cbb.top()+1,r"\font\cmssfont=cmss12\cmssfont{Frame %i/%i}" % (i,l),[pyx.text.size.LARGE])
            if conf.verb >= 2:
                os.write(1,".")
            d.append(pyx.document.page(c, paperformat=pyx.document.paperformat.A4,
                                       margin=1*pyx.unit.t_cm,
                                       fittosize=1))
        return d
                     
                 

    def psdump(self, filename = None, **kargs):
        """Creates a multipage poscript file with a psdump of every packet
        filename: name of the file to write to. If empty, a temporary file is used and
                  conf.prog.psreader is called"""
        d = self._dump_document(**kargs)
        if filename is None:
            filename = "/tmp/scapy.psd.%i" % os.getpid()
            d.writePSfile(filename)
            os.system("%s %s.ps &" % (conf.prog.psreader,filename))
        else:
            d.writePSfile(filename)
        print
        
    def pdfdump(self, filename = None, **kargs):
        """Creates a PDF file with a psdump of every packet
        filename: name of the file to write to. If empty, a temporary file is used and
                  conf.prog.pdfreader is called"""
        d = self._dump_document(**kargs)
        if filename is None:
            filename = "/tmp/scapy.psd.%i" % os.getpid()
            d.writePDFfile(filename)
            os.system("%s %s.pdf &" % (conf.prog.pdfreader,filename))
        else:
            d.writePDFfile(filename)
        print

    def sr(self,multi=0):
        """sr([multi=1]) -> (SndRcvList, PacketList)
        Matches packets in the list and return ( (matched couples), (unmatched packets) )"""
        remain = self.res[:]
        sr = []
        i = 0
        while i < len(remain):
            s = remain[i]
            j = i
            while j < len(remain)-1:
                j += 1
                r = remain[j]
                if r.answers(s):
                    sr.append((s,r))
                    if multi:
                        remain[i]._answered=1
                        remain[j]._answered=2
                        continue
                    del(remain[j])
                    del(remain[i])
                    i -= 1
                    break
            i += 1
        if multi:
            remain = filter(lambda x:not hasattr(x,"_answered"), remain)
        return SndRcvList(sr),PacketList(remain)
        


        


class Dot11PacketList(PacketList):
    def __init__(self, res=None, name="Dot11List", stats=None):
        if stats is None:
            stats = [Dot11WEP, Dot11Beacon, UDP, ICMP, TCP]

        PacketList.__init__(self, res, name, stats)
    def toEthernet(self):
        data = map(lambda x:x.getlayer(Dot11), filter(lambda x : x.haslayer(Dot11) and x.type == 2, self.res))
        r2 = []
        for p in data:
            q = p.copy()
            q.unwep()
            r2.append(Ether()/q.payload.payload.payload) #Dot11/LLC/SNAP/IP
        return PacketList(r2,name="Ether from %s"%self.listname)
        
        

class SndRcvList(PacketList):
    def __init__(self, res=None, name="Results", stats=None):
        PacketList.__init__(self, res, name, stats)
    def _elt2pkt(self, elt):
        return elt[1]
    def _elt2sum(self, elt):
        return "%s ==> %s" % (elt[0].summary(),elt[1].summary()) 


class ARPingResult(SndRcvList):
    def __init__(self, res=None, name="ARPing", stats=None):
        PacketList.__init__(self, res, name, stats)

    def show(self):
        for s,r in self.res:
            print r.sprintf("%Ether.src% %ARP.psrc%")


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
    
    

class TracerouteResult(SndRcvList):
    def __init__(self, res=None, name="Traceroute", stats=None):
        PacketList.__init__(self, res, name, stats)
        self.graphdef = None
        self.graphASres = 0
        self.padding = 0
        self.hloc = None
        self.nloc = None

    def show(self):
        return self.make_table(lambda (s,r): (s.sprintf("%IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
                                              s.ttl,
                                              r.sprintf("%-15s,IP.src% {TCP:%TCP.flags%}{ICMP:%ir,ICMP.type%}")))


    def get_trace(self):
        trace = {}
        for s,r in self.res:
            if IP not in s:
                continue
            d = s[IP].dst
            if d not in trace:
                trace[d] = {}
            trace[d][s[IP].ttl] = r[IP].src, ICMP not in r
        for k in trace.values():
            m = filter(lambda x:k[x][1], k.keys())
            if not m:
                continue
            m = min(m)
            for l in k.keys():
                if l > m:
                    del(k[l])
        return trace

    def trace3D(self):
        """Give a 3D representation of the traceroute.
        right button: rotate the scene
        middle button: zoom
        left button: move the scene
        left button on a ball: toggle IP displaying
        ctrl-left button on a ball: scan ports 21,22,23,25,80 and 443 and display the result"""
        trace = self.get_trace()
        import visual

        class IPsphere(visual.sphere):
            def __init__(self, ip, **kargs):
                visual.sphere.__init__(self, **kargs)
                self.ip=ip
                self.label=None
                self.setlabel(self.ip)
            def setlabel(self, txt,visible=None):
                if self.label is not None:
                    if visible is None:
                        visible = self.label.visible
                    self.label.visible = 0
                elif visible is None:
                    visible=0
                self.label=visual.label(text=txt, pos=self.pos, space=self.radius, xoffset=10, yoffset=20, visible=visible)
            def action(self):
                self.label.visible ^= 1

        visual.scene = visual.display()
        visual.scene.exit_on_close(0)
        start = visual.box()
        rings={}
        tr3d = {}
        for i in trace:
            tr = trace[i]
            tr3d[i] = []
            ttl = tr.keys()
            for t in range(1,max(ttl)+1):
                if t not in rings:
                    rings[t] = []
                if t in tr:
                    if tr[t] not in rings[t]:
                        rings[t].append(tr[t])
                    tr3d[i].append(rings[t].index(tr[t]))
                else:
                    rings[t].append(("unk",-1))
                    tr3d[i].append(len(rings[t])-1)
        for t in rings:
            r = rings[t]
            l = len(r)
            for i in range(l):
                if r[i][1] == -1:
                    col = (0.75,0.75,0.75)
                elif r[i][1]:
                    col = visual.color.green
                else:
                    col = visual.color.blue
                
                s = IPsphere(pos=((l-1)*visual.cos(2*i*visual.pi/l),(l-1)*visual.sin(2*i*visual.pi/l),2*t),
                             ip = r[i][0],
                             color = col)
                for trlst in tr3d.values():
                    if t <= len(trlst):
                        if trlst[t-1] == i:
                            trlst[t-1] = s
        forecol = colgen(0.625, 0.4375, 0.25, 0.125)
        for trlst in tr3d.values():
            col = forecol.next()
            start = (0,0,0)
            for ip in trlst:
                visual.cylinder(pos=start,axis=ip.pos-start,color=col,radius=0.2)
                start = ip.pos
        
        movcenter=None
        while 1:
            if visual.scene.kb.keys:
                k = visual.scene.kb.getkey()
                if k == "esc":
                    break
            if visual.scene.mouse.events:
                ev = visual.scene.mouse.getevent()
                if ev.press == "left":
                    o = ev.pick
                    if o:
                        if ev.ctrl:
                            if o.ip == "unk":
                                continue
                            savcolor = o.color
                            o.color = (1,0,0)
                            a,b=sr(IP(dst=o.ip)/TCP(dport=[21,22,23,25,80,443]),timeout=2)
                            o.color = savcolor
                            if len(a) == 0:
                                txt = "%s:\nno results" % o.ip
                            else:
                                txt = "%s:\n" % o.ip
                                for s,r in a:
                                    txt += r.sprintf("{TCP:%IP.src%:%TCP.sport% %TCP.flags%}{TCPerror:%IPerror.dst%:%TCPerror.dport% %IP.src% %ir,ICMP.type%}\n")
                            o.setlabel(txt, visible=1)
                        else:
                            if hasattr(o, "action"):
                                o.action()
                elif ev.drag == "left":
                    movcenter = ev.pos
                elif ev.drop == "left":
                    movcenter = None
            if movcenter:
                visual.scene.center -= visual.scene.mouse.pos-movcenter
                movcenter = visual.scene.mouse.pos
                
                
    def world_trace(self):
        ips = {}
        rt = {}
        ports_done = {}
        for s,r in self.res:
            ips[r.src] = None
            if s.haslayer(TCP) or s.haslayer(UDP):
                trace_id = (s.src,s.dst,s.proto,s.dport)
            elif s.haslayer(ICMP):
                trace_id = (s.src,s.dst,s.proto,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            if not r.haslayer(ICMP) or r.type != 11:
                if ports_done.has_key(trace_id):
                    continue
                ports_done[trace_id] = None
            trace[s.ttl] = r.src
            rt[trace_id] = trace

        trt = {}
        for trace_id in rt:
            trace = rt[trace_id]
            loctrace = []
            for i in range(max(trace.keys())):
                ip = trace.get(i,None)
                if ip is None:
                    continue
                loc = locate_ip(ip)
                if loc is None:
                    continue
#                loctrace.append((ip,loc)) # no labels yet
                loctrace.append(loc)
            if loctrace:
                trt[trace_id] = loctrace

        tr = map(lambda x: Gnuplot.Data(x,with="lines"), trt.values())
        g = Gnuplot.Gnuplot()
        world = Gnuplot.File(conf.gnuplot_world,with="lines")
        g.plot(world,*tr)
        return g

    def make_graph(self,ASres=None,padding=0):
        if ASres is None:
            ASres = conf.AS_resolver
        self.graphASres = ASres
        self.graphpadding = padding
        ips = {}
        rt = {}
        ports = {}
        ports_done = {}
        for s,r in self.res:
            r = r[IP] or r[IPv6] or r
            s = s[IP] or s[IPv6] or s
            ips[r.src] = None
            if TCP in s:
                trace_id = (s.src,s.dst,6,s.dport)
            elif UDP in s:
                trace_id = (s.src,s.dst,17,s.dport)
            elif ICMP in s:
                trace_id = (s.src,s.dst,1,s.type)
            else:
                trace_id = (s.src,s.dst,s.proto,0)
            trace = rt.get(trace_id,{})
            ttl = IPv6 in s and s.hlim or s.ttl
            if not (ICMP in r and r[ICMP].type == 11) and not (IPv6 in r and ICMPv6TimeExceeded in r):
                if trace_id in ports_done:
                    continue
                ports_done[trace_id] = None
                p = ports.get(r.src,[])
                if TCP in r:
                    p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))
                    trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
                elif UDP in r:
                    p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
                    trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
                elif ICMP in r:
                    p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
                    trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                else:
                    p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))
                    trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')
                ports[r.src] = p
            else:
                trace[ttl] = r.sprintf('"%r,src%"')
            rt[trace_id] = trace
    
        # Fill holes with unk%i nodes
        unknown_label = incremental_label("unk%i")
        blackholes = []
        bhip = {}
        for rtk in rt:
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                if not trace.has_key(n):
                    trace[n] = unknown_label.next()
            if not ports_done.has_key(rtk):
                if rtk[2] == 1: #ICMP
                    bh = "%s %i/icmp" % (rtk[1],rtk[3])
                elif rtk[2] == 6: #TCP
                    bh = "%s %i/tcp" % (rtk[1],rtk[3])
                elif rtk[2] == 17: #UDP                    
                    bh = '%s %i/udp' % (rtk[1],rtk[3])
                else:
                    bh = '%s %i/proto' % (rtk[1],rtk[2]) 
                ips[bh] = None
                bhip[rtk[1]] = bh
                bh = '"%s"' % bh
                trace[max(k)+1] = bh
                blackholes.append(bh)
    
        # Find AS numbers
        ASN_query_list = dict.fromkeys(map(lambda x:x.rsplit(" ",1)[0],ips)).keys()
        if ASres is None:            
            ASNlist = []
        else:
            ASNlist = ASres.resolve(*ASN_query_list)            
    
        ASNs = {}
        ASDs = {}
        for ip,asn,desc, in ASNlist:
            if asn is None:
                continue
            iplist = ASNs.get(asn,[])
            if ip in bhip:
                if ip in ports:
                    iplist.append(ip)
                iplist.append(bhip[ip])
            else:
                iplist.append(ip)
            ASNs[asn] = iplist
            ASDs[asn] = desc
    
    
        backcolorlist=colgen("60","86","ba","ff")
        forecolorlist=colgen("a0","70","40","20")
    
        s = "digraph trace {\n"
    
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
        s += "\n#ASN clustering\n"
        for asn in ASNs:
            s += '\tsubgraph cluster_%s {\n' % asn
            col = backcolorlist.next()
            s += '\t\tcolor="#%s%s%s";' % col
            s += '\t\tnode [fillcolor="#%s%s%s",style=filled];' % col
            s += '\t\tfontsize = 10;'
            s += '\t\tlabel = "%s\\n[%s]"\n' % (asn,ASDs[asn])
            for ip in ASNs[asn]:
    
                s += '\t\t"%s";\n'%ip
            s += "\t}\n"
    
    
    
    
        s += "#endpoints\n"
        for p in ports:
            s += '\t"%s" [shape=record,color=black,fillcolor=green,style=filled,label="%s|%s"];\n' % (p,p,"|".join(ports[p]))
    
        s += "\n#Blackholes\n"
        for bh in blackholes:
            s += '\t%s [shape=octagon,color=black,fillcolor=red,style=filled];\n' % bh

        if padding:
            s += "\n#Padding\n"
            pad={}
            for snd,rcv in self.res:
                if rcv.src not in ports and rcv.haslayer(Padding):
                    p = rcv.getlayer(Padding).load
                    if p != "\x00"*len(p):
                        pad[rcv.src]=None
            for rcv in pad:
                s += '\t"%s" [shape=triangle,color=black,fillcolor=red,style=filled];\n' % rcv
    
    
            
        s += "\n\tnode [shape=ellipse,color=black,style=solid];\n\n"
    
    
        for rtk in rt:
            s += "#---[%s\n" % `rtk`
            s += '\t\tedge [color="#%s%s%s"];\n' % forecolorlist.next()
            trace = rt[rtk]
            k = trace.keys()
            for n in range(min(k), max(k)):
                s += '\t%s ->\n' % trace[n]
            s += '\t%s;\n' % trace[max(k)]
    
        s += "}\n";
        self.graphdef = s
    
    def graph(self, ASres=None, padding=0, **kargs):
        """x.graph(ASres=conf.AS_resolver, other args):
        ASres=None          : no AS resolver => no clustering
        ASres=AS_resolver() : default whois AS resolver (riswhois.ripe.net)
        ASres=AS_resolver_cymru(): use whois.cymru.com whois database
        ASres=AS_resolver(server="whois.ra.net")
        type: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
        target: filename or redirect. Defaults pipe to Imagemagick's display program
        prog: which graphviz program to use"""
        if ASres is None:
            ASres = conf.AS_resolver
        if (self.graphdef is None or
            self.graphASres != ASres or
            self.graphpadding != padding):
            self.make_graph(ASres,padding)

        return do_graph(self.graphdef, **kargs)


conf.AS_resolver = AS_resolver_multi()
        
