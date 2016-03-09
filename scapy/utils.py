## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
General utility functions.
"""

from __future__ import with_statement
import os,sys,socket,types
import random,time
import gzip,zlib,cPickle
import re,struct,array
import subprocess

import warnings
warnings.filterwarnings("ignore","tempnam",RuntimeWarning, __name__)

from config import conf
from data import MTU
from error import log_runtime,log_loading,log_interactive, Scapy_Exception
from base_classes import BasePacketList

WINDOWS=sys.platform.startswith("win32")

###########
## Tools ##
###########

def get_temp_file(keep=False, autoext=""):
    f = os.tempnam("","scapy")
    if not keep:
        conf.temp_files.append(f+autoext)
    return f

def sane_color(x):
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+conf.color_theme.not_printable(".")
        else:
            r=r+i
    return r

def sane(x):
    r=""
    for i in x:
        j = ord(i)
        if (j < 32) or (j >= 127):
            r=r+"."
        else:
            r=r+i
    return r

def lhex(x):
    if type(x) in (int,long):
        return hex(x)
    elif type(x) is tuple:
        return "(%s)" % ", ".join(map(lhex, x))
    elif type(x) is list:
        return "[%s]" % ", ".join(map(lhex, x))
    else:
        return x

@conf.commands.register
def hexdump(x):
    x=str(x)
    l = len(x)
    i = 0
    while i < l:
        print "%04x  " % i,
        for j in xrange(16):
            if i+j < l:
                print "%02X" % ord(x[i+j]),
            else:
                print "  ",
            if j%16 == 7:
                print "",
        print " ",
        print sane_color(x[i:i+16])
        i += 16

@conf.commands.register
def linehexdump(x, onlyasc=0, onlyhex=0):
    x = str(x)
    l = len(x)
    if not onlyasc:
        for i in xrange(l):
            print "%02X" % ord(x[i]),
        print "",
    if not onlyhex:
        print sane_color(x)

def chexdump(x):
    x=str(x)
    print ", ".join(map(lambda x: "%#04x"%ord(x), x))
    
def hexstr(x, onlyasc=0, onlyhex=0):
    s = []
    if not onlyasc:
        s.append(" ".join(map(lambda x:"%02x"%ord(x), x)))
    if not onlyhex:
        s.append(sane(x)) 
    return "  ".join(s)


@conf.commands.register
def hexdiff(x,y):
    """Show differences between 2 binary strings"""
    x=str(x)[::-1]
    y=str(y)[::-1]
    SUBST=1
    INSERT=1
    d={}
    d[-1,-1] = 0,(-1,-1)
    for j in xrange(len(y)):
        d[-1,j] = d[-1,j-1][0]+INSERT, (-1,j-1)
    for i in xrange(len(x)):
        d[i,-1] = d[i-1,-1][0]+INSERT, (i-1,-1)

    for j in xrange(len(y)):
        for i in xrange(len(x)):
            d[i,j] = min( ( d[i-1,j-1][0]+SUBST*(x[i] != y[j]), (i-1,j-1) ),
                          ( d[i-1,j][0]+INSERT, (i-1,j) ),
                          ( d[i,j-1][0]+INSERT, (i,j-1) ) )
                          

    backtrackx = []
    backtracky = []
    i=len(x)-1
    j=len(y)-1
    while not (i == j == -1):
        i2,j2 = d[i,j][1]
        backtrackx.append(x[i2+1:i+1])
        backtracky.append(y[j2+1:j+1])
        i,j = i2,j2

        

    x = y = i = 0
    colorize = { 0: lambda x:x,
                -1: conf.color_theme.left,
                 1: conf.color_theme.right }
    
    dox=1
    doy=0
    l = len(backtrackx)
    while i < l:
        separate=0
        linex = backtrackx[i:i+16]
        liney = backtracky[i:i+16]
        xx = sum(len(k) for k in linex)
        yy = sum(len(k) for k in liney)
        if dox and not xx:
            dox = 0
            doy = 1
        if dox and linex == liney:
            doy=1
            
        if dox:
            xd = y
            j = 0
            while not linex[j]:
                j += 1
                xd -= 1
            print colorize[doy-dox]("%04x" % xd),
            x += xx
            line=linex
        else:
            print "    ",
        if doy:
            yd = y
            j = 0
            while not liney[j]:
                j += 1
                yd -= 1
            print colorize[doy-dox]("%04x" % yd),
            y += yy
            line=liney
        else:
            print "    ",
            
        print " ",
        
        cl = ""
        for j in xrange(16):
            if i+j < l:
                if line[j]:
                    col = colorize[(linex[j]!=liney[j])*(doy-dox)]
                    print col("%02X" % ord(line[j])),
                    if linex[j]==liney[j]:
                        cl += sane_color(line[j])
                    else:
                        cl += col(sane(line[j]))
                else:
                    print "  ",
                    cl += " "
            else:
                print "  ",
            if j == 7:
                print "",


        print " ",cl

        if doy or not yy:
            doy=0
            dox=1
            i += 16
        else:
            if yy:
                dox=0
                doy=1
            else:
                i += 16

    
crc32 = zlib.crc32

if struct.pack("H",1) == "\x00\x01": # big endian
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff
else:
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff


def _fletcher16(charbuf):
    # This is based on the GPLed C implementation in Zebra <http://www.zebra.org/>
    c0 = c1 = 0
    for char in charbuf:
        c0 += ord(char)
        c1 += c0

    c0 %= 255
    c1 %= 255
    return (c0,c1)

@conf.commands.register
def fletcher16_checksum(binbuf):
    """ Calculates Fletcher-16 checksum of the given buffer.
        
        Note:
        If the buffer contains the two checkbytes derived from the Fletcher-16 checksum
        the result of this function has to be 0. Otherwise the buffer has been corrupted.
    """
    (c0,c1)= _fletcher16(binbuf)
    return (c1 << 8) | c0


@conf.commands.register
def fletcher16_checkbytes(binbuf, offset):
    """ Calculates the Fletcher-16 checkbytes returned as 2 byte binary-string.
    
        Including the bytes into the buffer (at the position marked by offset) the
        global Fletcher-16 checksum of the buffer will be 0. Thus it is easy to verify
        the integrity of the buffer on the receiver side.
        
        For details on the algorithm, see RFC 2328 chapter 12.1.7 and RFC 905 Annex B.
    """
    
    # This is based on the GPLed C implementation in Zebra <http://www.zebra.org/>
    if len(binbuf) < offset:
        raise Exception("Packet too short for checkbytes %d" % len(binbuf))

    binbuf = binbuf[:offset] + "\x00\x00" + binbuf[offset + 2:]
    (c0,c1)= _fletcher16(binbuf)

    x = ((len(binbuf) - offset - 1) * c0 - c1) % 255

    if (x <= 0):
        x += 255

    y = 510 - c0 - x

    if (y > 255):
        y -= 255
    return chr(x) + chr(y)


def warning(x):
    log_runtime.warning(x)

def mac2str(mac):
    return "".join(map(lambda x: chr(int(x,16)), mac.split(":")))

def str2mac(s):
    return ("%02x:"*6)[:-1] % tuple(map(ord, s)) 

def strxor(x,y):
    return "".join(map(lambda x,y:chr(ord(x)^ord(y)),x,y))

# Workarround bug 643005 : https://sourceforge.net/tracker/?func=detail&atid=105470&aid=643005&group_id=5470
try:
    socket.inet_aton("255.255.255.255")
except socket.error:
    def inet_aton(x):
        if x == "255.255.255.255":
            return "\xff"*4
        else:
            return socket.inet_aton(x)
else:
    inet_aton = socket.inet_aton

inet_ntoa = socket.inet_ntoa
try:
    inet_ntop = socket.inet_ntop
    inet_pton = socket.inet_pton
except AttributeError:
    from scapy.pton_ntop import *
    log_loading.info("inet_ntop/pton functions not found. Python IPv6 support not present")


def atol(x):
    try:
        ip = inet_aton(x)
    except socket.error:
        ip = inet_aton(socket.gethostbyname(x))
    return struct.unpack("!I", ip)[0]
def ltoa(x):
    return inet_ntoa(struct.pack("!I", x&0xffffffff))

def itom(x):
    return (0xffffffff00000000L>>x)&0xffffffffL

def do_graph(graph,prog=None,format=None,target=None,type=None,string=None,options=None):
    """do_graph(graph, prog=conf.prog.dot, format="svg",
         target="| conf.prog.display", options=None, [string=1]):
    string: if not None, simply return the graph string
    graph: GraphViz graph description
    format: output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option
    target: filename or redirect. Defaults pipe to Imagemagick's display program
    prog: which graphviz program to use
    options: options to be passed to prog"""
        
    if format is None:
        if WINDOWS:
            format = "png" # use common format to make sure a viewer is installed
        else:
            format = "svg"
    if string:
        return graph
    if type is not None:
        format=type
    if prog is None:
        prog = conf.prog.dot
    start_viewer=False
    if target is None:
        if WINDOWS:
            tempfile = os.tempnam("", "scapy") + "." + format
            target = "> %s" % tempfile
            start_viewer = True
        else:
            target = "| %s" % conf.prog.display
    if format is not None:
        format = "-T %s" % format
    w,r = os.popen2("%s %s %s %s" % (prog,options or "", format or "", target))
    w.write(graph)
    w.close()
    if start_viewer:
        # Workaround for file not found error: We wait until tempfile is written.
        waiting_start = time.time()
        while not os.path.exists(tempfile):
            time.sleep(0.1)
            if time.time() - waiting_start > 3:
                warning("Temporary file '%s' could not be written. Graphic will not be displayed." % tempfile)
                break
        else:  
            if conf.prog.display == conf.prog._default:
                os.startfile(tempfile)
            else:
                subprocess.Popen([conf.prog.display, tempfile])

_TEX_TR = {
    "{":"{\\tt\\char123}",
    "}":"{\\tt\\char125}",
    "\\":"{\\tt\\char92}",
    "^":"\\^{}",
    "$":"\\$",
    "#":"\\#",
    "~":"\\~",
    "_":"\\_",
    "&":"\\&",
    "%":"\\%",
    "|":"{\\tt\\char124}",
    "~":"{\\tt\\char126}",
    "<":"{\\tt\\char60}",
    ">":"{\\tt\\char62}",
    }
    
def tex_escape(x):
    s = ""
    for c in x:
        s += _TEX_TR.get(c,c)
    return s

def colgen(*lstcol,**kargs):
    """Returns a generator that mixes provided quantities forever
    trans: a function to convert the three arguments into a color. lambda x,y,z:(x,y,z) by default"""
    if len(lstcol) < 2:
        lstcol *= 2
    trans = kargs.get("trans", lambda x,y,z: (x,y,z))
    while 1:
        for i in xrange(len(lstcol)):
            for j in xrange(len(lstcol)):
                for k in xrange(len(lstcol)):
                    if i != j or j != k or k != i:
                        yield trans(lstcol[(i+j)%len(lstcol)],lstcol[(j+k)%len(lstcol)],lstcol[(k+i)%len(lstcol)])

def incremental_label(label="tag%05i", start=0):
    while True:
        yield label % start
        start += 1


# Python <= 2.5 do not provide bin() built-in function
try:
    bin(0)
except NameError:
    def _binrepr(val):
        while val:
            yield val & 1
            val >>= 1

    binrepr = lambda val: "".join(reversed([str(bit) for bit in
                                            _binrepr(val)])) or "0"
else:
    binrepr = lambda val: bin(val)[2:]


#########################
#### Enum management ####
#########################

class EnumElement:
    _value=None
    def __init__(self, key, value):
        self._key = key
        self._value = value
    def __repr__(self):
        return "<%s %s[%r]>" % (self.__dict__.get("_name", self.__class__.__name__), self._key, self._value)
    def __getattr__(self, attr):
        return getattr(self._value, attr)
    def __str__(self):
        return self._key
    def __eq__(self, other):
        return self._value == int(other)


class Enum_metaclass(type):
    element_class = EnumElement
    def __new__(cls, name, bases, dct):
        rdict={}
        for k,v in dct.iteritems():
            if type(v) is int:
                v = cls.element_class(k,v)
                dct[k] = v
                rdict[v] = k
        dct["__rdict__"] = rdict
        return super(Enum_metaclass, cls).__new__(cls, name, bases, dct)
    def __getitem__(self, attr):
        return self.__rdict__[attr]
    def __contains__(self, val):
        return val in self.__rdict__
    def get(self, attr, val=None):
        return self.__rdict__.get(attr, val)
    def __repr__(self):
        return "<%s>" % self.__dict__.get("name", self.__name__)



###################
## Object saving ##
###################


def export_object(obj):
    print gzip.zlib.compress(cPickle.dumps(obj,2),9).encode("base64")

def import_object(obj=None):
    if obj is None:
        obj = sys.stdin.read()
    return cPickle.loads(gzip.zlib.decompress(obj.strip().decode("base64")))


def save_object(fname, obj):
    cPickle.dump(obj,gzip.open(fname,"wb"))

def load_object(fname):
    return cPickle.load(gzip.open(fname,"rb"))

@conf.commands.register
def corrupt_bytes(s, p=0.01, n=None):
    """Corrupt a given percentage or number of bytes from a string"""
    s = array.array("B",str(s))
    l = len(s)
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i] = (s[i]+random.randint(1,255))%256
    return s.tostring()

@conf.commands.register
def corrupt_bits(s, p=0.01, n=None):
    """Flip a given percentage or number of bits from a string"""
    s = array.array("B",str(s))
    l = len(s)*8
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i/8] ^= 1 << (i%8)
    return s.tostring()




#############################
## pcap capture file stuff ##
#############################

@conf.commands.register
def wrpcap(filename, pkt, *args, **kargs):
    """Write a list of packets to a pcap file

filename: the name of the file to write packets to, or an open,
          writable file-like object. The file descriptor will be
          closed at the end of the call, so do not use an object you
          do not want to close (e.g., running wrpcap(sys.stdout, [])
          in interactive mode will crash Scapy).
gz: set to 1 to save a gzipped capture
linktype: force linktype value
endianness: "<" or ">", force endianness
sync: do not bufferize writes to the capture file

    """
    with PcapWriter(filename, *args, **kargs) as fdesc:
        fdesc.write(pkt)

@conf.commands.register
def rdpcap(filename, count=-1):
    """Read a pcap or pcapng file and return a packet list

count: read only <count> packets

    """
    with PcapReader(filename) as fdesc:
        return fdesc.read_all(count=count)


class PcapReader_metaclass(type):
    """Metaclass for (Raw)Pcap(Ng)Readers"""

    def __new__(cls, name, bases, dct):
        """The `alternative` class attribute is declared in the PcapNg
        variant, and set here to the Pcap variant.

        """
        newcls = super(PcapReader_metaclass, cls).__new__(cls, name, bases, dct)
        if 'alternative' in dct:
            dct['alternative'].alternative = newcls
        return newcls

    def __call__(cls, filename):
        """Creates a cls instance, use the `alternative` if that
        fails.

        """
        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        filename, fdesc, magic = cls.open(filename)
        try:
            i.__init__(filename, fdesc, magic)
        except Scapy_Exception:
            if "alternative" in cls.__dict__:
                cls = cls.__dict__["alternative"]
                i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
                try:
                    i.__init__(filename, fdesc, magic)
                except Scapy_Exception:
                    try:
                        self.f.seek(-4, 1)
                    except:
                        pass
                    raise Scapy_Exception("Not a supported capture file")

        return i

    @staticmethod
    def open(filename):
        """Open (if necessary) filename, and read the magic."""
        if isinstance(filename, basestring):
            try:
                fdesc = gzip.open(filename,"rb")
                magic = fdesc.read(4)
            except IOError:
                fdesc = open(filename,"rb")
                magic = fdesc.read(4)
        else:
            fdesc = filename
            filename = (fdesc.name
                        if hasattr(fdesc, "name") else
                        "No name")
            magic = fdesc.read(4)
        return filename, fdesc, magic


class RawPcapReader:
    """A stateful pcap reader. Each packet is returned as a string"""
    __metaclass__ = PcapReader_metaclass
    def __init__(self, filename, fdesc, magic):
        self.filename = filename
        self.f = fdesc
        if magic == "\xa1\xb2\xc3\xd4": #big endian
            self.endian = ">"
        elif magic == "\xd4\xc3\xb2\xa1": #little endian
            self.endian = "<"
        else:
            raise Scapy_Exception(
                "Not a pcap capture file (bad magic: %r)" % magic
            )
        hdr = self.f.read(20)
        if len(hdr)<20:
            raise Scapy_Exception("Invalid pcap file (too short)")
        vermaj, vermin, tz, sig, snaplen, linktype = struct.unpack(
            self.endian + "HHIIII", hdr
        )
        self.linktype = linktype

    def __iter__(self):
        return self

    def next(self):
        """implement the iterator protocol on a set of packets in a pcap file"""
        pkt = self.read_packet()
        if pkt == None:
            raise StopIteration
        return pkt


    def read_packet(self, size=MTU):
        """return a single packet read from the file
        
        returns None when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            return None
        sec,usec,caplen,wirelen = struct.unpack(self.endian+"IIII", hdr)
        s = self.f.read(caplen)[:size]
        return s,(sec,usec,wirelen) # caplen = len(s)


    def dispatch(self, callback):
        """call the specified callback routine for each packet read
        
        This is just a convienience function for the main loop
        that allows for easy launching of packet processing in a 
        thread.
        """
        for p in self:
            callback(p)

    def read_all(self,count=-1):
        """return a list of all packets in the pcap file
        """
        res=[]
        while count != 0:
            count -= 1
            p = self.read_packet()
            if p is None:
                break
            res.append(p)
        return res

    def recv(self, size=MTU):
        """ Emulate a socket
        """
        return self.read_packet(size=size)[0]

    def fileno(self):
        return self.f.fileno()

    def close(self):
        return self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tracback):
        self.close()


class PcapReader(RawPcapReader):
    def __init__(self, filename, fdesc, magic):
        RawPcapReader.__init__(self, filename, fdesc, magic)
        try:
            self.LLcls = conf.l2types[self.linktype]
        except KeyError:
            warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype,self.linktype))
            self.LLcls = conf.raw_layer
    def read_packet(self, size=MTU):
        rp = RawPcapReader.read_packet(self, size=size)
        if rp is None:
            return None
        s,(sec,usec,wirelen) = rp
        
        try:
            p = self.LLcls(s)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            p = conf.raw_layer(s)
        p.time = sec+0.000001*usec
        return p
    def read_all(self,count=-1):
        res = RawPcapReader.read_all(self, count)
        import plist
        return plist.PacketList(res,name = os.path.basename(self.filename))
    def recv(self, size=MTU):
        return self.read_packet(size=size)


class RawPcapNgReader(RawPcapReader):
    """A stateful pcapng reader. Each packet is returned as a
    string.

    """

    alternative = RawPcapReader

    def __init__(self, filename, fdesc, magic):
        self.filename = filename
        self.f = fdesc
        # A list of (linktype, snaplen); will be populated by IDBs.
        self.interfaces = []
        self.blocktypes = {
            1: self.read_block_idb,
            6: self.read_block_epb,
        }
        if magic != "\x0a\x0d\x0d\x0a": # PcapNg:
            raise Scapy_Exception(
                "Not a pcapng capture file (bad magic: %r)" % magic
            )
        # see https://github.com/pcapng/pcapng
        blocklen, magic = self.f.read(4), self.f.read(4)
        if magic == "\x1a\x2b\x3c\x4d":
            self.endian = ">"
        elif magic == "\x4d\x3c\x2b\x1a":
            self.endian = "<"
        else:
            raise Scapy_Exception("Not a pcapng capture file (bad magic)")
        self.f.seek(0)

    def read_packet(self, size=MTU):
        """Read blocks until it reaches either EOF or a packet, and
        returns None or (packet, (linktype, sec, usec, wirelen)),
        where packet is a string.

        """
        while True:
            try:
                blocktype, blocklen = struct.unpack(self.endian + "2I",
                                                    self.f.read(8))
            except struct.error:
                return None
            block = self.f.read(blocklen - 12)
            try:
                if (blocklen,) != struct.unpack(self.endian + 'I',
                                                self.f.read(4)):
                    raise Scapy_Exception(
                        "Invalid pcapng block (bad blocklen)"
                    )
            except struct.error:
                return None
            res = self.blocktypes.get(blocktype,
                                      lambda block, size: None)(block, size)
            if res is not None:
                return res

    def read_block_idb(self, block, _):
        """Interface Description Block"""
        self.interfaces.append(struct.unpack(self.endian + "HxxI", block[:8]))

    def read_block_epb(self, block, size):
        """Enhanced Packet Block"""
        intid, sec, usec, caplen, wirelen = struct.unpack(self.endian + "5I",
                                                          block[:20])
        return (block[20:20 + caplen][:size],
                (self.interfaces[intid][0], sec, usec, wirelen))


class PcapNgReader(RawPcapNgReader):

    alternative = PcapReader

    def __init__(self, filename, fdesc, magic):
        RawPcapNgReader.__init__(self, filename, fdesc, magic)

    def read_packet(self, size=MTU):
        rp = RawPcapNgReader.read_packet(self, size=size)
        if rp is None:
            return None
        s, (linktype, sec, usec, wirelen) = rp
        try:
            p = conf.l2types[linktype](s)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            p = conf.raw_layer(s)
        p.time = sec+0.000001*usec
        return p
    def read_all(self,count=-1):
        res = RawPcapNgReader.read_all(self, count)
        import plist
        return plist.PacketList(res, name=os.path.basename(self.filename))
    def recv(self, size=MTU):
        return self.read_packet()


class RawPcapWriter:
    """A stream PCAP writer with more control than wrpcap()"""
    def __init__(self, filename, linktype=None, gz=False, endianness="", append=False, sync=False):
        """
filename: the name of the file to write packets to, or an open,
          writable file-like object.
linktype: force linktype to a given value. If None, linktype is taken
          from the first writter packet
gz: compress the capture on the fly
endianness: force an endianness (little:"<", big:">"). Default is native
append: append packets to the capture file instead of truncating it
sync: do not bufferize writes to the capture file

        """
        
        self.linktype = linktype
        self.header_present = 0
        self.append = append
        self.gz = gz
        self.endian = endianness
        self.sync = sync
        bufsz=4096
        if sync:
            bufsz = 0

        if isinstance(filename, basestring):
            self.filename = filename
            self.f = [open,gzip.open][gz](filename,append and "ab" or "wb", gz and 9 or bufsz)
        else:
            self.f = filename
            self.filename = (filename.name
                             if hasattr(filename, "name") else
                             "No name")

    def fileno(self):
        return self.f.fileno()

    def _write_header(self, pkt):
        self.header_present=1

        if self.append:
            # Even if prone to race conditions, this seems to be
            # safest way to tell whether the header is already present
            # because we have to handle compressed streams that
            # are not as flexible as basic files
            g = [open,gzip.open][self.gz](self.filename,"rb")
            if g.read(16):
                return
            
        self.f.write(struct.pack(self.endian+"IHHIIII", 0xa1b2c3d4L,
                                 2, 4, 0, 0, MTU, self.linktype))
        self.f.flush()
    

    def write(self, pkt):
        """accepts either a single packet or a list of packets to be
        written to the dumpfile

        """
        if type(pkt) is str:
            if not self.header_present:
                self._write_header(pkt)
            self._write_packet(pkt)
        else:
            pkt = pkt.__iter__()
            if not self.header_present:
                try:
                    p = pkt.next()
                except StopIteration:
                    self._write_header("")
                    return
                self._write_header(p)
                self._write_packet(p)
            for p in pkt:
                self._write_packet(p)

    def _write_packet(self, packet, sec=None, usec=None, caplen=None, wirelen=None):
        """writes a single packet to the pcap file
        """
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen
        if sec is None or usec is None:
            t=time.time()
            it = int(t)
            if sec is None:
                sec = it
            if usec is None:
                usec = int(round((t-it)*1000000))
        self.f.write(struct.pack(self.endian+"IIII", sec, usec, caplen, wirelen))
        self.f.write(packet)
        if self.sync:
            self.f.flush()

    def flush(self):
        return self.f.flush()

    def close(self):
        return self.f.close()

    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, tracback):
        self.flush()
        self.close()


class PcapWriter(RawPcapWriter):
    """A stream PCAP writer with more control than wrpcap()"""
    def _write_header(self, pkt):
        if self.linktype == None:
            try:
                self.linktype = conf.l2types[pkt.__class__]
            except KeyError:
                warning("PcapWriter: unknown LL type for %s. Using type 1 (Ethernet)" % pkt.__class__.__name__)
                self.linktype = 1
        RawPcapWriter._write_header(self, pkt)

    def _write_packet(self, packet):
        sec = int(packet.time)
        usec = int(round((packet.time-sec)*1000000))
        s = str(packet)
        caplen = len(s)
        RawPcapWriter._write_packet(self, s, sec, usec, caplen, caplen)


re_extract_hexcap = re.compile("^((0x)?[0-9a-fA-F]{2,}[ :\t]{,3}|) *(([0-9a-fA-F]{2} {,2}){,16})")

def import_hexcap():
    p = ""
    try:
        while 1:
            l = raw_input().strip()
            try:
                p += re_extract_hexcap.match(l).groups()[2]
            except:
                warning("Parsing error during hexcap")
                continue
    except EOFError:
        pass
    
    p = p.replace(" ","")
    return p.decode("hex")
        


@conf.commands.register
def wireshark(pktlist):
    """Run wireshark on a list of packets"""
    f = get_temp_file()
    wrpcap(f, pktlist)
    subprocess.Popen([conf.prog.wireshark, "-r", f])

@conf.commands.register
def hexedit(x):
    x = str(x)
    f = get_temp_file()
    open(f,"w").write(x)
    subprocess.call([conf.prog.hexedit, f])
    x = open(f).read()
    os.unlink(f)
    return x

def __make_table(yfmtfunc, fmtfunc, endline, list, fxyz, sortx=None, sorty=None, seplinefunc=None):
    vx = {} 
    vy = {} 
    vz = {}
    vxf = {}
    vyf = {}
    l = 0
    for e in list:
        xx,yy,zz = map(str, fxyz(e))
        l = max(len(yy),l)
        vx[xx] = max(vx.get(xx,0), len(xx), len(zz))
        vy[yy] = None
        vz[(xx,yy)] = zz

    vxk = vx.keys()
    vyk = vy.keys()
    if sortx:
        vxk.sort(sortx)
    else:
        try:
            vxk.sort(lambda x,y:int(x)-int(y))
        except:
            try:
                vxk.sort(lambda x,y: cmp(atol(x),atol(y)))
            except:
                vxk.sort()
    if sorty:
        vyk.sort(sorty)
    else:
        try:
            vyk.sort(lambda x,y:int(x)-int(y))
        except:
            try:
                vyk.sort(lambda x,y: cmp(atol(x),atol(y)))
            except:
                vyk.sort()


    if seplinefunc:
        sepline = seplinefunc(l, map(lambda x:vx[x],vxk))
        print sepline

    fmt = yfmtfunc(l)
    print fmt % "",
    for x in vxk:
        vxf[x] = fmtfunc(vx[x])
        print vxf[x] % x,
    print endline
    if seplinefunc:
        print sepline
    for y in vyk:
        print fmt % y,
        for x in vxk:
            print vxf[x] % vz.get((x,y), "-"),
        print endline
    if seplinefunc:
        print sepline

def make_table(*args, **kargs):
    __make_table(lambda l:"%%-%is" % l, lambda l:"%%-%is" % l, "", *args, **kargs)
    
def make_lined_table(*args, **kargs):
    __make_table(lambda l:"%%-%is |" % l, lambda l:"%%-%is |" % l, "",
                 seplinefunc=lambda a,x:"+".join(map(lambda y:"-"*(y+2), [a-1]+x+[-2])),
                 *args, **kargs)

def make_tex_table(*args, **kargs):
    __make_table(lambda l: "%s", lambda l: "& %s", "\\\\", seplinefunc=lambda a,x:"\\hline", *args, **kargs)

