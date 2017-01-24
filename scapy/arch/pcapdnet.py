## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Packet sending and receiving with libdnet and libpcap/WinPcap.
"""

import time,struct,sys
import socket
if not sys.platform.startswith("win"):
    from fcntl import ioctl

from scapy.data import *
from scapy.config import conf
from scapy.utils import mac2str
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception, log_loading, warning
import scapy.arch

if conf.use_winpcapy:
  #mostly code from https://github.com/phaethon/scapy translated to python2.X
  try:
    from scapy.arch.winpcapy import *
    def winpcapy_get_if_list():
      err = create_string_buffer(PCAP_ERRBUF_SIZE)
      devs = POINTER(pcap_if_t)()
      ret = []
      if pcap_findalldevs(byref(devs), err) < 0:
        return ret
      try:
        p = devs
        while p:
          ret.append(p.contents.name.decode('ascii'))
          p = p.contents.next
        return ret
      finally:
        pcap_freealldevs(devs)

  except OSError as e:
    def winpcapy_get_if_list():
        return []
    conf.use_winpcapy = False
    if conf.interactive:
      log_loading.warning("wpcap.dll is not installed. You won't be able to send/recieve packets. Visit the scapy's doc to install it")

  # From BSD net/bpf.h
  #BIOCIMMEDIATE=0x80044270
  BIOCIMMEDIATE=-2147204496

  class PcapTimeoutElapsed(Scapy_Exception):
      pass

  def get_if_raw_hwaddr(iff):
    err = create_string_buffer(PCAP_ERRBUF_SIZE)
    devs = POINTER(pcap_if_t)()
    ret = "\0\0\0\0\0\0"
    
    if pcap_findalldevs(byref(devs), err) < 0:
      return ret
    try:
      p = devs
      while p:
        if p.contents.name.endswith(iff):
          a = p.contents.addresses
          while a:
            if hasattr(socket, 'AF_LINK') and a.contents.addr.contents.sa_family == socket.AF_LINK:
              ap = a.contents.addr
              val = cast(ap, POINTER(sockaddr_dl))
              ret = str(val.contents.sdl_data[ val.contents.sdl_nlen : val.contents.sdl_nlen + val.contents.sdl_alen ])
            a = a.contents.next
          break
        p = p.contents.next
      return ret
    finally:
      pcap_freealldevs(devs)
  def get_if_raw_addr(iff):
    err = create_string_buffer(PCAP_ERRBUF_SIZE)
    devs = POINTER(pcap_if_t)()
    ret = "\0\0\0\0"

    if pcap_findalldevs(byref(devs), err) < 0:
      return ret
    try:
      p = devs
      while p:
        if p.contents.name.endswith(iff.guid):
          a = p.contents.addresses
          while a:
            if a.contents.addr.contents.sa_family == socket.AF_INET:
              ap = a.contents.addr
              val = cast(ap, POINTER(sockaddr_in))
              #ret = bytes(val.contents.sin_addr[:4])
              ret = "".join([chr(x) for x in val.contents.sin_addr[:4]])
            a = a.contents.next
          break
        p = p.contents.next
      return ret
    finally:
      pcap_freealldevs(devs)
  if conf.use_winpcapy:
      get_if_list = winpcapy_get_if_list
  def in6_getifaddr():
    err = create_string_buffer(PCAP_ERRBUF_SIZE)
    devs = POINTER(pcap_if_t)()
    ret = []
    if pcap_findalldevs(byref(devs), err) < 0:
      return ret
    try:
      p = devs
      ret = []
      while p:
        a = p.contents.addresses
        while a:
          if a.contents.addr.contents.sa_family == socket.AF_INET6:
            ap = a.contents.addr
            val = cast(ap, POINTER(sockaddr_in6))
            addr = socket.inet_ntop(socket.AF_INET6, str(val.contents.sin6_addr[:]))
            scope = scapy.utils6.in6_getscope(addr)
            ret.append((addr, scope, p.contents.name.decode('ascii')))
          a = a.contents.next
        p = p.contents.next
      return ret
    finally:
      pcap_freealldevs(devs)

  from ctypes import POINTER, byref, create_string_buffer
  class _PcapWrapper_pypcap:
      def __init__(self, device, snaplen, promisc, to_ms):
          self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
          self.iface = create_string_buffer(device)
          self.pcap = pcap_open_live(self.iface, snaplen, promisc, to_ms, self.errbuf)
          self.header = POINTER(pcap_pkthdr)()
          self.pkt_data = POINTER(c_ubyte)()
          self.bpf_program = bpf_program()
      def next(self):
          c = pcap_next_ex(self.pcap, byref(self.header), byref(self.pkt_data))
          if not c > 0:
              return
          ts = self.header.contents.ts.tv_sec
          pkt = "".join([ chr(i) for i in self.pkt_data[:self.header.contents.len] ])
          #pkt = bytes(self.pkt_data[:self.header.contents.len])
          return ts, pkt
      def datalink(self):
          return pcap_datalink(self.pcap)
      def fileno(self):
          if sys.platform.startswith("win"):
            log_loading.error("Cannot get selectable PCAP fd on Windows")
            return 0
          return pcap_get_selectable_fd(self.pcap) 
      def setfilter(self, f):
          filter_exp = create_string_buffer(f)
          if pcap_compile(self.pcap, byref(self.bpf_program), filter_exp, 0, -1) == -1:
            log_loading.error("Could not compile filter expression %s" % f)
            return False
          else:
            if pcap_setfilter(self.pcap, byref(self.bpf_program)) == -1:
              log_loading.error("Could not install filter %s" % f)
              return False
          return True
      def setnonblock(self, i):
          pcap_setnonblock(self.pcap, i, self.errbuf)
      def send(self, x):
          pcap_sendpacket(self.pcap, x, len(x))
      def close(self):
          pcap_close(self.pcap)
  open_pcap = lambda *args,**kargs: _PcapWrapper_pypcap(*args,**kargs)
  class PcapTimeoutElapsed(Scapy_Exception):
      pass

  class L2pcapListenSocket(SuperSocket):
      desc = "read packets at layer 2 using libpcap"
      def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
          self.type = type
          self.outs = None
          self.iface = iface
          if iface is None:
              iface = conf.iface
          if promisc is None:
              promisc = conf.sniff_promisc
          self.promisc = promisc
          self.ins = open_pcap(iface, 1600, self.promisc, 100)
          try:
              ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
          except:
              pass
          if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
              if conf.except_filter:
                  if filter:
                      filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                  else:
                      filter = "not (%s)" % conf.except_filter
              if filter:
                  self.ins.setfilter(filter)
  
      def close(self):
          self.ins.close()
          
      def recv(self, x=MTU):
          ll = self.ins.datalink()
          if ll in conf.l2types:
              cls = conf.l2types[ll]
          else:
              cls = conf.default_l2
              warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))

          pkt = None
          while pkt is None:
              pkt = self.ins.next()
              if pkt is not None:
                  ts,pkt = pkt
              if scapy.arch.WINDOWS and pkt is None:
                  raise PcapTimeoutElapsed
          try:
              pkt = cls(pkt)
          except KeyboardInterrupt:
              raise
          except:
              if conf.debug_dissector:
                  raise
              pkt = conf.raw_layer(pkt)
          pkt.time = ts
          return pkt
  
      def send(self, x):
          raise Scapy_Exception("Can't send anything with L2pcapListenSocket")
  

  conf.L2listen = L2pcapListenSocket
  class L2pcapSocket(SuperSocket):
      desc = "read/write packets at layer 2 using only libpcap"
      def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None, nofilter=0):
          if iface is None:
              iface = conf.iface
          self.iface = iface
          if promisc is None:
              promisc = 0
          self.promisc = promisc
          self.ins = open_pcap(iface, 1600, self.promisc, 100)
          try:
              ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
          except:
              pass
          if nofilter:
              if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                  filter = "ether proto %i" % type
              else:
                  filter = None
          else:
              if conf.except_filter:
                  if filter:
                      filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                  else:
                      filter = "not (%s)" % conf.except_filter
              if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                  if filter:
                      filter = "(ether proto %i) and (%s)" % (type,filter)
                  else:
                      filter = "ether proto %i" % type
          if filter:
              self.ins.setfilter(filter)
      def send(self, x):
          sx = str(x)
          if hasattr(x, "sent_time"):
              x.sent_time = time.time()
          return self.ins.send(sx)

      def recv(self,x=MTU):
          ll = self.ins.datalink()
          if ll in conf.l2types:
              cls = conf.l2types[ll]
          else:
              cls = conf.default_l2
              warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
  
          pkt = self.ins.next()
          if pkt is not None:
              ts,pkt = pkt
          if pkt is None:
              return
          
          try:
              pkt = cls(pkt)
          except KeyboardInterrupt:
              raise
          except:
              if conf.debug_dissector:
                  raise
              pkt = conf.raw_layer(pkt)
          pkt.time = ts
          return pkt
  
      def nonblock_recv(self):
          self.ins.setnonblock(1)
          p = self.recv(MTU)
          self.ins.setnonblock(0)
          return p
  
      def close(self):
          if hasattr(self, "ins"):
              self.ins.close()
          if hasattr(self, "outs"):
              self.outs.close()

  class L3pcapSocket(L2pcapSocket):
      desc = "read/write packets at layer 3 using only libpcap"
      #def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
      #    L2pcapSocket.__init__(self, iface, type, filter, nofilter)
      def recv(self, x = MTU):
          r = L2pcapSocket.recv(self, x) 
          if r:
            return r.payload
          else:
            return
      def send(self, x):
          cls = conf.l2types[1]
          sx = str(cls()/x)
          if hasattr(x, "sent_time"):
              x.sent_time = time.time()
          return self.ins.send(sx)
  conf.L2socket=L2pcapSocket
  conf.L3socket=L3pcapSocket
    
if conf.use_pcap:
    try:
        import pcap
    except ImportError,e:
        try:
            import pcapy as pcap
        except ImportError,e2:
            if conf.interactive:
                log_loading.error("Unable to import pcap module: %s/%s" % (e,e2))
                conf.use_pcap = False
            else:
                raise
    if conf.use_pcap:
        
        # From BSD net/bpf.h
        #BIOCIMMEDIATE=0x80044270
        BIOCIMMEDIATE=-2147204496

        if hasattr(pcap,"pcap"): # python-pypcap
            class _PcapWrapper_pypcap:
                def __init__(self, device, snaplen, promisc, to_ms):
                    try:
                        self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1, timeout_ms=to_ms)
                    except TypeError:
                        # Older pypcap versions do not support the timeout_ms argument
                        self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1)                    
                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)
                def __del__(self):
                    warning("__del__: don't know how to close the file descriptor. Bugs ahead ! Please report this bug.")
                def next(self):
                    c = self.pcap.next()
                    if c is None:
                        return
                    ts, pkt = c
                    return ts, str(pkt)
            open_pcap = lambda *args,**kargs: _PcapWrapper_pypcap(*args,**kargs)
        elif hasattr(pcap,"pcapObject"): # python-libpcap
            class _PcapWrapper_libpcap:
                def __init__(self, *args, **kargs):
                    self.pcap = pcap.pcapObject()
                    self.pcap.open_live(*args, **kargs)
                def setfilter(self, filter):
                    self.pcap.setfilter(filter, 0, 0)
                def next(self):
                    c = self.pcap.next()
                    if c is None:
                        return
                    l,pkt,ts = c 
                    return ts,pkt
                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)
                def __del__(self):
                    fd = self.pcap.fileno()
                    os.close(fd)
            open_pcap = lambda *args,**kargs: _PcapWrapper_libpcap(*args,**kargs)
        elif hasattr(pcap,"open_live"): # python-pcapy
            class _PcapWrapper_pcapy:
                def __init__(self, *args, **kargs):
                    self.pcap = pcap.open_live(*args, **kargs)
                def next(self):
                    try:
                        c = self.pcap.next()
                    except pcap.PcapError:
                        return None
                    else:
                        h,p = c
                        if h is None:
                            return
                        s,us = h.getts()
                        return (s+0.000001*us), p
                def fileno(self):
                    warning("fileno: pcapy API does not permit to get capure file descriptor. Bugs ahead! Press Enter to trigger packet reading")
                    return 0
                def __getattr__(self, attr):
                    return getattr(self.pcap, attr)
                def __del__(self):
                    warning("__del__: don't know how to close the file descriptor. Bugs ahead ! Please report this bug.")
            open_pcap = lambda *args,**kargs: _PcapWrapper_pcapy(*args,**kargs)

        
        class PcapTimeoutElapsed(Scapy_Exception):
            pass
    
        class L2pcapListenSocket(SuperSocket):
            desc = "read packets at layer 2 using libpcap"
            def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
                self.type = type
                self.outs = None
                self.iface = iface
                if iface is None:
                    iface = conf.iface
                if promisc is None:
                    promisc = conf.sniff_promisc
                self.promisc = promisc
                self.ins = open_pcap(iface, 1600, self.promisc, 100)
                try:
                    ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
                except:
                    pass
                if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
                    if conf.except_filter:
                        if filter:
                            filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                        else:
                            filter = "not (%s)" % conf.except_filter
                    if filter:
                        self.ins.setfilter(filter)
        
            def close(self):
                del(self.ins)
                
            def recv(self, x=MTU):
                ll = self.ins.datalink()
                if ll in conf.l2types:
                    cls = conf.l2types[ll]
                else:
                    cls = conf.default_l2
                    warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
        
                pkt = self.ins.next()
                if scapy.arch.WINDOWS and pkt is None:
                        raise PcapTimeoutElapsed
                if pkt is not None:
                    ts,pkt = pkt
                    try:
                        pkt = cls(pkt)
                    except KeyboardInterrupt:
                        raise
                    except:
                        if conf.debug_dissector:
                            raise
                        pkt = conf.raw_layer(pkt)
                    pkt.time = ts
                return pkt
        
            def send(self, x):
                raise Scapy_Exception("Can't send anything with L2pcapListenSocket")
        
    
        conf.L2listen = L2pcapListenSocket


if conf.use_dnet:
    try:
        try:
            # First try to import dnet
            import dnet
        except ImportError:
            # Then, try to import dumbnet as dnet
            import dumbnet as dnet
    except ImportError,e:
        if conf.interactive:
            log_loading.error("Unable to import dnet module: %s" % e)
            conf.use_dnet = False
            def get_if_raw_hwaddr(iff):
                "dummy"
                return (0,"\0\0\0\0\0\0")
            def get_if_raw_addr(iff):
                "dummy"
                return "\0\0\0\0"
            def get_if_list():
                "dummy"
                return []
        else:
            raise
    else:
        def get_if_raw_hwaddr(iff):
            """Return a tuple containing the link type and the raw hardware
               address corresponding to the interface 'iff'"""

            if iff == scapy.arch.LOOPBACK_NAME:
                return (ARPHDR_LOOPBACK, '\x00'*6)

            # Retrieve interface information
            try:
                l = dnet.intf().get(iff)
                link_addr = l["link_addr"]
            except:
                raise Scapy_Exception("Error in attempting to get hw address"
                                      " for interface [%s]" % iff)

            if hasattr(link_addr, "type"):
                # Legacy dnet module
                return link_addr.type, link_addr.data

            else:
                # dumbnet module
                mac = mac2str(str(link_addr))

                # Adjust the link type
                if l["type"] == 6:  # INTF_TYPE_ETH from dnet
                    return (ARPHDR_ETHER, mac)

                return (l["type"], mac)

        def get_if_raw_addr(ifname):
            i = dnet.intf()
            try:
                return i.get(ifname)["addr"].data
            except OSError:
                warning("No MAC address found on %s !" % ifname)
                return "\0\0\0\0"


        def get_if_list():
            return [i.get("name", None) for i in dnet.intf()]


if conf.use_pcap and conf.use_dnet:
    class L3dnetSocket(SuperSocket):
        desc = "read/write packets at layer 3 using libdnet and libpcap"
        def __init__(self, type = ETH_P_ALL, promisc=None, filter=None, iface=None, nofilter=0):
            self.iflist = {}
            self.intf = dnet.intf()
            if iface is None:
                iface = conf.iface
            self.iface = iface
            if promisc is None:
                promisc = 0
            self.promisc = promisc
            self.ins = open_pcap(iface, 1600, self.promisc, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            if nofilter:
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    filter = "ether proto %i" % type
                else:
                    filter = None
            else:
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    if filter:
                        filter = "(ether proto %i) and (%s)" % (type,filter)
                    else:
                        filter = "ether proto %i" % type
            if filter:
                self.ins.setfilter(filter)
        def send(self, x):
            iff,a,gw  = x.route()
            if iff is None:
                iff = conf.iface
            ifs,cls = self.iflist.get(iff,(None,None))
            if ifs is None:
                iftype = self.intf.get(iff)["type"]
                if iftype == dnet.INTF_TYPE_ETH:
                    try:
                        cls = conf.l2types[1]
                    except KeyError:
                        warning("Unable to find Ethernet class. Using nothing")
                    ifs = dnet.eth(iff)
                else:
                    ifs = dnet.ip()
                self.iflist[iff] = ifs,cls
            if cls is None:
                sx = str(x)
            else:
                sx = str(cls()/x)
            x.sent_time = time.time()
            ifs.send(sx)
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
    
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
    
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt.payload
    
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv()
            self.ins.setnonblock(0)
            return p
    
        def close(self):
            if hasattr(self, "ins"):
                del(self.ins)
            if hasattr(self, "outs"):
                del(self.outs)
    
    class L2dnetSocket(SuperSocket):
        desc = "read/write packets at layer 2 using libdnet and libpcap"
        def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None, nofilter=0):
            if iface is None:
                iface = conf.iface
            self.iface = iface
            if promisc is None:
                promisc = 0
            self.promisc = promisc
            self.ins = open_pcap(iface, 1600, self.promisc, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            if nofilter:
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    filter = "ether proto %i" % type
                else:
                    filter = None
            else:
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    if filter:
                        filter = "(ether proto %i) and (%s)" % (type,filter)
                    else:
                        filter = "ether proto %i" % type
            if filter:
                self.ins.setfilter(filter)
            self.outs = dnet.eth(iface)
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
    
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
            
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt
    
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv(MTU)
            self.ins.setnonblock(0)
            return p
    
        def close(self):
            if hasattr(self, "ins"):
                del(self.ins)
            if hasattr(self, "outs"):
                del(self.outs)

    conf.L3socket=L3dnetSocket
    conf.L2socket=L2dnetSocket

        
    
