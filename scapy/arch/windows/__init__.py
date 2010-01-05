## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import os,re,sys,socket,time
from glob import glob
from scapy.config import conf,ConfClass
from scapy.error import Scapy_Exception,log_loading,log_runtime
from scapy.utils import atol, inet_aton, inet_ntoa, PcapReader
from scapy.base_classes import Gen, Net, SetGen
import scapy.plist as plist
from scapy.sendrecv import debug, srp1
from scapy.layers.l2 import Ether, ARP
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP

conf.use_pcap = 1
conf.use_dnet = 1
from scapy.arch import pcapdnet
from scapy.arch.pcapdnet import *

LOOPBACK_NAME="lo0"
WINDOWS = True


def _where(filename, dirs=[], env="PATH"):
    """Find file in current dir or system path"""
    if not isinstance(dirs, list):
        dirs = [dirs]
    if glob(filename):
        return filename
    paths = [os.curdir] + os.environ[env].split(os.path.pathsep) + dirs
    for path in paths:
        for match in glob(os.path.join(path, filename)):
            if match:
                return os.path.normpath(match)
    raise IOError("File not found: %s" % filename)

def win_find_exe(filename, installsubdir=None, env="ProgramFiles"):
    """Find executable in current dir, system path or given ProgramFiles subdir"""
    for fn in [filename, filename+".exe"]:
        try:
            if installsubdir is None:
                path = _where(fn)
            else:
                path = _where(fn, dirs=[os.path.join(os.environ[env], installsubdir)])
        except IOError:
            path = filename
        else:
            break        
    return path


class WinProgPath(ConfClass):
    _default = "<System default>"
    # We try some magic to find the appropriate executables
    pdfreader = win_find_exe("AcroRd32") 
    psreader = win_find_exe("gsview32.exe", "Ghostgum/gsview")
    dot = win_find_exe("dot", "ATT/Graphviz/bin")
    tcpdump = win_find_exe("windump")
    tcpreplay = win_find_exe("tcpreplay")
    display = _default
    hexedit = win_find_exe("hexer")
    wireshark = win_find_exe("wireshark", "wireshark")

conf.prog = WinProgPath()



import _winreg


    
class PcapNameNotFoundError(Scapy_Exception):
    pass    

class NetworkInterface(object):
    """A network interface of your local host"""
    
    def __init__(self, dnetdict=None):
        self.name = None
        self.ip = None
        self.mac = None
        self.pcap_name = None
        self.win_name = None
        self.uuid = None
        self.dnetdict = dnetdict
        if dnetdict is not None:
            self.update(dnetdict)
        
    def update(self, dnetdict):
        """Update info about network interface according to given dnet dictionary"""
        self.name = dnetdict["name"]
        # Other attributes are optional
        try:
            self.ip = socket.inet_ntoa(dnetdict["addr"].ip)
        except (KeyError, AttributeError, NameError):
            pass
        try:
            self.mac = dnetdict["link_addr"]
        except KeyError:
            pass
        self._update_pcapdata()
    
    def _update_pcapdata(self):
        """Supplement more info from pypcap and the Windows registry"""
        
        # XXX: We try eth0 - eth29 by bruteforce and match by IP address, 
        # because only the IP is available in both pypcap and dnet.
        # This may not work with unorthodox network configurations and is
        # slow because we have to walk through the Windows registry.
        for n in range(30):
            guess = "eth%s" % n
            win_name = pcapdnet.pcap.ex_name(guess)
            if win_name.endswith("}"):
                try:
                    uuid = win_name[win_name.index("{"):win_name.index("}")+1]
                    keyname = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%s" % uuid
                    try:
                        key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, keyname)
                    except WindowsError:
                        log_loading.debug("Couldn't open 'HKEY_LOCAL_MACHINE\\%s' (for guessed pcap iface name '%s')." % (keyname, guess))
                        continue
                    try:    
                        fixed_ip = _winreg.QueryValueEx(key, "IPAddress")[0][0].encode("utf-8")
                    except (WindowsError, UnicodeDecodeError, IndexError):
                        fixed_ip = None
                    try:
                        dhcp_ip = _winreg.QueryValueEx(key, "DhcpIPAddress")[0].encode("utf-8")
                    except (WindowsError, UnicodeDecodeError, IndexError):
                        dhcp_ip = None
                    # "0.0.0.0" or None means the value is not set (at least not correctly).
                    # If both fixed_ip and dhcp_ip are set, fixed_ip takes precedence 
                    if fixed_ip is not None and fixed_ip != "0.0.0.0":
                        ip = fixed_ip
                    elif dhcp_ip is not None and dhcp_ip != "0.0.0.0":
                        ip = dhcp_ip
                    else:
                        continue
                except IOError:
                    continue
                else:
                    if ip == self.ip:
                        self.pcap_name = guess
                        self.win_name = win_name
                        self.uuid = uuid
                        break
        else:
            raise PcapNameNotFoundError
    
    def __repr__(self):
        return "<%s: %s %s %s pcap_name=%s win_name=%s>" % (self.__class__.__name__,
                     self.name, self.ip, self.mac, self.pcap_name, self.win_name)

from UserDict import IterableUserDict

class NetworkInterfaceDict(IterableUserDict):
    """Store information about network interfaces and convert between names""" 
    
    def load_from_dnet(self):
        """Populate interface table via dnet"""
        for i in pcapdnet.dnet.intf():
            try:
                # XXX: Only Ethernet for the moment: localhost is not supported by dnet and pcap
                # We only take interfaces that have an IP address, because the IP
                # is used for the mapping between dnet and pcap interface names
                # and this significantly improves Scapy's startup performance
                if i["name"].startswith("eth") and "addr" in i:
                    self.data[i["name"]] = NetworkInterface(i)
            except (KeyError, PcapNameNotFoundError):
                pass
        if len(self.data) == 0:
            log_loading.warning("No match between your pcap and dnet network interfaces found. "
                                "You probably won't be able to send packets. "
                                "Deactivating unneeded interfaces and restarting Scapy might help.")
    
    def pcap_name(self, devname):
        """Return pypcap device name for given libdnet/Scapy device name
        
        This mapping is necessary because pypcap numbers the devices differently."""
        
        try:
            pcap_name = self.data[devname].pcap_name
        except KeyError:
            raise ValueError("Unknown network interface %r" % devname)
        else:
            return pcap_name
            
    def devname(self, pcap_name):
        """Return libdnet/Scapy device name for given pypcap device name
        
        This mapping is necessary because pypcap numbers the devices differently."""
        
        for devname, iface in self.items():
            if iface.pcap_name == pcap_name:
                return iface.name
        raise ValueError("Unknown pypcap network interface %r" % pcap_name)
    
    def show(self, resolve_mac=True):
        """Print list of available network interfaces in human readable form"""
        print "%s  %s  %s" % ("IFACE".ljust(5), "IP".ljust(15), "MAC")
        for iface_name in sorted(self.data.keys()):
            dev = self.data[iface_name]
            mac = str(dev.mac)
            if resolve_mac:
                mac = conf.manufdb._resolve_MAC(mac)
            print "%s  %s  %s" % (str(dev.name).ljust(5), str(dev.ip).ljust(15), mac)     
            
ifaces = NetworkInterfaceDict()
ifaces.load_from_dnet()

def pcap_name(devname):
    """Return pypcap device name for given libdnet/Scapy device name"""  
    try:
        pcap_name = ifaces.pcap_name(devname)
    except ValueError:
        # pcap.pcap() will choose a sensible default for sniffing if iface=None
        pcap_name = None
    return pcap_name            

def devname(pcap_name):
    """Return libdnet/Scapy device name for given pypcap device name"""
    return ifaces.devname(pcap_name)
    
def show_interfaces(resolve_mac=True):
    """Print list of available network interfaces"""
    return ifaces.show(resolve_mac)

_orig_open_pcap = pcapdnet.open_pcap
pcapdnet.open_pcap = lambda iface,*args,**kargs: _orig_open_pcap(pcap_name(iface),*args,**kargs)

def read_routes():
    ok = 0
    routes = []
    ip = '(\d+\.\d+\.\d+\.\d+)'
    # On Vista and Windows 7 the gateway can be IP or 'On-link'.
    # But the exact 'On-link' string depends on the locale, so we allow any text.
    gw_pattern = '(.+)'
    metric_pattern = "(\d+)"
    delim = "\s+"        # The columns are separated by whitespace
    netstat_line = delim.join([ip, ip, gw_pattern, ip, metric_pattern])
    pattern = re.compile(netstat_line)
    f=os.popen("netstat -rn")
    for l in f.readlines():
        match = re.search(pattern,l)
        if match:
            dest   = match.group(1)
            mask   = match.group(2)
            gw     = match.group(3)
            netif  = match.group(4)
            metric = match.group(5)
            try:
                intf = pcapdnet.dnet.intf().get_dst(pcapdnet.dnet.addr(type=2, addrtxt=dest))
            except OSError:
                log_loading.warning("Building Scapy's routing table: Couldn't get outgoing interface for destination %s" % dest)
                continue               
            if not intf.has_key("addr"):
                break
            addr = str(intf["addr"])
            addr = addr.split("/")[0]
            
            dest = atol(dest)
            mask = atol(mask)
            # If the gateway is no IP we assume it's on-link
            gw_ipmatch = re.search('\d+\.\d+\.\d+\.\d+', gw)
            if gw_ipmatch:
                gw = gw_ipmatch.group(0)
            else:
                gw = netif
            routes.append((dest,mask,gw, str(intf["name"]), addr))
    f.close()
    return routes

def read_routes6():
    return []

def getmacbyip(ip, chainCC=0):
    """Return MAC address corresponding to a given IP address"""
    if isinstance(ip,Net):
        ip = iter(ip).next()
    tmp = map(ord, inet_aton(ip))
    if (tmp[0] & 0xf0) == 0xe0: # mcast @
        return "01:00:5e:%.2x:%.2x:%.2x" % (tmp[1]&0x7f,tmp[2],tmp[3])
    iff,a,gw = conf.route.route(ip)
    if ( (iff == LOOPBACK_NAME) or (ip == conf.route.get_if_bcast(iff)) ):
        return "ff:ff:ff:ff:ff:ff"
    # Windows uses local IP instead of 0.0.0.0 to represent locally reachable addresses
    ifip = str(pcapdnet.dnet.intf().get(iff)['addr'])
    if gw != ifip.split('/')[0]:
        ip = gw

    mac = conf.netcache.arp_cache.get(ip)
    if mac:
        return mac

    res = srp1(Ether(dst=ETHER_BROADCAST)/ARP(op="who-has", pdst=ip),
               type=ETH_P_ARP,
               iface = iff,
               timeout=2,
               verbose=0,
               chainCC=chainCC,
               nofilter=1)
    if res is not None:
        mac = res.payload.hwsrc
        conf.netcache.arp_cache[ip] = mac
        return mac
    return None

import scapy.layers.l2
scapy.layers.l2.getmacbyip = getmacbyip

try:
    import readline
    console = readline.GetOutputFile()
except (ImportError, AttributeError):
    log_loading.info("Could not get readline console. Will not interpret ANSI color codes.") 
else:
    conf.readfunc = readline.rl.readline
    orig_stdout = sys.stdout
    sys.stdout = console





def sndrcv(pks, pkt, timeout = 2, inter = 0, verbose=None, chainCC=0, retry=0, multi=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
        
    if verbose is None:
        verbose = conf.verb
    debug.recv = plist.PacketList([],"Unanswered")
    debug.sent = plist.PacketList([],"Sent")
    debug.match = plist.SndRcvList([])
    nbrecv=0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    all_stimuli = tobesent = [p for p in pkt]
    notans = len(tobesent)

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]
    if retry < 0:
        retry = -retry
        autostop=retry
    else:
        autostop=0


    while retry >= 0:
        found=0
    
        if timeout < 0:
            timeout = None

        pid=1
        try:
            if WINDOWS or pid == 0:
                try:
                    try:
                        i = 0
                        if verbose:
                            print "Begin emission:"
                        for p in tobesent:
                            pks.send(p)
                            i += 1
                            time.sleep(inter)
                        if verbose:
                            print "Finished to send %i packets." % i
                    except SystemExit:
                        pass
                    except KeyboardInterrupt:
                        pass
                    except:
                        log_runtime.exception("--- Error sending packets")
                        log_runtime.info("--- Error sending packets")
                finally:
                    try:
                        sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
                    except:
                        pass
            if WINDOWS or pid > 0:
                # Timeout starts after last packet is sent (as in Unix version) 
                if timeout:
                    stoptime = time.time()+timeout
                else:
                    stoptime = 0
                remaintime = None
                inmask = [pks.ins.fd]
                try:
                    try:
                        while 1:
                            if stoptime:
                                remaintime = stoptime-time.time()
                                if remaintime <= 0:
                                    break
                            r = pks.recv(MTU)
                            if r is None:
                                continue
                            ok = 0
                            h = r.hashret()
                            if h in hsent:
                                hlst = hsent[h]
                                for i in range(len(hlst)):
                                    if r.answers(hlst[i]):
                                        ans.append((hlst[i],r))
                                        if verbose > 1:
                                            os.write(1, "*")
                                        ok = 1                                
                                        if not multi:
                                            del(hlst[i])
                                            notans -= 1;
                                        else:
                                            if not hasattr(hlst[i], '_answered'):
                                                notans -= 1;
                                            hlst[i]._answered = 1;
                                        break
                            if notans == 0 and not multi:
                                break
                            if not ok:
                                if verbose > 1:
                                    os.write(1, ".")
                                nbrecv += 1
                                if conf.debug_match:
                                    debug.recv.append(r)
                    except KeyboardInterrupt:
                        if chainCC:
                            raise
                finally:
                    if WINDOWS:
                        for p,t in zip(all_stimuli, sent_times):
                            p.sent_time = t
        finally:
            pass

        remain = reduce(list.__add__, hsent.values(), [])
        if multi:
            remain = filter(lambda p: not hasattr(p, '_answered'), remain);
            
        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        if len(tobesent) == 0:
            break
        retry -= 1
        
    if conf.debug_match:
        debug.sent=plist.PacketList(remain[:],"Sent")
        debug.match=plist.SndRcvList(ans[:])

    #clean the ans list to delete the field _answered
    if (multi):
        for s,r in ans:
            if hasattr(s, '_answered'):
                del(s._answered)
    
    if verbose:
        print "\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans)
    return plist.SndRcvList(ans),plist.PacketList(remain,"Unanswered")


import scapy.sendrecv
scapy.sendrecv.sndrcv = sndrcv

def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
    """
    c = 0

    if offline is None:
        if L2socket is None:
            L2socket = conf.L2listen
        s = L2socket(type=ETH_P_ALL, *arg, **karg)
    else:
        s = PcapReader(offline)

    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    while 1:
        try:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break

            try:
                p = s.recv(MTU)
            except PcapTimeoutElapsed:
                continue
            if p is None:
                break
            if lfilter and not lfilter(p):
                continue
            if store:
                lst.append(p)
            c += 1
            if prn:
                r = prn(p)
                if r is not None:
                    print >> console, r
            if count > 0 and c >= count:
                break
        except KeyboardInterrupt:
            break
    s.close()
    return plist.PacketList(lst,"Sniffed")

import scapy.sendrecv
scapy.sendrecv.sniff = sniff

def get_if_list():
    return sorted(ifaces.keys())
        
def get_working_if():
    try:
        return devname(pcap.lookupdev())
    except Exception:
        return 'lo0'
