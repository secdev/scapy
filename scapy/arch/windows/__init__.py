## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Customizations needed to support Microsoft Windows.
"""

from __future__ import with_statement
import os,re,sys,socket,time, itertools
import subprocess as sp
from glob import glob
import tempfile

from scapy.config import conf,ConfClass
from scapy.error import Scapy_Exception,log_loading,log_runtime
from scapy.utils import atol, itom, inet_aton, inet_ntoa, PcapReader
from scapy.base_classes import Gen, Net, SetGen
import scapy.plist as plist
from scapy.sendrecv import debug, srp1
from scapy.layers.l2 import Ether, ARP
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP

conf.use_pcap = False
conf.use_dnet = False
conf.use_winpcapy = True


#hot-patching socket for missing variables on Windows
import socket
if not hasattr(socket, 'IPPROTO_IPIP'):
    socket.IPPROTO_IPIP=4
if not hasattr(socket, 'IPPROTO_AH'):
    socket.IPPROTO_AH=51
if not hasattr(socket, 'IPPROTO_ESP'):
    socket.IPPROTO_ESP=50


from scapy.arch import pcapdnet
from scapy.arch.pcapdnet import *

LOOPBACK_NAME="lo0"
WINDOWS = True

def _exec_query_ps(cmd, fields):
    """Execute a PowerShell query"""
    ps = sp.Popen([conf.prog.powershell] + cmd +
                  ['|', 'select %s' % ', '.join(fields), '|', 'fl'],
                  stdout=sp.PIPE,
                  universal_newlines=True)
    l=[]
    for line in ps.stdout:
        if not line.strip(): #skip empty lines
            continue
        l.append(line.split(':', 1)[1].strip())
        if len(l) == len(fields):
            yield l
            l=[]

def _vbs_exec_code(code):
    tmpfile = tempfile.NamedTemporaryFile(suffix=".vbs", delete=False)
    tmpfile.write(code)
    tmpfile.close()
    ps = sp.Popen([conf.prog.cscript, tmpfile.name],
                  stdout=sp.PIPE, stderr=open(os.devnull),
                  universal_newlines=True)
    for _ in xrange(3):
        # skip 3 first lines
        ps.stdout.readline()
    for line in ps.stdout:
        yield line
    os.unlink(tmpfile.name)

def _vbs_get_iface_guid(devid):
    try:
        devid = str(int(devid) + 1)
        guid = _vbs_exec_code("""WScript.Echo CreateObject("WScript.Shell").RegRead("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%s\\ServiceName")
""" % devid).__iter__().next()
        if guid.startswith('{') and guid.endswith('}\n'):
            return guid[:-1]
    except StopIteration:
        pass

# Some names differ between VBS and PS
## None: field will not be returned under VBS
_VBS_WMI_FIELDS = {
    "Win32_NetworkAdapter": {
        "InterfaceIndex": "Index",
        "InterfaceDescription": "Description",
        "GUID": "DeviceID",
    }
}

_VBS_WMI_OUTPUT = {
    "Win32_NetworkAdapter": {
        "DeviceID": _vbs_get_iface_guid,
    }
}

def _exec_query_vbs(cmd, fields):
    """Execute a query using VBS. Currently Get-WmiObject queries are
    supported.

    """
    assert len(cmd) == 2 and cmd[0] == "Get-WmiObject"
    fields = [_VBS_WMI_FIELDS.get(cmd[1], {}).get(fld, fld) for fld in fields]
    values = _vbs_exec_code("""Set wmi = GetObject("winmgmts:")
Set lines = wmi.InstancesOf("%s")
On Error Resume Next
Err.clear
For Each line in lines
  %s
Next
""" % (cmd[1], "\n  ".join("WScript.Echo line.%s" % fld for fld in fields
                           if fld is not None))).__iter__()
    while True:
        yield [None if fld is None else
               _VBS_WMI_OUTPUT.get(cmd[1], {}).get(fld, lambda x: x)(
                   values.next().strip()
               )
               for fld in fields]

def exec_query(cmd, fields):
    """Execute a system query using PowerShell if it is available, and
    using VBS/cscript as a fallback.

    """
    if conf.prog.powershell is None:
        return _exec_query_vbs(cmd, fields)
    return _exec_query_ps(cmd, fields)


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
    powershell = win_find_exe(
        "powershell",
        installsubdir="System32\\WindowsPowerShell\\v1.0",
        env="SystemRoot"
    )
    cscript = win_find_exe("cscript", installsubdir="System32",
                           env="SystemRoot")

conf.prog = WinProgPath()
if conf.prog.powershell == "powershell":
    conf.prog.powershell = None

class PcapNameNotFoundError(Scapy_Exception):
    pass    
import platform

def is_interface_valid(iface):
    if "guid" in iface and iface["guid"]:
        return True
    return False

def get_windows_if_list():
    if platform.release()=="post2008Server" or platform.release()=="8":
        # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
        query = exec_query(['Get-NetAdapter'],
                           ['Name', 'InterfaceIndex', 'InterfaceDescription',
                            'InterfaceGuid', 'MacAddress'])
    else:
        query = exec_query(['Get-WmiObject', 'Win32_NetworkAdapter'],
                           ['Name', 'InterfaceIndex', 'InterfaceDescription',
                            'GUID', 'MacAddress'])
    return [
        iface for iface in
        (dict(zip(['name', 'win_index', 'description', 'guid', 'mac'], line))
         for line in query)
        if is_interface_valid(iface)
    ]

def get_ip_from_name(ifname, v6=False):
    for descr, ipadrr in exec_query(['Get-WmiObject',
                                     'Win32_NetworkAdapterConfiguration'],
                                    ['Description', 'IPAddress']):
        if descr == ifname.strip():
            return ipaddr.split(",", 1)[v6].strip('{}').strip()
        
class NetworkInterface(object):
    """A network interface of your local host"""
    
    def __init__(self, data=None):
        self.name = None
        self.ip = None
        self.mac = None
        self.pcap_name = None
        self.description = None
        self.data = data
        if data is not None:
            self.update(data)

    def update(self, data):
        """Update info about network interface according to given dnet dictionary"""
        self.name = data["name"]
        self.description = data['description']
        self.win_index = data['win_index']
        self.guid = data['guid']
        # Other attributes are optional
        self._update_pcapdata()

        try:
            self.ip = socket.inet_ntoa(get_if_raw_addr(data['guid']))
        except (KeyError, AttributeError, NameError):
            pass

        try:
            if not self.ip:
                self.ip=get_ip_from_name(data['name'])
        except (KeyError, AttributeError, NameError) as e:
            print e
        try:
            self.mac = data['mac']
        except KeyError:
            pass

    def _update_pcapdata(self):
        for i in winpcapy_get_if_list():
            if i.endswith(self.data['guid']):
                self.pcap_name = i
                return

        raise PcapNameNotFoundError

    def __repr__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self.name, self.guid)

from UserDict import UserDict

class NetworkInterfaceDict(UserDict):
    """Store information about network interfaces and convert between names""" 
    def load_from_powershell(self):
        for i in get_windows_if_list():
            try:
                interface = NetworkInterface(i)
                self.data[interface.guid] = interface
            except (KeyError, PcapNameNotFoundError):
                pass
        
        if len(self.data) == 0:
            log_loading.warning("No match between your pcap and windows network interfaces found. "
                                "You probably won't be able to send packets. "
                                "Deactivating unneeded interfaces and restarting Scapy might help."
                                "Check your winpcap and powershell installation, and access rights.")

    def dev_from_name(self, name):
        """Return the first pcap device name for a given Windows
        device name.

        """
        for iface in self.itervalues():
            if iface.name == name:
                return iface
        raise ValueError("Unknown network interface %r" % name)

    def dev_from_pcapname(self, pcap_name):
        """Return Windows device name for given pcap device name."""
        for iface in self.itervalues():
            if iface.pcap_name == pcap_name:
                return iface
        raise ValueError("Unknown pypcap network interface %r" % pcap_name)

    def dev_from_index(self, if_index):
        """Return interface name from interface index"""
        for devname, iface in self.items():
            if iface.win_index == str(if_index):
                return iface
        raise ValueError("Unknown network interface index %r" % if_index)

    def show(self, resolve_mac=True):
        """Print list of available network interfaces in human readable form"""
        print "%s  %s  %s  %s" % ("INDEX".ljust(5), "IFACE".ljust(35), "IP".ljust(15), "MAC")
        for iface_name in sorted(self.data.keys()):
            dev = self.data[iface_name]
            mac = dev.mac
            if resolve_mac:
                mac = conf.manufdb._resolve_MAC(mac)
            print "%s  %s  %s  %s" % (str(dev.win_index).ljust(5), str(dev.name).ljust(35), str(dev.ip).ljust(15), mac)
            
IFACES = NetworkInterfaceDict()
IFACES.load_from_powershell()

def pcapname(dev):
    """Return pypcap device name for given interface or libdnet/Scapy
    device name.

    """
    if type(dev) is NetworkInterface:
        return dev.pcap_name
    try:
        return IFACES.dev_from_name(dev).pcap_name
    except ValueError:
        # pcap.pcap() will choose a sensible default for sniffing if
        # iface=None
        return None

def dev_from_pcapname(pcap_name):
    """Return libdnet/Scapy device name for given pypcap device name"""
    return IFACES.dev_from_pcapname(pcap_name)

def dev_from_index(if_index):
    """Return Windows adapter name for given Windows interface index"""
    return IFACES.dev_from_index(if_index)
    
def show_interfaces(resolve_mac=True):
    """Print list of available network interfaces"""
    return IFACES.show(resolve_mac)

_orig_open_pcap = pcapdnet.open_pcap
pcapdnet.open_pcap = lambda iface,*args,**kargs: _orig_open_pcap(pcapname(iface),*args,**kargs)

_orig_get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr
pcapdnet.get_if_raw_hwaddr = lambda iface, *args, **kargs: (
    ARPHDR_ETHER, IFACES.dev_from_pcapname(iface.pcap_name).mac.replace(':', '').decode('hex')
)
get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr

def read_routes_xp():
    # The InterfaceIndex in Win32_IP4RouteTable does not match the
    # InterfaceIndex in Win32_NetworkAdapter under some platforms
    # (namely Windows XP): let's try an IP association
    routes = []
    partial_routes = []
    # map local IP addresses to interfaces
    local_addresses = dict((iface.ip, iface)
                           for iface in IFACES.itervalues())
    iface_indexes = {}
    for line in exec_query(['Get-WmiObject', 'Win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex']):
        if line[2] in local_addresses:
            iface = local_addresses[line[2]]
            # This gives us an association InterfaceIndex <-> interface
            iface_indexes[line[3]] = iface
            routes.append((atol(line[0]), atol(line[1]), "0.0.0.0", iface,
                           iface.ip))
        else:
            partial_routes.append((atol(line[0]), atol(line[1]), line[2],
                                   line[3]))
    for dst, mask, gw, ifidx in partial_routes:
        if ifidx in iface_indexes:
            iface = iface_indexes[ifidx]
            routes.append((dst, mask, gw, iface, iface.ip))
    return routes

def read_routes_7():
    routes=[]
    for line in exec_query(['Get-WmiObject', 'win32_IP4RouteTable'],
                           ['Name', 'Mask', 'NextHop', 'InterfaceIndex']):
        try:
            iface = dev_from_index(line[3])
        except ValueError:
            continue
        routes.append((atol(line[0]), atol(line[1]), line[2], iface, iface.ip))
    return routes

def read_routes():
    routes = []
    release = platform.release()
    try:
        if release in ["post2008Server", "8"]:
            routes = read_routes_post2008()
        elif release == "XP":
            routes = read_routes_xp()
        else:
            routes = read_routes_7()
    except Exception as e:    
        log_loading.warning("Error building scapy routing table : %s"%str(e))
    else:
        if not routes:
            log_loading.warning("No default IPv4 routes found. Your Windows release may no be supported and you have to enter your routes manually")
    return routes
       
def read_routes_post2008():
    # XXX TODO: FIX THIS XXX
    routes = []
    if_index = '(\d+)'
    dest = '(\d+\.\d+\.\d+\.\d+)/(\d+)'
    next_hop = '(\d+\.\d+\.\d+\.\d+)'
    metric_pattern = "(\d+)"
    delim = "\s+"        # The columns are separated by whitespace
    netstat_line = delim.join([if_index, dest, next_hop, metric_pattern])
    pattern = re.compile(netstat_line)
    # This works only starting from Windows 8/2012 and up. For older Windows another solution is needed
    ps = sp.Popen([conf.prog.powershell, 'Get-NetRoute', '-AddressFamily IPV4', '|', 'select ifIndex, DestinationPrefix, NextHop, RouteMetric'], stdout = sp.PIPE, universal_newlines = True)
    stdout, stdin = ps.communicate()
    for l in stdout.split('\n'):
        match = re.search(pattern,l)
        if match:
            try:
                iface = dev_from_index(match.group(1))
            except:
                continue
            # try:
            #     intf = pcapdnet.dnet.intf().get_dst(pcapdnet.dnet.addr(type=2, addrtxt=dest))
            # except OSError:
            #     log_loading.warning("Building Scapy's routing table: Couldn't get outgoing interface for destination %s" % dest)
            #     continue               
            routes.append((atol(match.group(2)), itom(int(match.group(3))),
                           match.group(4), iface, iface.ip))
    return routes

def read_routes6():
    return []

if conf.interactive_shell != 'ipython':
    try:
        __IPYTHON__
    except NameError:
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
                                for i, sentpkt in enumerate(hlst):
                                    if r.answers(sentpkt):
                                        ans.append((sentpkt, r))
                                        if verbose > 1:
                                            os.write(1, "*")
                                        ok = 1
                                        if not multi:
                                            del hlst[i]
                                            notans -= 1
                                        else:
                                            if not hasattr(sentpkt, '_answered'):
                                                notans -= 1
                                            sentpkt._answered = 1
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

        remain = list(itertools.chain(*[ i for i in hsent.values() ]))
        if multi:
            remain = [ p for p in remain if not hasattr(p, '_answered')]
            
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
Select interface to sniff by setting conf.iface. Use show_interfaces() to see interface names.
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
        log_runtime.info('Sniffing on %s' % conf.iface)
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
                    print r
            if count > 0 and c >= count:
                break
        except KeyboardInterrupt:
            break
    s.close()
    return plist.PacketList(lst,"Sniffed")

import scapy.sendrecv
scapy.sendrecv.sniff = sniff

def get_working_if():
    try:
        # return the interface associated with the route with smallest
        # mask (route by default if it exists)
        return min(read_routes(), key=lambda x: x[1])[3]
    except ValueError:
        # no route
        return LOOPBACK_NAME

conf.iface = get_working_if()
