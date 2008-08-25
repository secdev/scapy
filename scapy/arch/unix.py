## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


import sys,os,struct,socket,time
from fcntl import ioctl
import scapy.utils
import scapy.arch

DNET=PCAP=1


try:
    import pcap
    PCAP = 1
except ImportError:
    if __name__ == "__main__":
        log_loading.error("did not find pcap module")
        raise SystemExit
    else:
        raise

try:
    import dnet
    DNET = 1
except ImportError:
    if __name__ == "__main__":
        log_loading.error("did not find dnet module")
        raise SystemExit
    else:
        raise


def get_if_raw_hwaddr(iff):
    if iff[:2] == scapy.arch.LOOPBACK_NAME:
        return (772, '\x00'*6)
    try:
        l = dnet.intf().get(iff)
        l = l["link_addr"]
    except:
        raise Scapy_Exception("Error in attempting to get hw address for interface [%s]" % iff)
    return l.type,l.data
def get_if_raw_addr(ifname):
    i = dnet.intf()
    return i.get(ifname)["addr"].data

def get_if_list():
    # remove 'any' interface
    return map(lambda x:x[0],filter(lambda x:x[1] is None,pcap.findalldevs()))
def get_working_if():
    try:
        return pcap.lookupdev()
    except Exception:
        return scapy.arch.LOOPBACK_NAME

def attach_filter(s, filter):
    warning("attach_filter() should not be called in PCAP mode")
def set_promisc(s,iff,val=1):
    warning("set_promisc() should not be called in DNET/PCAP mode")
    


##################
## Routes stuff ##
##################

def new_read_routes():

    rtlst = []
    def addrt(rt,lst):
        dst,gw = rt
        lst.append(rt)

    r = dnet.route()
    print r.loop(addrt, rtlst)
    return rtlst

def read_routes():
    if scapy.arch.SOLARIS:
        f=os.popen("netstat -rvn") # -f inet
    elif scapy.arch.FREEBSD:
        f=os.popen("netstat -rnW") # -W to handle long interface names
    else:
        f=os.popen("netstat -rn") # -f inet
    ok = 0
    mtu_present = False
    routes = []
    for l in f.readlines():
        if not l:
            break
        l = l.strip()
        if l.find("----") >= 0: # a separation line
            continue
        if l.find("Destination") >= 0:
            ok = 1
            if l.find("Mtu") >= 0:
                mtu_present = True
            continue
        if ok == 0:
            continue
        if not l:
            break
        if scapy.arch.SOLARIS:
            dest,mask,gw,netif,mxfrg,rtt,ref,flg = l.split()[:8]
        else:
            if mtu_present:
                dest,gw,flg,ref,use,mtu,netif = l.split()[:7]
            else:
                dest,gw,flg,ref,use,netif = l.split()[:6]
        if flg.find("Lc") >= 0:
            continue                
        if dest == "default":
            dest = 0L
            netmask = 0L
        else:
            if scapy.arch.SOLARIS:
                netmask = scapy.utils.atol(mask)
            elif "/" in dest:
                dest,netmask = dest.split("/")
                netmask = scapy.utils.itom(int(netmask))
            else:
                netmask = scapy.utils.itom((dest.count(".") + 1) * 8)
            dest += ".0"*(3-dest.count("."))
            dest = scapy.utils.atol(dest)
        if not "G" in flg:
            gw = '0.0.0.0'
        ifaddr = scapy.arch.get_if_addr(netif)
        routes.append((dest,netmask,gw,netif,ifaddr))
    f.close()
    return routes

def read_interfaces():
    i = dnet.intf()
    ifflist = {}
    def addif(iff,lst):
        if not iff.has_key("addr"):
            return
        if not iff.has_key("link_addr"):
            return
        rawip = iff["addr"].data
        ip = inet_ntoa(rawip)
        rawll = iff["link_addr"].data
        ll = scapy.arch.str2mac(rawll)
        lst[iff["name"]] = (rawll,ll,rawip,ip)
    i.loop(addif, ifflist)
    return ifflist

            



