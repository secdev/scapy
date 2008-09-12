## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


import sys,os,struct,socket,time
from fcntl import ioctl
from scapy.error import warning
import scapy.config
import scapy.utils
import scapy.arch

scapy.config.conf.use_pcap = 1
scapy.config.conf.use_dnet = 1
from pcapdnet import *


    


##################
## Routes stuff ##
##################


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
    pending_if = []
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
            lspl = l.split()
            if len(lspl) == 10:
                dest,mask,gw,netif,mxfrg,rtt,ref,flg = lspl[:8]
            else: # missing interface
                dest,mask,gw,mxfrg,rtt,ref,flg = lspl[:7]
                netif=None
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
        if netif is not None:
            ifaddr = scapy.arch.get_if_addr(netif)
            routes.append((dest,netmask,gw,netif,ifaddr))
        else:
            pending_if.append((dest,netmask,gw))
    f.close()

    # On Solaris, netstat does not provide output interfaces for some routes
    # We need to parse completely the routing table to route their gw and
    # know their output interface
    for dest,netmask,gw in pending_if:
        gw_l = scapy.utils.atol(gw)
        max_rtmask,gw_if,gw_if_addr, = 0,None,None
        for rtdst,rtmask,_,rtif,rtaddr in routes[:]:
            if gw_l & rtmask == rtdst:
                if rtmask >= max_rtmask:
                    max_rtmask = rtmask
                    gw_if = rtif
                    gw_if_addr = rtaddr
        if gw_if:
            routes.append((dest,netmask,gw,gw_if,gw_if_addr))
        else:
            warning("Did not find output interface to reach gateway %s" % gw)
            
    return routes


            



