## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license


import sys,os,struct,socket,time
from fcntl import ioctl
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


            



