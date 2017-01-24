## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
When wpcap.dll is not available, replace all sendrecv functions that won't work.
"""

from scapy.error import log_runtime
import scapy.sendrecv as sendrecv
import scapy.config as conf
from scapy.supersocket import SuperSocket

def log_warning():
    if conf.conf.interactive:
        log_runtime.warning("Function not available (winpcap is not installed)")
    else:
        raise ImportError("Function not available (winpcap is not installed)")

def not_available(*args, **kwargs):
    log_warning()
    return None

class not_available_socket(SuperSocket):
    desc = "wpcap.dll missing"
    def __init__(self, type=None, promisc=None, filter=None, iface=None, nofilter=0):
        log_warning()
        return
    def send(self, x):
        return
    def recv(self,x=None):
        return
    def nonblock_recv(self):
        return
    def close(self):
        return
    

sendrecv.send = not_available
sendrecv.sendp = not_available
sendrecv.sendpfast = not_available
sendrecv.sr = not_available
sendrecv.sr1 = not_available
sendrecv.srflood = not_available
sendrecv.srloop = not_available
sendrecv.srp = not_available
sendrecv.srp1 = not_available
sendrecv.srpflood = not_available
sendrecv.srploop = not_available
sendrecv.sniff = not_available
sendrecv.sndrcv = not_available
sendrecv.sndrcvflood = not_available
sendrecv.tshark = not_available

conf.L3socket=not_available_socket
conf.L2socket=not_available_socket
