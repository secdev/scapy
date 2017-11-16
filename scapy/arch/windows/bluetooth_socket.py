## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Gabriel Potter <gabriel@potter.fr>
## This program is published under a GPLv2 license

from scapy.supersocket import *
from win_btlib import _WinBluetoothSocket
from win_btlib import *

class WinBTSocket(SuperSocket, _WinBluetoothSocket):
    desc = "Scapy Windows only bluetooth socket implementation"
    def __init__ (self, bt_address, port=0, proto=RFCOMM, sockfd=None):
        _WinBluetoothSocket.__init__(self, proto, sockfd)
        self.connect((bt_address,port))
    def recv(self, x=MTU):
        return conf.raw_layer(self._recv(x))
    def send(self, x):
        sx = raw(x)
        if hasattr(x, "sent_time"):
            x.sent_time = time.time()
        return self._send(sx)
