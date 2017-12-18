## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Gabriel Potter <gabriel@potter.fr>
## This program is published under a GPLv2 license

from scapy.supersocket import *
from win_btlib import _WinBluetoothSocket
from win_btlib import *

import atexit

WINBT_DEFAULT_UUID = "94f39d29-7d6d-437d-973b-fba39e49d4ee"

class WinBTSocket(SuperSocket, _WinBluetoothSocket):
    desc = "Scapy bluetooth socket implementation. Windows only"
    def __init__ (self, bt_address, port=PORT_ANY, proto=RFCOMM, sockfd=None):
        _WinBluetoothSocket.__init__(self, proto, sockfd)
        if not sockfd:
            self.connect((bt_address,port))
        atexit.register(self.close)
    def recv(self, x=MTU):
        return conf.raw_layer(self._recv(x))
    def send(self, x):
        sx = raw(x)
        if hasattr(x, "sent_time"):
            x.sent_time = time.time()
        return self._send(sx)

class WinBTServerSocket(SuperSocket, _WinBluetoothSocket):
    desc = "Scapy bluetooth server socket implementation. Windows only"
    def __init__ (self, port=PORT_ANY, proto=RFCOMM, sockfd=None,
                  service_name="ScapyBTServer",
                  service_uuid=WINBT_DEFAULT_UUID):
        _WinBluetoothSocket.__init__(self, proto, sockfd)
        if not sockfd:
            self.bind(("", port))
            self.listen(1)
            self.address, self.port = self.getsockname()
            self.uuid = service_uuid
            self.service_name = service_name
            if proto == RFCOMM:
                advertise_service(self, service_name,
                           service_id = service_uuid,
                           service_classes = [ service_uuid, SERIAL_PORT_CLASS ],
                           profiles = [ SERIAL_PORT_PROFILE ])
                           # protocols = [ OBEX_UUID ])
            elif proto == L2CAP:
                advertise_service(self, service_name,
                       service_id = service_uuid,
                       service_classes = [ service_uuid ])
        atexit.register(self.close)
    def accept(self):
        client, addr_port = self._accept()
        return WinBTSocket(None, proto=client[0], sockfd=client[1]), addr_port
    def close(self):
        self._close()
        stop_advertising(self)
    def recv(self, *args):
        raise OSError("Cannot read a server socket")
    def send(self, *args):
        raise OSError("Cannot send on a server socket")

def discover_services(bt_address=None, dump=False):
    """Displays services being advertised on a specified bluetooth device"""
    services = find_service(address=bt_address)
    if dump:
        if len(services) > 0:
            print("Found %d services on %s" % (len(services), bt_address))
            print("")
        else:
            print("No services found")
        for svc in services:
            print("Service Name: %s"    % svc["name"])
            print("    Host:        %s" % svc["host"])
            print("    Description: %s" % svc["description"])
            print("    Provided By: %s" % svc["provider"])
            print("    Protocol:    %s" % svc["protocol"])
            print("    channel/PSM: %s" % svc["port"])
            print("    svc classes: %s "% svc["service-classes"])
            print("    profiles:    %s "% svc["profiles"])
            print("    service id:  %s "% svc["service-id"])
            print("")
    else:
        return services
