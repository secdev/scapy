import socket
from scapy.all import FieldLenField, FieldListField, ByteEnumField
from scapy.contrib.socks import *


PACKET_MAX_SIZE = 65536


def parse_socks_packet(data, packet_class):
    return packet_class(bytes(SOCKS(data).payload))


class SOCKS5ClientSocket(socket.socket):
    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)
        self.remote_address = None
        self.remote_port = None
    
    
    def connect(self, target_address, server_address, command="Connect", address_type="IPv4"):
        super().connect(server_address)
        self._greeting_and_auth()
        self._connect_remote_session(target_address[0], target_address[1], command, address_type)
    
    
    def _greeting_and_auth(self):
        # Sends greatings
        greating = SOCKS(vn="v5") / SOCKS5ClientGreating(auth=["No Authentication"])
        self.send(bytes(greating))
        
        # Recives the server's choice
        response = self.recv(PACKET_MAX_SIZE)
        server_choice = parse_socks_packet(response, SOCKS5ServerChoice)
        
        if server_choice.cauth == 0x00:
            # No Authentication needed
            pass
        elif server_choice.cauth == 0xFF:
            raise Exception("server refused the auth method you tried to enter with")
        else:
            raise Exception("code doesnt support this feature yet")
    
    
    def _connect_remote_session(self, target_address, target_port, command, address_type):
        if command == "Connect":
            self._start_tcp_remote_session(target_address, address_type, target_port)
        elif command == "Bind":
            #Isn't implamented yet - coming soon, tcp-bind
            self._start_tcp_bind_session(target_address, address_type, target_port)
        elif command == "UDP associate":
            # Isn't implamented yet - coming soon,  udp connection
            self._start_udp_session(target_address, address_type, target_port)
    
    
    def _start_tcp_remote_session(self, target_address, address_type, target_port):
        self.send(bytes(SOCKS(vn="v5") / SOCKS5Request(cd="Connect", atyp=address_type, addr=target_address, port=target_port)))
        response = self.recv(PACKET_MAX_SIZE)
        server_reply = parse_socks_packet(response, SOCKS5Reply)
        if server_reply.rep == 0x00:
            pass
        else:
            Exception("remote tcp session faild, {}".format(_socks5_rep[server_reply.rep]))
        self.remote_address = server_reply.addr
        self.remote_port = server_reply.port
    
    
    def _start_tcp_bind_remote_session(self, target_address, address_type, target_port):
        raise Exception("code doesnt support this feature yet")
    
    
    def _start_udp_remote_session(self, target_address, address_type, target_port):
        raise Exception("code doesnt support this feature yet")	