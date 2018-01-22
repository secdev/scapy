# coding=utf-8
import socket

from scapy.contrib.opcua.helpers import UaConnectionContext
from scapy.contrib.opcua.binary.networking import chunkify
from scapy.contrib.opcua.binary.automaton import _UaAutomaton
from scapy.automaton import ATMT, Automaton
from scapy.contrib.opcua.binary.uaTypes import *
from scapy.supersocket import SuperSocket
import scapy.contrib.opcua.binary.uaTypes as UA


class OpcTcpSuperSocket(SuperSocket):
    
    def __init__(self, connectionContext, family=socket.AF_INET, type=socket.SOCK_STREAM):
        self.socket = socket.socket(family, type)
        self.outs = self.socket
        self.ins = self.socket
        self.logger = logging.getLogger(__name__)
        self.connectionContext = connectionContext
        self.open = False
    
    def send(self, data):
        data = bytes(data)
        # print("Sent packet: ")
        # from scapy.packet import Packet
        # if isinstance(data, Packet):
        #     data.show2()
        # else:
        #     print(data)
        sent = 0
        try:
            while sent < len(data):
                part = self.socket.send(data[sent:])
                if part == 0:
                    raise RuntimeError("Connection broke")
                sent += part
        except BrokenPipeError as e:
            print(e)
            # self.lock.release()
            # raise self.START()
    
    def recv(self, x=0):
        headerLen = len(UA.UaTcpMessageHeader())
        header = self.socket.recv(headerLen)
        if not header:
            self.socket.close()
            self.logger.warning("TCP socket got disconnected")
            raise ConnectionAbortedError()
        
        decodedHeader = UA.UaTcpMessageHeader(header)
        size = decodedHeader.MessageSize - headerLen
        
        body = self.socket.recv(size)
        if not body:
            self.logger.error("Could net receive body. expected {} bytes".format(size))
            return None
        pkt = UA.UaTcp(header + body, connectionContext=self.connectionContext)
        # print("Received packet: ")
        # pkt.show()
        return pkt
    
    def connect(self, target):
        if not self.open:
            self.socket.connect(target)
            self.open = True
    
    def close(self):
        if self.open:
            self.socket.shutdown(socket.SHUT_WR)
            self.socket.close()
            self.open = False
    
    def sr(self, *args, **kargs):
        raise NotImplementedError()
    
    def sr1(self, *args, **kargs):
        raise NotImplementedError()
    
    def sniff(self, *args, **kargs):
        raise NotImplementedError()
    
    def fileno(self):
        return self.socket.fileno()


class UaTcpClient(Automaton):
    """
    This Automaton implements the ua tcp layer functionality.
    It can be used as part of an automaton that implements the SecureChannel layer.
    """
    
    def parse_args(self, connectionContext=UaConnectionContext(), target="localhost",
                   targetPort=4840, debug=0, store=1, **kwargs):
        super(UaTcpClient, self).parse_args(debug, store, **kwargs)
        self.target = target
        self.targetPort = targetPort
        self.logger = logging.getLogger(__name__)
        self.connectionContext = connectionContext
    
    @ATMT.state(initial=1)
    def START(self):
        pass
    
    @ATMT.state()
    def TCP_CONNECTED(self):
        pass
    
    @ATMT.state()
    def CONNECTING(self):
        pass
    
    @ATMT.state()
    def CONNECTED(self):
        pass
    
    @ATMT.state()
    def TCP_DISCONNECTING(self):
        pass
    
    @ATMT.state()
    def TCP_DISCONNECTED(self):
        pass
    
    @ATMT.state(final=1)
    def END(self):
        pass
    
    @ATMT.condition(START)
    def connectTCP(self):
        self.send_sock = OpcTcpSuperSocket(self.connectionContext)
        self.listen_sock = self.send_sock
        
        try:
            self.send_sock.connect((self.target, self.targetPort))
            self.logger.debug("TCP connected")
        except ConnectionRefusedError:
            self.logger.warning("TCP connection refused.")
            raise self.END()
        raise self.TCP_CONNECTED()
    
    @ATMT.condition(TCP_CONNECTED)
    def connect(self):
        self.logger.debug("Sending HEL")
        self.send(UaTcp(Message=UaTcpHelloMessage(), connectionContext=self.connectionContext))
        raise self.CONNECTING()
    
    @ATMT.receive_condition(CONNECTING)
    def receive_ack(self, pkt):
        if isinstance(pkt, UaTcp) and isinstance(pkt.Message, UaTcpAcknowledgeMessage):
            self.logger.debug("Received ACK")
            raise self.CONNECTED()
        elif isinstance(pkt, UaTcp) and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.debug("Received ERR")
            raise self.END()
        else:
            self.logger.debug("Unexpected message received")
            raise self.END()
    
    @ATMT.condition(TCP_DISCONNECTING)
    def tcp_disconnect(self):
        self.send_sock.close()
        raise self.TCP_DISCONNECTED()
    
    @ATMT.condition(TCP_DISCONNECTED)
    def end(self):
        raise self.END()
    
    @ATMT.receive_condition(CONNECTED, prio=1)
    def receive_response(self, pkt):
        print("Receiving")
        # pkt = self.recv()
        self.oi.uatcp.send(pkt.original)
        raise self.CONNECTED()
    
    @ATMT.receive_condition(CONNECTED, prio=0)
    def error_received(self, pkt):
        if type(pkt) is UaTcp and isinstance(pkt.Message, UaTcpErrorMessage):
            self.logger.warning("ERR received... Closing connection")
            raise self.TCP_DISCONNECTING()
        elif not isinstance(pkt, UaTcp):
            self.logger.warning("Unexpected message received... Closing connection")
            raise self.TCP_DISCONNECTING()
    
    @ATMT.ioevent(CONNECTED, "uatcp", as_supersocket="uatcplink")
    def socket_send(self, fd):
        raise self.CONNECTED().action_parameters(fd.recv())
    
    @ATMT.action(socket_send)
    def send_data(self, data):
        from scapy.packet import Raw
        self.send(Raw(data))
