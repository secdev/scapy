# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
TFTP (Trivial File Transfer Protocol).
"""

from __future__ import absolute_import
import os
import random

from scapy.packet import Packet, bind_layers, split_bottom_up, bind_bottom_up
from scapy.fields import PacketListField, ShortEnumField, ShortField, \
    StrNullField
from scapy.automaton import ATMT, Automaton
from scapy.layers.inet import UDP, IP
from scapy.modules.six.moves import range
from scapy.config import conf
from scapy.volatile import RandShort


TFTP_operations = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR", 6: "OACK"}  # noqa: E501


class TFTP(Packet):
    name = "TFTP opcode"
    fields_desc = [ShortEnumField("op", 1, TFTP_operations), ]


class TFTP_RRQ(Packet):
    name = "TFTP Read Request"
    fields_desc = [StrNullField("filename", ""),
                   StrNullField("mode", "octet")]

    def answers(self, other):
        return 0

    def mysummary(self):
        return self.sprintf("RRQ %filename%"), [UDP]


class TFTP_WRQ(Packet):
    name = "TFTP Write Request"
    fields_desc = [StrNullField("filename", ""),
                   StrNullField("mode", "octet")]

    def answers(self, other):
        return 0

    def mysummary(self):
        return self.sprintf("WRQ %filename%"), [UDP]


class TFTP_DATA(Packet):
    name = "TFTP Data"
    fields_desc = [ShortField("block", 0)]

    def answers(self, other):
        return self.block == 1 and isinstance(other, TFTP_RRQ)

    def mysummary(self):
        return self.sprintf("DATA %block%"), [UDP]


class TFTP_Option(Packet):
    fields_desc = [StrNullField("oname", ""),
                   StrNullField("value", "")]

    def extract_padding(self, pkt):
        return "", pkt


class TFTP_Options(Packet):
    fields_desc = [PacketListField("options", [], TFTP_Option, length_from=lambda x:None)]  # noqa: E501


class TFTP_ACK(Packet):
    name = "TFTP Ack"
    fields_desc = [ShortField("block", 0)]

    def answers(self, other):
        if isinstance(other, TFTP_DATA):
            return self.block == other.block
        elif isinstance(other, TFTP_RRQ) or isinstance(other, TFTP_WRQ) or isinstance(other, TFTP_OACK):  # noqa: E501
            return self.block == 0
        return 0

    def mysummary(self):
        return self.sprintf("ACK %block%"), [UDP]


TFTP_Error_Codes = {0: "Not defined",
                    1: "File not found",
                    2: "Access violation",
                    3: "Disk full or allocation exceeded",
                    4: "Illegal TFTP operation",
                    5: "Unknown transfer ID",
                    6: "File already exists",
                    7: "No such user",
                    8: "Terminate transfer due to option negotiation",
                    }


class TFTP_ERROR(Packet):
    name = "TFTP Error"
    fields_desc = [ShortEnumField("errorcode", 0, TFTP_Error_Codes),
                   StrNullField("errormsg", "")]

    def answers(self, other):
        return (isinstance(other, TFTP_DATA) or
                isinstance(other, TFTP_RRQ) or
                isinstance(other, TFTP_WRQ) or
                isinstance(other, TFTP_ACK))

    def mysummary(self):
        return self.sprintf("ERROR %errorcode%: %errormsg%"), [UDP]


class TFTP_OACK(Packet):
    name = "TFTP Option Ack"
    fields_desc = []

    def answers(self, other):
        return isinstance(other, TFTP_WRQ) or isinstance(other, TFTP_RRQ)


bind_layers(UDP, TFTP, dport=69)
bind_layers(TFTP, TFTP_RRQ, op=1)
bind_layers(TFTP, TFTP_WRQ, op=2)
bind_layers(TFTP, TFTP_DATA, op=3)
bind_layers(TFTP, TFTP_ACK, op=4)
bind_layers(TFTP, TFTP_ERROR, op=5)
bind_layers(TFTP, TFTP_OACK, op=6)
bind_layers(TFTP_RRQ, TFTP_Options)
bind_layers(TFTP_WRQ, TFTP_Options)
bind_layers(TFTP_OACK, TFTP_Options)


class TFTP_read(Automaton):
    def parse_args(self, filename, server, sport=None, port=69, **kargs):
        Automaton.parse_args(self, **kargs)
        self.filename = filename
        self.server = server
        self.port = port
        self.sport = sport

    def master_filter(self, pkt):
        return (IP in pkt and pkt[IP].src == self.server and UDP in pkt and
                pkt[UDP].dport == self.my_tid and
                (self.server_tid is None or pkt[UDP].sport == self.server_tid))

    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.blocksize = 512
        self.my_tid = self.sport or RandShort()._fix()
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)
        self.server_tid = None
        self.res = b""

        self.l3 = IP(dst=self.server) / UDP(sport=self.my_tid, dport=self.port) / TFTP()  # noqa: E501
        self.last_packet = self.l3 / TFTP_RRQ(filename=self.filename, mode="octet")  # noqa: E501
        self.send(self.last_packet)
        self.awaiting = 1

        raise self.WAITING()

    # WAITING
    @ATMT.state()
    def WAITING(self):
        pass

    @ATMT.receive_condition(WAITING)
    def receive_data(self, pkt):
        if TFTP_DATA in pkt and pkt[TFTP_DATA].block == self.awaiting:
            if self.server_tid is None:
                self.server_tid = pkt[UDP].sport
                self.l3[UDP].dport = self.server_tid
            raise self.RECEIVING(pkt)

    @ATMT.receive_condition(WAITING, prio=1)
    def receive_error(self, pkt):
        if TFTP_ERROR in pkt:
            raise self.ERROR(pkt)

    @ATMT.timeout(WAITING, 3)
    def timeout_waiting(self):
        raise self.WAITING()

    @ATMT.action(timeout_waiting)
    def retransmit_last_packet(self):
        self.send(self.last_packet)

    @ATMT.action(receive_data)
#    @ATMT.action(receive_error)
    def send_ack(self):
        self.last_packet = self.l3 / TFTP_ACK(block=self.awaiting)
        self.send(self.last_packet)

    # RECEIVED
    @ATMT.state()
    def RECEIVING(self, pkt):
        if conf.raw_layer in pkt:
            recvd = pkt[conf.raw_layer].load
        else:
            recvd = b""
        self.res += recvd
        self.awaiting += 1
        if len(recvd) == self.blocksize:
            raise self.WAITING()
        raise self.END()

    # ERROR
    @ATMT.state(error=1)
    def ERROR(self, pkt):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        return pkt[TFTP_ERROR].summary()

    # END
    @ATMT.state(final=1)
    def END(self):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        return self.res


class TFTP_write(Automaton):
    def parse_args(self, filename, data, server, sport=None, port=69, **kargs):
        Automaton.parse_args(self, **kargs)
        self.filename = filename
        self.server = server
        self.port = port
        self.sport = sport
        self.blocksize = 512
        self.origdata = data

    def master_filter(self, pkt):
        return (IP in pkt and pkt[IP].src == self.server and UDP in pkt and
                pkt[UDP].dport == self.my_tid and
                (self.server_tid is None or pkt[UDP].sport == self.server_tid))

    # BEGIN
    @ATMT.state(initial=1)
    def BEGIN(self):
        self.data = [self.origdata[i * self.blocksize:(i + 1) * self.blocksize]
                     for i in range(len(self.origdata) // self.blocksize + 1)]
        self.my_tid = self.sport or RandShort()._fix()
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)
        self.server_tid = None

        self.l3 = IP(dst=self.server) / UDP(sport=self.my_tid, dport=self.port) / TFTP()  # noqa: E501
        self.last_packet = self.l3 / TFTP_WRQ(filename=self.filename, mode="octet")  # noqa: E501
        self.send(self.last_packet)
        self.res = ""
        self.awaiting = 0

        raise self.WAITING_ACK()

    # WAITING_ACK
    @ATMT.state()
    def WAITING_ACK(self):
        pass

    @ATMT.receive_condition(WAITING_ACK)
    def received_ack(self, pkt):
        if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.awaiting:
            if self.server_tid is None:
                self.server_tid = pkt[UDP].sport
                self.l3[UDP].dport = self.server_tid
            raise self.SEND_DATA()

    @ATMT.receive_condition(WAITING_ACK)
    def received_error(self, pkt):
        if TFTP_ERROR in pkt:
            raise self.ERROR(pkt)

    @ATMT.timeout(WAITING_ACK, 3)
    def timeout_waiting(self):
        raise self.WAITING_ACK()

    @ATMT.action(timeout_waiting)
    def retransmit_last_packet(self):
        self.send(self.last_packet)

    # SEND_DATA
    @ATMT.state()
    def SEND_DATA(self):
        self.awaiting += 1
        self.last_packet = self.l3 / TFTP_DATA(block=self.awaiting) / self.data.pop(0)  # noqa: E501
        self.send(self.last_packet)
        if self.data:
            raise self.WAITING_ACK()
        raise self.END()

    # ERROR
    @ATMT.state(error=1)
    def ERROR(self, pkt):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        return pkt[TFTP_ERROR].summary()

    # END
    @ATMT.state(final=1)
    def END(self):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)


class TFTP_WRQ_server(Automaton):

    def parse_args(self, ip=None, sport=None, *args, **kargs):
        Automaton.parse_args(self, *args, **kargs)
        self.ip = ip
        self.sport = sport

    def master_filter(self, pkt):
        return TFTP in pkt and (not self.ip or pkt[IP].dst == self.ip)

    @ATMT.state(initial=1)
    def BEGIN(self):
        self.blksize = 512
        self.blk = 1
        self.filedata = b""
        self.my_tid = self.sport or random.randint(10000, 65500)
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)

    @ATMT.receive_condition(BEGIN)
    def receive_WRQ(self, pkt):
        if TFTP_WRQ in pkt:
            raise self.WAIT_DATA().action_parameters(pkt)

    @ATMT.action(receive_WRQ)
    def ack_WRQ(self, pkt):
        ip = pkt[IP]
        self.ip = ip.dst
        self.dst = ip.src
        self.filename = pkt[TFTP_WRQ].filename
        options = pkt.getlayer(TFTP_Options)
        self.l3 = IP(src=ip.dst, dst=ip.src) / UDP(sport=self.my_tid, dport=pkt.sport) / TFTP()  # noqa: E501
        if options is None:
            self.last_packet = self.l3 / TFTP_ACK(block=0)
            self.send(self.last_packet)
        else:
            opt = [x for x in options.options if x.oname.upper() == "BLKSIZE"]
            if opt:
                self.blksize = int(opt[0].value)
                self.debug(2, "Negotiated new blksize at %i" % self.blksize)
            self.last_packet = self.l3 / TFTP_OACK() / TFTP_Options(options=opt)  # noqa: E501
            self.send(self.last_packet)

    @ATMT.state()
    def WAIT_DATA(self):
        pass

    @ATMT.timeout(WAIT_DATA, 1)
    def resend_ack(self):
        self.send(self.last_packet)
        raise self.WAIT_DATA()

    @ATMT.receive_condition(WAIT_DATA)
    def receive_data(self, pkt):
        if TFTP_DATA in pkt:
            data = pkt[TFTP_DATA]
            if data.block == self.blk:
                raise self.DATA(data)

    @ATMT.action(receive_data)
    def ack_data(self):
        self.last_packet = self.l3 / TFTP_ACK(block=self.blk)
        self.send(self.last_packet)

    @ATMT.state()
    def DATA(self, data):
        self.filedata += data.load
        if len(data.load) < self.blksize:
            raise self.END()
        self.blk += 1
        raise self.WAIT_DATA()

    @ATMT.state(final=1)
    def END(self):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
        return self.filename, self.filedata


class TFTP_RRQ_server(Automaton):
    def parse_args(self, store=None, joker=None, dir=None, ip=None, sport=None, serve_one=False, **kargs):  # noqa: E501
        Automaton.parse_args(self, **kargs)
        if store is None:
            store = {}
        if dir is not None:
            self.dir = os.path.join(os.path.abspath(dir), "")
        else:
            self.dir = None
        self.store = store
        self.joker = joker
        self.ip = ip
        self.sport = sport
        self.serve_one = serve_one
        self.my_tid = self.sport or random.randint(10000, 65500)
        bind_bottom_up(UDP, TFTP, dport=self.my_tid)

    def master_filter(self, pkt):
        return TFTP in pkt and (not self.ip or pkt[IP].dst == self.ip)

    @ATMT.state(initial=1)
    def WAIT_RRQ(self):
        self.blksize = 512
        self.blk = 0

    @ATMT.receive_condition(WAIT_RRQ)
    def receive_rrq(self, pkt):
        if TFTP_RRQ in pkt:
            raise self.RECEIVED_RRQ(pkt)

    @ATMT.state()
    def RECEIVED_RRQ(self, pkt):
        ip = pkt[IP]
        options = pkt[TFTP_Options]
        self.l3 = IP(src=ip.dst, dst=ip.src) / UDP(sport=self.my_tid, dport=ip.sport) / TFTP()  # noqa: E501
        self.filename = pkt[TFTP_RRQ].filename.decode("utf-8", "ignore")
        self.blk = 1
        self.data = None
        if self.filename in self.store:
            self.data = self.store[self.filename]
        elif self.dir is not None:
            fn = os.path.abspath(os.path.join(self.dir, self.filename))
            if fn.startswith(self.dir):  # Check we're still in the server's directory  # noqa: E501
                try:
                    with open(fn) as fd:
                        self.data = fd.read()
                except IOError:
                    pass
        if self.data is None:
            self.data = self.joker

        if options:
            opt = [x for x in options.options if x.oname.upper() == "BLKSIZE"]
            if opt:
                self.blksize = int(opt[0].value)
                self.debug(2, "Negotiated new blksize at %i" % self.blksize)
            self.last_packet = self.l3 / TFTP_OACK() / TFTP_Options(options=opt)  # noqa: E501
            self.send(self.last_packet)

    @ATMT.condition(RECEIVED_RRQ)
    def file_in_store(self):
        if self.data is not None:
            self.blknb = len(self.data) / self.blksize + 1
            raise self.SEND_FILE()

    @ATMT.condition(RECEIVED_RRQ)
    def file_not_found(self):
        if self.data is None:
            raise self.WAIT_RRQ()

    @ATMT.action(file_not_found)
    def send_error(self):
        self.send(self.l3 / TFTP_ERROR(errorcode=1, errormsg=TFTP_Error_Codes[1]))  # noqa: E501

    @ATMT.state()
    def SEND_FILE(self):
        self.send(self.l3 / TFTP_DATA(block=self.blk) / self.data[(self.blk - 1) * self.blksize:self.blk * self.blksize])  # noqa: E501

    @ATMT.timeout(SEND_FILE, 3)
    def timeout_waiting_ack(self):
        raise self.SEND_FILE()

    @ATMT.receive_condition(SEND_FILE)
    def received_ack(self, pkt):
        if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.blk:
            raise self.RECEIVED_ACK()

    @ATMT.state()
    def RECEIVED_ACK(self):
        self.blk += 1

    @ATMT.condition(RECEIVED_ACK)
    def no_more_data(self):
        if self.blk > self.blknb:
            if self.serve_one:
                raise self.END()
            raise self.WAIT_RRQ()

    @ATMT.condition(RECEIVED_ACK, prio=2)
    def data_remaining(self):
        raise self.SEND_FILE()

    @ATMT.state(final=1)
    def END(self):
        split_bottom_up(UDP, TFTP, dport=self.my_tid)
