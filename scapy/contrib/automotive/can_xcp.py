#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Fabian Wiche <f.wiche@gmx.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = XCP over CAN(CAN-XCP)
# scapy.contrib.status = loads

import threading
import time
import scapy.modules.six as six
from scapy.config import LINUX
from scapy.layers.can import CAN


class Verbose():
    """Class just just for printing"""
    def __init__(self, verbose=False):
        self.__verbose = verbose

    def println(self, string):
        if self.__verbose:
            print(string)


class XCP_Port():
    """ Reresentation of a XCP Port,
        Holds all infomration of a found port.
            """
    def __init__(self, request_id, response_id, resource,
                 comm_mode_basic, max_cto, max_dto,
                 xcp_protocol_version, xcp_transport_version):
        """
        Constructor for XCP_Port
        :param request_id: XPC ID used for sending requests
                to the ECU
        :param response_id: ID where the ECU send the XCP
                responses
        :param resource: Byte for the resoruce transsmited during
                connect
        :param comm_mode_basic: Byte for comm_mode_basic
                transmitted during connect
        :param max_cto: Maximum number of CTOs in XCP
        :param max_dto: Maximum number of Data transmisstion Objects
                during XCP connection (for DAQ)
        :param xcp_protocol_version: Verison of used XCP Protokoll
        :param xcp_transport_version: Versiuon of transport Protokoll
        """
        self.__resource = resource
        self.__comm_mode_basic = comm_mode_basic
        self.__max_cto = max_cto
        self.__max_dto = max_dto
        self.__xcp_protocol_version = xcp_protocol_version
        self.__xcp_transport_version = xcp_transport_version
        self.__request_id = request_id
        self.__response_id = response_id

    def RESOURCE(self):
        return self.__resource

    def COMM_MODE_BASIC(self):
        return self.__comm_mode_basic

    def MAX_CTO(self):
        return self.__max_cto

    def MAX_DTO(self):
        return self.__max_dto

    def XCP_PROTOCOL_VERSION(self):
        return self.__xcp_protocol_version

    def XCP_TRANSPORT_VERSION(self):
        return self.__xcp_transport_version

    def REQUEST_ID(self):
        return self.__request_id

    def RESPONSE_ID(self):
        return self.__response_id

    def __init(self):
        pass

    def init_port_from_connect_msg(self, connect_msg):
        pass

    def __str__(self):
        return """  Found XCP Port
                    Request ID: 0x%x
                    Response ID: 0x%x
                    Comm_Mode: 0x%x, Resource: 0x%x,
                    max_cto: %d, max_dto: %d,
                    portocol_verison: %d, transport_version: %d
               """ % (self.__request_id, self.__response_id,
                      self.__comm_mode_basic, self.__resource,
                      self.__max_cto, self.__max_dto,
                      self.__xcp_protocol_version,
                      self.__xcp_transport_version)


class XCP_SEND_THREAD(threading.Thread):
    """
    Thread used for Sending XCP connects during sniffing
    """
    def __init__(self, message, start_id, end_id,
                 can_socket, current_id_var, console, cycle_time=0.01):
        """
        Constructor
        :param message: Message sent for connect attempts
        :param start_id: First ID tried for connecting
        :param end_id: Last ID until which connecting
                should be tried
        :param can_socket: Socket used for sending messages
        :param current_id_var: Shard variable that holds the last
                used ID set by this thread
        """
        threading.Thread.__init__(self)
        self.__message = message
        self.__start = start_id
        self.__end = end_id
        self.__socket = can_socket
        self.__current_id_var = current_id_var
        self.__console = console
        self.__cycle_time = cycle_time

    def run(self):
        """
        Main funciton in send thread
        Sends the messeage set in Constructor every 0.02 Seconds
        and increases the id of the msg after each send
        until __end is reached
        """
        self.__console.println("Start Sending")
        for i in range(self.__start, self.__end + 1):
            self.__message.identifier = i
            self.__current_id_var.c.acquire()
            self.__current_id_var.id = i
            self.__current_id_var.c.release()
            self.__socket.send(self.__message)
            time.sleep(self.__cycle_time)
        self.__console.println("Done")


class XCP_SNIFF_THREAD(threading.Thread):
    """
    Reads data from the can bus and checks if a XCP Response
    has been sent on the CANBus
    """
    def __init__(self, can_socket,
                 current_id_var, result_list, known_ids, console):
        """
        Constructor
        :param can_socket: Socket used for sending messages
        :param current_id_var: Shard variable that holds the last
            used ID set by the sending thread
        :param result_list: list of detected XCP-Connections
        :param konwn_ids: Noise message IDs sent during sniff.
            Holds all message IDs sent during the first
            3 seconds at Bus startup
        """
        threading.Thread.__init__(self)
        self.__socket = can_socket
        if isinstance(known_ids, list):
            self.__known_ids = known_ids
        else:
            self.__known_ids = list()
        self.__current_id_var = current_id_var
        self.__result_list = result_list
        self._stop_event = threading.Event()
        self.__console = console

    def set_known_ids(self, ids):
        self.__known_ids = ids

    def run(self):
        """
        Main Funciton of sniffer:
        Receives all message sent on CAN. If a XCP response has been
            received a result is added
        to the result list
        """
        data_array = list()
        self.__console.println("Start Sniffing")
        while not self._stop_event.is_set():
            try:
                msg = self.__socket.recv()
            except TypeError:
                continue
            if msg:
                data_array = [x for x in msg.data]
            if (msg and data_array and data_array[0] == 0xFF and
                    msg.identifier not in self.__known_ids and
                    msg.length == 8 and
                    msg.identifier != self.__current_id_var.id):
                self.__console.println(hex(msg.identifier) +
                                       " " +
                                       hex(self.__current_id_var.id))
                request_id = self.__current_id_var.id
                response_id = msg.identifier
                max_dto = (data_array[4] << 8) + data_array[5]
                Port = XCP_Port(request_id, response_id, data_array[1],
                                data_array[2], data_array[3],
                                max_dto, data_array[6], data_array[7])
                self.__result_list.append(Port)
                self.__console.println(Port)

    # @overrides threading.Thread.join
    def join(self, timeout=None):
        self._stop_event.set()
        return threading.Thread.join(self, timeout)


class SHARED_ID():
    """Struct for shared variale with semaphore"""
    id = 0
    c = threading.Condition()


class XCP_CAN_SCANNER():
    """
    Main class for scanning
    """
    def __init__(self, can_socket, start, end, use_extended_can_id,
                 console, timeout=0.02):
        """
        Constructor
        :param can_socket: Socket where scan is happening
        :param start: Start ID for scanning
        :param end: Last ID for scanning
        :param use_extended_can_id: True if extended IDs are used
        :param console: Used for printing log messages :type Verbose
        :param timeout: Timeout for receiveing messiages
        """
        self.__socket = can_socket
        self.__start = start
        self.__end = end
        self.__use_extended_can_id = use_extended_can_id
        self.__receive_thread = None
        self.__send_thread = None
        self.__current_id_var = SHARED_ID()
        self.__results = list()
        self.__console = console
        self.__known_ids = list()
        if use_extended_can_id:
            flags = 0x04
        else:
            flags = 0
        self.__requestMSG = CAN(identifier=0,
                                data=b'\xff\x00\xAA\xAA\xAA\xAA\xAA\xAA',
                                flags=flags)
        self.__send_thread = XCP_SEND_THREAD(self.__requestMSG, self.__start,
                                             self.__end, self.__socket,
                                             self.__current_id_var, console)
        self.__sniff_thread = XCP_SNIFF_THREAD(self.__socket,
                                               self.__current_id_var,
                                               self.__results,
                                               None, self.__console)
        if six.PY2 or not LINUX:
            self.__socket.timeout = timeout
        else:
            self.__socket.ins.settimeout(timeout)  # Set RX-timeout of socket

    def get_known_ids(self):
        """
        Wakes up CAN and safes all ids on the bus
        """
        self.__console.println("Getting known ids")
        wakeup_id = 0x01
        msg = CAN(identifier=wakeup_id, flags=0, data=b"\x00")
        self.__socket.send(msg)
        known_ids = list()
        rcv = True
        start_time = time.time()
        while time.time() - start_time < 1:
            try:
                rcv = self.__socket.recv()
            except TypeError:
                continue
            if rcv and rcv.identifier not in known_ids:
                if wakeup_id and rcv.identifier == wakeup_id:
                    wakeup_id = False
                else:
                    known_ids.append(rcv.identifier)
        return known_ids

    def KNOWN_IDS(self):
        return self.__known_ids

    def start_scan(self):
        """Starts the Scan"""
        self.__known_ids = self.get_known_ids()
        self.__sniff_thread.set_known_ids(self.__known_ids)
        self.__sniff_thread.start()
        self.__send_thread.start()
        self.__send_thread.join()
        self.__sniff_thread.join()

    def get_results(self):
        return self.__results
