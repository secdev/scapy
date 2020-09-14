# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = XCPScanner
# scapy.contrib.status = loads

from typing import Optional, List, Tuple

from scapy.contrib.automotive.xcp.cto_commands_master import \
    TransportLayerCmd, TransportLayerCmdGetSlaveId
from scapy.contrib.automotive.xcp.xcp import CTORequest, XCPOnCAN
from scapy.contrib.cansocket_native import CANSocket


class XCPScannerResult:
    def __init__(self, slave_id, response_id):
        self.slave_id = slave_id
        self.response_id = response_id


class XCPOnCANScanner:
    """
    Scans for XCP Slave on CAN
    """

    def __init__(self, can_socket,
                 broadcast_id=None, broadcast_id_range=None,
                 sniff_time=0.1, verbose=False):
        # type: (CANSocket, Optional[int], Optional[Tuple[int, int]], Optional[float], Optional[bool]) -> None # noqa: E501

        """
        Constructor
        :param can_socket: Can Socket with XCPonCAN as basecls for scan
        :param broadcast_id: XCP broadcast Id in network (if known)
        :param sniff_time: time the scan waits for a response
                           after sending a request
        """
        self.__socket = can_socket
        self.broadcast_id = broadcast_id
        self.broadcast_id_range = broadcast_id_range
        self.__flags = 0
        self.__sniff_time = sniff_time
        self.__verbose = verbose

    def broadcast_get_slave_id(self, identifier):
        # type: (int) -> List[XCPScannerResult]
        """
        Sends GET_SLAVE_ID Message on the Control Area Network
        """

        self.log_verbose("Scan for broadcast id: " + str(identifier))
        cto_request = \
            XCPOnCAN(identifier=identifier,
                     flags=self.__flags) \
            / CTORequest() \
            / TransportLayerCmd() \
            / TransportLayerCmdGetSlaveId()

        cto_responses, _unanswered = \
            self.__socket.sr(cto_request, timeout=self.__sniff_time,
                             verbose=self.__verbose, multi=True)
        all_slaves = []
        if len(cto_responses) == 0:
            self.log_verbose(
                "No XCP slave detected for broadcast identifier: " + str(
                    identifier))
            return []

        for pkt_pair in cto_responses:
            answer = pkt_pair[1]
            if "TransportLayerCmdGetSlaveIdResponse" not in answer:
                continue
            # The protocol will also mark other XCP messages that might be
            # send as TransportLayerCmdGetSlaveIdResponse
            # -> Payload must be checked. It must include XCP
            if answer.position_1 != 0x58 or answer.position_2 != 0x43 or \
                    answer.position_3 != 0x50:
                continue

            # Identifier that the master must use to send packets to the slave
            # and the slave will answer with
            slave_id = \
                answer["TransportLayerCmdGetSlaveIdResponse"].can_identifier

            result = XCPScannerResult(slave_id, answer.identifier)
            all_slaves.append(result)
            self.log_verbose(
                "Detected XCP slave for broadcast identifier: " + str(
                    identifier) + "\nResponse: " + str(result))

        return all_slaves

    def start_scan(self):
        # type: () -> List[XCPScannerResult]
        """Starts the scan for XCP devices on CAN"""
        if self.broadcast_id:
            self.log_verbose("Start scan with single broadcast id: " + str(
                self.broadcast_id))
            return self.broadcast_get_slave_id(self.broadcast_id)

        broadcast_id_range = self.broadcast_id_range or (0, 0x7ff)

        self.log_verbose("Start scan with broadcast id in range: " + str(
            broadcast_id_range))

        for identifier in range(broadcast_id_range[0],
                                broadcast_id_range[1] + 1):
            ids = self.broadcast_get_slave_id(identifier)
            if len(ids) > 0:
                return ids

        return []

    def log_verbose(self, output):
        if self.__verbose:
            print(output)
