# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>

# scapy.contrib.description = XCPScanner
# scapy.contrib.status = loads
import logging
from collections import namedtuple

from scapy.config import conf
from scapy.contrib.automotive import log_automotive
from scapy.contrib.automotive.xcp.cto_commands_master import \
    TransportLayerCmd, TransportLayerCmdGetSlaveId, Connect
from scapy.contrib.automotive.xcp.cto_commands_slave import \
    ConnectPositiveResponse, TransportLayerCmdGetSlaveIdResponse
from scapy.contrib.automotive.xcp.xcp import CTORequest, XCPOnCAN
from scapy.contrib.cansocket_native import CANSocket

# Typing imports
from typing import (
    Optional,
    List,
    Type,
    Iterator,
)

XCPScannerResult = namedtuple('XCPScannerResult', 'request_id response_id')


class XCPOnCANScanner:
    """
    Scans for XCP Slave on CAN
    """

    def __init__(self, can_socket, id_range=None,
                 sniff_time=0.1, add_padding=False, verbose=False):
        # type: (CANSocket, Optional[Iterator[int]], Optional[float], Optional[bool], Optional[bool]) -> None # noqa: E501

        """
        Constructor
        :param can_socket: Can Socket with XCPonCAN as basecls for scan
        :param id_range: CAN id range to scan
        :param sniff_time: time the scan waits for a response
                           after sending a request
        """

        conf.contribs["XCP"]["add_padding_for_can"] = add_padding
        self.__socket = can_socket
        self.id_range = id_range or range(0, 0x800)
        self.__sniff_time = sniff_time
        if verbose:
            log_automotive.setLevel(logging.DEBUG)

    def _scan(self, identifier, body, pid, answer_type):
        # type: (int, CTORequest, int, Type) -> List # noqa: E501

        log_automotive.info("Scan for id: " + str(identifier))
        flags = 'extended' if identifier >= 0x800 else 0
        cto_request = \
            XCPOnCAN(identifier=identifier, flags=flags) \
            / CTORequest(pid=pid) / body

        req_and_res_list, _unanswered = \
            self.__socket.sr(cto_request, timeout=self.__sniff_time,
                             verbose=False, multi=True)

        if len(req_and_res_list) == 0:
            log_automotive.info(
                "No answer for identifier: " + str(identifier))
            return []

        valid_req_and_res_list = filter(
            lambda req_and_res: req_and_res[1].haslayer(answer_type),
            req_and_res_list)
        return list(valid_req_and_res_list)

    def _send_connect(self, identifier):
        # type: (int) -> List[XCPScannerResult]
        """
        Sends CONNECT Message on the Control Area Network
        """
        all_slaves = []
        body = Connect(connection_mode=0x00)
        xcp_req_and_res_list = self._scan(identifier, body, 0xFF,
                                          ConnectPositiveResponse)

        for req_and_res in xcp_req_and_res_list:
            result = XCPScannerResult(response_id=req_and_res[1].identifier,
                                      request_id=identifier)
            all_slaves.append(result)
            log_automotive.info(
                "Detected XCP slave for broadcast identifier: " + str(
                    identifier) + "\nResponse: " + str(result))

        if len(all_slaves) == 0:
            log_automotive.info(
                "No XCP slave detected for identifier: " + str(identifier))
        return all_slaves

    def _send_get_slave_id(self, identifier):
        # type: (int) -> List[XCPScannerResult]
        """
        Sends GET_SLAVE_ID message on the Control Area Network
        """
        all_slaves = []
        body = TransportLayerCmd() / TransportLayerCmdGetSlaveId()
        xcp_req_and_res_list = \
            self._scan(
                identifier, body, 0xF2, TransportLayerCmdGetSlaveIdResponse)

        for req_and_res in xcp_req_and_res_list:
            response = req_and_res[1]
            # The protocol will also mark other XCP messages that might be
            # send as TransportLayerCmdGetSlaveIdResponse
            # -> Payload must be checked. It must include XCP
            if response.position_1 != 0x58 or response.position_2 != 0x43 or \
                    response.position_3 != 0x50:
                continue

            # Identifier that the master must use to send packets to the slave
            # and the slave will answer with
            request_id = \
                response["TransportLayerCmdGetSlaveIdResponse"].can_identifier

            result = XCPScannerResult(request_id=request_id,
                                      response_id=response.identifier)
            all_slaves.append(result)
            log_automotive.info(
                "Detected XCP slave for broadcast identifier: " + str(
                    identifier) + "\nResponse: " + str(result))

        return all_slaves

    def scan_with_get_slave_id(self):
        # type: () -> List[XCPScannerResult]
        """Starts the scan for XCP devices on CAN with the transport specific
        GetSlaveId Message"""
        log_automotive.info("Start scan with GetSlaveId id in range: " + str(
            self.id_range))

        for identifier in self.id_range:
            ids = self._send_get_slave_id(identifier)
            if len(ids) > 0:
                return ids

        return []

    def scan_with_connect(self):
        # type: () -> List[XCPScannerResult]
        log_automotive.info("Start scan with CONNECT id in range: " + str(
            self.id_range))
        results = []
        for identifier in self.id_range:
            result = self._send_connect(identifier)
            if len(result) > 0:
                results.extend(result)
        return results
