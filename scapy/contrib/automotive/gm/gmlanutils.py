#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Markus Schroetter <project.m.schroetter@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = GMLAN Utilities
# scapy.contrib.status = loads

import time

from typing import Optional, Callable, Any

from scapy.config import conf
from scapy.contrib.isotp import ISOTPSocket
from scapy.error import warning, log_loading
from scapy.packet import Packet
from scapy.utils import PeriodicSenderThread
from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_SA, GMLAN_RD, \
    GMLAN_TD, GMLAN_PM, GMLAN_RMBA

__all__ = ["GMLAN_TesterPresentSender", "GMLAN_InitDiagnostics",
           "GMLAN_GetSecurityAccess", "GMLAN_RequestDownload",
           "GMLAN_TransferData", "GMLAN_TransferPayload",
           "GMLAN_ReadMemoryByAddress", "GMLAN_BroadcastSocket"]


log_loading.info("\"conf.contribs['GMLAN']"
                 "['treat-response-pending-as-answer']\" set to True). This "
                 "is required by the GMLAN-Utils module to operate "
                 "correctly.")
try:
    conf.contribs['GMLAN']['treat-response-pending-as-answer'] = False
except KeyError:
    conf.contribs['GMLAN'] = {'treat-response-pending-as-answer': False}


# Helper function
def _check_response(resp, verbose):
    # type: (Optional[Packet], Optional[bool]) -> bool
    if resp is None:
        if verbose:
            print("Timeout.")
        return False
    if verbose:
        resp.show()
    service = resp.service  # type: int
    return service != 0x7f  # NegativeResponse


class GMLAN_TesterPresentSender(PeriodicSenderThread):
    def __init__(self, sock, pkt=GMLAN(service="TesterPresent"), interval=2):
        # type: (ISOTPSocket, Optional[GMLAN], Optional[int]) -> None
        """ Thread to send TesterPresent messages packets periodically

        :param sock: socket where packet is sent periodically
        :param pkt: packet to send
        :param interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)

    def run(self):
        # type: () -> None
        while not self._stopped.is_set():
            self._socket.sr1(self._pkt, verbose=False, timeout=0.1)
            time.sleep(self._interval)


def GMLAN_BroadcastSocket(interface):
    # type: (Any) -> ISOTPSocket
    """Returns a GMLAN broadcast socket using interface."""
    return ISOTPSocket(interface, sid=0x101, did=0x0, basecls=GMLAN,
                       extended_addr=0xfe, padding=True)


def GMLAN_InitDiagnostics(
        sock, broadcastsocket=None, timeout=None, verbose=None, retry=0):
    # type: (ISOTPSocket, Optional[ISOTPSocket], Optional[int], Optional[bool], int) -> bool  # noqa: E501
    """ Send messages to put an ECU into diagnostic/programming state.

    :param sock: socket for communication.
    :param broadcastsocket: socket for broadcasting. If provided some message
                            will be sent as broadcast. Recommended when used on
                            a network with several ECUs.
    :param timeout: timeout for sending, receiving or sniffing packages.
    :param verbose: set verbosity level
    :param retry: number of retries in case of failure.
    :return: True on success else False
    """
    # Helper function
    def _send_and_check_response(sock, req, timeout, verbose):
        # type: (ISOTPSocket, Packet, Optional[int], bool) -> bool
        if verbose:
            print("Sending %s" % repr(req))
        resp = sock.sr1(req, timeout=timeout, verbose=False)
        return _check_response(resp, verbose)

    if verbose is None:
        verbose = conf.verb > 0

    retry = abs(retry)

    while retry >= 0:
        retry -= 1

        # DisableNormalCommunication
        p = GMLAN(service="DisableNormalCommunication")
        if broadcastsocket is None:
            if not _send_and_check_response(sock, p, timeout, verbose):
                continue
        else:
            if verbose:
                print("Sending %s as broadcast" % repr(p))
            broadcastsocket.send(p)
        time.sleep(0.05)

        # ReportProgrammedState
        p = GMLAN(service="ReportProgrammingState")
        if not _send_and_check_response(sock, p, timeout, verbose):
            continue
        # ProgrammingMode requestProgramming
        p = GMLAN() / GMLAN_PM(subfunction="requestProgrammingMode")
        if not _send_and_check_response(sock, p, timeout, verbose):
            continue
        time.sleep(0.05)

        # InitiateProgramming enableProgramming
        # No response expected
        p = GMLAN() / GMLAN_PM(subfunction="enableProgrammingMode")
        if verbose:
            print("Sending %s" % repr(p))
        sock.send(p)
        time.sleep(0.05)
        return True
    return False


def GMLAN_GetSecurityAccess(sock, keyFunction, level=1, timeout=None,
                            verbose=None, retry=0):
    # type: (ISOTPSocket, Callable[[int], int], int, Optional[int], Optional[bool], int) -> bool  # noqa: E501
    """Authenticate on ECU. Implements Seey-Key procedure.

    Args:
        sock:        socket to send the message on.
        keyFunction: function implementing the key algorithm.
        level:       level of access
        timeout:     timeout for sending, receiving or sniffing packages.
        verbose:     set verbosity level
        retry:       number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb > 1
    retry = abs(retry)

    if keyFunction is None:
        return False

    if level % 2 == 0:
        warning("Parameter Error: Level must be an odd number.")
        return False

    while retry >= 0:
        retry -= 1

        request = GMLAN() / GMLAN_SA(subfunction=level)
        if verbose:
            print("Requesting seed..")
        resp = sock.sr1(request, timeout=timeout, verbose=0)
        if not _check_response(resp, verbose):
            if verbose:
                print("Negative Response.")
            continue

        seed = resp.securitySeed
        if seed == 0:
            if verbose:
                print("ECU security already unlocked. (seed is 0x0000)")
            return True

        keypkt = GMLAN() / GMLAN_SA(subfunction=level + 1,
                                    securityKey=keyFunction(seed))
        if verbose:
            print("Responding with key..")
        resp = sock.sr1(keypkt, timeout=timeout, verbose=0)
        if resp is None:
            if verbose:
                print("Timeout.")
            continue
        if verbose:
            resp.show()
        if resp.sprintf("%GMLAN.service%") == "SecurityAccessPositiveResponse":   # noqa: E501
            if verbose:
                print("SecurityAccess granted.")
            return True
        # Invalid Key
        elif resp.sprintf("%GMLAN.service%") == "NegativeResponse" and \
                resp.sprintf("%GMLAN.returnCode%") == "InvalidKey":
            if verbose:
                print("Key invalid")
            continue

    return False


def GMLAN_RequestDownload(sock, length, timeout=None, verbose=None, retry=0):
    # type: (ISOTPSocket, int, Optional[int], Optional[bool], int) -> bool
    """Send RequestDownload message.

    Usually used before calling TransferData.

    Args:
        sock:       socket to send the message on.
        length:     value for the message's parameter 'unCompressedMemorySize'.
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb > 1
    retry = abs(retry)

    while retry >= 0:
        # RequestDownload
        pkt = GMLAN() / GMLAN_RD(memorySize=length)
        resp = sock.sr1(pkt, timeout=timeout, verbose=0)
        if _check_response(resp, verbose):
            return True
        retry -= 1
        if retry >= 0 and verbose:
            print("Retrying..")
    return False


def GMLAN_TransferData(sock, addr, payload, maxmsglen=None, timeout=None,
                       verbose=None, retry=0):
    # type: (ISOTPSocket, int, bytes, Optional[int], Optional[int], Optional[bool], int) -> bool  # noqa: E501
    """Send TransferData message.

    Usually used after calling RequestDownload.

    Args:
        sock:       socket to send the message on.
        addr:       destination memory address on the ECU.
        payload:    data to be sent.
        maxmsglen:  maximum length of a single iso-tp message. (default:
                    maximum length)
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb > 1
    retry = abs(retry)
    startretry = retry

    scheme = conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']  # type: int
    if addr < 0 or addr >= 2**(8 * scheme):
        warning("Error: Invalid address " + hex(addr) + " for scheme " +
                str(scheme))
        return False

    # max size of dataRecord according to gmlan protocol
    if maxmsglen is None:
        maxmsglen = (4093 - scheme)
    elif maxmsglen <= 0 or maxmsglen > (4093 - scheme):
        maxmsglen = (4093 - scheme)

    for i in range(0, len(payload), maxmsglen):
        retry = startretry
        while True:
            if len(payload[i:]) > maxmsglen:
                transdata = payload[i:i + maxmsglen]
            else:
                transdata = payload[i:]
            pkt = GMLAN() / GMLAN_TD(startingAddress=addr + i,
                                     dataRecord=transdata)
            resp = sock.sr1(pkt, timeout=timeout, verbose=0)
            if _check_response(resp, verbose):
                break
            retry -= 1
            if retry >= 0:
                if verbose:
                    print("Retrying..")
            else:
                return False

    return True


def GMLAN_TransferPayload(sock, addr, payload, maxmsglen=None, timeout=None,
                          verbose=None, retry=0):
    # type: (ISOTPSocket, int, bytes, Optional[int], Optional[int], Optional[bool], int) -> bool  # noqa: E501
    """Send data by using GMLAN services.

    Args:
        sock:       socket to send the data on.
        addr:       destination memory address on the ECU.
        payload:    data to be sent.
        maxmsglen:  maximum length of a single iso-tp message. (default:
                    maximum length)
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if not GMLAN_RequestDownload(sock, len(payload), timeout=timeout,
                                 verbose=verbose, retry=retry):
        return False
    if not GMLAN_TransferData(sock, addr, payload, maxmsglen=maxmsglen,
                              timeout=timeout, verbose=verbose, retry=retry):
        return False
    return True


def GMLAN_ReadMemoryByAddress(sock, addr, length, timeout=None,
                              verbose=None, retry=0):
    # type: (ISOTPSocket, int, int, Optional[int], Optional[bool], int) -> Optional[bytes]  # noqa: E501
    """Read data from ECU memory.

    Args:
        sock:       socket to send the data on.
        addr:       source memory address on the ECU.
        length:     bytes to read
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns the bytes read.
    """
    if verbose is None:
        verbose = conf.verb > 1
    retry = abs(retry)

    scheme = conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']
    if addr < 0 or addr >= 2**(8 * scheme):
        warning("Error: Invalid address " + hex(addr) + " for scheme " +
                str(scheme))
        return None

    # max size of dataRecord according to gmlan protocol
    if length <= 0 or length > (4094 - scheme):
        warning("Error: Invalid length " + hex(length) + " for scheme " +
                str(scheme) + ". Choose between 0x1 and " + hex(4094 - scheme))
        return None

    while retry >= 0:
        # RequestDownload
        pkt = GMLAN() / GMLAN_RMBA(memoryAddress=addr, memorySize=length)
        resp = sock.sr1(pkt, timeout=timeout, verbose=0)
        if _check_response(resp, verbose):
            data = resp.dataRecord  # type: bytes
            return data
        retry -= 1
        if retry >= 0 and verbose:
            print("Retrying..")
    return None
