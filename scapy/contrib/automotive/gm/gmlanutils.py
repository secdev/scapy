#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Markus Schroetter <project.m.schroetter@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = GMLAN Utilities
# scapy.contrib.status = loads

import time

from scapy.compat import Optional, cast, Callable

from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_SA, GMLAN_RD, \
    GMLAN_TD, GMLAN_PM, GMLAN_RMBA
from scapy.config import conf
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.contrib.isotp import ISOTPSocket
from scapy.error import warning, log_loading
from scapy.utils import PeriodicSenderThread

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
    return resp.service != 0x7f  # NegativeResponse


class GMLAN_TesterPresentSender(PeriodicSenderThread):

    def __init__(self, sock, pkt=GMLAN(service="TesterPresent"), interval=2):
        # type: (SuperSocket, Packet, int) -> None
        """ Thread to send GMLAN TesterPresent packets periodically

        :param sock: socket where packet is sent periodically
        :param pkt: packet to send
        :param interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)

    def run(self):
        # type: () -> None
        while not self._stopped.is_set():
            for p in self._pkts:
                self._socket.sr1(p, verbose=False, timeout=0.1)
                time.sleep(self._interval)


def GMLAN_InitDiagnostics(
        sock,  # type: SuperSocket
        broadcast_socket=None,  # type: Optional[SuperSocket]
        timeout=None,  # type: Optional[int]
        verbose=None,  # type: Optional[bool]
        retry=0  # type: int
):
    # type: (...) -> bool
    """ Send messages to put an ECU into diagnostic/programming state.

    :param sock: socket for communication.
    :param broadcast_socket: socket for broadcasting. If provided some message
                             will be sent as broadcast. Recommended when used
                             on a network with several ECUs.
    :param timeout: timeout for sending, receiving or sniffing packages.
    :param verbose: set verbosity level
    :param retry: number of retries in case of failure.
    :return: True on success else False
    """
    # Helper function
    def _send_and_check_response(sock, req, timeout, verbose):
        # type: (SuperSocket, Packet, Optional[int], Optional[bool]) -> bool
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
        if broadcast_socket is None:
            if not _send_and_check_response(sock, p, timeout, verbose):
                continue
        else:
            if verbose:
                print("Sending %s as broadcast" % repr(p))
            broadcast_socket.send(p)
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


def GMLAN_GetSecurityAccess(
        sock,  # type: SuperSocket
        key_function,  # type: Callable[[int], int]
        level=1,  # type: int
        timeout=None,  # type: Optional[int]
        verbose=None,  # type: Optional[bool]
        retry=0  # type: int
):
    # type: (...) -> bool
    """ Authenticate on ECU. Implements Seey-Key procedure.

    :param sock: socket to send the message on.
    :param key_function: function implementing the key algorithm.
    :param level: level of access
    :param timeout: timeout for sending, receiving or sniffing packages.
    :param verbose: set verbosity level
    :param retry: number of retries in case of failure.
    :return: True on success.
    """
    if verbose is None:
        verbose = conf.verb > 0
    retry = abs(retry)

    if key_function is None:
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
            if resp is not None and resp.returnCode == 0x37 and retry:
                if verbose:
                    print("RequiredTimeDelayNotExpired. Wait 10s.")
                time.sleep(10)
            if verbose:
                print("Negative Response.")
            continue

        seed = cast(Packet, resp).securitySeed
        if seed == 0:
            if verbose:
                print("ECU security already unlocked. (seed is 0x0000)")
            return True

        keypkt = GMLAN() / GMLAN_SA(subfunction=level + 1,
                                    securityKey=key_function(seed))
        if verbose:
            print("Responding with key..")
        resp = sock.sr1(keypkt, timeout=timeout, verbose=0)
        if resp is None:
            if verbose:
                print("Timeout.")
            continue
        if verbose:
            resp.show()
        if resp.service == 0x67:
            if verbose:
                print("SecurityAccess granted.")
            return True
        # Invalid Key
        elif resp.service == 0x7f and resp.returnCode == 0x35:
            if verbose:
                print("Key invalid")
            continue

    return False


def GMLAN_RequestDownload(sock, length, timeout=None, verbose=None, retry=0):
    # type: (SuperSocket, int, Optional[int], Optional[bool], int) -> bool
    """ Send RequestDownload message.

        Usually used before calling TransferData.

    :param sock: socket to send the message on.
    :param length: value for the message's parameter 'unCompressedMemorySize'.
    :param timeout: timeout for sending, receiving or sniffing packages.
    :param verbose: set verbosity level.
    :param retry: number of retries in case of failure.
    :return: True on success
    """
    if verbose is None:
        verbose = conf.verb > 0
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


def GMLAN_TransferData(
        sock,  # type: SuperSocket
        addr,  # type: int
        payload,  # type: bytes
        maxmsglen=None,  # type: Optional[int]
        timeout=None,  # type: Optional[int]
        verbose=None,  # type: Optional[bool]
        retry=0  # type: int
):
    # type: (...) -> bool
    """ Send TransferData message.

    Usually used after calling RequestDownload.

    :param sock: socket to send the message on.
    :param addr: destination memory address on the ECU.
    :param payload: data to be sent.
    :param maxmsglen: maximum length of a single iso-tp message.
                      default: maximum length
    :param timeout: timeout for sending, receiving or sniffing packages.
    :param verbose: set verbosity level.
    :param retry: number of retries in case of failure.
    :return: True on success.
    """
    if verbose is None:
        verbose = conf.verb > 0

    retry = abs(retry)
    startretry = retry

    scheme = conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']
    if addr < 0 or addr >= 2**(8 * scheme):
        warning("Error: Invalid address %s for scheme %s",
                hex(addr), str(scheme))
        return False

    # max size of dataRecord according to gmlan protocol
    if maxmsglen is None or maxmsglen <= 0 or maxmsglen > (4093 - scheme):
        maxmsglen = (4093 - scheme)

    maxmsglen = cast(int, maxmsglen)

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


def GMLAN_TransferPayload(
        sock,  # type: SuperSocket
        addr,  # type: int
        payload,  # type: bytes
        maxmsglen=None,  # type: Optional[int]
        timeout=None,  # type: Optional[int]
        verbose=None,  # type: Optional[bool]
        retry=0  # type: int
):
    # type: (...) -> bool
    """ Send data by using GMLAN services.

    :param sock: socket to send the data on.
    :param addr: destination memory address on the ECU.
    :param payload: data to be sent.
    :param maxmsglen: maximum length of a single iso-tp message.
                      default: maximum length
    :param timeout: timeout for sending, receiving or sniffing packages.
    :param verbose: set verbosity level.
    :param retry: number of retries in case of failure.
    :return: True on success.
    """
    if not GMLAN_RequestDownload(sock, len(payload), timeout=timeout,
                                 verbose=verbose, retry=retry):
        return False
    if not GMLAN_TransferData(sock, addr, payload, maxmsglen=maxmsglen,
                              timeout=timeout, verbose=verbose, retry=retry):
        return False
    return True


def GMLAN_ReadMemoryByAddress(
        sock,  # type: SuperSocket
        addr,  # type: int
        length,  # type: int
        timeout=None,  # type: Optional[int]
        verbose=None,  # type: Optional[bool]
        retry=0  # type: int
):
    # type: (...) -> Optional[bytes]
    """ Read data from ECU memory.

    :param sock: socket to send the data on.
    :param addr: source memory address on the ECU.
    :param length: bytes to read.
    :param timeout: timeout for sending, receiving or sniffing packages.
    :param verbose: set verbosity level.
    :param retry: number of retries in case of failure.
    :return: bytes red or None
    """
    if verbose is None:
        verbose = conf.verb > 0
    retry = abs(retry)

    scheme = conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']
    if addr < 0 or addr >= 2**(8 * scheme):
        warning("Error: Invalid address %s for scheme %s",
                hex(addr), str(scheme))
        return None

    # max size of dataRecord according to gmlan protocol
    if length <= 0 or length > (4094 - scheme):
        warning("Error: Invalid length %s for scheme %s. "
                "Choose between 0x1 and %s",
                hex(length), str(scheme), hex(4094 - scheme))
        return None

    while retry >= 0:
        # RequestDownload
        pkt = GMLAN() / GMLAN_RMBA(memoryAddress=addr, memorySize=length)
        resp = sock.sr1(pkt, timeout=timeout, verbose=0)
        if _check_response(resp, verbose):
            return cast(Packet, resp).dataRecord
        retry -= 1
        if retry >= 0 and verbose:
            print("Retrying..")
    return None


def GMLAN_BroadcastSocket(interface):
    # type: (str) -> SuperSocket
    """ Returns a GMLAN broadcast socket using interface.

    :param interface: interface name
    :return: ISOTPSocket configured as GMLAN Broadcast Socket
    """
    return ISOTPSocket(interface, sid=0x101, did=0x0, basecls=GMLAN,
                       extended_addr=0xfe, padding=True)
