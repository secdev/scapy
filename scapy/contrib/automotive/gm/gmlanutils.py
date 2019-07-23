#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Markus Schroetter <xito300@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = General Motors Local Area Network Utilities (GMLAN-Utils)
# scapy.contrib.status = loads

from time import sleep
from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_SA, GMLAN_RD, \
    GMLAN_TD, GMLAN_PM, GMLAN_RMBA, GMLAN_NR
from scapy.config import conf
from scapy.contrib.isotp import ISOTPSocket
from scapy.error import warning
from scapy.utils import PeriodicSenderThread


__all__ = ["GMLAN_TesterPresentSender", "GMLAN_InitDiagnostics",
           "GMLAN_GetSecurityAccess", "GMLAN_RequestDownload",
           "GMLAN_TransferData", "GMLAN_TransferPayload",
           "GMLAN_ReadMemoryByAddress", "GMLAN_BroadcastSocket"]


class GMLAN_TesterPresentSender(PeriodicSenderThread):
    def __init__(self, sock, pkt=GMLAN(service="TesterPresent"), interval=2):
        """ Thread to send TesterPresent messages packets periodically

        Args:
            sock: socket where packet is sent periodically
            pkt: packet to send
            interval: interval between two packets
        """
        PeriodicSenderThread.__init__(self, sock, pkt, interval)


def GMLAN_InitDiagnostics(socket, broadcastsocket=None, timeout=None,
                          verbose=None, retry=0):
    """Send messages to put an ECU into an diagnostic/programming state.

    Args:
        socket:     socket to send the message on.
        broadcast:  socket for broadcasting. If provided some message will be
                    sent as broadcast. Recommended when used on a network with
                    several ECUs.
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)

    while retry >= 0:
        retry -= 1

        # DisableNormalCommunication
        p = GMLAN(service="DisableNormalCommunication")
        if broadcastsocket is None:
            if verbose:
                print("Sending %s" % repr(p))
            resp = socket.sr1(p, timeout=timeout, verbose=0)
            if resp is not None:
                if verbose:
                    resp.show()
                if resp.service != GMLAN(service="DisableNormalCommunicationPositiveResponse").service:   # noqa: E501
                    continue
            else:
                if verbose:
                    print("Timeout.")
                continue
        else:
            if verbose:
                print("Sending %s as broadcast" % repr(p))
            broadcastsocket.send(p)
        sleep(0.05)

        # ReportProgrammedState
        p = GMLAN(service="ReportProgrammingState")
        if verbose:
            print("Sending %s" % repr(p))
        resp = socket.sr1(p, timeout=timeout, verbose=0)
        if resp is not None:
            if verbose:
                resp.show()
            if resp.service != GMLAN(service="ReportProgrammingStatePositiveResponse").service:   # noqa: E501
                continue
        else:
            if verbose:
                print("Timeout.")
            continue

        # ProgrammingMode requestProgramming
        p = GMLAN() / GMLAN_PM(subfunction="requestProgrammingMode")
        if verbose:
            print("Sending %s" % repr(p))
        resp = socket.sr1(p, timeout=timeout, verbose=0)
        if resp is not None:
            if verbose:
                resp.show()
            if resp.service != GMLAN(service="ProgrammingModePositiveResponse").service:   # noqa: E501
                continue
        else:
            if verbose:
                print("Timeout.")
            continue
        sleep(0.05)

        # InitiateProgramming enableProgramming
        # No response expected
        p = GMLAN() / GMLAN_PM(subfunction="enableProgrammingMode")
        if verbose:
            print("Sending %s" % repr(p))
        socket.send(p)
        sleep(0.05)
        return True
    return False


def GMLAN_GetSecurityAccess(socket, keyFunction, level=1, timeout=None,
                            verbose=None, retry=0):
    """Authenticate on ECU. Implements Seey-Key procedure.

    Args:
        socket:      socket to send the message on.
        keyFunction: function implementing the key algorithm.
        level:       level of access
        timeout:     timeout for sending, receiving or sniffing packages.
        verbose:     set verbosity level
        retry:       number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)

    if level % 2 == 0:
        warning("Parameter Error: Level must be an odd number.")
        return False

    request = GMLAN() / GMLAN_SA(subfunction=level)

    while retry >= 0:
        retry -= 1
        if verbose:
            print("Requesting seed..")
        resp = socket.sr1(request, timeout=timeout, verbose=0)
        if resp is not None:
            if verbose:
                resp.show()
            if resp.service != GMLAN(service="SecurityAccessPositiveResponse").service:   # noqa: E501
                if verbose:
                    print("Negative Response.")
                continue
        else:
            if verbose:
                print("Timeout.")
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
        resp = socket.sr1(keypkt, timeout=timeout, verbose=0)
        if resp is not None:
            if verbose:
                resp.show()
            if resp.service == GMLAN(service="SecurityAccessPositiveResponse").service:   # noqa: E501
                if verbose:
                    print("SecurityAccess granted.")
                return True
            # Invalid Key
            elif resp.service == GMLAN(service="NegativeResponse") and \
                    resp.returnCode == GMLAN_NR(returnCode="InvalidKey").returnCode:   # noqa: E501
                if verbose:
                    print("Key invalid")
                continue
        else:
            if verbose:
                print("Timeout.")
            continue
    return False


def GMLAN_RequestDownload(socket, length, timeout=None, verbose=None, retry=0):
    """Send RequestDownload message.

    Usually used before calling TransferData.

    Args:
        socket:     socket to send the message on.
        length:     value for the message's parameter 'unCompressedMemorySize'.
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if verbose is None:
        verbose = conf.verb
    retry = abs(retry)

    while retry >= 0:
        # RequestDownload
        pkt = GMLAN() / GMLAN_RD(memorySize=length)
        resp = socket.sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            if verbose:
                print("Timeout.")
        else:
            # filter Response Pending
            while (resp.service == GMLAN(service="NegativeResponse").service and   # noqa: E501
                   resp.returnCode == GMLAN_NR(returnCode="RequestCorrectlyReceived-ResponsePending").returnCode and   # noqa: E501
                   resp.requestServiceId == GMLAN(service="RequestDownload").service):   # noqa: E501
                sniffed = socket.sniff(count=1, timeout=timeout,
                                       lfilter=lambda p: p.answers(pkt))
                if len(sniffed) < 1:
                    resp = None
                    break
                resp = sniffed[0]

            if resp is None:
                if verbose:
                    print("Timeout.")
            elif resp.service != GMLAN(service="RequestDownloadPositiveResponse").service:   # noqa: E501
                if verbose:
                    resp.show()
                    print("Negative Response.")
            else:
                return True

        retry -= 1
        if retry >= 0:
            if verbose:
                print("Retrying..")
    return False


def GMLAN_TransferData(socket, addr, payload, maxmsglen=None, timeout=None,
                       verbose=None, retry=0):
    """Send TransferData message.

    Usually used after calling RequestDownload.

    Args:
        socket:     socket to send the message on.
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
        verbose = conf.verb
    retry = abs(retry)
    startretry = retry

    scheme = conf.contribs['GMLAN']['GMLAN_ECU_AddressingScheme']
    if addr < 0 or addr >= 2**(8 * scheme):
        warning("Error: Invalid address " + hex(addr) + " for scheme " +
                str(scheme))
        return False

    # max size of dataRecord according to gmlan protocol
    if maxmsglen is None or maxmsglen <= 0 or maxmsglen > (4093 - scheme):
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
            resp = socket.sr1(pkt, timeout=timeout, verbose=0)

            if resp is None:
                if verbose:
                    print("Timeout.")
            else:
                # filter Response Pending
                while (resp.service == GMLAN(service="NegativeResponse").service and   # noqa: E501
                   resp.returnCode == GMLAN_NR(returnCode="RequestCorrectlyReceived-ResponsePending").returnCode and   # noqa: E501
                   resp.requestServiceId == GMLAN(service="TransferData").service):   # noqa: E501
                    sniffed = socket.sniff(count=1, timeout=timeout,
                                           lfilter=lambda p: p.answers(pkt))
                    if len(sniffed) < 1:
                        resp = None
                        break
                    resp = sniffed[0]

                if resp is None:
                    if verbose:
                        print("Timeout.")
                elif resp.service != GMLAN(service="TransferDataPositiveResponse").service:   # noqa: E501
                    if verbose:
                        resp.show()
                        print("Negative Response.")
                else:
                    break

            retry -= 1
            if retry >= 0:
                if verbose:
                    print("Retrying..")
            else:
                return False

    return True


def GMLAN_TransferPayload(socket, addr, payload, maxmsglen=None, timeout=None,
                          verbose=None, retry=0):
    """Send data by using GMLAN services.

    Args:
        socket:     socket to send the data on.
        addr:       destination memory address on the ECU.
        payload:    data to be sent.
        maxmsglen:  maximum length of a single iso-tp message. (default:
                    maximum length)
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns true on success.
    """
    if not GMLAN_RequestDownload(socket, len(payload), timeout=timeout,
                                 verbose=verbose, retry=retry):
        return False
    if not GMLAN_TransferData(socket, addr, payload, maxmsglen=maxmsglen,
                              timeout=timeout, verbose=verbose, retry=retry):
        return False
    return True


def GMLAN_ReadMemoryByAddress(socket, addr, length, timeout=None,
                              verbose=None, retry=0):
    """Read data from ECU memory.

    Args:
        socket:     socket to send the data on.
        addr:       source memory address on the ECU.
        length:     bytes to read
        timeout:    timeout for sending, receiving or sniffing packages.
        verbose:    set verbosity level.
        retry:      number of retries in case of failure.

    Returns the bytes read.
    """
    if verbose is None:
        verbose = conf.verb
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
        resp = socket.sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            if verbose:
                print("Timeout.")
        else:
            # filter Response Pending
            while (resp.service == GMLAN(service="NegativeResponse").service and   # noqa: E501
                   resp.returnCode == GMLAN_NR(returnCode="RequestCorrectlyReceived-ResponsePending").returnCode and   # noqa: E501
                   resp.requestServiceId == GMLAN(service="ReadMemoryByAddress").service):   # noqa: E501
                sniffed = socket.sniff(count=1, timeout=timeout,
                                       lfilter=lambda p: p.answers(pkt))
                if len(sniffed) < 1:
                    resp = None
                    break
                resp = sniffed[0]

            if resp is None:
                if verbose:
                    print("Timeout.")
            elif resp.service != GMLAN(service="ReadMemoryByAddressPositiveResponse").service:   # noqa: E501
                if verbose:
                    resp.show()
                    print("Negative Response.")
            else:
                return resp.dataRecord

        retry -= 1
        if retry >= 0:
            if verbose:
                print("Retrying..")
    return None


def GMLAN_BroadcastSocket(interface):
    """Returns a GMLAN broadcast socket using interface."""
    return ISOTPSocket(interface, sid=0x101, did=0x0, basecls=GMLAN,
                       extended_addr=0xfe)
