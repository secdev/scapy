# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.korb@e-mundo.de>
# Copyright (C) Friedrich Feigel <friedrich.feigel@e-mundo.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = OnBoardDiagnosticScanner
# scapy.contrib.status = loads

# XXX TODO This file contains illegal E501 issues D:

from scapy.compat import chb
from scapy.contrib.automotive.obd.obd import OBD, OBD_S03, OBD_S07, OBD_S0A, \
    OBD_S01, OBD_S06, OBD_S08, OBD_S09


def _supported_id_numbers(socket, timeout, service_class, id_name, verbose):
    """ Check which Parameter IDs are supported by the vehicle

    Args:
        socket: is the ISOTPSocket, over which the OBD-Services communicate.
                the id 0x7df acts as a broadcast address for all obd-supporting ECUs.
        timeout: only required for the OBD Simulator, since it might tell it
                 supports a PID, while it actually doesn't and won't respond to this PID.
                 If this happens with a real ECU, it is an implementation error.
        service_class: specifies, which OBD-Service should be queried.
        id_name: describes the car domain (e.g.: mid = IDs in Motor Domain).
        verbose: specifies, whether the sr1()-method gives feedback or not.

    This method sends a query message via a ISOTPSocket, which will be responded by the ECUs with
    a message containing Bits, representing whether a PID is supported by the vehicle's protocol implementation or not.
    The first Message has the PID 0x00 and contains 32 Bits, which indicate by their index and value, which PIDs are
    supported.
    If  the PID 0x20 is supported, that means, there are more supported PIDs within the next 32 PIDs, which will result
    in a new query message being sent, that contains the next 32 Bits.
    There is a maximum of 256 possible PIDs.
    The supported PIDs will be returned as set.
    """

    supported_id_numbers = set()
    supported_prop = 'supported_' + id_name + 's'

    # ID 0x00 requests the first range of supported IDs in OBD
    supported_ids_req = OBD() / service_class(b'\x00')

    while supported_ids_req is not None:
        resp = socket.sr1(supported_ids_req, timeout=timeout, verbose=verbose)

        # If None, the device did not respond.
        # Usually only occurs, if device is off.
        if resp is None or resp.service == 0x7f:
            break

        supported_ids_req = None

        all_supported_in_range = getattr(resp.data_records[0], supported_prop)

        for supported in all_supported_in_range:
            id_number = int(supported[-2:], 16)
            supported_id_numbers.add(id_number)

            # send a new query if the next PID range is supported
            if id_number % 0x20 == 0:
                supported_ids_req = OBD() / service_class(chb(id_number))

    return supported_id_numbers


def _scan_id_service(socket, timeout, service_class, id_numbers, verbose):
    """ Queries certain PIDs and stores their return value

    Args:
        socket: is the ISOTPSocket, over which the OBD-Services communicate.
                the id 0x7df acts as a broadcast address for all obd-supporting ECUs.
        timeout: only required for the OBD Simulator, since it might tell it
                 supports a PID, while it actually doesn't and won't respond to this PID.
                 If this happens with a real ECU, it is an implementation error.
        service_class: specifies, which OBD-Service should be queried.
        id_numbers: a set of PIDs, which should be queried by the method.
        verbose: specifies, whether the sr1()-method gives feedback or not.

    This method queries the specified id_numbers and stores their responses in a dictionary, which is then returned.
    """

    data = dict()

    for id_number in id_numbers:
        id_byte = chb(id_number)
        # assemble request packet
        pkt = OBD() / service_class(id_byte)
        resp = socket.sr1(pkt, timeout=timeout, verbose=verbose)

        if resp is not None:
            data[id_number] = bytes(resp)
    return data


def _scan_dtc_service(socket, timeout, service_class, verbose):
    """ Queries Diagnostic Trouble Code Parameters and stores their return value

    Args:
        socket: is the ISOTPSocket, over which the OBD-Services communicate.
                the id 0x7df acts as a broadcast address for all obd-supporting ECUs.
        timeout: only required for the OBD Simulator, since it might tell it
                 supports a PID, while it actually doesn't and won't respond to this PID.
                 If this happens with a real ECU, it is an implementation error.
        service_class: specifies, which OBD-Service should be queried.
        verbose: specifies, whether the sr1()-method gives feedback or not.

    This method queries the specified Diagnostic Trouble Code Parameters and stores their responses in a dictionary,
    which is then returned.
    """

    req = OBD() / service_class()
    resp = socket.sr1(req, timeout=timeout, verbose=verbose)
    if resp is not None:
        return bytes(resp)


def obd_scan(socket, timeout=0.1, supported_ids=False,
             unsupported_ids=False, verbose=False):
    """ Scans for all accessible information of each commonly used OBD service classes and prints the results

    Args:
        socket: is the ISOTPSocket, over which the OBD-Services communicate.
                the id 0x7df acts as a broadcast address for all obd-supporting ECUs.
        timeout: only required for the OBD Simulator, since it might tell it
                 supports a PID, while it actually doesn't and won't respond to this PID.
                 If this happens with a real ECU, it is an implementation error.
        supported_ids: specifies, whether to check for supported Parameter IDs.
                       The OBD-Protocol offers querying, which PIDs the implemented ECUs support.
        unsupported_ids: specifies, whether to check for unsupported or hidden Parameter IDs.
                         There is a possibility of PIDs answering, which are addressed directly, but which are
                         not listed in the supported query response. We call these PIDs unsupported PIDs, because
                         they are seemingly unsupported.
        verbose: specifies, whether the sr1()-method gives feedback or not and turns.

    This method queries the Diagnostic Trouble Code Parameters and if selected, supported and/or unsupported PIDS and
    prints the results.
    """

    dtc = dict()
    supported = dict()
    unsupported = dict()

    if verbose:
        print("\nStarting OBD-Scan...")

    print("\nScanning Diagnostic Trouble Codes:")
    # Emission-related DTCs
    dtc[3] = _scan_dtc_service(socket, timeout, OBD_S03, verbose)
    # Emission-related DTCs detected during current or last completed driving
    # cycle
    dtc[7] = _scan_dtc_service(socket, timeout, OBD_S07, verbose)
    # Permanent DTCs
    dtc[10] = _scan_dtc_service(socket, timeout, OBD_S0A, verbose)
    print("Service 3:")
    print(dtc[3])
    print("Service 7:")
    print(dtc[7])
    print("Service 10:")
    print(dtc[10])

    if not supported_ids and not unsupported_ids:
        return dtc

    # Powertrain
    supported_ids_s01 = _supported_id_numbers(
        socket, timeout, OBD_S01, 'pid', verbose)
    # On-board monitoring test results for non-continuously monitored systems
    supported_ids_s06 = _supported_id_numbers(
        socket, timeout, OBD_S06, 'mid', verbose)
    # Control of on-board system, test or component
    supported_ids_s08 = _supported_id_numbers(
        socket, timeout, OBD_S08, 'tid', verbose)
    # On-board monitoring test results for non-continuously monitored systems
    supported_ids_s09 = _supported_id_numbers(
        socket, timeout, OBD_S09, 'iid', verbose)

    if supported_ids:
        print("\nScanning supported Parameter IDs")
        supported[1] = _scan_id_service(
            socket, timeout, OBD_S01, supported_ids_s01, verbose)
        supported[6] = _scan_id_service(
            socket, timeout, OBD_S06, supported_ids_s06, verbose)
        supported[8] = _scan_id_service(
            socket, timeout, OBD_S08, supported_ids_s08, verbose)
        supported[9] = _scan_id_service(
            socket, timeout, OBD_S09, supported_ids_s09, verbose)
        print("\nSupported PIDs of Service 1:")
        print(supported[1])
        print("Supported PIDs of Service 6:")
        print(supported[6])
        print("Supported PIDs of Service 8:")
        print(supported[8])
        print("Supported PIDs of Service 9:")

    # this option will slow down the test a lot, since it tests for seemingly unsupported ids
    # the chances of those actually responding will be small, so a lot of
    # timeouts can be expected
    if unsupported_ids:
        # the complete id range is from 1 to 255
        all_ids_set = set(range(1, 256))
        # the unsupported id ranges are obtained by creating the compliment set
        # excluding 0
        unsupported_ids_s01 = all_ids_set - supported_ids_s01
        unsupported_ids_s06 = all_ids_set - supported_ids_s06
        unsupported_ids_s08 = all_ids_set - supported_ids_s08
        unsupported_ids_s09 = all_ids_set - supported_ids_s09

        print("\nScanning unsupported Parameter IDs")
        if verbose:
            print("This may take a while...")
        unsupported[1] = _scan_id_service(
            socket, timeout, OBD_S01, unsupported_ids_s01, verbose)
        unsupported[6] = _scan_id_service(
            socket, timeout, OBD_S06, unsupported_ids_s06, verbose)
        unsupported[8] = _scan_id_service(
            socket, timeout, OBD_S08, unsupported_ids_s08, verbose)
        unsupported[9] = _scan_id_service(
            socket, timeout, OBD_S09, unsupported_ids_s09, verbose)
        print("\nUnsupported PIDs of Service 1:")
        print(unsupported[1])
        print("Unsupported PIDs of Service 6:")
        print(unsupported[6])
        print("unsupported PIDs of Service 8:")
        print(unsupported[8])
        print("Unsupported PIDs of Service 9:")
        print(unsupported[9])

    return dtc, supported, unsupported
