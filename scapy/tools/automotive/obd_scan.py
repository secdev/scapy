# flake8: noqa: F405

from scapy.compat import chb
from scapy.contrib.automotive.obd.obd import *


def _supported_id_numbers(socket, timeout, service_class, id_name):
    # timeout only required for the OBD Simulator, since it might tell it
    # supports a PID, while it actually doesn't and won't respond to this PID.
    # If this happens with a real ECU, it is an implementation error.

    supported_id_numbers = set()
    supported_prop = 'supported_' + id_name + 's'

    # ID 0x00 requests the first range of supported IDs in OBD
    supported_ids_req = OBD()/service_class(b'\x00')

    while supported_ids_req is not None:
        resp = socket.sr1(supported_ids_req, timeout=timeout)

        # If None, the device did not respond.
        # Usually only occurs, if device is off.
        if resp is None:
            break

        supported_ids_req = None

        all_supported_in_range = getattr(resp.data_records[0], supported_prop)

        for supported in all_supported_in_range:
            id_number = int(supported[-2:], 16)
            supported_id_numbers.add(id_number)

            # check whether supported id is for next id range
            if id_number % 20 == 0:
                supported_ids_req = OBD()/service_class(chb(id_number))

    return supported_id_numbers


def _scan_id_service(socket, timeout, service_class, id_numbers):
    data = dict()

    for id_number in id_numbers:
        id_byte = chb(id_number)
        # assemble request packet
        pkt = OBD()/service_class(id_byte)
        resp = socket.sr1(pkt, timeout=timeout)

        if resp is not None:
            data[id_number] = bytes(resp)
    return data


def _scan_dtc_service(socket, timeout, service_class):
    req = OBD()/service_class()
    resp = socket.sr1(req, timeout=timeout)
    if resp is not None:
        return bytes(resp)


def obd_scan(socket, timeout=0.1, supported_ids=True, unsupported_ids=False):
    dtc = dict()
    supported = dict()
    unsupported = dict()

    # Diagnostic Trouble Codes
    dtc[3] = _scan_dtc_service(socket, timeout, OBD_S03)
    dtc[7] = _scan_dtc_service(socket, timeout, OBD_S07)
    dtc[10] = _scan_dtc_service(socket, timeout, OBD_S0A)

    if not supported_ids and not unsupported_ids:
        return dtc

    supported_ids_s01 = _supported_id_numbers(socket, timeout, OBD_S01, 'pid')
    supported_ids_s06 = _supported_id_numbers(socket, timeout, OBD_S06, 'mid')
    supported_ids_s08 = _supported_id_numbers(socket, timeout, OBD_S08, 'tid')
    supported_ids_s09 = _supported_id_numbers(socket, timeout, OBD_S09, 'iid')

    if supported_ids:
        supported[1] = _scan_id_service(socket, timeout, OBD_S01, supported_ids_s01)
        supported[6] = _scan_id_service(socket, timeout, OBD_S06, supported_ids_s06)
        supported[8] = _scan_id_service(socket, timeout, OBD_S08, supported_ids_s08)
        supported[9] = _scan_id_service(socket, timeout, OBD_S09, supported_ids_s09)

    # this option will slow down the test a lot, since it tests for seemingly unsupported ids
    # the chances of those actually responding will be small, so a lot of timeouts can be expected
    if unsupported_ids:
        # the complete id range is from 1 to 255
        all_ids_set = set(range(1, 256))
        
        # the unsupported id ranges are obtained by creating the compliment set excluding 0
        unsupported_ids_s01 = all_ids_set - supported_ids_s01
        unsupported_ids_s06 = all_ids_set - supported_ids_s06
        unsupported_ids_s08 = all_ids_set - supported_ids_s08
        unsupported_ids_s09 = all_ids_set - supported_ids_s09

        unsupported[1] = _scan_id_service(socket, timeout, OBD_S01, unsupported_ids_s01)
        unsupported[6] = _scan_id_service(socket, timeout, OBD_S06, unsupported_ids_s06)
        unsupported[8] = _scan_id_service(socket, timeout, OBD_S08, unsupported_ids_s08)
        unsupported[9] = _scan_id_service(socket, timeout, OBD_S09, unsupported_ids_s09)

    return dtc, supported, unsupported
