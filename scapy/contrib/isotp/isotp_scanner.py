# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Alexander Schroeder <alexander1.schroeder@st.othr.de>
import itertools
import json
# scapy.contrib.description = ISO-TP (ISO 15765-2) Scanner Utility
# scapy.contrib.status = library
import logging
import time

from threading import Event

from scapy.packet import Packet
from scapy.compat import orb
from scapy.layers.can import CAN
from scapy.supersocket import SuperSocket
from scapy.contrib.cansocket import PYTHON_CAN
from scapy.contrib.isotp.isotp_packet import ISOTPHeader, ISOTPHeaderEA, \
    ISOTP_FF, ISOTP

# Typing imports
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
)

log_isotp = logging.getLogger("scapy.contrib.isotp")


def send_multiple_ext(sock, ext_id, packet, number_of_packets):
    # type: (SuperSocket, int, Packet, int) -> None
    """Send multiple packets with extended addresses at once.

    This function is used for scanning with extended addresses.
    It sends multiple packets at once. The number of packets
    is defined in the number_of_packets variable.
    It only iterates the extended ID, NOT the actual CAN ID of the packet.
    This method is used in extended scan function.

    :param sock: CAN interface to send packets
    :param ext_id: Extended ISOTP-Address
    :param packet: Template Packet
    :param number_of_packets: number of packets to send in one batch
    """
    end_id = min(ext_id + number_of_packets, 255)
    for i in range(ext_id, end_id + 1):
        packet.extended_address = i
        sock.send(packet)


def get_isotp_packet(identifier=0x0, extended=False, extended_can_id=False):
    # type: (int, bool, bool) -> Packet
    """Craft ISO-TP packet

    :param identifier: identifier of crafted packet
    :param extended: boolean if packet uses extended address
    :param extended_can_id: boolean if CAN should use extended Ids
    :return: Crafted Packet
    """

    if extended:
        pkt = ISOTPHeaderEA() / ISOTP_FF()  # type: Packet
        pkt.extended_address = 0
        pkt.data = b'\x00\x00\x00\x00\x00'
    else:
        pkt = ISOTPHeader() / ISOTP_FF()
        pkt.data = b'\x00\x00\x00\x00\x00\x00'
    if extended_can_id:
        pkt.flags = "extended"

    pkt.identifier = identifier
    pkt.message_size = 100
    return pkt


def filter_periodic_packets(packet_dict):
    # type: (Dict[int, Tuple[Packet, int]]) -> None
    """Filter to remove periodic packets from packet_dict

    ISOTP-Filter for periodic packets (same ID, always same time-gaps)
    Deletes periodic packets in packet_dict

    :param packet_dict: Dictionary, where the filter is applied
    """
    filter_dict = {}  # type: Dict[int, Tuple[List[int], List[Packet]]]

    for key, value in packet_dict.items():
        pkt = value[0]
        idn = value[1]
        if idn not in filter_dict:
            filter_dict[idn] = ([key], [pkt])
        else:
            key_lst, pkt_lst = filter_dict[idn]
            filter_dict[idn] = (key_lst + [key], pkt_lst + [pkt])

    for idn in filter_dict:
        key_lst = filter_dict[idn][0]
        pkt_lst = filter_dict[idn][1]
        if len(pkt_lst) < 3:
            continue

        tg = [float(p1.time) - float(p2.time)
              for p1, p2 in zip(pkt_lst[1:], pkt_lst[:-1])]
        if all(abs(t1 - t2) < 0.001 for t1, t2 in zip(tg[1:], tg[:-1])):
            log_isotp.info(
                "[i] Identifier 0x%03x seems to be periodic. Filtered.")
            for k in key_lst:
                del packet_dict[k]


def get_isotp_fc(
        id_value,  # type: int
        id_list,  # type: Union[List[int], Dict[int, Tuple[Packet, int]]]
        noise_ids,  # type: Optional[List[int]]
        extended,  # type: bool
        packet,  # type: Packet
):
    # type: (...) -> None
    """Callback for sniff function when packet received

    If received packet is a FlowControl and not in noise_ids append it
    to id_list.

    :param id_value: packet id of send packet
    :param id_list: list of received IDs
    :param noise_ids: list of packet IDs which will not be considered when
                      received during scan
    :param extended: boolean if extended scan
    :param packet: received packet
    """
    if packet.flags and packet.flags != "extended":
        return

    if noise_ids is not None and packet.identifier in noise_ids:
        return

    try:
        index = 1 if extended else 0
        isotp_pci = orb(packet.data[index]) >> 4
        isotp_fc = orb(packet.data[index]) & 0x0f
        if isotp_pci == 3 and 0 <= isotp_fc <= 2:
            log_isotp.info("Found flow-control frame from identifier "
                           "0x%03x when testing identifier 0x%03x",
                           packet.identifier, id_value)
            if isinstance(id_list, dict):
                id_list[id_value] = (packet, packet.identifier)
            elif isinstance(id_list, list):
                id_list.append(id_value)
            else:
                raise TypeError("Unknown type of id_list")
        else:
            if noise_ids is not None:
                noise_ids.append(packet.identifier)
    except Exception as e:
        log_isotp.exception(
            "Unknown message Exception: %s on packet: %s",
            e, repr(packet))


def scan(sock,  # type: SuperSocket
         scan_range=range(0x800),  # type: Iterable[int]
         noise_ids=None,  # type: Optional[List[int]]
         sniff_time=0.1,  # type: float
         extended_can_id=False,  # type: bool
         verify_results=True,  # type: bool
         stop_event=None  # type: Optional[Event]
         ):  # type: (...) -> Dict[int, Tuple[Packet, int]]
    """Scan and return dictionary of detections

    ISOTP-Scan - NO extended IDs
    found_packets = Dictionary with Send-to-ID as
    key and a tuple (received packet, Recv_ID)

    :param sock: socket for can interface
    :param scan_range: hexadecimal range of IDs to scan. Default is 0x0 - 0x7ff
    :param noise_ids: list of packet IDs which will not be tested during scan
    :param sniff_time: time the scan waits for isotp flow control responses
                       after sending a first frame
    :param extended_can_id: Send extended can frames
    :param verify_results: Verify scan results. This will cause a second scan
                           of all possible candidates for ISOTP Sockets
    :param stop_event: Event object to asynchronously stop the scan
    :return: Dictionary with all found packets
    """
    return_values = dict()  # type: Dict[int, Tuple[Packet, int]]
    for value in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if noise_ids and value in noise_ids:
            continue
        sock.send(get_isotp_packet(value, False, extended_can_id))
        sock.sniff(prn=lambda pkt: get_isotp_fc(value, return_values,
                                                noise_ids, False, pkt),
                   timeout=sniff_time, store=False)

    if not verify_results:
        return return_values

    cleaned_ret_val = dict()  # type: Dict[int, Tuple[Packet, int]]
    retest_ids = list(set(
        itertools.chain.from_iterable(
            range(max(0, i - 2), i + 2) for i in return_values.keys())))
    for value in retest_ids:
        if stop_event is not None and stop_event.is_set():
            break
        sock.send(get_isotp_packet(value, False, extended_can_id))
        sock.sniff(prn=lambda pkt: get_isotp_fc(value, cleaned_ret_val,
                                                noise_ids, False, pkt),
                   timeout=sniff_time * 10, store=False)

    return cleaned_ret_val


def scan_extended(sock,  # type: SuperSocket
                  scan_range=range(0x800),  # type: Iterable[int]
                  scan_block_size=32,  # type: int
                  extended_scan_range=range(0x100),  # type: Iterable[int]
                  noise_ids=None,  # type: Optional[List[int]]
                  sniff_time=0.1,  # type: float
                  extended_can_id=False,  # type: bool
                  stop_event=None  # type: Optional[Event]
                  ):  # type: (...) -> Dict[int, Tuple[Packet, int]]
    """Scan with ISOTP extended addresses and return dictionary of detections

    If an answer-packet found -> slow scan with
    single packages with extended ID 0 - 255
    found_packets = Dictionary with Send-to-ID
    as key and a tuple (received packet, Recv_ID)

    :param sock: socket for can interface
    :param scan_range: hexadecimal range of IDs to scan. Default is 0x0 - 0x7ff
    :param scan_block_size: count of packets send at once
    :param extended_scan_range: range to search for extended ISOTP addresses
    :param noise_ids: list of packet IDs which will not be tested during scan
    :param sniff_time: time the scan waits for isotp flow control responses
                       after sending a first frame
    :param extended_can_id: Send extended can frames
    :param stop_event: Event object to asynchronously stop the scan
    :return: Dictionary with all found packets
    """
    return_values = dict()  # type: Dict[int, Tuple[Packet, int]]
    scan_block_size = scan_block_size or 1
    r = list(extended_scan_range)

    for value in scan_range:
        if noise_ids and value in noise_ids:
            continue

        pkt = get_isotp_packet(
            value, extended=True, extended_can_id=extended_can_id)
        id_list = []  # type: List[int]
        for ext_isotp_id in range(r[0], r[-1], scan_block_size):
            if stop_event is not None and stop_event.is_set():
                break
            send_multiple_ext(sock, ext_isotp_id, pkt, scan_block_size)
            sock.sniff(prn=lambda p: get_isotp_fc(ext_isotp_id, id_list,
                                                  noise_ids, True, p),
                       timeout=sniff_time * 3, store=False)
            # sleep to prevent flooding
            time.sleep(sniff_time)

        # remove duplicate IDs
        id_list = list(set(id_list))
        for ext_isotp_id in id_list:
            if stop_event is not None and stop_event.is_set():
                break
            for ext_id in range(max(ext_isotp_id - 2, 0),
                                min(ext_isotp_id + scan_block_size + 2, 256)):
                if stop_event is not None and stop_event.is_set():
                    break
                pkt.extended_address = ext_id
                full_id = (value << 8) + ext_id
                sock.send(pkt)
                sock.sniff(prn=lambda pkt: get_isotp_fc(full_id,
                                                        return_values,
                                                        noise_ids, True,
                                                        pkt),
                           timeout=sniff_time * 2, store=False)

    return return_values


def isotp_scan(sock,  # type: SuperSocket
               scan_range=range(0x7ff + 1),  # type: Iterable[int]
               extended_addressing=False,  # type: bool
               extended_scan_range=range(0x100),  # type: Iterable[int]
               noise_listen_time=2,  # type: int
               sniff_time=0.1,  # type: float
               output_format=None,  # type: Optional[str]
               can_interface=None,  # type: Optional[str]
               extended_can_id=False,  # type: bool
               verify_results=True,  # type: bool
               verbose=False,  # type: bool
               stop_event=None  # type: Optional[Event]
               ):
    # type: (...) -> Union[str, List[SuperSocket]]
    """Scan for ISOTP Sockets on a bus and return findings

    Scan for ISOTP Sockets in the defined range and returns found sockets
    in a specified format. The format can be:

    - text: human readable output
    - code: python code for copy&paste
    - json: json string
    - sockets: if output format is not specified, ISOTPSockets will be
      created and returned in a list

    :param sock: CANSocket object to communicate with the bus under scan
    :param scan_range: range of CAN-Identifiers to scan. Default is 0x0 - 0x7ff
    :param extended_addressing: scan with ISOTP extended addressing
    :param extended_scan_range: range for ISOTP extended addressing values
    :param noise_listen_time: seconds to listen for default communication on
                              the bus
    :param sniff_time: time the scan waits for isotp flow control responses
                       after sending a first frame
    :param output_format: defines the format of the returned results
                          (text, code or sockets). Provide a string e.g.
                          "text". Default is "socket".
    :param can_interface: interface used to create the returned code/sockets
    :param extended_can_id: Use Extended CAN-Frames
    :param verify_results: Verify scan results. This will cause a second scan
                           of all possible candidates for ISOTP Sockets
    :param verbose: displays information during scan
    :param stop_event: Event object to asynchronously stop the scan
    :return:
    """
    if verbose:
        log_isotp.setLevel(logging.DEBUG)

    log_isotp.info("Filtering background noise...")

    # Send dummy packet. In most cases, this triggers activity on the bus.

    dummy_pkt = CAN(identifier=0x123,
                    data=b'\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb')

    background_pkts = sock.sniff(
        timeout=noise_listen_time,
        started_callback=lambda: sock.send(dummy_pkt))

    noise_ids = list(set(pkt.identifier for pkt in background_pkts))

    if extended_addressing:
        found_packets = scan_extended(sock, scan_range,
                                      extended_scan_range=extended_scan_range,
                                      noise_ids=noise_ids,
                                      sniff_time=sniff_time,
                                      extended_can_id=extended_can_id,
                                      stop_event=stop_event)
    else:
        found_packets = scan(sock, scan_range,
                             noise_ids=noise_ids,
                             sniff_time=sniff_time,
                             extended_can_id=extended_can_id,
                             verify_results=verify_results,
                             stop_event=stop_event)

    filter_periodic_packets(found_packets)

    if output_format == "text":
        return generate_text_output(found_packets, extended_addressing)

    if output_format == "code":
        return generate_code_output(found_packets, can_interface,
                                    extended_addressing)

    if output_format == "json":
        return generate_json_output(found_packets, can_interface,
                                    extended_addressing)

    return generate_isotp_list(found_packets, can_interface or sock,
                               extended_addressing)


def generate_text_output(found_packets, extended_addressing=False):
    # type: (Dict[int, Tuple[Packet, int]], bool) -> str
    """Generate a human readable output from the result of the `scan` or the
    `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param extended_addressing: print results from a scan with
                                ISOTP extended addressing
    :return: human readable scan results
    """
    if not found_packets:
        return "No packets found."

    text = "\nFound %s ISOTP-FlowControl Packet(s):" % len(found_packets)
    for pack in found_packets:
        if extended_addressing:
            send_id = pack // 256
            send_ext = pack - (send_id * 256)
            ext_id = hex(orb(found_packets[pack][0].data[0]))
            text += "\nSend to ID:             %s" \
                    "\nSend to extended ID:    %s" \
                    "\nReceived ID:            %s" \
                    "\nReceived extended ID:   %s" \
                    "\nMessage:                %s" % \
                    (hex(send_id), hex(send_ext),
                     hex(found_packets[pack][0].identifier), ext_id,
                     repr(found_packets[pack][0]))
        else:
            text += "\nSend to ID:             %s" \
                    "\nReceived ID:            %s" \
                    "\nMessage:                %s" % \
                    (hex(pack),
                     hex(found_packets[pack][0].identifier),
                     repr(found_packets[pack][0]))

        padding = found_packets[pack][0].length == 8
        if padding:
            text += "\nPadding enabled"
        else:
            text += "\nNo Padding"

        text += "\n"
    return text


def generate_code_output(found_packets, can_interface="iface",
                         extended_addressing=False):
    # type: (Dict[int, Tuple[Packet, int]], Optional[str], bool) -> str
    """Generate a copy&past-able output from the result of the `scan` or
    the `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param can_interface: description string for a CAN interface to be
                          used for the creation of the output.
    :param extended_addressing: print results from a scan with ISOTP
                                extended addressing
    :return: Python-code as string to generate all found sockets
    """
    result = ""
    if not found_packets:
        return result

    header = "\n\nimport can\n" \
             "conf.contribs['CANSocket'] = {'use-python-can': %s}\n" \
             "load_contrib('cansocket')\n" \
             "load_contrib('isotp')\n\n" % PYTHON_CAN

    for pack in found_packets:
        if extended_addressing:
            send_id = pack // 256
            send_ext = pack - (send_id * 256)
            ext_id = orb(found_packets[pack][0].data[0])
            result += "ISOTPSocket(%s, tx_id=0x%x, rx_id=0x%x, padding=%s, " \
                      "ext_address=0x%x, rx_ext_address=0x%x, " \
                      "basecls=ISOTP)\n" % \
                      (can_interface, send_id,
                       int(found_packets[pack][0].identifier),
                       found_packets[pack][0].length == 8,
                       send_ext,
                       ext_id)

        else:
            result += "ISOTPSocket(%s, tx_id=0x%x, rx_id=0x%x, padding=%s, " \
                      "basecls=ISOTP)\n" % \
                      (can_interface, pack,
                       int(found_packets[pack][0].identifier),
                       found_packets[pack][0].length == 8)
    return header + result


def generate_json_output(found_packets,  # type: Dict[int, Tuple[Packet, int]]
                         can_interface="iface",  # type: Optional[str]
                         extended_addressing=False  # type: bool
                         ):
    # type: (...) -> str
    """Generate a list of ISOTPSocket objects from the result of the `scan` or
    the `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param can_interface: description string for a CAN interface to be
                          used for the creation of the output.
    :param extended_addressing: print results from a scan with ISOTP
                                extended addressing
    :return: A list of all found ISOTPSockets
    """
    socket_list = []  # type: List[Dict[str, Any]]
    for pack in found_packets:
        pkt = found_packets[pack][0]

        dest_id = pkt.identifier
        pad = True if pkt.length == 8 else False

        if extended_addressing:
            source_id = pack >> 8
            source_ext = int(pack - (source_id * 256))
            dest_ext = orb(pkt.data[0])
            socket_list.append({"iface": can_interface,
                                "tx_id": source_id,
                                "ext_address": source_ext,
                                "rx_id": dest_id,
                                "rx_ext_address": dest_ext,
                                "padding": pad,
                                "basecls": ISOTP.__name__})
        else:
            source_id = pack
            socket_list.append({"iface": can_interface,
                                "tx_id": source_id,
                                "rx_id": dest_id,
                                "padding": pad,
                                "basecls": ISOTP.__name__})
    return json.dumps(socket_list)


def generate_isotp_list(found_packets,  # type: Dict[int, Tuple[Packet, int]]
                        can_interface,  # type: Union[SuperSocket, str]
                        extended_addressing=False  # type: bool
                        ):
    # type: (...) -> List[SuperSocket]
    """Generate a list of ISOTPSocket objects from the result of the `scan` or
    the `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param can_interface: description string for a CAN interface to be
                          used for the creation of the output.
    :param extended_addressing: print results from a scan with ISOTP
                                extended addressing
    :return: A list of all found ISOTPSockets
    """
    from scapy.contrib.isotp import ISOTPSocket

    socket_list = []  # type: List[SuperSocket]
    for pack in found_packets:
        pkt = found_packets[pack][0]

        dest_id = pkt.identifier
        pad = True if pkt.length == 8 else False

        if extended_addressing:
            source_id = pack >> 8
            source_ext = int(pack - (source_id * 256))
            dest_ext = orb(pkt.data[0])
            socket_list.append(ISOTPSocket(can_interface, tx_id=source_id,
                                           ext_address=source_ext,
                                           rx_id=dest_id,
                                           rx_ext_address=dest_ext,
                                           padding=pad,
                                           basecls=ISOTP))
        else:
            source_id = pack
            socket_list.append(ISOTPSocket(can_interface, tx_id=source_id,
                                           rx_id=dest_id, padding=pad,
                                           basecls=ISOTP))
    return socket_list
