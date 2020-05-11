#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Fabian Wiche <f.wiche@gmx.de>
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>

# This program is published under a GPLv2 license
import argparse
import signal
import sys

from scapy.contrib.automotive.xcp.scanner import XCPOnCANScanner
from scapy.contrib.automotive.xcp.xcp import XCPOnCAN
from scapy.contrib.cansocket import CANSocket


class ScannerParams:
    def __init__(self):
        self.use_extended_can_id = False
        self.broadcast_id = None
        self.broadcast_id_range = None
        self.verbose = False
        self.channel = None


def signal_handler(_sig, _frame):
    print('Interrupting scan!')
    sys.exit(0)


def init_socket(scan_params):
    print("Initializing socket for" + scan_params.channel)
    try:
        sock = CANSocket(scan_params.channel)
    except Exception as e:
        print("\nSocket could not be created:" + str(e))
        sys.exit(1)
    sock.basecls = XCPOnCAN
    return sock


def parse_inputs():
    scanner_params = ScannerParams()

    parser = argparse.ArgumentParser()
    parser.description = "Finds XCP slaves using the XCP Broadcast-CAN " \
                         "identifier. (Use with python3 only"
    parser.add_argument('--broadcast_id', '-b',
                        help='XCP Broadcast CAN identifier (in hex)')
    parser.add_argument('--start', '-s',
                        help='Start XCP Broadcast CAN identifier Start ID '
                             '(in hex)\nIf actual ID is unknown the scan will '
                             'test broadcast ids between  --start and --end')
    parser.add_argument('--end', '-e',
                        help='End XCP Broadcast CAN identifier End ID (in hex)'
                             '\nIf actual ID is unknown the scan will test '
                             'broadcast ids between  --start and --end')
    parser.add_argument('channel',
                        help='Linux SocketCAN interface name, e.g.: vcan0')
    parser.add_argument('--extended_can_ids', '-x', type=bool,
                        help='Use extended CAN identifiers')
    parser.add_argument('--verbose', '-v', type=bool,
                        help='Display information during scan')
    args = parser.parse_args()
    scanner_params.channel = args.channel
    scanner_params.use_extended_can_id = args.extended_can_ids
    scanner_params.verbose = args.verbose

    if args.broadcast_id:
        scanner_params.broadcast_id = int(args.broadcast_id, 16)

    if args.start is not None and args.end is not None:
        scanner_params.broadcast_id_range = (
            int(args.start, 16), int(args.end, 16))
    elif bool(args.start) != bool(args.end):
        parser.error("You can not only set --end/-e or --start/-s."
                     "You have to set both.")
        sys.exit(1)

    if scanner_params.broadcast_id_range is not None and \
            scanner_params.broadcast_id_range[0] >= \
            scanner_params.broadcast_id_range[1]:
        parser.error(
            "Start identifier must be smaller than the end identifier")
        sys.exit(1)

    return scanner_params


def main():
    scanner_params = parse_inputs()
    can_socket = init_socket(scanner_params)

    try:
        if scanner_params.broadcast_id is not None:
            scanner = XCPOnCANScanner(can_socket,
                                      broadcast_id=scanner_params.broadcast_id,
                                      use_extended_can_id=scanner_params.use_extended_can_id,  # noqa: E501
                                      verbose=scanner_params.verbose)  # noqa: E501

        elif scanner_params.broadcast_id_range is not None:
            scanner = XCPOnCANScanner(can_socket,
                                      broadcast_id_range=scanner_params.broadcast_id_range,  # noqa: E501
                                      use_extended_can_id=scanner_params.use_extended_can_id,  # noqa: E501
                                      verbose=scanner_params.verbose)  # noqa: E501

        else:
            scanner = XCPOnCANScanner(can_socket,
                                      use_extended_can_id=scanner_params.use_extended_can_id,  # noqa: E501
                                      verbose=scanner_params.verbose)  # noqa: E501

        signal.signal(signal.SIGINT, signal_handler)

        results = scanner.start_scan()  # Blocking

        if isinstance(results, list) and len(results) > 0:
            for r in results:
                print(r)
        else:
            print("Detected no XCP slave.")
    except Exception as err:
        print(err)
        sys.exit(1)
    finally:
        can_socket.close()


if __name__ == "__main__":
    main()
