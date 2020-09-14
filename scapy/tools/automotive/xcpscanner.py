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
        self.broadcast_id = None
        self.broadcast_id_range = None
        self.sniff_time = None
        self.verbose = False
        self.channel = None


def signal_handler(sig, _frame):
    sys.stderr.write("Interrupting scan!\n")
    # Use same convention as the bash shell
    # 128+n where n is the fatal error signal
    # https://tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
    sys.exit(128 + sig)


def init_socket(scan_params):
    print("Initializing socket for " + scan_params.channel)
    try:
        sock = CANSocket(scan_params.channel)
    except Exception as e:
        sys.stderr.write("\nSocket could not be created: " + str(e) + "\n")
        sys.exit(1)
    sock.basecls = XCPOnCAN
    return sock


def parse_inputs():
    scanner_params = ScannerParams()

    parser = argparse.ArgumentParser()
    parser.description = "Finds XCP slaves using the XCP Broadcast-CAN " \
                         "identifier."
    parser.add_argument('--broadcast_id', '-b',
                        help='XCP Broadcast CAN identifier (in hex), e.g. 7F0')
    parser.add_argument('--start', '-s',
                        help='XCP Broadcast CAN identifier Start ID '
                             '(in hex).\n'
                             'If actual ID is unknown the scan will '
                             'test broadcast ids between --start and --end '
                             '(inclusive)')
    parser.add_argument('--end', '-e',
                        help='End XCP Broadcast CAN identifier End ID '
                             '(in hex).\n'
                             'If actual ID is unknown the scan will test '
                             'broadcast ids between --start and --end '
                             '(inclusive)')
    parser.add_argument('--sniff_time', '-t',
                        help='Duration in milliseconds a sniff is waiting '
                             'for a response.', type=int, default=100)
    parser.add_argument('channel',
                        help='Linux SocketCAN interface name, e.g.: vcan0')
    parser.add_argument('--verbose', '-v', action="store_true",
                        help='Display information during scan')
    args = parser.parse_args()
    scanner_params.channel = args.channel
    scanner_params.verbose = args.verbose
    scanner_params.sniff_time = float(args.sniff_time) / 1000

    if args.broadcast_id:
        scanner_params.broadcast_id = int(args.broadcast_id, 16)

    if args.start is not None and args.end is not None:
        scanner_params.broadcast_id_range = (
            int(args.start, 16), int(args.end, 16))
    elif bool(args.start) != bool(args.end):
        parser.error("You can not only set --end/-e or --start/-s. "
                     "You have to set both.")
        sys.exit(1)

    if scanner_params.broadcast_id_range is not None and \
            scanner_params.broadcast_id_range[0] >= \
            scanner_params.broadcast_id_range[1]:
        parser.error(
            "Start identifier must be smaller than the end identifier.")
        sys.exit(1)

    return scanner_params


def main():
    scanner_params = parse_inputs()
    can_socket = init_socket(scanner_params)

    try:
        if scanner_params.broadcast_id is not None:
            scanner = XCPOnCANScanner(can_socket,
                                      broadcast_id=scanner_params.broadcast_id,
                                      sniff_time=scanner_params.sniff_time,
                                      verbose=scanner_params.verbose)

        elif scanner_params.broadcast_id_range is not None:
            scanner = XCPOnCANScanner(can_socket,
                                      broadcast_id_range=scanner_params.broadcast_id_range,  # noqa: E501
                                      sniff_time=scanner_params.sniff_time,
                                      verbose=scanner_params.verbose)

        else:
            scanner = XCPOnCANScanner(can_socket,
                                      sniff_time=scanner_params.sniff_time,
                                      verbose=scanner_params.verbose)

        signal.signal(signal.SIGINT, signal_handler)

        results = scanner.start_scan()  # Blocking

        if isinstance(results, list) and len(results) > 0:
            for r in results:
                print(r)
        else:
            print("Detected no XCP slave.")
    except Exception as err:
        sys.stderr.write(str(err) + "\n")
        sys.exit(1)
    finally:
        can_socket.close()


if __name__ == "__main__":
    main()
