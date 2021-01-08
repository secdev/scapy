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
        self.id_range = None
        self.sniff_time = None
        self.verbose = False
        self.channel = None
        self.broadcast = False


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
    parser.add_argument('--start', '-s',
                        help='Start ID CAN (in hex).\n'
                             'If actual ID is unknown the scan will '
                             'test broadcast ids between --start and --end '
                             '(inclusive). Default: 0x00')
    parser.add_argument('--end', '-e',
                        help='End ID CAN (in hex).\n'
                             'If actual ID is unknown the scan will test '
                             'broadcast ids between --start and --end '
                             '(inclusive). Default: 0x7ff')
    parser.add_argument('--sniff_time', '-t',
                        help='Duration in milliseconds a sniff is waiting '
                             'for a response.', type=int, default=100)
    parser.add_argument('channel',
                        help='Linux SocketCAN interface name, e.g.: vcan0')
    parser.add_argument('--verbose', '-v', action="store_true",
                        help='Display information during scan')
    parser.add_argument('--broadcast', '-b', action="store_true",
                        help='Use Broadcast-message GetSlaveId instead of '
                             'default "Connect"')

    args = parser.parse_args()
    scanner_params.channel = args.channel
    scanner_params.verbose = args.verbose
    scanner_params.use_broadcast = args.broadcast
    scanner_params.sniff_time = float(args.sniff_time) / 1000

    start_id = int(args.start, 16) if args.start is not None else 0
    end_id = int(args.end, 16) if args.end is not None else 0x7ff

    if start_id > end_id:
        parser.error(
            "End identifier must not be smaller than the start identifier.")
        sys.exit(1)
    scanner_params.id_range = range(start_id, end_id + 1)

    return scanner_params


def main():
    scanner_params = parse_inputs()
    can_socket = init_socket(scanner_params)

    try:
        scanner = XCPOnCANScanner(can_socket,
                                  id_range=scanner_params.id_range,
                                  sniff_time=scanner_params.sniff_time,
                                  verbose=scanner_params.verbose)

        signal.signal(signal.SIGINT, signal_handler)

        results = scanner.scan_with_get_slave_id() \
            if scanner_params.broadcast \
            else scanner.scan_with_connect()  # Blocking

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
