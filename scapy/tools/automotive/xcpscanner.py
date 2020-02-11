#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Fabian Wiche <f.wiche@gmx.de>
# This program is published under a GPLv2 license
import getopt
import sys

import scapy.modules.six as six
from scapy.config import conf
from scapy.consts import LINUX
if six.PY2 or not LINUX:
    conf.contribs['CANSocket'] = {'use-python-can': True}
from scapy.contrib.cansocket import CANSocket, PYTHON_CAN  # noqa: F401
from scapy.contrib.automotive.xcp import XCP_CAN_SCANNER  # noqa: F401 E501


def usage():
    usage_str = """
    Finds open XCP Ports: It is recommended to use this tool with python3
    parameters:
        --channnel=CHANNEL      Defines CAN channel e.g "PCAN_USBBUS0", "can0"
        --start=START           Start ID for XCP Scan in hex
        --end=END               End ID for XCP Scan in hex
        -x, --extended_can_ids  Use extended CAN Frames
        --interface=IFACE       Interface for python-can e.g. "pcan", "vector"
        --budrate=500000        Set baudrate, standard is 500000
        -h, --help              Show this

        Example without python-can:
            python3.6 -m scapy.tools.automotive.xcpscanner\
 --channel=can0 --start=0 --end=12 --extended_can_ids
        Example with python-can (On Windows or python2):
            python2.7 -m scapy.tools.automotive.xcpcanner --channel=\
PCAN_USBUS1 --interface="pcan" --start=12 --end=15 --baudrate=500000
    """
    print(usage_str)


def init_socket(can_channel="PCAN_USBBUS0", interface="pcan", bitrate=500000):
    if PYTHON_CAN:
        import can
        can.rc['interface'] = interface
        can.rc['channel'] = can_channel
        can.rc['bitrate'] = bitrate
        scan_interface = can.interface.Bus()
        interface_string = """
        CANSocket(iface=can.interface.Bus(bustype=" "'%s'," +
        "channel='%s', bitrate = %d))""" % (interface, can_channel, bitrate)
    else:
        sock = None
        scan_interface = can_channel
        interface_string = "\"%s\"" % can_channel
    try:
        sock = CANSocket(iface=scan_interface)
        sock.nonblocking_socket = False
    except Exception as e:
        print(e)
        print("Could not find " + interface_string)
        sys.exit(-1)
    return sock


def get_int_from_input(string, option, base=16):
    if base == 16:
        format = "hex"
    elif base == 10:
        format = "dec"
    else:
        format = ""
    try:
        ret = int(string, base)
    except ValueError:
        print("Error: " + option + "´must be integer in " +
              format + " format")
        sys.exit(-1)
    return ret


def parse_inputs():
    ret = {"extended": False,
           "verbose": False,
           "interface": "pcan",
           "baudrate": 500000}
    opts = "h:vx"
    opt_strings = ["help", "start=", "end=",
                   "extended_can_ids", "channel=",
                   "verbose", "interface=", "baudrate="]
    try:
        opts = getopt.getopt(sys.argv[1:], opts, opt_strings)[0]
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit()
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-x", "--extended_can_ids"):
            ret["extended"] = True
        elif o == "--start":
            ret["start"] = get_int_from_input(a, o, 16)
        elif o == "--end":
            ret["end"] = get_int_from_input(a, o, 16)
        elif o == "--channel":
            ret["can_channel"] = a
        elif o in ("-v", "--versbose"):
            ret["verbose"] = True
        elif o == "--interface":
            ret["interface"] = a
        elif o == "--baudrate":
            ret["baudrate"] = get_int_from_input(a, o, 10)
        else:
            print("unknown option " + str(o))
            sys.exit(-1)

    return ret


def main():
    ret = parse_inputs()

    if ret["can_channel"] is None or\
            ret["end"] is None or\
            ret["start"] is None:
        print("Please set channel, end and start")
        usage()
        sys.exit()

    if ret["end"] < ret["start"]:
        print("end must be higher than start")
        sys.exit()

    if ret["end"] > 0x7FF and not ret["extended"]:
        print("Please use -x option for extended CAN-IDs")
        sys.exit()

    extended_can_id = ret["extended"]
    start = ret["start"]
    end = ret["end"]
    can_channel = ret["can_channel"]
    verbose = ret["verbose"]
    baudrate = ret["baudrate"]
    interface = ret["interface"]

    can_socket = init_socket(can_channel, interface=interface,
                             bitrate=baudrate)
    scanner = XCP_CAN_SCANNER(can_socket, start,
                              end, extended_can_id, verbose)
    scanner.start_scan()  # Blocking
    results = scanner.get_results()

    if isinstance(results, list) and len(results) > 0:
        for r in results:
            print(r)
    else:
        print("No XCP-Port found between IDs " +
              hex(start) + " and " + hex(end))


if __name__ == "__main__":
    main()
