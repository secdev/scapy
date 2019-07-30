#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.korb@e-mundo.de>
# Copyright (C) Friedrich Feigel <friedrich.feigel@e-mundo.de>
# This program is published under a GPLv2 license

from __future__ import print_function

import getopt
import sys
import signal
import json

import scapy.modules.six as six
import scapy.contrib.automotive.obd.obd as OBD
from scapy.config import conf
from scapy.consts import LINUX

if six.PY2 or not LINUX:
    conf.contribs['CANSocket'] = {'use-python-can': True}

from scapy.contrib.isotp import ISOTPSocket                 # noqa: E402
from scapy.contrib.cansocket import CANSocket, PYTHON_CAN   # noqa: E402
from scapy.contrib.automotive.obd.scanner import obd_scan   # noqa: E402


def signal_handler(sig, frame):
    print('Interrupting scan!')
    sys.exit(0)


def usage():
    print('''usage:\tobdscanner [-i interface] [-c channel] [-s source] [-d destination] [-b bitrate] 
                                [-h help] [-t timeout] [-r supported] [-u unsupported]\n
    Scan for all possible obd service classes and their subfunctions.\n
    optional arguments:
    -i, --interface             python-can interface for the scan.
                                Depends on used interpreter and system,
                                see examples below. Any python-can interface can
                                be provided. Please see:
                                https://python-can.readthedocs.io for
                                further interface examples.
    -c, --channel               python-can channel or Linux SocketCAN interface name
    -s, --source                ISOTP-socket source id (hex)
    -d, --destination           ISOTP-socket destination id (hex)
    -b, --bitrate               python-can bitrate.\n
    optional arguments:
    -h, --help                  show this help message and exit
    -t, --timeout               Timeout after which the scanner proceeds to next service [seconds]
    -r, --supported             Check for supported id services
    -u, --unsupported           Check for unsupported id services\n
    Example of use:\n
    Python2 or Windows:
    python2 -m scapy.tools.automotive.obdscanner --interface=pcan --channel=PCAN_USBBUS1 --source=0x070 --destination 0x034 --bitrate 250000
    python2 -m scapy.tools.automotive.obdscanner --interface vector --channel 0 --source 0x000 --destination 0x734 --bitrate 500000
    python2 -m scapy.tools.automotive.obdscanner --interface socketcan --channel=can0 --source 0x089 --destination 0x234  --bitrate=250000\n
    Python3 on Linux:
    python3 -m scapy.tools.automotive.obdscanner --channel can0 --source 0x123 --destination 0x456 \n''',  # noqa: E501
          file=sys.stderr)


def main():

    channel = None
    interface = None
    source = None
    destination = None
    bitrate = None
    timeout = 0.1
    supported = False
    unsupported = False

    options = getopt.getopt(
        sys.argv[1:],
        'i:c:s:d:b:t:hru',
        ['interface=', 'channel=', 'source=', 'destination=', 'bitrate=',
         'help', 'timeout=', 'supported', 'unsupported'])

    try:
        for opt, arg in options[0]:
            if opt in ('-i', '--interface'):
                interface = arg
            elif opt in ('-c', '--channel'):
                channel = arg
            elif opt in ('-s', '--source'):
                source = int(arg)
            elif opt in ('-d', '--destination'):
                destination = int(arg)
            elif opt in ('-b', '--bitrate'):
                bitrate = int(arg)
            elif opt in ('-h', '--help'):
                usage()
                sys.exit(-1)
            elif opt in ('-r', '--supported'):
                supported = True
            elif opt in ('-u', '--unsupported'):
                unsupported = True

    except getopt.GetoptError as msg:
        usage()
        print("ERROR:", msg, file=sys.stderr)
        raise SystemExit

    if channel is None or \
            source is None or \
            destination is None or \
            bitrate is None or \
            (PYTHON_CAN and (interface is None or bitrate is None)):
        usage()
        print("\nPlease provide all required arguments.\n",
              file=sys.stderr)
        sys.exit(-1)

    if 0 > source >= 0x800 or 0 > destination >= 0x800 or source == destination:
        print("The ids must be >= 0 and < 0x800.", file=sys.stderr)
        sys.exit(-1)

    if 0 > timeout:
        print("The timeout must be a positive value")
        sys.exit(-1)

    if PYTHON_CAN:
        import can
        try:
            can.rc['interface'] = interface
            can.rc['channel'] = channel
            can.rc['bitrate'] = bitrate
            scan_interface = can.interface.Bus()
        except Exception as e:
            usage()
            print("\nCheck python-can interface assignment.\n",
                  file=sys.stderr)
            print(e, file=sys.stderr)
            sys.exit(-1)
    else:
        scan_interface = channel

    try:
        csock = CANSocket(iface=scan_interface)
    except Exception as e:
        usage()
        print("\nSocket couldn't be created. Check your arguments.\n",
              file=sys.stderr)
        print(e, file=sys.stderr)
        sys.exit(-1)

    isock = ISOTPSocket(csock, source, destination, basecls=OBD, padding=True)

    signal.signal(signal.SIGINT, signal_handler)

    result = obd_scan(isock, timeout=timeout, supported_ids=supported, unsupported_ids=unsupported)

    print("Scan: \n%s" % json.dumps(result[0], ensure_ascii=False))
    if supported:
        print("Scan: \n%s" % json.dumps(result[1], ensure_ascii=False))
    if supported:
        print("Scan: \n%s" % json.dumps(result[1], ensure_ascii=False))


if __name__ == '__main__':
    main()
