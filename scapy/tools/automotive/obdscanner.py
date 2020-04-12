#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.korb@e-mundo.de>
# Copyright (C) Friedrich Feigel <friedrich.feigel@e-mundo.de>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

from __future__ import print_function

import getopt
import sys
import signal
import re

from ast import literal_eval

import scapy.modules.six as six
from scapy.config import conf
from scapy.consts import LINUX

if six.PY2 or not LINUX or conf.use_pypy:
    conf.contribs['CANSocket'] = {'use-python-can': True}

from scapy.contrib.isotp import ISOTPSocket                 # noqa: E402
from scapy.contrib.cansocket import CANSocket, PYTHON_CAN   # noqa: E402
from scapy.contrib.automotive.obd.obd import OBD            # noqa: E402
from scapy.contrib.automotive.obd.scanner import obd_scan   # noqa: E402


def signal_handler(sig, frame):
    print('Interrupting scan!')
    sys.exit(0)


def usage(is_error):
    print('''usage:\tobdscanner [-i|--interface] [-c|--channel] [-b|--bitrate]
                                [-a|--python-can_args] [-h|--help]
                                [-s|--source] [-d|--destination]
                                [-t|--timeout] [-r|--supported]
                                [-u|--unsupported] [-v|--verbose]\n
    Scan for all possible obd service classes and their subfunctions.\n
    optional arguments:
    -c, --channel               python-can channel or Linux SocketCAN interface name\n
    additional required arguments for WINDOWS or Python 2:
    -i, --interface             python-can interface for the scan.
                                Depends on used interpreter and system,
                                see examples below. Any python-can interface can
                                be provided. Please see:
                                https://python-can.readthedocs.io for
                                further interface examples.
    optional arguments:
    -a, --python-can_args       Additional arguments for a python-can Bus object.
    -h, --help                  show this help message and exit
    -s, --source                ISOTP-socket source id (hex)
    -d, --destination           ISOTP-socket destination id (hex)
    -t, --timeout               Timeout after which the scanner proceeds to next service [seconds]
    -r, --supported             Check for supported id services
    -u, --unsupported           Check for unsupported id services
    -v, --verbose               Display information during scan\n
    Example of use:\n
    Python2 or Windows:
    python2 -m scapy.tools.automotive.obdscanner --interface=pcan --channel=PCAN_USBBUS1 --source=0x070 --destination 0x034
    python2 -m scapy.tools.automotive.obdscanner --interface vector --channel 0 --source 0x000 --destination 0x734
    python2 -m scapy.tools.automotive.obdscanner --interface socketcan --channel=can0 --source 0x089 --destination 0x234
    python2 -m scapy.tools.automotive.obdscanner --interface vector --channel 0 --python-can_args 'bitrate=500000, poll_interval=1' --source=0x070 --destination 0x034\n
    Python3 on Linux:
    python3 -m scapy.tools.automotive.obdscanner --channel can0 --source 0x123 --destination 0x456 \n''',  # noqa: E501
          file=sys.stderr if is_error else sys.stdout)


def main():

    channel = None
    interface = None
    source = 0x7e0
    destination = 0x7df
    timeout = 0.1
    supported = False
    unsupported = False
    verbose = False
    python_can_args = None

    options = getopt.getopt(
        sys.argv[1:],
        'i:c:s:d:a:t:hruv',
        ['interface=', 'channel=', 'source=', 'destination=',
         'help', 'timeout=', 'python-can_args=', 'supported', 'unsupported',
         'verbose'])

    try:
        for opt, arg in options[0]:
            if opt in ('-i', '--interface'):
                interface = arg
            elif opt in ('-c', '--channel'):
                channel = arg
            elif opt in ('-a', '--python-can_args'):
                python_can_args = arg
            elif opt in ('-s', '--source'):
                source = int(arg, 16)
            elif opt in ('-d', '--destination'):
                destination = int(arg, 16)
            elif opt in ('-h', '--help'):
                usage(False)
                sys.exit(0)
            elif opt in ('-t', '--timeout'):
                timeout = float(arg)
            elif opt in ('-r', '--supported'):
                supported = True
            elif opt in ('-u', '--unsupported'):
                unsupported = True
            elif opt in ('-v', '--verbose'):
                verbose = True
    except getopt.GetoptError as msg:
        usage(True)
        print("ERROR:", msg, file=sys.stderr)
        raise SystemExit

    if channel is None or \
            (PYTHON_CAN and interface is None):
        usage(True)
        print("\nPlease provide all required arguments.\n",
              file=sys.stderr)
        sys.exit(1)

    if 0 > source >= 0x800 or 0 > destination >= 0x800\
            or source == destination:
        print("The ids must be >= 0 and < 0x800 and not equal.",
              file=sys.stderr)
        sys.exit(1)

    if 0 > timeout:
        print("The timeout must be a positive value")
        sys.exit(1)

    csock = None
    try:
        if PYTHON_CAN:
            if python_can_args:
                arg_dict = dict((k, literal_eval(v)) for k, v in
                                (pair.split('=') for pair in
                                 re.split(', | |,', python_can_args)))
                csock = CANSocket(bustype=interface, channel=channel,
                                  **arg_dict)
            else:
                csock = CANSocket(bustype=interface, channel=channel)
        else:
            csock = CANSocket(channel=channel)

        with ISOTPSocket(csock, source, destination,
                         basecls=OBD, padding=True) as isock:
            signal.signal(signal.SIGINT, signal_handler)
            obd_scan(isock, timeout, supported, unsupported, verbose)

    except Exception as e:
        usage(True)
        print("\nSocket couldn't be created. Check your arguments.\n",
              file=sys.stderr)
        print(e, file=sys.stderr)
        sys.exit(1)

    finally:
        if csock is not None:
            csock.close()


if __name__ == '__main__':
    main()
