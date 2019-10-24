#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Alexander Schroeder <alexander1.schroeder@st.othr.de>
# This program is published under a GPLv2 license

from __future__ import print_function

import getopt
import sys
import signal

import scapy.modules.six as six
from scapy.config import conf
from scapy.consts import LINUX

if six.PY2 or not LINUX:
    conf.contribs['CANSocket'] = {'use-python-can': True}

from scapy.contrib.cansocket import CANSocket, PYTHON_CAN   # noqa: E402
from scapy.contrib.isotp import ISOTPScan                   # noqa: E402


def signal_handler(sig, frame):
    print('Interrupting scan!')
    sys.exit(0)


def usage():
    print('''usage:\tisotpscanner [-i interface] [-c channel] [-b bitrate]
                [-n NOISE_LISTEN_TIME] [-t SNIFF_TIME] [-x|--extended]
                [-C|--piso] [-v|--verbose] [-h|--help] [-s start] [-e end]\n
    Scan for open ISOTP-Sockets.\n
    required arguments:
    -c, --channel         python-can channel or Linux SocketCAN interface name
    -s, --start           Start scan at this identifier (hex)
    -e, --end             End scan at this identifier (hex)\n
    additional required arguments for WINDOWS or Python 2:
    -i, --interface       python-can interface for the scan.
                          Depends on used interpreter and system,
                          see examples below. Any python-can interface can
                          be provided. Please see:
                          https://python-can.readthedocs.io for
                          further interface examples.
    -b, --bitrate         python-can bitrate.\n
    optional arguments:
    -h, --help            show this help message and exit
    -n NOISE_LISTEN_TIME, --noise_listen_time NOISE_LISTEN_TIME
                          Seconds listening for noise before scan.
    -t SNIFF_TIME, --sniff_time SNIFF_TIME
                          Duration in milliseconds a sniff is waiting for a
                          flow-control response.
    -x, --extended        Scan with ISOTP extended addressing. 
                          This has nothing to do with extended CAN Frames                          
    -C, --piso            Print 'Copy&Paste'-ready ISOTPSockets.
    -v, --verbose         Display information during scan.\n
    -w, --wide            Enable scanning spaces greater than 0x800
    	--extended_can_id    Use extended CAN Frames 
    Example of use:\n
    Python2 or Windows:
    python2 -m scapy.tools.automotive.isotpscanner --interface=pcan --channel=PCAN_USBBUS1 --bitrate=250000 --start 0 --end 100
    python2 -m scapy.tools.automotive.isotpscanner --interface vector --channel 0 --bitrate 250000 --start 0 --end 100
    python2 -m scapy.tools.automotive.isotpscanner --interface socketcan --channel=can0 --bitrate=250000 --start 0 --end 100\n
    Python3 on Linux:
    python3 -m scapy.tools.automotive.isotpscanner --channel can0 --start 0 --end 100 \n''',  # noqa: E501
          file=sys.stderr)


def main():
    extended = False
    piso = False
    verbose = False
    wide_option = False
    extended_can_id = False
    sniff_time = 100
    noise_listen_time = 2
    start = None
    end = None
    channel = None
    interface = None
    bitrate = None

    options = getopt.getopt(
        sys.argv[1:],
        'vxCt:n:i:c:b:s:e:h:w',
        ['verbose', 'noise_listen_time=', 'sniff_time=', 'interface=', 'piso',
         'channel=', 'bitrate=', 'start=', 'end=', 'help', 'extended', 'wide', 'extended_can_id'])

    try:
        for opt, arg in options[0]:
            if opt in ('-v', '--verbose'):
                verbose = True
            elif opt in ('-x', '--extended'):
                extended = True
            elif opt in ('-C', '--piso'):
                piso = True
            elif opt in ('-h', '--help'):
                usage()
                sys.exit(-1)
            elif opt in ('-t', '--sniff_time'):
                sniff_time = int(arg)
            elif opt in ('-n', '--noise_listen_time'):
                noise_listen_time = int(arg)
            elif opt in ('-i', '--interface'):
                interface = arg
            elif opt in ('-c', '--channel'):
                channel = arg
            elif opt in ('-b', '--bitrate'):
                bitrate = int(arg)
            elif opt in ('-s', '--start'):
                start = int(arg, 16)
            elif opt in ('-e', '--end'):
                end = int(arg, 16)
            elif opt in ('-w', '--wide'):
                wide_option = True
            elif opt in '--extended_can_id':
                extended_can_id = True
    except getopt.GetoptError as msg:
        usage()
        print("ERROR:", msg, file=sys.stderr)
        raise SystemExit

    if start is None or \
            end is None or \
            channel is None or \
            (PYTHON_CAN and (bitrate is None or interface is None)):
        usage()
        print("\nPlease provide all required arguments.\n", file=sys.stderr)
        sys.exit(-1)

    if end >= 2**29:
        print("end must be < " + hex(2**29), file=sys.stderr)
        sys.exit(-1)
    elif not extended_can_id and end >= 0x800:
        print("Standard IDs must be <= 0x800.\n"
              "Use --extended_can_id option for extended CAN range.", file=sys.stderr)
        sys.exit(-1)

    if end - start > 0x800 and not wide_option:
        print("Scanning big address spaces takes a lot of time.\n"
              "Please use --wide option in order to scan spaces greater than 0x800", file=sys.stderr)
        sys.exit(-1)

    if end < start:
        print("start must be equal or smaller than end.", file=sys.stderr)
        sys.exit(-1)

    if PYTHON_CAN:
        import can
        try:
            can.rc['interface'] = interface
            can.rc['channel'] = channel
            can.rc['bitrate'] = bitrate
            scan_interface = can.interface.Bus()
            interface_string = "CANSocket(iface=can.interface.Bus(bustype=" \
                               "'%s', channel='%s', bitrate=%d))" % \
                               (interface, channel, bitrate)
        except Exception as e:
            usage()
            print("\nCheck python-can interface assignment.\n",
                  file=sys.stderr)
            print(e, file=sys.stderr)
            sys.exit(-1)
    else:
        scan_interface = channel
        interface_string = "\"%s\"" % channel

    try:
        sock = CANSocket(iface=scan_interface)
    except Exception as e:
        usage()
        print("\nSocket couldn't be created. Check your arguments.\n",
              file=sys.stderr)
        print(e, file=sys.stderr)
        sys.exit(-1)

    if verbose:
        print("Start scan (%s - %s)" % (hex(start), hex(end)))

    signal.signal(signal.SIGINT, signal_handler)

    result = ISOTPScan(sock,
                       range(start, end + 1),
                       extended_addressing=extended,
                       noise_listen_time=noise_listen_time,
                       sniff_time=float(sniff_time) / 1000,
                       output_format="code" if piso else "text",
                       can_interface=interface_string,
                       extended_can_id=extended_can_id,
                       verbose=verbose)

    print("Scan: \n%s" % result)


if __name__ == '__main__':
    main()
