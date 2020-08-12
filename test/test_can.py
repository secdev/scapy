import pytest  # noqa: F401

from scapy.all import load_layer, conf, fuzz, bind_layers, ConditionalField, \
    Padding, Raw, CookedLinux, Scapy_Exception, ByteField, Packet, rdpcap, raw

from scapy.layers.can import CAN, rdcandump, CandumpReader, SignalPacket, \
    SignalField, LEUnsignedSignalField, BEUnsignedSignalField, \
    LESignedSignalField, BESignedSignalField, LEFloatSignalField, \
    BEFloatSignalField, SignalHeader

import math
import struct
import random
from io import BytesIO
import io

random.seed()
load_layer("can")


def test_Buildapacket():
    """
    Build a packet
    """
    pkt = CAN(flags="error", identifier=1234, data="test")
    assert pkt.flags == "error"
    assert pkt.identifier == 1234
    assert pkt.data == b"test"


def test_Dissectparse():
    """
    Dissect & parse
    """
    pkt = CAN(flags="error", identifier=1234, data="test")
    pkt = CAN(raw(pkt))
    assert pkt.flags == "error" and pkt.identifier == 1234 \
           and pkt.length == 4 and pkt.data == b"test"


def test_Checkflagsvalues():
    """
    Check flags values
    """
    pkt = CAN(flags="remote_transmission_request")
    assert pkt.flags == 0x2
    pkt = CAN(flags="extended")
    assert pkt.flags == 0x4


packets = None


def test_ReadPCAPfile():
    """
    Read PCAP file
    """
    global packets
    pcap_fd = BytesIO(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x04\x00\xe3\x00\x00\x00\xe2\xf3'
                      b'mT\x93\x8c\x03\x00\t\x00\x00\x00\t\x00\x00\x00\x00\x00'
                      b'\x073\x01\x00\x00\x00\x00\xe2\xf3mT\xae\x8c\x03\x00\n'
                      b'\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x02\x7f\x00'
                      b'\x00\x81\x00\xe2\xf3mTI\x8f\x03\x00\t\x00\x00\x00\t'
                      b'\x00\x00\x00\x00\x00\x07B\x01\x00\x00\x00\x00\xe2\xf3m'
                      b'TM\x8f\x03\x00\t\x00\x00\x00\t\x00\x00\x00\x00\x00\x07'
                      b'c\x01\x00\x00\x00\x00\xe2\xf3mTN\x8f\x03\x00\t\x00\x00'
                      b'\x00\t\x00\x00\x00\x00\x00\x07!\x01\x00\x00\x00\x00'
                      b'\xf8\xf3mTv\x98\x04\x00\x10\x00\x00\x00\x10\x00\x00'
                      b'\x00\x00\x00\x06B\x08\x7f\x00\x00@\x08\x10\x00\x00\x00'
                      b'\x00\x00\xf8\xf3mT\x96\x98\x04\x00\x10\x00\x00\x00\x10'
                      b'\x00\x00\x00\x00\x00\x05\xc2\x08\x7f\x00\x00A\x08\x10'
                      b'\x00\x15\x00\x00\x00\xf8\xf3mT\xd4\x98\x04\x00\x10\x00'
                      b'\x00\x00\x10\x00\x00\x00\x00\x00\x06B\x08\x00\x00\x00`'
                      b'\x00\x00\x00\x00\x00\x00\x00\xf8\xf3mT\x12\x99\x04\x00'
                      b'\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x06B\x08\x00'
                      b'\x00\x00\x80\x00\x00\x00!\x00\x00\x08\xf8\xf3mTC\x99'
                      b'\x04\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x05'
                      b'\xc2\x08\x7f\x00\x00\x00UltraHi\xf8\xf3mTx\x99\x04\x00'
                      b'\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x06B\x08\x00'
                      b'\x00\x00\x80\x00\x00\x00!\x00\x00\x08\xf8\xf3mT\xce'
                      b'\x99\x04\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00'
                      b'\x06B\x08\x00\x00\x00p\x00\x00\x00\x00\x00\x00\x00\xf8'
                      b'\xf3mT\xe0\x99\x04\x00\x10\x00\x00\x00\x10\x00\x00\x00'
                      b'\x00\x00\x06B\x08\x00\x00\x00\x80\x00\x00\x00!\x00\x00'
                      b'\x08\xf8\xf3mT \x9a\x04\x00\x10\x00\x00\x00\x10\x00'
                      b'\x00\x00\x00\x00\x06B\x08\x00\x00\x00\x80\x00\x00\x00!'
                      b'\x00\x00\x08\xf8\xf3mTo\x9a\x04\x00\x10\x00\x00\x00'
                      b'\x10\x00\x00\x00\x00\x00\x05\xc2\x08\x00\x00\x00\x80'
                      b'\x00\x00\x00!\x00\x00\x083\xf4mTw\xbe\t\x00\x10\x00'
                      b'\x00\x00\x10\x00\x00\x00\x00\x00\x06B\x08\x7f\x00'
                      b'\x00@\x08\x10*\x00\x00\x00\x003\xf4mT4\xc0\t\x00\x10'
                      b'\x00\x00\x00\x10\x00\x00\x00\x00\x00\x05\xc2\x08\x00'
                      b'\x00\x00\x80\x08\x10*\x11\x00\t\x06i\xf4mT\xb0\x88\x0c'
                      b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x07\xe5'
                      b'\x08\x7f\x00\x00L\x00\x00\x00\x00\x00\x00\x00i\xf4mT+'
                      b'\x89\x0c\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00'
                      b'\x07\xe4\x08\x7f\x00\x00P\x00\x00\x00\x00\x00\x00\x00i'
                      b'\xf4mT-\x89\x0c\x00\x10\x00\x00\x00\x10\x00\x00\x00'
                      b'\x00\x00\x07\xe4\x08\x7f\x00\x00P\x00\x00\x00\x00\x00'
                      b'\x00\x00i\xf4mTS\x89\x0c\x00\x10\x00\x00\x00\x10\x00'
                      b'\x00\x00\x00\x00\x07\xe4\x08\x7f\x00\x00P\x00\x00\x00'
                      b'\x00\x00\x00\x00i\xf4mT\x99\x89\x0c\x00\x10\x00\x00'
                      b'\x00\x10\x00\x00\x00\x00\x00\x07\xe4\x08\x00\x00\x00P'
                      b'\x00\x00\x00\x00\x00\x00\x00\x8e\xf4mT\x86\xc4\x04'
                      b'\x00\n\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x02'
                      b'\x00\x00\x00\x01B\x92\xf4mT\xae\xf0\x07\x00\n\x00\x00'
                      b'\x00\n\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01'
                      b'\x00\xba\xf4mT%\xaa\x0b\x00\n\x00\x00\x00\n\x00\x00'
                      b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02c\xe8\xf4mT'
                      b'\xbc\x0f\x06\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00'
                      b'\x00\x06B\x08\x7f\x00\x00#\x00b\x01asdf\xe8\xf4mT\x07'
                      b'\x10\x06\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00'
                      b'\x05\xc2\x08\x00\x00\x00\x80\x00b\x01\x00\x00\x02\x06'
                      b'\x0f\xf5mT\x1c\x81\x00\x00\x10\x00\x00\x00\x10\x00\x00'
                      b'\x00\x00\x00\x06B\x08\x7f\x00\x00@\x00b\x01\x00\x00'
                      b'\x00\x00\x0f\xf5mT\xfe\x81\x00\x00\x10\x00\x00\x00\x10'
                      b'\x00\x00\x00\x00\x00\x05\xc2\x08\x00\x00\x00\x80\x00b'
                      b'\x01\x00\x00\x02\x068\xf5mT\x19\xc3\x00\x00\x10\x00'
                      b'\x00\x00\x10\x00\x00\x00\x00\x00\x06B\x08\x7f\x00\x00'
                      b'\xa0\x08\x10\x00\x10\x00\x00\x008\xf5mTg\xc3\x00\x00'
                      b'\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00\x05\xc2\x08'
                      b'\x7f\x00\x00\xc2\x08\x10\x00\x15\x00\x00\x008\xf5mT'
                      b'\xd8\xc3\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00'
                      b'\x00\x06B\x08\x00\x00\x00\x80\x00\x00\x00!\x00\x00\x08'
                      b'8\xf5mT\x17\xc4\x00\x00\x10\x00\x00\x00\x10\x00\x00'
                      b'\x00\x00\x00\x06B\x08\x7f\x00\x00\xa3\x00\x00\x00\x00'
                      b'\x00\x00\x008\xf5mT\xca\xc4\x00\x00\x10\x00\x00\x00'
                      b'\x10\x00\x00\x00\x00\x00\x05\xc2\x08\x00\x00\x00\x80'
                      b'\x00\x00\x00!\x00\x00\x08')

    packets = rdpcap(pcap_fd)
    # Check if parsing worked: each packet has a CAN layer
    assert all(CAN in pkt for pkt in packets)
    # Check if parsing worked: no packet has a Raw or Padding layer
    assert not any(Raw in pkt or Padding in pkt for pkt in packets)
    # Identifiers
    assert set(pkt.identifier for pkt in packets) == {0, 1474, 1602, 1825,
                                                      1843, 1858, 1891,
                                                      2020, 2021}
    # Flags
    assert set(pkt.flags for pkt in packets) == {0}
    # Data length
    assert set(pkt.length for pkt in packets) == {1, 2, 8}
    # Check if parsing worked: no packet has a Raw or Padding layer
    assert not any(Raw in pkt or Padding in pkt for pkt in packets)


packets_can_a = None
packets_can_b = None


def test_readPCAPofaCookedLinuxSocketCANcaptureCANstandardandextended():
    """
    read PCAP of a CookedLinux/SocketCAN capture (CAN standard and extended)
    """
    global packets_can_a, packets_can_b
    conf.contribs['CAN']['swap-bytes'] = True
    pcap_fd_can_a = BytesIO(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00'
                            b'\x00\x00\x00\x00\x00\x00\x00\x04\x00q\x00\x00'
                            b'\x00\x15f`Zv\xde\n\x00 \x00\x00\x00 \x00\x00'
                            b'\x00\x00\x01\x01\x18\x00\x00\x00\x00\x00\x00'
                            b'\x00\x00\x00\x00\x00\x0c\xdf\x07\x00\x00\x03'
                            b'\x00\x00\x00\x02\x01\r\x00\x00\x00\x00\x00')
    packets_can_a = rdpcap(pcap_fd_can_a)
    pcap_fd_can_b = BytesIO(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00'
                            b'\x00\x00\x00\x00\x00\x00\x00\x04\x00q\x00\x00'
                            b'\x00\xf4i`Z\xf3\x99\x07\x00 \x00\x00\x00 \x00'
                            b'\x00\x00\x00\x01\x01\x18\x00\x00\x00\x00\x00'
                            b'\x00\x00\x00\x00\x00\x00\x0c\xf13\xdb\x98\x03'
                            b'\x00\x00\x00\x02\x01\r\x00\x00\x00\x00\x00')

    packets_can_b = rdpcap(pcap_fd_can_b)
    assert all(CAN in pkt for pkt in packets_can_a)
    assert all(CAN in pkt for pkt in packets_can_b)
    assert all(CookedLinux in pkt for pkt in packets_can_a)
    assert all(CookedLinux in pkt for pkt in packets_can_b)

    # Check byte swap for dissection
    assert packets_can_a[0].identifier == 0x7df
    assert packets_can_a[0].flags == 0x0
    assert packets_can_b[0].identifier == 0x18db33f1
    assert packets_can_b[0].flags == "extended"

    # Check byte swap-back for building
    assert raw(packets_can_a[0]) == b'\x00\x01\x01\x18\x00\x00\x00\x00\x00' \
                                    b'\x00\x00\x00\x00\x00\x00\x0c\xdf\x07' \
                                    b'\x00\x00\x03\x00\x00\x00\x02\x01\r\x00' \
                                    b'\x00\x00\x00\x00'
    assert raw(packets_can_b[0]) == b'\x00\x01\x01\x18\x00\x00\x00\x00\x00' \
                                    b'\x00\x00\x00\x00\x00\x00\x0c\xf13\xdb' \
                                    b'\x98\x03\x00\x00\x00\x02\x01\r\x00\x00' \
                                    b'\x00\x00\x00'
    conf.contribs['CAN']['swap-bytes'] = False


def test_CheckbuildingCANpacketwithnotpaddeddatafield():
    """
    Check building CAN packet with not padded data field
    """
    p = CAN(flags='error', identifier=1234, data=b'')
    bytes(p)

    p = CAN(flags='error', identifier=1234, data=b'\x0a\x0b')
    bytes(p)

    p_too_much_data = CAN(flags='error', length=1, identifier=1234,
                          data=b'\x01\x02')
    p = CAN(bytes(p_too_much_data))

    assert p.haslayer('Padding') and p['Padding'].load == b'\x02'


def test_Checkrdcandumpdefault():
    """
    Check rdcandump default
    """
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan0 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan0 1F334455#1122334455667788
                        (1539191494.084177) vcan0 1F334455#1122334455667788
                        (1539191494.724228) vcan0 1F334455#1122334455667788
                        (1539191495.148182) vcan0 1F334455#1122334455667788
                        (1539191495.563320) vcan0 1F334455#1122334455667788''')
    packets = rdcandump(pcap_fd)
    assert len(packets) == 9
    assert packets[0].identifier == 0x123
    assert packets[8].identifier == 0x1F334455
    assert packets[8].flags == 0b100
    assert packets[0].length == 4
    assert packets[8].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[8].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_Checkrdcandumpdefaultcompressed():
    """
    Check rdcandump default compressed
    """
    pcap_fd = "test/pcaps/candump.gz"
    packets = rdcandump(pcap_fd)
    assert len(packets) == 9
    assert packets[0].identifier == 0x123
    assert packets[8].identifier == 0x1F334455
    assert packets[8].flags == 0b100
    assert packets[0].length == 4
    assert packets[8].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[8].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_CheckCandumpReaderdispatch():
    """
    Check rdcandump default
    """
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan0 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan0 1F334455#1122334455667788
                        (1539191494.084177) vcan0 1F334455#1122334455667788
                        (1539191494.724228) vcan0 1F334455#1122334455667788
                        (1539191495.148182) vcan0 1F334455#1122334455667788
                        (1539191495.563320) vcan0 1F334455#1122334455667788''')
    r = CandumpReader(pcap_fd)

    packets = list()
    r.dispatch(packets.append)

    try:
        r.fileno()
        assert False
    except io.UnsupportedOperation:
        assert True

    assert len(packets) == 9
    assert packets[0].identifier == 0x123
    assert packets[8].identifier == 0x1F334455
    assert packets[8].flags == 0b100
    assert packets[0].length == 4
    assert packets[8].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[8].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_Checkrdcandumpiterabledefault():
    """
    Check rdcandump_iterable default
    """
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan0 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan0 1F334455#1122334455667788
                        (1539191494.084177) vcan0 1F334455#1122334455667788
                        (1539191494.724228) vcan0 1F334455#1122334455667788
                        (1539191495.148182) vcan0 1F334455#1122334455667788
                        (1539191495.563320) vcan0 1F334455#1122334455667788''')
    packets = [x for x in CandumpReader(pcap_fd)]
    assert len(packets) == 9
    assert packets[0].identifier == 0x123
    assert packets[8].identifier == 0x1F334455
    assert packets[8].flags == 0b100
    assert packets[0].length == 4
    assert packets[8].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[8].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_Checkrdcandumpfilter():
    """
    Check rdcandump filter
    """
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan1 123#11223344
                        (1539191471.503168) vcan1 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan0 1F334455#1122334455667788
                        (1539191494.084177) vcan1 1F334455#1122334455667788
                        (1539191494.724228) vcan1 1F334455#1122334455667788
                        (1539191495.148182) vcan0 1F334455#1122334455667788
                        (1539191495.563320) vcan1 1F334455#1122334455667788''')
    packets = rdcandump(pcap_fd, interface="vcan0")
    assert len(packets) == 4
    assert packets[0].identifier == 0x123
    assert packets[-1].identifier == 0x1F334455
    assert packets[-1].flags == 0b100
    assert packets[0].length == 4
    assert packets[-1].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[-1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan0 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan1 1F334455#1122334455667788
                        (1539191494.084177) vcan1 1F334455#1122334455667788
                        (1539191494.724228) vcan1 1F334455#1122334455667788
                        (1539191495.148182) vcan1 1F334455#1122334455667788
                        (1539191495.563320) vcan1 1F334455#1122334455667788''')
    packets = rdcandump(pcap_fd, interface="vcan0")
    assert len(packets) == 4
    assert packets[0].identifier == 0x123
    assert packets[0].length == 4
    assert packets[0].data == b'\x11\x22\x33\x44'
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan0 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan1 1F334455#1122334455667788
                        (1539191494.084177) vcan1 1F334455#1122334455667788
                        (1539191494.724228) vcan1 1F334455#1122334455667788
                        (1539191495.148182) vcan1 1F334455#1122334455667788
                        (1539191495.563320) vcan1 1F334455#1122334455667788''')
    packets = rdcandump(pcap_fd, interface="vcan1")
    assert len(packets) == 5
    assert packets[-1].identifier == 0x1F334455
    assert packets[-1].flags == 0b100
    assert packets[-1].length == 8
    assert packets[-1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan2 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan2 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan1 1F334455#1122334455667788
                        (1539191494.084177) vcan1 1F334455#1122334455667788
                        (1539191494.724228) vcan2 1F334455#1122334455667788
                        (1539191495.148182) vcan1 1F334455#1122334455667788
                        (1539191495.563320) vcan2 1F334455#1122334455667788''')
    packets = rdcandump(pcap_fd, interface=["vcan1", "vcan0"])
    assert len(packets) == 5
    assert packets[0].identifier == 0x123
    assert packets[-1].identifier == 0x1F334455
    assert packets[-1].flags == 0b100
    assert packets[0].length == 4
    assert packets[-1].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[-1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_interfacenotlogfileformat():
    """
    interface not log file format
    """
    pcap_fd = BytesIO(b'''  vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan0  1F334455   [4]  11 22 33 44
      vcan0       1F3   [4]  11 22 33 44''')
    packets = rdcandump(pcap_fd)
    assert len(packets) == 8
    packets[-1].show()
    assert packets[-1].identifier == 0x1F3
    assert packets[1].identifier == 0x1F3
    assert packets[0].identifier == 0x1F334455
    assert packets[0].flags == 0b100
    assert packets[-1].length == 4
    assert packets[0].length == 8
    assert packets[1].length == 8
    assert packets[-1].data == b'\x11\x22\x33\x44'
    assert packets[0].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    assert packets[1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_interfacenotlogfileformatfiltered1():
    """
    interface not log file format filtered 1
    """
    pcap_fd = BytesIO(b'''  vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan1       1F3   [8]  11 22 33 44 55 66 77 88
      vcan1       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan1  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan1  1F334455   [4]  11 22 33 44
      vcan0       1F3   [4]  11 22 33 44
    ''')
    packets = rdcandump(pcap_fd, interface="vcan0")
    assert len(packets) == 4
    assert packets[-1].identifier == 0x1F3
    assert packets[2].identifier == 0x1F3
    assert packets[0].identifier == 0x1F334455
    assert packets[0].flags == 0b100
    assert packets[-1].length == 4
    assert packets[0].length == 8
    assert packets[2].length == 8
    assert packets[-1].data == b'\x11\x22\x33\x44'
    assert packets[0].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    assert packets[2].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_interfacenotlogfileformatfiltered2():
    """
    interface not log file format filtered 2
    """
    pcap_fd = BytesIO(b'''  vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan1       1F3   [8]  11 22 33 44 55 66 77 88
      vcan2       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan1  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan2  1F334455   [4]  11 22 33 44
      vcan0       1F3   [4]  11 22 33 44
    ''')
    packets = rdcandump(pcap_fd, interface=["vcan0", "vcan1"])
    assert len(packets) == 6
    assert packets[-1].identifier == 0x1F3
    assert packets[1].identifier == 0x1F3
    assert packets[0].identifier == 0x1F334455
    assert packets[0].flags == 0b100
    assert packets[-1].length == 4
    assert packets[0].length == 8
    assert packets[1].length == 8
    assert packets[-1].data == b'\x11\x22\x33\x44'
    assert packets[0].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    assert packets[1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_interfacenotlogfileformatfiltered2count1():
    """
    interface not log file format filtered 2 count 1
    """
    pcap_fd = BytesIO(b'''  vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan1       1F3   [8]  11 22 33 44 55 66 77 88
      vcan2       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan2  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan2  1F334455   [4]  11 22 33 44
      vcan0       1F3   [4]  11 22 33 44
    ''')
    packets = rdcandump(pcap_fd, interface=["vcan2"],
                        count=2)
    assert len(packets) == 2
    assert packets[0].identifier == 0x1F3
    assert packets[-1].identifier == 0x1F334455
    assert packets[-1].flags == 0b100
    assert packets[-1].length == 8
    assert packets[0].length == 8
    assert packets[1].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    assert packets[1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_interfacenotlogfileformatfiltered2count2():
    """
    interface not log file format filtered 2 count 2
    """
    pcap_fd = BytesIO(b'''  vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan1       1F3   [8]  11 22 33 44 55 66 77 88
      vcan2       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan2  1F334455   [8]  11 22 33 44 55 66 77 88
      vcan2  1F334455   [4]  11 22 33 44
      vcan0       1F3   [4]  11 22 33 44
    ''')
    packets = rdcandump(pcap_fd, count=2)
    assert len(packets) == 2
    assert packets[1].identifier == 0x1F3
    assert packets[0].identifier == 0x1F334455
    assert packets[0].flags == 0b100
    assert packets[-1].length == 8
    assert packets[0].length == 8
    assert packets[1].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    assert packets[1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_defaultreading():
    """
    default reading
    """
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan0 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan0 1F334455#1122334455667788
                        (1539191494.084177) vcan0 1F334455#1122334455667788
                        (1539191494.724228) vcan0 1F334455#1122334455667788
                        (1539191495.148182) vcan0 1F334455#1122334455667788
                        (1539191495.563320) vcan0 1F334455#1122334455667788''')
    packets = rdcandump(pcap_fd, count=5)
    assert len(packets) == 5
    assert packets[0].identifier == 0x123
    assert packets[-1].identifier == 0x1F334455
    assert packets[-1].flags == 0b100
    assert packets[0].length == 4
    assert packets[-1].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[-1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_defaultreading_2():
    """
    default reading
    """
    pcap_fd = BytesIO(b'''(1539191392.761779) vcan0 123#11223344
                        (1539191470.820239) vcan0 123#11223344
                        (1539191471.503168) vcan0 123#11223344
                        (1539191471.891423) vcan0 123#11223344
                        (1539191492.026403) vcan0 00000055#1122334455667788
                        (1539191494.084177) vcan0 00000055#1122334455667788
                        (1539191494.724228) vcan0 00000055#1122334455667788
                        (1539191495.148182) vcan0 00000055#1122334455667788
                        (1539191495.563320) vcan0 00000055#1122334455667788''')
    packets = rdcandump(pcap_fd)
    assert len(packets) == 9
    assert packets[0].identifier == 0x123
    assert packets[8].identifier == 0x55
    assert packets[8].flags == 0b100
    assert packets[0].length == 4
    assert packets[8].length == 8
    assert packets[0].data == b'\x11\x22\x33\x44'
    assert packets[8].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_interfacenotlogfileformat_2():
    """
    interface not log file format
    """
    pcap_fd = BytesIO(b'''  vcan0  00000055   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  00000055   [8]  11 22 33 44 55 66 77 88
      vcan0       1F3   [8]  11 22 33 44 55 66 77 88
      vcan0  00000055   [8]  11 22 33 44 55 66 77 88
      vcan0  00000055   [4]  11 22 33 44
      vcan0       1F3   [4]  11 22 33 44''')
    packets = rdcandump(pcap_fd)
    assert len(packets) == 8
    packets[-1].show()
    assert packets[-1].identifier == 0x1F3
    assert packets[1].identifier == 0x1F3
    assert packets[0].identifier == 0x55
    assert packets[0].flags == 0b100
    assert packets[-1].length == 4
    assert packets[0].length == 8
    assert packets[1].length == 8
    assert packets[-1].data == b'\x11\x22\x33\x44'
    assert packets[0].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'
    assert packets[1].data == b'\x11\x22\x33\x44\x55\x66\x77\x88'


def test_Testinvalidfieldsdesc():
    """
    Test invalid fields_desc
    """

    class testFrame1(SignalPacket):
        fields_desc = [
            ByteField("sig0", 0),
            SignalField("sig1", default=0, start=7, size=6, fmt=">B")
        ]

    passed = False
    try:
        testFrame1(b"\xff\xff")
    except Scapy_Exception:
        passed = True
    assert passed


def test_TestinvalidfieldsdescwithConditionalField():
    """
    Test invalid fields_desc with ConditionalField
    """

    class testFrame1(SignalPacket):
        fields_desc = [
            ConditionalField(ByteField("sig0", 0), lambda x: True),
            SignalField("sig1", default=0, start=7, size=6, fmt=">B")
        ]

    passed = False
    try:
        testFrame1(b"\xff\xff")
    except Scapy_Exception:
        passed = True
    assert passed


def test_MotorolabyteorderBigEndianexceptiontest():
    """
    Motorola byte order (Big Endian) exception test
    """

    class testFrame1234(SignalPacket):
        fields_desc = [
            SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
            SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
            SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
            SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
            SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
            SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
            SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
            SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
            SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
            SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
            SignalField("sig10", default=0, start=63, size=2, fmt=">B"),
            SignalField("sig11", default=0, start=65, size=2, fmt=">B")
        ]

    try:
        testFrame1234(b'\xff\xff\xff\xff\xff\xff\xff\xff')
        assert False
    except Scapy_Exception:
        assert True


def test_MotorolabyteorderBigEndianexceptiontest2():
    """
    Motorola byte order (Big Endian) exception test
    """

    class testFrame12345(SignalPacket):
        fields_desc = [
            SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
            SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
            SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
            SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
            SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
            SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
            SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
            SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
            SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
            SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
            SignalField("sig10", default=0, start=63, size=16, fmt=">B")
        ]

    try:
        testFrame12345(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff')
        assert False
    except Scapy_Exception:
        assert True


def test_MotorolabyteorderBigEndianexceptiontest3():
    """
    Motorola byte order (Big Endian) exception test
    """

    class testFrame123456(Packet):
        fields_desc = [
            SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
            SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
            SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
            SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
            SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
            SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
            SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
            SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
            SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
            SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
            SignalField("sig10", default=0, start=63, size=16, fmt=">B")
        ]

    try:
        testFrame123456(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff')
        assert False
    except Scapy_Exception:
        assert True


def test_MotorolabyteorderBigEndianexceptiontest4():
    """
    Motorola byte order (Big Endian) exception test
    """
    try:

        class testFrame1234567(SignalPacket):
            fields_desc = [
                SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
                SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
                SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
                SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
                SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
                SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
                SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
                SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
                SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
                SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
                SignalField("sig10", default=0, start=63, size=16, fmt="f")
            ]

        testFrame1234567(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff')
        assert False
    except Scapy_Exception:
        assert True


class testFrame1(SignalPacket):
    fields_desc = [
        SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
        SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
        SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
        SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
        SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
        SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
        SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
        SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
        SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
        SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
        SignalField("sig10", default=0, start=63, size=2, fmt=">B")
    ]


def test_MotorolabyteorderBigEndiandissecttest():
    """
    Motorola byte order (Big Endian) dissect test
    """
    pkt = testFrame1(b'\xff\xff\xff\xff\xff\xff\xff\xff')
    assert pkt.sig0 == 3
    assert pkt.sig1 == 0x3f
    assert pkt.sig2 == 0x7ff
    assert pkt.sig3 == 0xfff
    assert pkt.sig4 == 0x1ff
    assert pkt.sig7 == 0x3ff
    assert pkt.sig5 == 7
    assert pkt.sig6 == 7
    assert pkt.sig8 == 7
    assert pkt.sig9 == 7
    assert pkt.sig10 == 3
    pkt = testFrame1(struct.pack("<Q", int("10010101"  # byte 7: 63 - 56
                                           "11010101"
                                           "10000000"
                                           "00000001"
                                           "11111110"
                                           "11100000"
                                           "00000001"
                                           "01010101", 2)))  # byte 0: 7 - 0
    assert pkt.sig0 == 1
    assert pkt.sig1 == 21
    assert pkt.sig2 == 15
    assert pkt.sig3 == 0x7f
    assert pkt.sig4 == 0x1
    assert pkt.sig7 == 0x203
    assert pkt.sig5 == 5
    assert pkt.sig6 == 2
    assert pkt.sig8 == 5
    assert pkt.sig9 == 2
    assert pkt.sig10 == 2


def test_MotorolabyteorderBigEndianbuildtest():
    """
    Motorola byte order (Big Endian) build test
    """
    pkt = testFrame1()
    pkt.sig0 = 1
    pkt.sig1 = 21
    pkt.sig2 = 15
    pkt.sig3 = 0x7f
    pkt.sig4 = 0x1
    pkt.sig7 = 0x203
    pkt.sig5 = 5
    pkt.sig6 = 2
    pkt.sig8 = 5
    pkt.sig9 = 2
    pkt.sig10 = 2
    test = bytes(pkt)
    assert bytes(test) == b'U\x01\xe0\xfe\x01\x80\xd5\x95'


class testFrame6(SignalPacket):
    fields_desc = [
        SignalField("sig10", default=0, start=63, size=2, fmt=">B"),
        SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
        SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
        SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
        SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
        SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
        SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
        SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
        SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
        SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
        SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
    ]


def test_MotorolabyteorderBigEndiandissecttestwithmixedfieldorder():
    """
    Motorola byte order (Big Endian) dissect test with mixed field order
    """
    pkt = testFrame6(struct.pack("<Q", int("10010101"  # byte 7: 63 - 56
                                           "11010101"
                                           "10000000"
                                           "00000001"
                                           "11111110"
                                           "11100000"
                                           "00000001"
                                           "01010101", 2)))  # byte 0: 7 - 0
    assert pkt.sig0 == 1
    assert pkt.sig1 == 21
    assert pkt.sig2 == 15
    assert pkt.sig3 == 0x7f
    assert pkt.sig4 == 0x1
    assert pkt.sig7 == 0x203
    assert pkt.sig5 == 5
    assert pkt.sig6 == 2
    assert pkt.sig8 == 5
    assert pkt.sig9 == 2
    assert pkt.sig10 == 2


class testFrame7(SignalPacket):
    fields_desc = [
        SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
        SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
        SignalField("sig10", default=0, start=63, size=2, fmt=">B"),
        SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
        SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
        SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
        SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
        SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
        SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
        SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
        SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
    ]


def test_MotorolabyteorderBigEndianbuildtestwithmixedfieldorder():
    """
    Motorola byte order (Big Endian) build test with mixed field order
    """
    pkt = testFrame7()
    pkt.sig0 = 1
    pkt.sig1 = 21
    pkt.sig2 = 15
    pkt.sig3 = 0x7f
    pkt.sig4 = 0x1
    pkt.sig7 = 0x203
    pkt.sig5 = 5
    pkt.sig6 = 2
    pkt.sig8 = 5
    pkt.sig9 = 2
    pkt.sig10 = 2
    test = bytes(pkt)
    print(test)
    assert bytes(test) == b'U\x01\xe0\xfe\x01\x80\xd5\x95'


def test_IntelbyteorderLittleEndiandissecttest():
    """
    Intel byte order (Little Endian) dissect test
    """

    class testFrame2(SignalPacket):
        fields_desc = [
            SignalField("secSig12", default=0, start=0, size=8, fmt="<B"),
            SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
            SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
            SignalField("secSig11", default=0, start=24, size=10, fmt="<B"),
            SignalField("secSig5", default=0, start=34, size=3, fmt="<B"),
            SignalField("secSig6", default=0, start=37, size=3, fmt="<B"),
            SignalField("secSig9", default=0, start=52, size=3, fmt="<B"),
            SignalField("secSig2", default=0, start=55, size=1, fmt="<B"),
            SignalField("secSig8", default=0, start=56, size=3, fmt="<B"),
            SignalField("secSig7", default=0, start=59, size=1, fmt="<B"),
            SignalField("secSig1", default=0, start=60, size=2, fmt="<B"),
            SignalField("secSig4", default=0, start=62, size=2, fmt="<B"),
        ]

    pkt = testFrame2(b'\xff\xff\xff\xff\xff\xff\xff\xff')
    assert pkt.secSig1 == 0x3
    assert pkt.secSig2 == 0x1
    assert pkt.secSig3 == 0xf
    assert pkt.secSig4 == 0x3
    assert pkt.secSig7 == 0x1
    assert pkt.secSig5 == 7
    assert pkt.secSig6 == 7
    assert pkt.secSig8 == 7
    assert pkt.secSig9 == 7
    assert pkt.secSig10 == 0xfff
    assert pkt.secSig11 == 0x3ff
    assert pkt.secSig12 == 0xff
    pkt = testFrame2(struct.pack("<Q", int("10010101"  # byte 7: 63 - 56
                                           "11010101"
                                           "10000000"
                                           "00000001"
                                           "11111110"
                                           "11100000"
                                           "00000001"
                                           "10100101", 2)))  # byte 0: 7 - 0
    assert pkt.secSig1 == 0x1
    assert pkt.secSig2 == 0x1
    assert pkt.secSig3 == 0xe
    assert pkt.secSig4 == 0x2
    assert pkt.secSig7 == 0x0
    assert pkt.secSig5 == 0
    assert pkt.secSig6 == 0
    assert pkt.secSig8 == 5
    assert pkt.secSig9 == 5
    assert pkt.secSig10 == 1
    assert pkt.secSig11 == 0x1fe
    assert pkt.secSig12 == 0xA5


def test_IntelbyteorderLittleEndianbuildtest():
    """
    Intel byte order (Little Endian) build test
    """

    class testFrame2(SignalPacket):
        fields_desc = [
            SignalField("secSig12", default=0, start=0, size=8, fmt="<B"),
            SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
            SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
            SignalField("secSig11", default=0, start=24, size=10, fmt="<B"),
            SignalField("secSig5", default=0, start=34, size=3, fmt="<B"),
            SignalField("secSig6", default=0, start=37, size=3, fmt="<B"),
            SignalField("secSig9", default=0, start=52, size=3, fmt="<B"),
            SignalField("secSig2", default=0, start=55, size=1, fmt="<B"),
            SignalField("secSig8", default=0, start=56, size=3, fmt="<B"),
            SignalField("secSig7", default=0, start=59, size=1, fmt="<B"),
            SignalField("secSig1", default=0, start=60, size=2, fmt="<B"),
            SignalField("secSig4", default=0, start=62, size=2, fmt="<B"),
        ]

    pkt = testFrame2()
    pkt.secSig12 = 0xA5
    pkt.secSig10 = 1
    pkt.secSig3 = 14
    pkt.secSig11 = 0x1fe
    pkt.secSig5 = 0
    pkt.secSig6 = 0
    pkt.secSig9 = 5
    pkt.secSig2 = 1
    pkt.secSig8 = 5
    pkt.secSig7 = 0
    pkt.secSig1 = 1
    pkt.secSig4 = 2
    assert bytes(pkt) == b'\xa5\x01\xe0\xfe\x01\x00\xd0\x95'


def test_IntelbyteorderLittleEndianbuildtestwithmixedfieldorder():
    """
    Intel byte order (Little Endian) build test with mixed field order
    """

    class testFrame2(SignalPacket):
        fields_desc = [
            SignalField("secSig1", default=0, start=60, size=2, fmt="<B"),
            SignalField("secSig12", default=0, start=0, size=8, fmt="<B"),
            SignalField("secSig2", default=0, start=55, size=1, fmt="<B"),
            SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
            SignalField("secSig5", default=0, start=34, size=3, fmt="<B"),
            SignalField("secSig9", default=0, start=52, size=3, fmt="<B"),
            SignalField("secSig8", default=0, start=56, size=3, fmt="<B"),
            SignalField("secSig11", default=0, start=24, size=10, fmt="<B"),
            SignalField("secSig7", default=0, start=59, size=1, fmt="<B"),
            SignalField("secSig6", default=0, start=37, size=3, fmt="<B"),
            SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
            SignalField("secSig4", default=0, start=62, size=2, fmt="<B"),
        ]

    pkt = testFrame2()
    pkt.secSig12 = 0xA5
    pkt.secSig10 = 1
    pkt.secSig3 = 14
    pkt.secSig11 = 0x1fe
    pkt.secSig5 = 0
    pkt.secSig6 = 0
    pkt.secSig9 = 5
    pkt.secSig2 = 1
    pkt.secSig8 = 5
    pkt.secSig7 = 0
    pkt.secSig1 = 1
    pkt.secSig4 = 2
    assert bytes(pkt) == b'\xa5\x01\xe0\xfe\x01\x00\xd0\x95'


class testFrame2(SignalPacket):
    fields_desc = [
        SignalField("secSig12", default=0, start=0, size=8, fmt="<B"),
        SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
        SignalField("secSig11", default=0, start=24, size=10, fmt="<B"),
        SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
    ]


def test_IntelbyteorderLittleEndianbuildtestwithshortpackage():
    """
    Intel byte order (Little Endian) build test with short package
    """
    pkt = testFrame2()
    pkt.secSig12 = 0xA5
    pkt.secSig10 = 1
    pkt.secSig3 = 14
    pkt.secSig11 = 0x1fe
    assert bytes(pkt) == b'\xa5\x01\xe0\xfe\x01'
    assert len(pkt) == 5
    pkt.secSig11 = 0x0fe
    assert bytes(pkt) == b'\xa5\x01\xe0\xfe\x00'
    assert len(pkt) == 5


class testFrame3(SignalPacket):
    fields_desc = [
        SignalField("myMuxer", default=0, start=53, size=3, fmt="<B"),
        SignalField("muxSig5", default=0, start=22, size=7, fmt="<B"),
        SignalField("muxSig6", default=0, start=32, size=9, fmt="<B"),
        SignalField("muxSig7", default=0, start=2, size=8, fmt=">B"),
        SignalField("muxSig8", default=0, start=3, size=3, fmt="<B"),
        SignalField("muxSig9", default=0, start=41, size=7, fmt="<B"),
    ]


def test_Packetwithmixedendiannessfieldsbuildtest():
    """
    Packet with mixed endianness fields build test
    """
    pkt = testFrame3()
    pkt.myMuxer = 0x7
    pkt.muxSig5 = 0x72
    pkt.muxSig6 = 0x10f
    pkt.muxSig7 = 0xA5
    pkt.muxSig8 = 0x03
    pkt.muxSig9 = 0x11
    assert bytes(pkt) == b'\x1d\x28\x80\x1c\x0f\x23\xe0'
    assert len(pkt) == 7


def test_MuxedPacketwithmixedendiannessfieldsbuildtest():
    """
    Muxed Packet with mixed endianness fields build test
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3, fmt="<B"),
            ConditionalField(SignalField("muxSig5", default=0, start=22,
                                         size=7, fmt="<B"),
                             lambda p: p.myMuxer == 1),
            ConditionalField(SignalField("muxSig6", default=0, start=32,
                                         size=9, fmt="<B"),
                             lambda p: p.myMuxer == 1),
            ConditionalField(SignalField("muxSig7", default=0, start=2,
                                         size=8, fmt=">B"),
                             lambda p: p.myMuxer == 0),
            ConditionalField(SignalField("muxSig8", default=0, start=3,
                                         size=3, fmt="<B"),
                             lambda p: p.myMuxer == 0),
            ConditionalField(SignalField("muxSig9", default=0, start=41,
                                         size=7, fmt="<B"),
                             lambda p: p.myMuxer == 1)
        ]

    pkt = testFrame3()
    pkt.myMuxer = 0x0
    pkt.muxSig5 = 0x72
    pkt.muxSig6 = 0x10f
    pkt.muxSig7 = 0xA5
    pkt.muxSig8 = 0x03
    pkt.muxSig9 = 0x11
    assert bytes(pkt) == b'\x1d\x28\x00\x00\x00\x00\x00'
    assert len(pkt) == 7
    pkt.myMuxer = 0x1
    assert bytes(pkt) == b'\x00\x00\x80\x1c\x0f\x23\x20'
    assert len(pkt) == 7


def test_MuxedPacketbuildtest():
    """
    Muxed Packet build test
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=0, size=8, fmt="<B"),
            ConditionalField(SignalField("muxSig5", default=0, start=8,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 1),
            ConditionalField(SignalField("muxSig6", default=0, start=8,
                                         size=16, fmt="<B"),
                             lambda p: p.myMuxer == 0),
            ConditionalField(SignalField("muxSig7", default=0, start=16,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 1),
            ConditionalField(SignalField("muxSig8", default=0, start=24,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 0),
            ConditionalField(SignalField("muxSig9", default=0, start=32,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 0)
        ]

    pkt = testFrame3(b'\x01\xff\xff\xff\xff\xff\xff')
    assert pkt.myMuxer == 0x1
    assert pkt.muxSig5 == 0xff
    assert pkt.muxSig7 == 0xff
    pkt = testFrame3(b'\x00\xff\xff\xff\xff\xff\xff')
    assert pkt.myMuxer == 0x0
    assert pkt.muxSig6 == 0xffff
    assert pkt.muxSig8 == 0xff
    assert pkt.muxSig9 == 0xff
    pkt = testFrame3()
    pkt.myMuxer = 0x1
    pkt.muxSig5 = 0xaa
    pkt.muxSig7 = 0xaa
    assert bytes(pkt) == b'\x01\xaa\xaa'
    assert len(pkt) == 3
    pkt = testFrame3()
    pkt.myMuxer = 0x0
    pkt.muxSig5 = 0xaa
    pkt.muxSig6 = 0xbb
    pkt.muxSig7 = 0xaa
    pkt.muxSig8 = 0xbb
    pkt.muxSig9 = 0xbb
    assert bytes(pkt) == b'\x00\xbb\x00\xbb\xbb'
    assert len(pkt) == 5


def test_SignalHeaderMuxedPacketbuildtest():
    """
    SignalHeader Muxed Packet build test
    """

    conf.contribs['CAN']['swap-bytes'] = False

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=0, size=8, fmt="<B"),
            ConditionalField(SignalField("muxSig5", default=0, start=8,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 1),
            ConditionalField(SignalField("muxSig6", default=0, start=8,
                                         size=16, fmt="<B"),
                             lambda p: p.myMuxer == 0),
            ConditionalField(SignalField("muxSig7", default=0, start=16,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 1),
            ConditionalField(SignalField("muxSig8", default=0, start=24,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 0),
            ConditionalField(SignalField("muxSig9", default=0, start=32,
                                         size=8, fmt="<B"),
                             lambda p: p.myMuxer == 0)
        ]

    bind_layers(SignalHeader, testFrame3, identifier=0x123)
    pkt = SignalHeader(b'\x00\x00\x01#\x00\x00\x00\x00\x01'
                       b'\xff\xff\xff\xff\xff\xff')
    assert pkt.myMuxer == 0x1
    assert pkt.muxSig5 == 0xff
    assert pkt.muxSig7 == 0xff
    pkt = SignalHeader(b'\x00\x00\x01#\x00\x00\x00\x00\x00'
                       b'\xff\xff\xff\xff\xff\xff')
    assert pkt.myMuxer == 0x0
    assert pkt.muxSig6 == 0xffff
    assert pkt.muxSig8 == 0xff
    assert pkt.muxSig9 == 0xff
    pkt = SignalHeader() / testFrame3()
    pkt.myMuxer = 0x1
    pkt.muxSig5 = 0xaa
    pkt.muxSig7 = 0xaa
    assert bytes(pkt) == b'\x00\x00\x01#\x03\x00\x00\x00\x01\xaa\xaa'
    assert len(pkt) == 8 + 3
    pkt = SignalHeader() / testFrame3()
    pkt.myMuxer = 0x0
    pkt.muxSig5 = 0xaa
    pkt.muxSig6 = 0xbb
    pkt.muxSig7 = 0xaa
    pkt.muxSig8 = 0xbb
    pkt.muxSig9 = 0xbb
    assert bytes(pkt) == b'\x00\x00\x01#\x05\x00\x00\x00\x00\xbb\x00\xbb\xbb'
    assert len(pkt) == 8 + 5


def test_IntelbyteorderLittleEndianSignalPacketdissecttest():
    """
    Intel byte order (Little Endian) SignalPacket dissect test
    """

    class testFrame2(SignalPacket):
        fields_desc = [
            SignalField("secSig12", default=0, start=0, size=8, fmt="<B"),
            SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
            SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
            SignalField("secSig11", default=0, start=24, size=10, fmt="<B"),
            SignalField("secSig5", default=0, start=34, size=3, fmt="<B"),
            SignalField("secSig6", default=0, start=37, size=3, fmt="<B"),
            SignalField("secSig9", default=0, start=52, size=3, fmt="<B"),
            SignalField("secSig2", default=0, start=55, size=1, fmt="<B"),
            SignalField("secSig8", default=0, start=56, size=3, fmt="<B"),
            SignalField("secSig7", default=0, start=59, size=1, fmt="<B"),
            SignalField("secSig1", default=0, start=60, size=2, fmt="<B"),
            SignalField("secSig4", default=0, start=62, size=2, fmt="<B"),
        ]

    pkt = testFrame2(b'\xff\xff\xff\xff\xff\xff\xff\xff')
    assert pkt.secSig1 == 0x3
    assert pkt.secSig2 == 0x1
    assert pkt.secSig3 == 0xf
    assert pkt.secSig4 == 0x3
    assert pkt.secSig7 == 0x1
    assert pkt.secSig5 == 7
    assert pkt.secSig6 == 7
    assert pkt.secSig8 == 7
    assert pkt.secSig9 == 7
    assert pkt.secSig10 == 0xfff
    assert pkt.secSig11 == 0x3ff
    assert pkt.secSig12 == 0xff
    assert len(pkt) == 8
    pkt = testFrame2(struct.pack("<Q", int("10010101"  # byte 7: 63 - 56
                                           "11010101"
                                           "10000000"
                                           "00000001"
                                           "11111110"
                                           "11100000"
                                           "00000001"
                                           "10100101", 2)))  # byte 0: 7 - 0
    assert pkt.secSig1 == 0x1
    assert pkt.secSig2 == 0x1
    assert pkt.secSig3 == 0xe
    assert pkt.secSig4 == 0x2
    assert pkt.secSig7 == 0x0
    assert pkt.secSig5 == 0
    assert pkt.secSig6 == 0
    assert pkt.secSig8 == 5
    assert pkt.secSig9 == 5
    assert pkt.secSig10 == 1
    assert pkt.secSig11 == 0x1fe
    assert pkt.secSig12 == 0xA5
    assert len(pkt) == 8


def test_IntelbyteorderLittleEndianshortSignalPacketdissecttest():
    """
    Intel byte order (Little Endian) short SignalPacket dissect test
    """

    class testFrame2(SignalPacket):
        fields_desc = [
            SignalField("secSig12", default=0, start=0, size=8, fmt="<B"),
            SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
            SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
            SignalField("secSig11", default=0, start=24, size=10, fmt="<B"),
            SignalField("secSig5", default=0, start=34, size=3, fmt="<B"),
            SignalField("secSig6", default=0, start=37, size=3, fmt="<B"),
        ]

    pkt = testFrame2(b'\xff\xff\xff\xff\xff')
    assert pkt.secSig3 == 0xf
    assert pkt.secSig5 == 7
    assert pkt.secSig6 == 7
    assert pkt.secSig10 == 0xfff
    assert pkt.secSig11 == 0x3ff
    assert pkt.secSig12 == 0xff
    assert len(pkt) == 5
    pkt = testFrame2(struct.pack("<Q", int("00000001"
                                           "11111110"
                                           "11100000"
                                           "00000001"
                                           "10100101", 2))[0:5])
    assert pkt.secSig3 == 0xe
    assert pkt.secSig5 == 0
    assert pkt.secSig6 == 0
    assert pkt.secSig10 == 1
    assert pkt.secSig11 == 0x1fe
    assert pkt.secSig12 == 0xA5
    assert len(pkt) == 5


def test_IntelbyteorderLittleEndianshortSignalPacketdissecttestmixedfieldorder():  # noqa: E501
    """
    Intel byte order (Little Endian) short SignalPacket dissect test mixed field order  # noqa: E501
    """

    class testFrame2(SignalPacket):
        fields_desc = [
            SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
            SignalField("secSig6", default=0, start=37, size=3, fmt="<B"),
            SignalField("secSig11", default=0, start=24, size=10, fmt="<B"),
            SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
            SignalField("secSig5", default=0, start=34, size=3, fmt="<B"),
            SignalField("secSig12", default=0, start=0, size=8, fmt="<B"),
        ]

    pkt = testFrame2(b'\xff\xff\xff\xff\xff')
    assert pkt.secSig3 == 0xf
    assert pkt.secSig5 == 7
    assert pkt.secSig6 == 7
    assert pkt.secSig10 == 0xfff
    assert pkt.secSig11 == 0x3ff
    assert pkt.secSig12 == 0xff
    assert len(pkt) == 5
    pkt = testFrame2(struct.pack("<Q", int("00000001"
                                           "11111110"
                                           "11100000"
                                           "00000001"
                                           "10100101", 2))[0:5])
    assert pkt.secSig3 == 0xe
    assert pkt.secSig5 == 0
    assert pkt.secSig6 == 0
    assert pkt.secSig10 == 1
    assert pkt.secSig11 == 0x1fe
    assert pkt.secSig12 == 0xA5
    assert len(pkt) == 5


def test_Packetwithmixedendiannessfieldsbuildtest_2():
    """
    Packet with mixed endianness fields build test
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3, fmt="<B"),
            SignalField("muxSig5", default=0, start=22, size=7, fmt="<B"),
            SignalField("muxSig6", default=0, start=32, size=9, fmt="<B"),
            SignalField("muxSig7", default=0, start=2, size=8, fmt=">B"),
            SignalField("muxSig8", default=0, start=3, size=3, fmt="<B"),
            SignalField("muxSig9", default=0, start=41, size=7, fmt="<B"),
        ]

    pkt = testFrame3()
    pkt.myMuxer = 0x7
    pkt.muxSig5 = 0x72
    pkt.muxSig6 = 0x10f
    pkt.muxSig7 = 0xA5
    pkt.muxSig8 = 0x03
    pkt.muxSig9 = 0x11
    assert bytes(pkt) == b'\x1d\x28\x80\x1c\x0f\x23\xe0'
    assert len(pkt) == 7


def test_Packetwithmixedendiannessfieldsbuildtestmixedfieldorder():
    """
    Packet with mixed endianness fields build test, mixed field order
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3, fmt="<B"),
            SignalField("muxSig9", default=0, start=41, size=7, fmt="<B"),
            SignalField("muxSig6", default=0, start=32, size=9, fmt="<B"),
            SignalField("muxSig7", default=0, start=2, size=8, fmt=">B"),
            SignalField("muxSig8", default=0, start=3, size=3, fmt="<B"),
            SignalField("muxSig5", default=0, start=22, size=7, fmt="<B"),
        ]

    pkt = testFrame3()
    pkt.myMuxer = 0x7
    pkt.muxSig5 = 0x72
    pkt.muxSig6 = 0x10f
    pkt.muxSig7 = 0xA5
    pkt.muxSig8 = 0x03
    pkt.muxSig9 = 0x11
    assert bytes(pkt) == b'\x1d\x28\x80\x1c\x0f\x23\xe0'
    assert len(pkt) == 7


def test_Packetwithmixedendiannessfieldsdissecttestmixedfieldorder():
    """
    Packet with mixed endianness fields dissect test, mixed field order
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3, fmt="<B"),
            SignalField("muxSig9", default=0, start=41, size=7, fmt="<B"),
            SignalField("muxSig6", default=0, start=32, size=9, fmt="<B"),
            SignalField("muxSig7", default=0, start=2, size=8, fmt=">B"),
            SignalField("muxSig8", default=0, start=3, size=3, fmt="<B"),
            SignalField("muxSig5", default=0, start=22, size=7, fmt="<B"),
        ]

    pkt = testFrame3(b'\x1d\x28\x80\x1c\x0f\x23\xe0')
    assert len(pkt) == 7
    assert pkt.myMuxer == 0x7
    assert pkt.muxSig5 == 0x72
    assert pkt.muxSig6 == 0x10f
    assert pkt.muxSig7 == 0xA5
    assert pkt.muxSig8 == 0x03
    assert pkt.muxSig9 == 0x11


def test_Packetwithmixedendiannessfieldsdissecttestmixedfieldorderandscaling():
    """
    Packet with mixed endianness fields dissect test, mixed field order and scaling  # noqa: E501
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3,
                        scaling=0.1, fmt="<B"),
            SignalField("muxSig9", default=0, start=41, size=7,
                        scaling=100, fmt="<B"),
            SignalField("muxSig6", default=0, start=32, size=9,
                        scaling=2, fmt="<B"),
            SignalField("muxSig7", default=0, start=2, size=8,
                        scaling=0.5, fmt=">B"),
            SignalField("muxSig8", default=0, start=3, size=3,
                        scaling=10, fmt="<B"),
            SignalField("muxSig5", default=0, start=22, size=7,
                        scaling=0.01, fmt="<B"),
        ]

    pkt = testFrame3(b'\x1d\x28\x80\x1c\x0f\x23\xe0')
    assert len(pkt) == 7
    assert pkt.myMuxer == 0.7
    assert pkt.muxSig5 == 1.14
    assert pkt.muxSig6 == 0x10f << 1
    assert pkt.muxSig7 == 82.5
    assert pkt.muxSig8 == 30
    assert pkt.muxSig9 == 1700


def test_Packetwithmixedendiannessfieldsdissecttestmixedfieldorderandscaling2():  # noqa: E501
    """
    Packet with mixed endianness fields dissect test, mixed field order and scaling  # noqa: E501
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3,
                        scaling=0.1, fmt="<B"),
            SignalField("muxSig9", default=0, start=41, size=7,
                        scaling=100, fmt="<B"),
            SignalField("muxSig6", default=0, start=32, size=9,
                        scaling=2, fmt="<B"),
            SignalField("muxSig7", default=0, start=2, size=8,
                        scaling=0.5, fmt=">B"),
            SignalField("muxSig8", default=0, start=3, size=3,
                        scaling=10, fmt="<B"),
            SignalField("muxSig5", default=0, start=22, size=7,
                        scaling=0.01, fmt="<B"),
        ]

    pkt = testFrame3(b'\x1d\x28\x80\x1c\x0f\x23\xe0')
    assert len(pkt) == 7
    assert pkt.myMuxer == 0.7
    assert pkt.muxSig5 == 1.14
    assert pkt.muxSig6 == 0x10f << 1
    assert pkt.muxSig7 == 82.5
    assert pkt.muxSig8 == 30
    assert pkt.muxSig9 == 1700


def test_Packetwithmixedendiannessfieldsdissecttestmixedfieldorderandscalingandoffset():  # noqa: E501
    """
    Packet with mixed endianness fields dissect test, mixed field order and scaling and offset  # noqa: E501
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3,
                        scaling=0.1, offset=5, fmt="<B"),
            SignalField("muxSig9", default=0, start=41, size=7,
                        scaling=100, offset=1, fmt="<B"),
            SignalField("muxSig6", default=0, start=32, size=9,
                        scaling=2, offset=-10, fmt="<B"),
            SignalField("muxSig7", default=0, start=2, size=8,
                        scaling=0.5, offset=0.1, fmt=">B"),
            SignalField("muxSig8", default=0, start=3, size=3,
                        scaling=10, offset=100, fmt="<B"),
            SignalField("muxSig5", default=0, start=22, size=7,
                        scaling=0.01, fmt="<B"),
        ]

    pkt = testFrame3(b'\x1d\x28\x80\x1c\x0f\x23\xe0')
    assert len(pkt) == 7
    assert pkt.myMuxer == 5.7
    assert pkt.muxSig5 == 1.14
    assert pkt.muxSig6 == 532
    assert pkt.muxSig7 == 82.6
    assert pkt.muxSig8 == 130
    assert pkt.muxSig9 == 1701


def test_Packetwithmixedendiannessfieldsdissecttestmixedfieldorderandscalingandoffset3():  # noqa: E501
    """
    Packet with mixed endianness fields dissect test, mixed field order and scaling and offset  # noqa: E501
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            LEUnsignedSignalField("myMuxer", default=0, start=53, size=3,
                                  scaling=0.1, offset=5),
            LEUnsignedSignalField("muxSig9", default=0, start=41, size=7,
                                  scaling=100, offset=1),
            LEUnsignedSignalField("muxSig6", default=0, start=32, size=9,
                                  scaling=2, offset=-10),
            BEUnsignedSignalField("muxSig7", default=0, start=2, size=8,
                                  scaling=0.5, offset=0.1),
            LEUnsignedSignalField("muxSig8", default=0, start=3, size=3,
                                  scaling=10, offset=100),
            LEUnsignedSignalField("muxSig5", default=0, start=22, size=7,
                                  scaling=0.01),
        ]

    pkt = testFrame3(b'\x1d\x28\x80\x1c\x0f\x23\xe0')
    assert len(pkt) == 7
    assert pkt.myMuxer == 5.7
    assert pkt.muxSig5 == 1.14
    assert pkt.muxSig6 == 532
    assert pkt.muxSig7 == 82.6
    assert pkt.muxSig8 == 130
    assert pkt.muxSig9 == 1701


def test_Packetwithmixedendiannessfieldsdissecttestmixedfieldorderandscalingwithsignedvalues():  # noqa: E501
    """
    Packet with mixed endianness fields dissect test, mixed field order and scaling with signed values  # noqa: E501
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            SignalField("myMuxer", default=0, start=53, size=3,
                        scaling=0.1, fmt="<B"),
            SignalField("muxSig9", default=0, start=41, size=7,
                        scaling=100, fmt="<B"),
            SignalField("muxSig6", default=0, start=32, size=9,
                        scaling=2, fmt="<B"),
            SignalField("muxSig7", default=0, start=2, size=8,
                        scaling=0.5, fmt=">b"),
            SignalField("muxSig8", default=0, start=3, size=3,
                        scaling=10, fmt="<b"),
            SignalField("muxSig5", default=0, start=22, size=7,
                        scaling=0.01, fmt="<b"),
        ]

    pkt = testFrame3(b'\x1d\x28\x80\x1c\x0f\x23\xe0')
    assert len(pkt) == 7
    assert pkt.myMuxer == 0.7
    assert pkt.muxSig5 == -0.14
    assert pkt.muxSig6 == 0x10f << 1
    assert pkt.muxSig7 == -45.5
    assert pkt.muxSig8 == 30
    assert pkt.muxSig9 == 1700


def test_Packetwithmixedendiannessfieldsdissecttestmixedfieldorderandscalingwithsignedvalues4():  # noqa: E501
    """
    Packet with mixed endianness fields dissect test, mixed field order and scaling with signed values  # noqa: E501
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            LEUnsignedSignalField("myMuxer", default=0, start=53, size=3,
                                  scaling=0.1),
            LEUnsignedSignalField("muxSig9", default=0, start=41, size=7,
                                  scaling=100),
            LEUnsignedSignalField("muxSig6", default=0, start=32, size=9,
                                  scaling=2),
            BESignedSignalField("muxSig7", default=0, start=2, size=8,
                                scaling=0.5),
            LESignedSignalField("muxSig8", default=0, start=3, size=3,
                                scaling=10),
            LESignedSignalField("muxSig5", default=0, start=22, size=7,
                                scaling=0.01),
        ]

    pkt = testFrame3(b'\x1d\x28\x80\x1c\x0f\x23\xe0')
    assert len(pkt) == 7
    assert pkt.myMuxer == 0.7
    assert pkt.muxSig5 == -0.14
    assert pkt.muxSig6 == 0x10f << 1
    assert pkt.muxSig7 == -45.5
    assert pkt.muxSig8 == 30
    assert pkt.muxSig9 == 1700


def test_Packetwithbigendiannesssignals():
    """
    Packet with big endianness signals
    """

    class testFrame4(SignalPacket):
        fields_desc = [
            SignalField("sig0", default=0, start=1, size=2, fmt=">B"),
            SignalField("sig1", default=0, start=7, size=6, fmt=">B"),
            SignalField("sig2", default=0, start=15, size=11, fmt=">B"),
            SignalField("sig3", default=0, start=20, size=12, fmt=">B"),
            SignalField("sig4", default=0, start=24, size=9, fmt=">B"),
            SignalField("sig5", default=0, start=50, size=3, fmt=">B"),
            SignalField("sig6", default=0, start=53, size=3, fmt=">B"),
            SignalField("sig7", default=0, start=47, size=10, fmt=">B"),
            SignalField("sig8", default=0, start=58, size=3, fmt=">B"),
            SignalField("sig9", default=0, start=61, size=3, fmt=">B"),
            SignalField("sig10", default=0, start=63, size=2, fmt=">B")
        ]

    pkt = testFrame4()
    pkt.sig0 = 1
    pkt.sig1 = 35
    pkt.sig2 = 0
    pkt.sig3 = 2048
    pkt.sig4 = 256
    pkt.sig5 = 1
    pkt.sig6 = 0
    pkt.sig7 = 520
    pkt.sig8 = 0
    pkt.sig9 = 0
    pkt.sig10 = 0
    assert bytes(pkt) == b'\x8d\x00\x10\x01\x00\x82\x01\x00'


def test_Packetwithlittleendiannesssignals():
    """
    Packet with little endianness signals
    """

    class testFrame5(SignalPacket):
        fields_desc = [
            SignalField("secSig1", default=0, start=60, size=2, fmt="<B"),
            SignalField("secSig2", default=0, start=55, size=1, fmt="<B"),
            SignalField("secSig3", default=0, start=20, size=4, fmt="<B"),
            SignalField("secSig4", default=0, start=62, size=2, fmt="<B"),
            SignalField("secSig5", default=0, start=34, size=3, fmt="<B"),
            SignalField("secSig6", default=0, start=37, size=3, fmt="<B"),
            SignalField("secSig7", default=0, start=59, size=1, fmt="<B"),
            SignalField("secSig8", default=0, start=56, size=3, fmt="<B"),
            SignalField("secSig9", default=0, start=52, size=3, fmt="<B"),
            SignalField("secSig10", default=0, start=8, size=12, fmt="<B"),
            SignalField("secSig11", default=0, start=24, size=10, fmt="<b"),
            SignalField("secSig12", default=0, start=0, size=8, fmt="<B")
        ]

    pkt = testFrame5()
    pkt.secSig1 = 0
    pkt.secSig2 = 0
    pkt.secSig3 = 0
    pkt.secSig4 = 2
    pkt.secSig5 = 0
    pkt.secSig6 = 0
    pkt.secSig7 = 0
    pkt.secSig8 = 3
    pkt.secSig9 = 1
    pkt.secSig10 = 1280
    pkt.secSig11 = -144
    pkt.secSig12 = 12
    assert bytes(pkt) == b'\x0c\x00\x05p\x03\x00\x10\x83'


def test_Packetwithfloatsignalsbuildtest():
    """
    Packet with float signals build test
    """

    class testFrame6(SignalPacket):
        fields_desc = [
            SignalField("floatSignal2", default=0, start=32,
                        size=32, fmt="<f"),
            SignalField("floatSignal1", default=0, start=7, size=32, fmt=">f")
        ]

    pkt = testFrame6()
    pkt.floatSignal1 = 5.424999835668132e-05
    pkt.floatSignal2 = 6.176799774169922
    assert bytes(pkt) == b'8c\x8a~X\xa8\xc5@'


def test_Packetwithfloatsignalsdissecttest():
    """
    Packet with float signals dissect test
    """

    class testFrame6(SignalPacket):
        fields_desc = [
            SignalField("floatSignal2", default=0, start=32,
                        size=32, fmt="<f"),
            SignalField("floatSignal1", default=0, start=7, size=32, fmt=">f")
        ]

    pkt = testFrame6(b'8c\x8a~X\xa8\xc5@')
    assert pkt.floatSignal1 == 5.424999835668132e-05
    assert pkt.floatSignal2 == 6.176799774169922


def test_Packetwithfloatsignalsbuildtest2():
    """
    Packet with float signals build test 2
    """

    class testFrame6(SignalPacket):
        fields_desc = [
            LEFloatSignalField("floatSignal2", default=0, start=32),
            BEFloatSignalField("floatSignal1", default=0, start=7)
        ]

    pkt = testFrame6()
    pkt.floatSignal1 = 5.424999835668132e-05
    pkt.floatSignal2 = 6.176799774169922
    assert bytes(pkt) == b'8c\x8a~X\xa8\xc5@'


def test_Packetwithfloatsignalsdissecttest2():
    """
    Packet with float signals dissect test 2
    """

    class testFrame6(SignalPacket):
        fields_desc = [
            LEFloatSignalField("floatSignal2", default=0, start=32),
            BEFloatSignalField("floatSignal1", default=0, start=7)
        ]

    pkt = testFrame6(b'8c\x8a~X\xa8\xc5@')
    assert pkt.floatSignal1 == 5.424999835668132e-05
    assert pkt.floatSignal2 == 6.176799774169922


def test_Packetwithfloatsignalsrandval():
    """
    Packet with float signals randval
    """

    class testFrame6(SignalPacket):
        fields_desc = [
            LEFloatSignalField("floatSignal2", default=0, start=32),
            BEFloatSignalField("floatSignal1", default=0, start=7)
        ]

    pkt = testFrame6(b'8c\x8a~X\xa8\xc5@')
    assert pkt.fields_desc[0].randval() != 6.176799774169922
    assert pkt.fields_desc[1].randval() != 5.424999835668132e-05


def test_Packetwithfloatsignalsfuzz():
    """
    Packet with float signals fuzz
    """

    class testFrame6(SignalPacket):
        fields_desc = [
            LEFloatSignalField("floatSignal2", default=0, start=32),
            BEFloatSignalField("floatSignal1", default=0, start=7)
        ]

    pkt = testFrame6()
    f = fuzz(pkt)
    assert bytes(f) != bytes(f)


def test_Testsignalfuzzingoffset1():
    """
    Test signal fuzzing offset 1
    """
    test_offset = 100

    class testFrame3(SignalPacket):
        fields_desc = [
            BEUnsignedSignalField("muxSig7", default=0, start=2, size=8,
                                  scaling=1, offset=test_offset),
        ]

    pkt = testFrame3()
    pkt = fuzz(pkt)
    li = [pkt.muxSig7._fix() for x in range(100000)]
    assert abs(round(sum(li) / len(li)) - 128 - test_offset) < 2


def test_Testsignalfuzzingoffset2andscaling():
    """
    Test signal fuzzing offset 2 and scaling
    """
    test_offset = 100

    class testFrame3(SignalPacket):
        fields_desc = [
            BEUnsignedSignalField("muxSig7", default=0, start=2, size=8,
                                  scaling=0.1, offset=test_offset),
        ]

    pkt = testFrame3()
    pkt = fuzz(pkt)
    li = [pkt.muxSig7._fix() for x in range(100000)]
    assert abs(round(sum(li) / len(li)) - 12.8 - test_offset) < 2


def test_Testsignalfuzzingoffset3():
    """
    Test signal fuzzing offset 3
    """
    test_offset = -100

    class testFrame3(SignalPacket):
        fields_desc = [
            BESignedSignalField("muxSig7", default=0, start=2, size=8,
                                scaling=1, offset=test_offset),
        ]

    pkt = testFrame3()
    pkt = fuzz(pkt)
    li = [pkt.muxSig7._fix() for x in range(100000)]
    assert abs(round(sum(li) / len(li)) - test_offset) < 2


def test_Testsignalfuzzingoffset4andscaling():
    """
    Test signal fuzzing offset 4 and scaling
    """
    test_offset = 10

    class testFrame3(SignalPacket):
        fields_desc = [
            LESignedSignalField("muxSig7", default=0, start=2, size=8,
                                scaling=10, offset=test_offset),
        ]

    pkt = testFrame3()
    pkt = fuzz(pkt)
    li = [pkt.muxSig7._fix() for x in range(100000)]
    assert abs(round(sum(li) / len(li)) - test_offset) < 20


def test_Testsignalfuzzingoffset5andscaling():
    """
    Test signal fuzzing offset 5 and scaling
    """
    test_offset = 10

    class testFrame3(SignalPacket):
        fields_desc = [
            BESignedSignalField("muxSig7", default=0, start=2, size=8,
                                scaling=0.271, offset=test_offset),
        ]

    pkt = testFrame3()
    pkt = fuzz(pkt)
    li = [pkt.muxSig7._fix() for x in range(100000)]
    assert abs(round(sum(li) / len(li)) - test_offset) < 2


def test_TestFloatSignalfuzzing1():
    """
    Test FloatSignal fuzzing 1
    """

    class testFrame3(SignalPacket):
        fields_desc = [
            BEFloatSignalField("muxSig7", default=0, start=7),
        ]

    pkt = testFrame3()
    pkt = fuzz(pkt)
    testlen = 10000
    li = [pkt.muxSig7._fix() for x in range(testlen)]
    gz = [x for x in li if not math.isnan(x) and x >= 0]
    lz = [x for x in li if not math.isnan(x) and x < 0]
    nan = [x for x in li if math.isnan(x)]
    assert len(nan) >= 0
    assert abs(len(gz) - len(lz)) < (testlen // 10)
