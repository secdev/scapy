import pytest
from scapy.all import conf, load_layer, load_contrib, bridge_and_sniff, Raw

import os
import threading
from subprocess import call

from scapy.contrib.isotp import ISOTPHeader, ISOTP_FF


def test_Loadmodule():
    """
    Load module
    """
    conf.contribs['CAN'] = {'swap-bytes': False}
    load_layer("can", globals_dict=globals())
    conf.contribs['CANSocket'] = {'use-python-can': True}
    load_contrib("cansocket")


from scapy.layers.can import CAN  # noqa: E402
from scapy.contrib.cansocket_python_can import CANSocket  # noqa: E402


@pytest.mark.linux
@pytest.mark.needs_root
@pytest.mark.vcan_socket
def test_Setupvcan0():
    """
    Setup vcan0
    """
    bashCommand = "/bin/bash -c 'sudo modprobe vcan; sudo ip link add name " \
                  "vcan0 type vcan; sudo ip link set dev vcan0 up'"
    assert 0 == os.system(bashCommand)


# Define common used functions
send_done = threading.Event()


def sender(sock, msg):
    if not hasattr(msg, "__iter__"):
        msg = [msg]
    for m in msg:
        sock.send(m)
    send_done.set()


def test_CANPacketinit():
    """
    CAN Packet init
    """ 
    canframe = CAN(identifier=0x7ff,
                   length=8,
                   data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    assert bytes(canframe) == \
           b'\x00\x00\x07\xff\x08\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08'


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_CANSocketInit():
    """
    CAN Socket Init
    """
    sock1 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1.close()
    del sock1


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_CANSocketsendrecvsmallpacket():
    """
    CAN Socket send recv small packet
    """
    sock1 = CANSocket(bustype='socketcan', channel='vcan0')
    sock2 = CANSocket(bustype='socketcan', channel='vcan0')
    thread = threading.Thread(target=sender, args=(sock2, CAN(identifier=0x7ff,
                                                              length=1,
                                                              data=b'\x01'), ))
    thread.start()
    send_done.wait(timeout=1)
    send_done.clear()
    rx = sock1.recv()
    sock1.close()
    sock2.close()
    assert rx == CAN(identifier=0x7ff, length=1, data=b'\x01')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_CANSocketsendrecvsmallpackettestwith():
    """
    CAN Socket send recv small packet test with
    """

    with CANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(
            target=sender,
            args=(sock2, CAN(identifier=0x7ff,
                             length=1,
                             data=b'\x01'),))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        rx = sock1.recv()

    assert rx == CAN(identifier=0x7ff, length=1, data=b'\x01')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_CANSocketsendrecvISOTPPacket():
    """
    CAN Socket send recv ISOTP_Packet
    """

    with CANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(
            target=sender,
            args=(sock2, ISOTPHeader(identifier=0x7ff) / ISOTP_FF(
                message_size=100, data=b'abcdef'),))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        rx = sock1.recv()

    assert rx == CAN(identifier=0x7ff, length=8, data=b'\x10\x64abcdef')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_CANSocketbaseclstest():
    """
    CAN Socket basecls test
    """

    with CANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(
            target=sender,
            args=(sock2, CAN(identifier=0x7ff,
                             length=8,
                             data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),))
        thread.start()
        sock1.basecls = Raw
        send_done.wait(timeout=1)
        send_done.clear()
        rx = sock1.recv()

    assert rx == Raw(bytes(CAN(identifier=0x7ff, length=8,
                               data=b'\x01\x02\x03\x04\x05\x06\x07\x08')))


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_CANSocketsendrecv():
    """
    CAN Socket send recv
    """

    with CANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(
            target=sender,
            args=(sock2, CAN(identifier=0x7ff,
                             length=8,
                             data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),))
        thread.start()
        sock1.basecls = CAN
        send_done.wait(timeout=1)
        send_done.clear()
        rx = sock1.recv()

    assert rx == CAN(identifier=0x7ff, length=8,
                     data=b'\x01\x02\x03\x04\x05\x06\x07\x08')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_CANSocketsendrecvswapped():
    """
    CAN Socket send recv swapped
    """
    conf.contribs['CAN']['swap-bytes'] = True

    with CANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(
            target=sender,
            args=(sock2, CAN(identifier=0x7ff, length=8,
                             data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),))
        thread.start()
        sock1.basecls = CAN
        send_done.wait(timeout=1)
        send_done.clear()
        rx = sock1.recv()

    assert rx == CAN(identifier=0x7ff, length=8,
                     data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    conf.contribs['CAN']['swap-bytes'] = False


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_sniffwithfiltermask0x7ff():
    """
    sniff with filtermask 0x7ff
    """
    msgs = [
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x300, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x300, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x100, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')]

    with CANSocket(bustype='socketcan', channel='vcan0',
                   can_filters=[
                       {'can_id': 0x200, 'can_mask': 0x7ff}]) as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        packets = sock1.sniff(timeout=0.1)

    assert len(packets) == 3


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_sniffwithfiltermask0x700():
    """
    sniff with filtermask 0x700
    """

    msgs = [
        CAN(identifier=0x212, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x300, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x2ff, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x1ff, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x2aa, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')]

    with CANSocket(bustype='socketcan', channel='vcan0',
                   can_filters=[
                       {'can_id': 0x200, 'can_mask': 0x700}]) as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        packets = sock1.sniff(timeout=0.1)

    assert len(packets) == 4


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_sniffwithfiltermask0x0ff():
    """
    sniff with filtermask 0x0ff
    """

    msgs = [
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x301, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x300, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x1ff, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x700, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x100, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')]

    with CANSocket(bustype='socketcan', channel='vcan0',
                   can_filters=[
                       {'can_id': 0x200, 'can_mask': 0xff}]) as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        packets = sock1.sniff(timeout=0.1)

    assert len(packets) == 4


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_sniffwithmultiplefilters():
    """
    sniff with multiple filters
    """

    msgs = [
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x300, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x400, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x500, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x600, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x700, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x7ff, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')]

    with CANSocket(bustype='socketcan', channel='vcan0',
                   can_filters=[
                       {'can_id': 0x200, 'can_mask': 0x7ff},
                       {'can_id': 0x400, 'can_mask': 0x7ff},
                       {'can_id': 0x600, 'can_mask': 0x7ff},
                       {'can_id': 0x7ff, 'can_mask': 0x7ff}]) as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        packets = sock1.sniff(timeout=0.1)

    assert len(packets) == 4


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_sniffwithfiltermask0x7ff_2():
    """
    sniff with filtermask 0x7ff
    """

    msgs = [
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x300, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x100, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(identifier=0x200, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')]

    with CANSocket(bustype='socketcan', channel='vcan0',
                   can_filters=[
                       {'can_id': 0x200, 'can_mask': 0x7ff}]) as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        packets = sock1.sniff(timeout=0.1)

    assert len(packets) == 4


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_sniffwithfiltermask0x1FFFFFFF():
    """
    sniff with filtermask 0x1FFFFFFF
    """
    msgs = [
        CAN(flags='extended', identifier=0x10010000, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(flags='extended', identifier=0x10020000, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(flags='extended', identifier=0x10000000, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(flags='extended', identifier=0x10030000, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(flags='extended', identifier=0x10040000, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08'),
        CAN(flags='extended', identifier=0x10000000, length=8,
            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')]

    with CANSocket(bustype='socketcan', channel='vcan0',
                   can_filters=[
                       {'can_id': 0x10000000,
                        'can_mask': 0x1fffffff}]) as sock1, \
            CANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        thread.start()
        send_done.wait(timeout=1)
        send_done.clear()
        packets = sock1.sniff(timeout=0.1)

    assert len(packets) == 2


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan1packageforwarding():
    """
    bridge and sniff setup vcan1 package forwarding
    """

    bashCommand = "/bin/bash -c 'sudo ip link add name vcan1 type vcan; " \
                  "sudo ip link set dev vcan1 up'"
    assert 0 == os.system(bashCommand)

    sock0 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1 = CANSocket(bustype='socketcan', channel='vcan1')

    def senderVCan0():
        sock0.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10020000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10030000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10040000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))

    bridgeStarted = threading.Event()

    def bridge():
        bSock0 = CANSocket(
            bustype='socketcan', channel='vcan0', bitrate=250000)
        bSock1 = CANSocket(
            bustype='socketcan', channel='vcan1', bitrate=250000)

        def pnr(pkt):
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01

        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=pnr, xfrm21=pnr,
                         timeout=0.5, started_callback=bridgeStarted.set)

        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(target=bridge)
    threadBridge.start()

    threadSender = threading.Thread(target=senderVCan0)
    bridgeStarted.wait()

    packetsVCan1 = sock1.sniff(timeout=0.5,
                               started_callback=threadSender.start)

    assert len(packetsVCan1) == 6

    sock1.close()
    sock0.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan0packageforwarding():
    """
    bridge and sniff setup vcan0 package forwarding
    """

    sock0 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1 = CANSocket(bustype='socketcan', channel='vcan1')

    def senderVCan1():
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x80, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))

    bridgeStarted = threading.Event()

    def bridge():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnr(pkt):
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=pnr, xfrm21=pnr,
                         timeout=0.5, started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(target=bridge)
    threadBridge.start()

    threadSender = threading.Thread(target=senderVCan1)
    bridgeStarted.wait()

    packetsVCan0 = sock0.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    assert len(packetsVCan0) == 4

    sock0.close()
    sock1.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan0vcan1packageforwardingbothdirections():
    """
    bridge and sniff setup vcan0 vcan1 package forwarding both directions
    """

    sock0 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1 = CANSocket(bustype='socketcan', channel='vcan1')

    def senderBothVCans():
        sock0.send(CAN(flags='extended', identifier=0x25, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x20, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x25, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x25, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x20, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x30, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock1.send(CAN(flags='extended', identifier=0x40, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x40, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x80, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x40, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))

    bridgeStarted = threading.Event()

    def bridge():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnr(pkt):
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=pnr, xfrm21=pnr,
                         timeout=0.5, started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(target=bridge)
    threadBridge.start()

    threadSender = threading.Thread(target=senderBothVCans)
    bridgeStarted.wait()

    packetsVCan0 = sock0.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    packetsVCan1 = sock1.sniff(timeout=0.3)
    assert len(packetsVCan0) == 4
    assert len(packetsVCan1) == 6

    sock0.close()
    sock1.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan1packagechange():
    """
    bridge and sniff setup vcan1 package change
    """

    sock0 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1 = CANSocket(bustype='socketcan', channel='vcan1',
                      can_filters=[{'can_id': 0x10010000,
                                    'can_mask': 0x1fffffff}])

    def senderVCan0():
        sock0.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10020000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10030000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10040000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))

    bridgeStarted = threading.Event()

    def bridgeWithPackageChangeVCan0ToVCan1():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnr(pkt):
            pkt.data = b'\x08\x07\x06\x05\x04\x03\x02\x01'
            pkt.identifier = 0x10010000
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=pnr, timeout=0.5,
                         started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(target=bridgeWithPackageChangeVCan0ToVCan1)
    threadBridge.start()

    threadSender = threading.Thread(target=senderVCan0)
    bridgeStarted.wait()

    packetsVCan1 = sock1.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    assert len(packetsVCan1) == 6

    sock0.close()
    sock1.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan0packagechange():
    """
    bridge and sniff setup vcan0 package change
    """

    sock1 = CANSocket(bustype='socketcan', channel='vcan1')
    sock0 = CANSocket(bustype='socketcan', channel='vcan0',
                      can_filters=[{'can_id': 0x10010000,
                                    'can_mask': 0x1fffffff}])

    def senderVCan1():
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10050000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))

    bridgeStarted = threading.Event()

    def bridgeWithPackageChangeVCan1ToVCan0():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnr(pkt):
            pkt.data = b'\x08\x07\x06\x05\x04\x03\x02\x01'
            pkt.identifier = 0x10010000
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm21=pnr, timeout=0.5,
                         started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(target=bridgeWithPackageChangeVCan1ToVCan0)
    threadBridge.start()

    threadSender = threading.Thread(target=senderVCan1)
    bridgeStarted.wait()

    packetsVCan0 = sock0.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    assert len(packetsVCan0) == 4

    sock0.close()
    sock1.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan0andvcan1packagechangeinbothdirections():
    """
    bridge and sniff setup vcan0 and vcan1 package change in both directions
    """

    sock0 = CANSocket(bustype='socketcan', channel='vcan0',
                      can_filters=[{'can_id': 0x10010000,
                                    'can_mask': 0x1fffffff}])
    sock1 = CANSocket(bustype='socketcan', channel='vcan1',
                      can_filters=[{'can_id': 0x10010000,
                                    'can_mask': 0x1fffffff}])

    def senderBothVCans():
        sock0.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10020000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10030000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10040000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10050000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))

    bridgeStarted = threading.Event()

    def bridgeWithPackageChangeBothDirections():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnr(pkt):
            pkt.data = b'\x08\x07\x06\x05\x04\x03\x02\x01'
            pkt.identifier = 0x10010000
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=pnr, xfrm21=pnr,
                         timeout=0.5, started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(
        target=bridgeWithPackageChangeBothDirections)
    threadBridge.start()

    threadSender = threading.Thread(target=senderBothVCans)
    bridgeStarted.wait()

    packetsVCan0 = sock0.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    packetsVCan1 = sock1.sniff(timeout=0.3)
    assert len(packetsVCan0) == 4
    assert len(packetsVCan1) == 6

    sock0.close()
    sock1.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan0packageremove():
    """
    bridge and sniff setup vcan0 package remove
    """

    sock0 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1 = CANSocket(bustype='socketcan', channel='vcan1')

    def senderVCan0():
        sock0.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10020000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10030000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10040000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))

    bridgeStarted = threading.Event()

    def bridgeWithRemovePackageFromVCan0ToVCan1():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnr(pkt):
            if pkt.identifier == 0x10020000:
                pkt = None
            else:
                pkt = pkt
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=pnr, timeout=0.5,
                         started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(
        target=bridgeWithRemovePackageFromVCan0ToVCan1)
    threadBridge.start()

    threadSender = threading.Thread(target=senderVCan0)
    bridgeStarted.wait()

    packetsVCan1 = sock1.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    assert len(packetsVCan1) == 5

    sock0.close()
    sock1.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan1packageremove():
    """
    bridge and sniff setup vcan1 package remove
    """

    sock0 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1 = CANSocket(bustype='socketcan', channel='vcan1')

    def senderVCan1():
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10050000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))

    bridgeStarted = threading.Event()

    def bridgeWithRemovePackageFromVCan1ToVCan0():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnr(pkt):
            if pkt.identifier == 0x10050000:
                pkt = None
            else:
                pkt = pkt
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm21=pnr, timeout=0.5,
                         started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(
        target=bridgeWithRemovePackageFromVCan1ToVCan0)
    threadBridge.start()

    threadSender = threading.Thread(target=senderVCan1)
    bridgeStarted.wait()

    packetsVCan0 = sock0.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    assert len(packetsVCan0) == 3

    sock0.close()
    sock1.close()
    threadBridge.join()
    threadSender.join()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_bridgeandsniffsetupvcan0andvcan1packageremovebothdirections():
    """
    bridge and sniff setup vcan0 and vcan1 package remove both directions
    """

    sock0 = CANSocket(bustype='socketcan', channel='vcan0')
    sock1 = CANSocket(bustype='socketcan', channel='vcan1')

    def senderBothVCans():
        sock0.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10020000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10030000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10040000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock0.send(CAN(flags='extended', identifier=0x10000000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x06\x07\x08'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10050000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))
        sock1.send(CAN(flags='extended', identifier=0x10010000, length=8,
                       data=b'\x01\x02\x03\x04\x05\x04\x05\x06'))

    bridgeStarted = threading.Event()

    def bridgeWithRemovePackageInBothDirections():
        bSock0 = CANSocket(bustype='socketcan', channel='vcan0')
        bSock1 = CANSocket(bustype='socketcan', channel='vcan1')

        def pnrA(pkt):
            if pkt.identifier == 0x10020000:
                pkt = None
            else:
                pkt = pkt
            return pkt

        def pnrB(pkt):
            if pkt.identifier == 0x10050000:
                pkt = None
            else:
                pkt = pkt
            return pkt

        bSock0.timeout = 0.01
        bSock1.timeout = 0.01
        bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=pnrA, xfrm21=pnrB,
                         timeout=0.5, started_callback=bridgeStarted.set)
        bSock0.close()
        bSock1.close()

    threadBridge = threading.Thread(
        target=bridgeWithRemovePackageInBothDirections)
    threadBridge.start()

    threadSender = threading.Thread(target=senderBothVCans)
    bridgeStarted.wait()

    packetsVCan0 = sock0.sniff(timeout=0.3,
                               started_callback=threadSender.start)
    packetsVCan1 = sock1.sniff(timeout=0.3)
    assert len(packetsVCan0) == 3
    assert len(packetsVCan1) == 5
    sock0.close()
    sock1.close()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_Deletevcaninterfaces():
    """
    Delete vcan interfaces
    """
    if 0 != call(["sudo", "ip", "link", "delete", "vcan0"]):
        raise Exception("vcan0 could not be deleted")
    if 0 != call(["sudo", "ip", "link", "delete", "vcan1"]):
        raise Exception("vcan1 could not be deleted")
