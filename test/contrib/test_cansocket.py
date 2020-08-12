import pytest
from scapy.all import bridge_and_sniff, conf, load_layer

import os
import threading
from subprocess import call
import time

from scapy.layers.can import CAN

from scapy.contrib.cansocket_python_can import PythonCANSocket

try:
    from scapy.contrib.cansocket_native import NativeCANSocket
except ImportError:
    pass

send_done = threading.Event()


def sender(sock, msg):
    if not hasattr(msg, "__iter__"):
        msg = [msg]
    for m in msg:
        sock.send(m)
    send_done.set()


def test_Loadmodule():
    """
    Load module
    """
    load_layer("can")
    conf.contribs['CAN'] = {'swap-bytes': False}


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_Setupvcan0():
    """
    Setup vcan0
    """
    bashCommand = "/bin/bash -c 'sudo modprobe vcan; " \
                  "sudo ip link add name vcan0 type vcan; " \
                  "sudo ip link set dev vcan0 up'"
    assert 0 == os.system(bashCommand)


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.python3_only
@pytest.mark.vcan_socket
def test_NativeCANSocketsendrecvsmallpacket():
    """
    NativeCANSocket send recv small packet
    """
    global send_done

    sock1 = NativeCANSocket(bustype='socketcan', channel='vcan0')
    sock2 = NativeCANSocket(bustype='socketcan', channel='vcan0')

    thread = threading.Thread(target=sender,
                              args=(sock2, CAN(identifier=0x7ff,
                                               length=1, data=b'\x01'), ))
    thread.start()
    send_done.wait(timeout=1)
    rx = sock1.recv()

    sock1.close()
    sock2.close()

    thread.join(timeout=5)
    assert rx == CAN(identifier=0x7ff, length=1, data=b'\x01')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.python3_only
@pytest.mark.vcan_socket
def test_NativeCANSocketsendrecvsmallpackettestwith():
    """
    NativeCANSocket send recv small packet test with
    """

    with NativeCANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            NativeCANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender,
                                  args=(sock2,
                                        CAN(identifier=0x7ff,
                                            length=1, data=b'\x01'),))
        thread.start()
        send_done.wait(timeout=1)
        rx = sock1.recv()
        thread.join(timeout=5)

    assert rx == CAN(identifier=0x7ff, length=1, data=b'\x01')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.vcan_socket
def test_PythonCANSocketsendrecvsmallpacket():
    """
    PythonCANSocket send recv small packet
    """
    sock1 = PythonCANSocket(bustype='socketcan', channel='vcan0')
    sock2 = PythonCANSocket(bustype='socketcan', channel='vcan0')
    thread = threading.Thread(target=sender,
                              args=(sock2,
                                    CAN(identifier=0x7ff,
                                        length=1, data=b'\x01'), ))
    thread.start()

    send_done.wait(timeout=1)
    rx = sock1.recv()

    sock1.close()
    sock2.close()
    thread.join(timeout=5)

    assert rx == CAN(identifier=0x7ff, length=1, data=b'\x01')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.vcan_socket
def test_PythonCANSocketsendrecvsmallpackettestwith():
    """
    PythonCANSocket send recv small packet test with
    """

    with PythonCANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            PythonCANSocket(bustype='socketcan', channel='vcan0') as sock2:

        thread = threading.Thread(target=sender, args=(sock2,
                                                       CAN(identifier=0x7ff,
                                                           length=1,
                                                           data=b'\x01'),))
        thread.start()
        send_done.wait(timeout=1)
        rx = sock1.recv()
        thread.join(timeout=5)

    assert rx == CAN(identifier=0x7ff, length=1, data=b'\x01')


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.python3_only
@pytest.mark.vcan_socket
def test_NativeCANSocketsendrecvswapped():
    """
    NativeCANSocket send recv swapped
    """

    conf.contribs['CAN']['swap-bytes'] = True

    with NativeCANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            NativeCANSocket(bustype='socketcan', channel='vcan0') as sock2:

        time.sleep(0)
        thread = threading.Thread(target=sender,
                                  args=(sock2,
                                        CAN(identifier=0x7ff, length=8,
                                            data=b'\x01\x02\x03\x04'
                                                 b'\x05\x06\x07\x08'),))

        rx = sock1.sniff(count=1, timeout=1, started_callback=thread.start)

        assert len(rx) == 1
        assert rx[0] == CAN(identifier=0x7ff, length=8,
                            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
        thread.join(timeout=5)

    conf.contribs['CAN']['swap-bytes'] = False


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.vcan_socket
def test_PythonCANSocketsendrecvswapped():
    """
    PythonCANSocket send recv swapped
    """

    conf.contribs['CAN']['swap-bytes'] = True
    with PythonCANSocket(bustype='socketcan', channel='vcan0') as sock1, \
            PythonCANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender,
                                  args=(sock2,
                                        CAN(identifier=0x7ff,
                                            length=8,
                                            data=b'\x01\x02\x03\x04'
                                                 b'\x05\x06\x07\x08'),))

        rx = sock1.sniff(count=1, timeout=1, started_callback=thread.start)
        assert rx[0] == CAN(identifier=0x7ff, length=8,
                            data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
        thread.join(timeout=5)

    conf.contribs['CAN']['swap-bytes'] = False


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.python3_only
@pytest.mark.vcan_socket
def test_NativeCANSocketsniffwithfiltermask0x7ff():
    """
    NativeCANSocket sniff with filtermask 0x7ff
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
    with NativeCANSocket(bustype='socketcan', channel='vcan0',
                         can_filters=[
                             {'can_id': 0x200, 'can_mask': 0x7ff}]) as sock1, \
            NativeCANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        packets = sock1.sniff(timeout=0.1, started_callback=thread.start)
        assert len(packets) == 3
        thread.join(timeout=5)


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.vcan_socket
def test_PythonCANSocketsniffwithfiltermask0x7ff():
    """
    PythonCANSocket sniff with filtermask 0x7ff
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
    with PythonCANSocket(bustype='socketcan', channel='vcan0',
                         can_filters=[{'can_id': 0x200,
                                       'can_mask': 0x7ff}]) as sock1, \
            PythonCANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        packets = sock1.sniff(timeout=0.1, started_callback=thread.start)
        assert len(packets) == 3
        thread.join(timeout=5)


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.python3_only
@pytest.mark.vcan_socket
def test_NativeCANSocketsniffwithmultiplefilters():
    """
    NativeCANSocket sniff with multiple filters
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
    with NativeCANSocket(bustype='socketcan', channel='vcan0',
                         can_filters=[
                             {'can_id': 0x200, 'can_mask': 0x7ff},
                             {'can_id': 0x400, 'can_mask': 0x7ff},
                             {'can_id': 0x600, 'can_mask': 0x7ff},
                             {'can_id': 0x7ff, 'can_mask': 0x7ff}]) as sock1, \
            NativeCANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        packets = sock1.sniff(timeout=0.1, started_callback=thread.start)
        assert len(packets) == 4
        thread.join(timeout=5)


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.vcan_socket
def test_PythonCANSocketsniffwithmultiplefilters():
    """
    PythonCANSocket sniff with multiple filters
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
    with PythonCANSocket(bustype='socketcan', channel='vcan0',
                         can_filters=[
                             {'can_id': 0x200, 'can_mask': 0x7ff},
                             {'can_id': 0x400, 'can_mask': 0x7ff},
                             {'can_id': 0x600, 'can_mask': 0x7ff},
                             {'can_id': 0x7ff, 'can_mask': 0x7ff}]) as sock1, \
            PythonCANSocket(bustype='socketcan', channel='vcan0') as sock2:
        thread = threading.Thread(target=sender, args=(sock2, msgs,))
        packets = sock1.sniff(timeout=0.1, started_callback=thread.start)
        assert len(packets) == 4
        thread.join(timeout=5)


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.vcan_socket
def test_Setupvcan1interface():
    """
    Setup vcan1 interface
    """
    bashCommand = "/bin/bash -c 'sudo ip link add name vcan1 type vcan; " \
                  "sudo ip link set dev vcan1 up'"
    assert 0 == os.system(bashCommand)


bridgeStarted = threading.Event()


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.python3_only
@pytest.mark.vcan_socket
def test_NativeCANSocketbridgeandsniffsetupvcan1packageforwarding():
    """
    NativeCANSocket bridge and sniff setup vcan1 package forwarding
    """
    global bridgeStarted

    def senderVCan0():
        with NativeCANSocket(bustype='socketcan', channel='vcan0') as sock0:
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

    def bridge():
        global bridgeStarted
        with NativeCANSocket(bustype='socketcan', channel='vcan0') as bSock0, \
                NativeCANSocket(bustype='socketcan',
                                channel='vcan1') as bSock1:
            bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=lambda p: p,
                             xfrm21=lambda p: p, timeout=0.5,
                             started_callback=bridgeStarted.set)

    threadBridge = threading.Thread(target=bridge)
    threadBridge.start()
    threadSender = threading.Thread(target=senderVCan0)
    bridgeStarted.wait(timeout=0.2)

    with NativeCANSocket(bustype='socketcan', channel='vcan1') as sock1:
        packetsVCan1 = sock1.sniff(timeout=0.5,
                                   started_callback=threadSender.start)

    threadBridge.join()
    threadSender.join()

    assert len(packetsVCan1) == 6


@pytest.mark.needs_root
@pytest.mark.linux
@pytest.mark.not_pypy
@pytest.mark.vcan_socket
def test_PythonCANSocketbridgeandsniffsetupvcan1packageforwarding():
    """
    PythonCANSocket bridge and sniff setup vcan1 package forwarding
    """

    def senderVCan0():
        with PythonCANSocket(bustype='socketcan', channel='vcan0') as sock0:
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

    def bridge():
        global bridgeStarted
        with PythonCANSocket(bustype='socketcan', channel='vcan0') as bSock0, \
                PythonCANSocket(bustype='socketcan',
                                channel='vcan1') as bSock1:
            bridge_and_sniff(if1=bSock0, if2=bSock1, xfrm12=lambda p: p,
                             xfrm21=lambda p: p, timeout=0.5,
                             started_callback=bridgeStarted.set)

    threadBridge = threading.Thread(target=bridge)
    threadBridge.start()
    threadSender = threading.Thread(target=senderVCan0)

    bridgeStarted.wait(timeout=5)

    with PythonCANSocket(bustype='socketcan', channel='vcan1') as sock1:
        packetsVCan1 = sock1.sniff(timeout=0.5,
                                   started_callback=threadSender.start)

    threadBridge.join(timeout=5)
    threadSender.join(timeout=5)

    assert len(packetsVCan1) == 6


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
