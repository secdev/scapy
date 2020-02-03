
import threading
import time

from scapy.config import conf
from scapy.volatile import RandNum
from scapy.config import LINUX
import scapy.modules.six as six


conf.contribs['CAN']['swap-bytes'] = False
iface0 = "vcan0"
iface1 = "vcan1"

from scapy.layers.can import CAN  # noqa: E402
from scapy.contrib.cansocket import *  # noqa: F401, F403

from scapy.contrib.cansocket_python_can import *  # noqa: F401, F403
import can as python_can  # noqa: E402

new_can_socket = lambda iface: CANSocket(iface=python_can.interface.Bus(bustype='virtual', channel=iface))  # noqa: E501
new_can_socket0 = lambda: CANSocket(iface=python_can.interface.Bus(bustype='virtual', channel=iface0), timeout=0.01)  # noqa: E501
new_can_socket1 = lambda: CANSocket(iface=python_can.interface.Bus(bustype='virtual', channel=iface1), timeout=0.01)  # noqa: E501

if six.PY3 and LINUX:
    from scapy.contrib.cansocket_native import CANSocket  # noqa: F811
    new_can_socket = lambda iface: CANSocket(iface)
    new_can_socket0 = lambda: CANSocket(iface0)
    new_can_socket1 = lambda: CANSocket(iface1)

if "python_can" in CANSocket.__module__:
    new_can_socket = lambda iface: CANSocket(iface=python_can.interface.Bus(bustype='socketcan', channel=iface), timeout=0.01)  # noqa: E501
    new_can_socket0 = lambda: CANSocket(iface=python_can.interface.Bus(bustype='socketcan', channel=iface0), timeout=0.01)  # noqa: E501
    new_can_socket1 = lambda: CANSocket(iface=python_can.interface.Bus(bustype='socketcan', channel=iface1), timeout=0.01)  # noqa: E501


from scapy.contrib.isotp import ISOTPSocket, ISOTPScan, scan, scan_extended, ISOTPSoftSocket  # noqa: E501, E402


def check_loading():
    return "Loaded"


def make_noise(p):
    with new_can_socket0() as s:
        for _ in range(20):
            s.send(p)
            time.sleep(0.021)


def test_scan(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(idx):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x700 + idx, did=0x600 + idx) as sock:
            sock.sniff(timeout=30, count=1, started_callback=semaphore.release)

    listen_sockets = list()
    for i in range(1, 4):
        listen_sockets.append(
            threading.Thread(target=isotpserver, args=(int(i),)))
        listen_sockets[-1].start()

    for _ in range(len(listen_sockets)):
        semaphore.acquire()

    with new_can_socket0() as scansock:
        found_packets = scan(scansock, range(0x5ff, 0x604), noise_ids=[0x701],
                             sniff_time=sniff_time, verbose=True)

    with new_can_socket0() as cans:
        for _ in range(5):
            cans.send(CAN(identifier=0x601, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x602, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x603, data=b'\x01\xaa'))
            time.sleep(0)

    print(len(listen_sockets))

    for thread in listen_sockets:
        thread.join(timeout=1)

    print(len(found_packets))
    assert len(found_packets) == 2


def test_scan_extended(sniff_time=0.02):
    recvpacket = CAN(flags=0, identifier=0x700, length=4,
                     data=b'\xaa0\x00\x00')
    semaphore = threading.Semaphore(0)

    def isotpserver():
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x700, did=0x601,
                            extended_addr=0xaa, extended_rx_addr=0xbb) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    thread = threading.Thread(target=isotpserver)
    thread.start()

    semaphore.acquire()

    with new_can_socket0() as scansock:
        found_packets = scan_extended(scansock, [0x600, 0x601],
                                      sniff_time=sniff_time)

    with new_can_socket0() as cans:
        cans.send(CAN(identifier=0x601, data=b'\xbb\x01\xaa'))
        thread.join(timeout=10)

    fpkt = found_packets[list(found_packets.keys())[0]][0]
    rpkt = recvpacket

    assert fpkt.length == rpkt.length
    assert fpkt.data == rpkt.data
    assert fpkt.identifier == rpkt.identifier


def test_isotpscan_text(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x700 + i, did=0x600 + i) as isotpsock:
            isotpsock.sniff(timeout=10, count=1,
                            started_callback=semaphore.release)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))
    thread_noise.start()

    thread1 = threading.Thread(target=isotpserver, args=(2,))
    thread2 = threading.Thread(target=isotpserver, args=(3,))
    thread1.start()
    thread2.start()

    semaphore.acquire()
    semaphore.acquire()

    with new_can_socket0() as scansock:
        result = ISOTPScan(scansock, range(0x5ff, 0x604 + 1),
                           output_format="text", noise_listen_time=0.3,
                           sniff_time=sniff_time, verbose=True)

    with new_can_socket0() as cans:
        cans.send(CAN(identifier=0x601, data=b'\x01\xaa'))
        cans.send(CAN(identifier=0x602, data=b'\x01\xaa'))
        cans.send(CAN(identifier=0x603, data=b'\x01\xaa'))

    thread1.join(timeout=10)
    thread2.join(timeout=10)
    thread_noise.join(timeout=10)

    text = "\nFound 2 ISOTP-FlowControl Packet(s):"
    assert text in result
    assert "0x602" in result
    assert "0x603" in result
    assert "0x702" in result
    assert "0x703" in result
    assert "No Padding" in result


def test_isotpscan_text_extended_can_id(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan,
                            sid=0x1ffff700 + i,
                            did=0x1ffff600 + i) as isotpsock1:
            isotpsock1.sniff(timeout=10, count=1,
                             started_callback=semaphore.release)

    pkt = CAN(identifier=0x1ffff701, flags="extended", length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))
    thread_noise.start()

    thread1 = threading.Thread(target=isotpserver, args=(2,))
    thread2 = threading.Thread(target=isotpserver, args=(3,))
    thread1.start()
    thread2.start()
    semaphore.acquire()
    semaphore.acquire()

    with new_can_socket0() as scansock:
        result = ISOTPScan(scansock, range(0x1ffff5ff, 0x1ffff604 + 1),
                           output_format="text", noise_listen_time=0.3,
                           sniff_time=sniff_time, extended_can_id=True,
                           verbose=True)

    with new_can_socket0() as cans:
        cans.send(CAN(identifier=0x1ffff601, flags="extended",
                      data=b'\x01\xaa'))
        cans.send(CAN(identifier=0x1ffff602, flags="extended",
                      data=b'\x01\xaa'))
        cans.send(CAN(identifier=0x1ffff603, flags="extended",
                      data=b'\x01\xaa'))

    thread1.join(timeout=10)
    thread2.join(timeout=10)
    thread_noise.join(timeout=10)

    print(result)
    text = "\nFound 2 ISOTP-FlowControl Packet(s):"
    assert text in result
    assert "0x1ffff602" in result
    assert "0x1ffff603" in result
    assert "0x1ffff702" in result
    assert "0x1ffff703" in result
    assert "No Padding" in result


def test_isotpscan_code(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x700 + i, did=0x600 + i) as isotpsock:
            isotpsock.sniff(timeout=60, count=1,
                            started_callback=semaphore.release)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))
    thread_noise.start()

    thread1 = threading.Thread(target=isotpserver, args=(2,))
    thread2 = threading.Thread(target=isotpserver, args=(3,))
    thread1.start()
    thread2.start()
    semaphore.acquire()
    semaphore.acquire()

    with new_can_socket0() as scansock:
        result = ISOTPScan(scansock, range(0x5ff, 0x603 + 1),
                           output_format="code", noise_listen_time=0.31,
                           sniff_time=sniff_time, can_interface="can0",
                           verbose=True)

    with new_can_socket0() as cans:
        cans.send(CAN(identifier=0x601, data=b'\x01\xaa'))
        cans.send(CAN(identifier=0x602, data=b'\x01\xaa'))
        cans.send(CAN(identifier=0x603, data=b'\x01\xaa'))

    thread1.join(timeout=10)
    thread2.join(timeout=10)
    thread_noise.join(timeout=10)

    s1 = "ISOTPSocket(can0, sid=0x602, did=0x702, " \
         "padding=False, basecls=ISOTP)\n"
    s2 = "ISOTPSocket(can0, sid=0x603, did=0x703, " \
         "padding=False, basecls=ISOTP)\n"

    print(result)
    assert s1 in result
    assert s2 in result


def test_extended_isotpscan_code(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x700 + i, did=0x600 + i,
                            extended_addr=0x11, extended_rx_addr=0x22) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))

    thread1 = threading.Thread(target=isotpserver, args=(2,))
    thread2 = threading.Thread(target=isotpserver, args=(3,))
    thread1.start()
    thread2.start()

    semaphore.acquire()
    semaphore.acquire()
    thread_noise.start()

    with new_can_socket0() as scansock:
        result = ISOTPScan(scansock, range(0x5ff, 0x603 + 1),
                           extended_addressing=True, sniff_time=sniff_time,
                           noise_listen_time=0.31, output_format="code",
                           can_interface="can0", verbose=True)

    with new_can_socket0() as cans:
        cans.send(CAN(identifier=0x602, data=b'\x22\x01\xaa'))
        cans.send(CAN(identifier=0x603, data=b'\x22\x01\xaa'))
        time.sleep(0)
        cans.send(CAN(identifier=0x602, data=b'\x22\x01\xaa'))
        cans.send(CAN(identifier=0x603, data=b'\x22\x01\xaa'))
        thread1.join(timeout=10)
        thread2.join(timeout=10)
        thread_noise.join(timeout=10)

    s1 = "ISOTPSocket(can0, sid=0x602, did=0x702, padding=False, " \
         "extended_addr=0x22, extended_rx_addr=0x11, basecls=ISOTP)"
    s2 = "ISOTPSocket(can0, sid=0x603, did=0x703, padding=False, " \
         "extended_addr=0x22, extended_rx_addr=0x11, basecls=ISOTP)"
    print(result)
    assert s1 in result
    assert s2 in result


def test_extended_isotpscan_code_extended_can_id(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x1ffff700 + i, did=0x1ffff600 + i,
                            extended_addr=0x11, extended_rx_addr=0x22) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    pkt = CAN(identifier=0x1ffff701, flags="extended", length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))

    thread1 = threading.Thread(target=isotpserver, args=(2,))
    thread2 = threading.Thread(target=isotpserver, args=(3,))
    thread1.start()
    thread2.start()

    semaphore.acquire()
    semaphore.acquire()

    thread_noise.start()

    with new_can_socket0() as scansock:
        result = ISOTPScan(scansock, range(0x1ffff5ff, 0x1ffff604 + 1),
                           extended_can_id=True, extended_addressing=True,
                           sniff_time=sniff_time, noise_listen_time=0.31,
                           output_format="code", can_interface="can0",
                           verbose=True)

    with new_can_socket0() as cans:
        cans.send(CAN(identifier=0x1ffff602, flags="extended",
                      data=b'\x22\x01\xaa'))
        cans.send(CAN(identifier=0x1ffff603, flags="extended",
                      data=b'\x22\x01\xaa'))
        thread1.join(timeout=10)
        thread2.join(timeout=10)
        thread_noise.join(timeout=10)

    s1 = "ISOTPSocket(can0, sid=0x1ffff602, did=0x1ffff702, padding=False, " \
         "extended_addr=0x22, extended_rx_addr=0x11, basecls=ISOTP)"
    s2 = "ISOTPSocket(can0, sid=0x1ffff603, did=0x1ffff703, padding=False, " \
         "extended_addr=0x22, extended_rx_addr=0x11, basecls=ISOTP)"
    print(result)
    assert s1 in result
    assert s2 in result


def test_isotpscan_none(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x700 + i, did=0x600 + i) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    def make_noise(p):
        with new_can_socket0() as s:
            for _ in range(20):
                s.send(p)
                time.sleep(0.021)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))

    thread1 = threading.Thread(target=isotpserver, args=(2,))
    thread2 = threading.Thread(target=isotpserver, args=(3,))
    thread1.start()
    thread2.start()

    semaphore.acquire()
    semaphore.acquire()

    with new_can_socket0() as socks_interface:
        thread_noise.start()

        with new_can_socket0() as scansock:
            result = ISOTPScan(scansock, range(0x5ff, 0x603 + 1),
                               can_interface=socks_interface,
                               sniff_time=sniff_time,
                               noise_listen_time=0.31,
                               verbose=True)

        result = sorted(result, key=lambda x: x.src)

        with new_can_socket0() as cans:
            cans.send(CAN(identifier=0x601, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x602, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x603, data=b'\x01\xaa'))

            for s in result:
                # This helps to close ISOTPSoftSockets
                cans.send(CAN(identifier=0x702, data=b'\x01\xaa'))
                cans.send(CAN(identifier=0x703, data=b'\x01\xaa'))
                s.close()
                cans.send(CAN(identifier=0x702, data=b'\x01\xaa'))
                cans.send(CAN(identifier=0x703, data=b'\x01\xaa'))
                time.sleep(0)

            thread1.join(timeout=10)
            thread2.join(timeout=10)
            thread_noise.join(timeout=10)

    assert len(result) == 2
    assert 0x602 == result[0].src
    assert 0x702 == result[0].dst
    assert 0x603 == result[1].src
    assert 0x703 == result[1].dst

    for s in result:
        del s


def test_isotpscan_none_2(sniff_time=0.02):
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, ISOTPSocket(isocan, sid=0x700 + i,
                                                      did=0x600 + i) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))

    thread1 = threading.Thread(target=isotpserver, args=(9,))
    thread2 = threading.Thread(target=isotpserver, args=(8,))
    thread1.start()
    thread2.start()

    semaphore.acquire()
    semaphore.acquire()
    thread_noise.start()

    with new_can_socket0() as socks_interface:
        with new_can_socket0() as scansock:
            result = ISOTPScan(scansock, range(0x607, 0x6A0),
                               can_interface=socks_interface,
                               sniff_time=sniff_time,
                               noise_listen_time=0.31,
                               verbose=True)

        result = sorted(result, key=lambda x: x.src)

        with new_can_socket0() as cans:
            cans.send(CAN(identifier=0x609, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x608, data=b'\x01\xaa'))

            for s in result:
                # This helps to close ISOTPSoftSockets
                cans.send(CAN(identifier=0x709, data=b'\x01\xaa'))
                cans.send(CAN(identifier=0x708, data=b'\x01\xaa'))
                s.close()
                time.sleep(0)
                cans.send(CAN(identifier=0x709, data=b'\x01\xaa'))
                cans.send(CAN(identifier=0x708, data=b'\x01\xaa'))

            thread1.join(timeout=10)
            thread2.join(timeout=10)
            thread_noise.join(timeout=10)

    assert len(result) == 2
    assert 0x608 == result[0].src
    assert 0x708 == result[0].dst
    assert 0x609 == result[1].src
    assert 0x709 == result[1].dst

    for s in result:
        del s


def test_extended_isotpscan_none(sniff_time=0.02):

    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x700 + i, did=0x600 + i,
                            extended_addr=0x11, extended_rx_addr=0x22) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))

    thread1 = threading.Thread(target=isotpserver, args=(2,))
    thread2 = threading.Thread(target=isotpserver, args=(3,))
    thread1.start()
    thread2.start()

    semaphore.acquire()
    semaphore.acquire()

    with new_can_socket0() as socks_interface:
        thread_noise.start()

        with new_can_socket0() as scansock:
            result = ISOTPScan(scansock, range(0x5ff, 0x603 + 1),
                               extended_addressing=True,
                               can_interface=socks_interface,
                               sniff_time=sniff_time,
                               noise_listen_time=0.31)

        result = sorted(result, key=lambda x: x.src)

        with new_can_socket0() as cans:
            cans.send(CAN(identifier=0x602, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x603, data=b'\x01\xaa'))
            time.sleep(0.00)
            cans.send(CAN(identifier=0x602, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x603, data=b'\x01\xaa'))
            time.sleep(0.00)
            cans.send(CAN(identifier=0x602, data=b'\x01\xaa'))
            cans.send(CAN(identifier=0x603, data=b'\x01\xaa'))

            for s in result:
                # This helps to close ISOTPSoftSockets
                cans.send(CAN(identifier=0x702, data=b'\x11\x01\xaa'))
                cans.send(CAN(identifier=0x703, data=b'\x11\x01\xaa'))
                s.close()
                time.sleep(0)
                cans.send(CAN(identifier=0x702, data=b'\x11\x01\xaa'))
                cans.send(CAN(identifier=0x703, data=b'\x11\x01\xaa'))

        thread1.join(timeout=10)
        thread2.join(timeout=10)
        thread_noise.join(timeout=10)

    assert len(result) == 2
    assert 0x602 == result[0].src
    assert 0x702 == result[0].dst
    assert 0x22 == result[0].exsrc
    assert 0x11 == result[0].exdst
    assert 0x603 == result[1].src
    assert 0x703 == result[1].dst
    assert 0x22 == result[1].exsrc
    assert 0x11 == result[1].exdst

    for s in result:
        del s


def test_isotpscan_none_random_ids(sniff_time=0.02):
    rnd = RandNum(0x1, 0x100)
    ids = set(rnd._fix() for _ in range(10))

    print(ids)

    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x100 + i, did=i) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt,))

    threads = [threading.Thread(target=isotpserver, args=(x,)) for x in ids]
    [t.start() for t in threads]

    for _ in range(len(threads)):
        semaphore.acquire()

    with new_can_socket0() as socks_interface:
        thread_noise.start()

        with new_can_socket0() as scansock:
            result = ISOTPScan(scansock, range(0x000, 0x101),
                               can_interface=socks_interface,
                               noise_listen_time=0.31,
                               sniff_time=sniff_time,
                               verbose=True)

            result = sorted(result, key=lambda x: x.src)

        with new_can_socket0() as cans:
            for i in ids:
                # This helps to close ISOTPSoftSockets
                cans.send(CAN(identifier=i, data=b'\x01\xaa'))
                time.sleep(0)
                cans.send(CAN(identifier=i, data=b'\x01\xaa'))

            for s in result:
                # This helps to close ISOTPSoftSockets
                cans.send(CAN(identifier=s.dst, data=b'\x01\xaa'))
                cans.send(CAN(identifier=s.src, data=b'\x01\xaa'))
                s.close()
                time.sleep(0)
                cans.send(CAN(identifier=s.dst, data=b'\x01\xaa'))
                cans.send(CAN(identifier=s.src, data=b'\x01\xaa'))
            [t.join(timeout=10) for t in threads]
            thread_noise.join(timeout=10)

    assert len(result) == len(ids)
    ids = sorted(ids)
    for i, s in zip(ids, result):
        assert i == s.src
        assert i + 0x100 == s.dst

    for s in result:
        del s


def test_isotpscan_none_random_ids_padding(sniff_time=0.02):
    rnd = RandNum(0x1, 0x100)
    ids = set(rnd._fix() for _ in range(10))
    semaphore = threading.Semaphore(0)

    def isotpserver(i):
        with new_can_socket0() as isocan, \
                ISOTPSocket(isocan, sid=0x100 + i, did=i, padding=True) as s:
            s.sniff(timeout=60, count=1, started_callback=semaphore.release)

    pkt = CAN(identifier=0x701, length=8,
              data=b'\x01\x02\x03\x04\x05\x06\x07\x08')
    thread_noise = threading.Thread(target=make_noise, args=(pkt, ))

    threads = [threading.Thread(target=isotpserver, args=(x,)) for x in ids]
    [t.start() for t in threads]

    for _ in range(len(threads)):
        semaphore.acquire()

    with new_can_socket0() as socks_interface:
        thread_noise.start()

        with new_can_socket0() as scansock:
            result = ISOTPScan(scansock, range(0x000, 0x101),
                               can_interface=socks_interface,
                               noise_listen_time=0.31,
                               sniff_time=sniff_time, verbose=True)

            result = sorted(result, key=lambda x: x.src)

        with new_can_socket0() as cans:
            for i in ids:
                # This helps to close ISOTPSoftSockets
                cans.send(CAN(identifier=i, data=b'\x01\xaa'))
                time.sleep(0)
                cans.send(CAN(identifier=i, data=b'\x01\xaa'))

            for s in result:
                # This helps to close ISOTPSoftSockets
                cans.send(CAN(identifier=s.dst, data=b'\x01\xaa'))
                cans.send(CAN(identifier=s.src, data=b'\x01\xaa'))
                s.close()
                cans.send(CAN(identifier=s.dst, data=b'\x01\xaa'))
                cans.send(CAN(identifier=s.src, data=b'\x01\xaa'))
                time.sleep(0)

        [t.join(timeout=10) for t in threads]
        thread_noise.join(timeout=10)

    assert len(result) == len(ids)
    ids = sorted(ids)
    for i, s in zip(ids, result):
        assert i == s.src
        assert i + 0x100 == s.dst
        if isinstance(s, ISOTPSoftSocket):
            assert s.impl.padding is True

    for s in result:
        del s
