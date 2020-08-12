import pytest
from scapy.all import load_layer, rdpcap, six, Raw, raw, conf
import mock

from scapy.layers.usb import USBpcap, USBpcapTransferControl, \
    USBpcapTransferIsochronous, USBpcapTransferInterrupt


def test_loadmodule():
    """
    load module
    """
    load_layer("usb")


class Bunch:
    __init__ = lambda self, **kw: setattr(self, '__dict__', kw)


def test_linklayertest():
    """
    linklayer test
    """
    data = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00" \
           b"\x00\xff\xff\x00\x00\xf9\x00\x00\x00\xb6\xaau[B\xd7\n\x00'\x00" \
           b"\x00\x00'\x00\x00\x00\x1b\x00\x008\xeeM\n\x97\xff\xff\x00\x00" \
           b"\x00\x00\t\x00\x01\x01\x00\x04\x00\x81\x01\x0c\x00\x00\x00\x01" \
           b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbd\xaau[\xdc\x88" \
           b"\x0c\x00$\x00\x00\x00$\x00\x00\x00\x1c\x000g4K\n\x97\xff\xff" \
           b"\x00\x00\x00\x00\x0b\x00\x00\x01\x00\x05\x00\x00\x02\x08\x00" \
           b"\x00\x00\x00\x80\x06\x00\x01\x00\x00\x12\x00\xbd\xaau[}\xa7\x0c" \
           b"\x00.\x00\x00\x00.\x00\x00\x00\x1c\x000g4K\n\x97\xff\xff\x00" \
           b"\x00\x00\x00\x0b\x00\x01\x01\x00\x05\x00\x00\x02\x12\x00\x00" \
           b"\x00\x01\x12\x01\x10\x02\x00\x00\x00@^\x04\xe8\x07\x07\x02\x01" \
           b"\x02\x00\x01\xbd\xaau[\x7f\xa7\x0c\x00\x1c\x00\x00\x00\x1c\x00" \
           b"\x00\x00\x1c\x000g4K\n\x97\xff\xff\x00\x00\x00\x00\x0b\x00\x01" \
           b"\x01\x00\x05\x00\x00\x02\x00\x00\x00\x00\x02\xbd\xaau[\x8d\xa7" \
           b"\x0c\x00$\x00\x00\x00$\x00\x00\x00\x1c\x00\x10\xe0\x98J\n\x97" \
           b"\xff\xff\x00\x00\x00\x00\x0b\x00\x00\x01\x00\x05\x00\x00\x02" \
           b"\x08\x00\x00\x00\x00\x80\x06\x00\x02\x00\x00\t\x00"

    pcap = rdpcap(six.BytesIO(data))
    pkt1 = USBpcap(function=9, info=1, endpoint=129, res=0, transfer=1,
                   usbd_status=0, dataLength=12, bus=1, device=4,
                   irpId=18446628669245765632, headerLen=27) / Raw(
        load=b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    assert raw(pcap[0]) == raw(pkt1)
    assert isinstance(pcap[0], USBpcap)

    pkt2 = USBpcap(
        function=11, info=0, endpoint=0, res=0, transfer=2, usbd_status=0,
        dataLength=8, bus=1, device=5, irpId=18446628669200033584,
        headerLen=28) / USBpcapTransferControl(stage=0) / Raw(
        load=b'\x80\x06\x00\x01\x00\x00\x12\x00')

    assert raw(pcap[1]) == raw(pkt2)
    assert USBpcap in pcap[1]
    assert USBpcapTransferControl in pcap[1]


def test_USBpcapTransferIsochronous():
    """
    USBpcapTransferIsochronous
    """
    pkt = USBpcap(
        irpId=0x359275, function=0x1235, info=10,
        bus=35) / USBpcapTransferIsochronous(usbd_status=0x40000000)

    assert raw(pkt) == b"'\x00u\x925\x00\x00\x00\x00\x00\x00\x00\x00\x005" \
                       b"\x12\n#\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00" \
                       b"\x00\x00\x00\x00\x00\x00\x00\x00\x00@"


def test_USBpcapTransferInterrupt():
    """
    USBpcapTransferInterrupt
    """
    pkt = USBpcap(irpId=0x359275, function=0x1235, info=10,
                  bus=35) / USBpcapTransferInterrupt(
        startFrame=0x40000000, numberOfPackets=0x80000000, errorCount=2)
    assert raw(pkt) == b"'\x00u\x925\x00\x00\x00\x00\x00\x00\x00\x00\x005" \
                       b"\x12\n#\x00\x00\x00\x00\x01\x0c\x00\x00\x00\x00" \
                       b"\x00\x00@\x00\x00\x00\x80\x02\x00\x00\x00"


def test_USBpcapTransferControl():
    """
    USBpcapTransferControl
    """
    pkt = USBpcap(irpId=0x359275, function=0x1235, info=10,
                  bus=35) / USBpcapTransferControl(stage=11)
    assert raw(pkt) == b'\x1c\x00u\x925\x00\x00\x00\x00\x00\x00\x00\x00\x005' \
                       b'\x12\n#\x00\x00\x00\x00\x02\x01\x00\x00\x00\x0b'


@pytest.mark.windows
def test_mockedgetusbpcapinterfaces():
    """
    mocked get_usbpcap_interfaces()
    """
    from scapy.layers.usb import get_usbpcap_interfaces  # noqa: E501, F401

    @mock.patch("scapy.layers.usb.subprocess.Popen")
    def test_get_usbpcap_interfaces(mock_Popen):
        conf.prog.usbpcapcmd = "C:/the_program_is_not_installed__test_only"
        data = """
    interface {value=\\\\.\\USBPcap1}{display=USBPcap1}
    """
        mock_Popen.side_effect = lambda *args, **kwargs: Bunch(
            returncode=0, communicate=(lambda *args, **kargs: (data, None)))
        assert get_usbpcap_interfaces() == [('\\\\.\\USBPcap1', 'USBPcap1')]

    test_get_usbpcap_interfaces()


@pytest.mark.windows
def test_mockedgetusbpcapdevices():
    """
    mocked get_usbpcap_devices()
    """
    from scapy.layers.usb import get_usbpcap_devices  # noqa: E501, F401

    @mock.patch("scapy.layers.usb.subprocess.Popen")
    def test_get_usbpcap_devices(mock_Popen):
        conf.prog.usbpcapcmd = "C:/the_program_is_not_installed__test_only"
        data = """
    arg {number=0}{call=--snaplen}{display=Snapshot length}{tooltip=Snapshot length}{type=integer}{range=0,65535}{default=65535}
    arg {number=1}{call=--bufferlen}{display=Capture buffer length}{tooltip=USBPcap kernel-mode capture buffer length in bytes}{type=integer}{range=0,134217728}{default=1048576}
    arg {number=2}{call=--capture-from-all-devices}{display=Capture from all devices connected}{tooltip=Capture from all devices connected despite other options}{type=boolflag}{default=true}
    arg {number=3}{call=--capture-from-new-devices}{display=Capture from newly connected devices}{tooltip=Automatically start capture on all newly connected devices}{type=boolflag}{default=true}
    arg {number=99}{call=--devices}{display=Attached USB Devices}{tooltip=Select individual devices to capture from}{type=multicheck}
    value {arg=99}{value=2}{display=[2] Marvell AVASTAR Bluetooth Radio Adapter}{enabled=true}
    value {arg=99}{value=3}{display=[3] Peripherique d entree USB}{enabled=true}
    value {arg=99}{value=3_1}{display=Surface Type Cover Filter Device}{enabled=false}{parent=3}
    value {arg=99}{value=3_2}{display=Souris HID}{enabled=false}{parent=3}
    value {arg=99}{value=3_3}{display=Peripherique de control consommateur conforme aux Peripheriques d'interface utilisateur (HID)}{enabled=false}{parent=3}
    value {arg=99}{value=3_4}{display=Surface Pro 4 Type Cover Integration}{enabled=false}{parent=3}
    value {arg=99}{value=3_5}{display=Surface Keyboard Backlight}{enabled=false}{parent=3_4}
    value {arg=99}{value=3_6}{display=Surface Pro 4 Firmware Update}{enabled=false}{parent=3_4}
    value {arg=99}{value=3_7}{display=Peripherique fournisseur HID}{enabled=false}{parent=3}
    value {arg=99}{value=3_8}{display=Surface PTP Filter}{enabled=false}{parent=3}
    value {arg=99}{value=3_9}{display=Microsoft Input Configuration Device}{enabled=false}{parent=3}
    value {arg=99}{value=3_10}{display=Peripherique fournisseur HID}{enabled=false}{parent=3}
    value {arg=99}{value=3_11}{display=Peripherique fournisseur HID}{enabled=false}{parent=3}
    value {arg=99}{value=3_12}{display=Peripherique fournisseur HID}{enabled=false}{parent=3}
    """  # noqa: E501

        mock_Popen.side_effect = lambda *args, **kwargs: Bunch(
            returncode=0, communicate=(lambda *args, **kargs: (data, None)))
        assert get_usbpcap_devices('\\\\.\\USBPcap1') == [
            ('2', '[2] Marvell AVASTAR Bluetooth Radio Adapter', True),
            ('3', '[3] Peripherique d entree USB', True)]

    test_get_usbpcap_devices()
