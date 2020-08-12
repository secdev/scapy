from __future__ import print_function

import pytest
from scapy.all import load_module, IP, UDP, raw, ICMP, IPerror, UDPerror, \
    TCP, conf

import re as re_
import os

from scapy.modules.nmap import nmap_udppacket_sig, nmap_tcppacket_sig, \
    nmap_kdb, nmap_fp, nmap_sig2txt, nmap_sig


def test_Moduleloading():
    """
    Module loading
    """
    load_module('nmap')


def test_Testfunctions():
    """
    Test functions
    """
    d = nmap_udppacket_sig(
        IP() / UDP(),
        IP(raw(IP() / ICMP(type=3, code=2) / IPerror() / UDPerror())))

    assert len(d) == 9
    d = nmap_tcppacket_sig(IP() / TCP())
    assert len(d) == 5


@pytest.mark.netaccess
def test_Fetchdatabase():
    """
    Fetch database
    """
    try:
        from urllib.request import urlopen
    except ImportError:
        from urllib2 import urlopen

    url = 'https://raw.githubusercontent.com/nmap/nmap/9efe1892/nmap-os-fingerprints'  # noqa: E501

    for i in range(10):
        try:
            open('nmap-os-fingerprints', 'wb').write(urlopen(url).read())
            break
        except Exception:
            pass

    conf.nmap_base = 'nmap-os-fingerprints'


@pytest.mark.netaccess
def test_Databaseloading():
    """
    Database loading
    """
    assert len(nmap_kdb.get_base()) > 100


@pytest.mark.netaccess
def test_fingerprinttestwwwsecdevorg():
    """
    fingerprint test: www.secdev.org
    """
    score, fprint = nmap_fp('www.secdev.org')
    print(score, fprint)

    assert score > 0.5
    assert fprint


@pytest.mark.netaccess
def test_fingerprinttestgateway():
    """
    fingerprint test: gateway
    """
    score, fprint = nmap_fp(conf.route.route('0.0.0.0')[2])
    print(score, fprint)

    assert score > 0.5
    assert fprint


@pytest.mark.netaccess
def test_fingerprinttesttotext():
    """
    fingerprint test: to text
    """
    a = nmap_sig("www.secdev.org", 80, 81)

    for x in nmap_sig2txt(a).split("\n"):
        assert re_.match(r"\w{2,4}\(.*\)", x)


@pytest.mark.netaccess
def test_nmapudppacketsigtestwwwgooglecom():
    """
    nmap_udppacket_sig test: www.google.com
    """
    a = nmap_sig("www.google.com", ucport=80)

    assert len(a) > 3
    assert len(a["PU"]) > 0


def test_Nmapbasenotavailable():
    """
    Nmap base not available
    """
    nmap_kdb.filename = "invalid"
    nmap_kdb.reload()

    assert nmap_kdb.filename is None


def test_Cleartempfiles():
    """
    Clear temp files
    """
    try:
        os.remove('nmap-os-fingerprints')
    except Exception:
        pass
