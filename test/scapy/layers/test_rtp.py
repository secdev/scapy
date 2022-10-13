import pytest
from scapy.all import *


@pytest.mark.rtp
def test_rtpwithextensionheader():
    """
    test rtp with extension header 
    """
    data = b'\x90o\x14~YY\xf5h\xcc#\xd7\xcfUH\x00\x03\x167116621 \x000\x00'
    pkt = RTP(data)
    assert "RTP" in pkt
    parsed = pkt["RTP"]
    assert parsed.version == 2
    assert parsed.extension
    assert parsed.numsync == 0
    assert not parsed.marker
    assert parsed.payload_type == 111
    assert parsed.sequence == 5246
    assert parsed.timestamp == 1499067752
    assert parsed.sourcesync == 0xcc23d7cf
    assert "RTPExtension" in parsed, parsed.show()
    assert parsed["RTPExtension"].header_id == 0x5548
    assert parsed["RTPExtension"].header == [0x16373131, 0x36363231,
                                             0x20003000]


@pytest.mark.rtp
def test_layercreation():
    """
    test layer creation 
    """
    created = RTP(extension=True, payload_type="PCMA", sequence=0x1234,
                  timestamp=12345678, sourcesync=0xabcdef01)
    created /= RTPExtension(header_id=0x4321, header=[0x11223344])
    assert raw(
        created) == b'\x90\x08\x124\x00\xbcaN\xab\xcd\xef\x01C!\x00\x01\x11"3D'
    parsed = RTP(raw(created))
    assert parsed.payload_type == 8
    assert "RTPExtension" in parsed, parsed.show()
    assert parsed["RTPExtension"].header == [0x11223344]


@pytest.mark.rtp
def test_RTPwithoutextension():
    """
    test RTP without extension 
    """
    created = RTP(extension=False, payload_type="DVI4", sequence=0x1234,
                  timestamp=12345678, sourcesync=0xabcdef01)
    assert raw(created) == b'\x80\x11\x124\x00\xbcaN\xab\xcd\xef\x01'
    parsed = RTP(raw(created))
    assert parsed.sourcesync == 0xabcdef01
    assert "RTPExtension" not in parsed
