from scapy.contrib.http3 import H3Frame, H3_DATA, H3_SETTINGS, h3_parse_frames

def test_http3_data_roundtrip():
    f = H3Frame(type=H3_DATA, data=b"hello")
    raw = bytes(f)
    f2 = H3Frame(raw)
    assert f2.type == H3_DATA
    assert bytes(f2.data) == b"hello"

def test_http3_concat_and_parse():
    a = bytes(H3Frame(type=H3_SETTINGS, data=b"\x00"))
    b = bytes(H3Frame(type=H3_DATA, data=b"abc"))
    frames = h3_parse_frames(a + b)
    assert len(frames) == 2
    assert frames[0].type == H3_SETTINGS and bytes(frames[0].data) == b"\x00"
    assert frames[1].type == H3_DATA and bytes(frames[1].data) == b"abc"
