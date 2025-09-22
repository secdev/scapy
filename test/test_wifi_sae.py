import pytest

from scapy.layers.dot11 import Dot11Auth
from scapy.contrib.wifi_sae import (
    sae_commit_frame, sae_confirm_frame,
    is_sae_auth, sae_is_commit, sae_is_confirm, get_sae_payload,
)

STA = "00:11:22:33:44:55"
AP = "66:77:88:99:aa:bb"
BSSID = AP

def test_sae_commit_and_confirm_helpers():
    payload = b"\x01\x02\x03"
    cmt = sae_commit_frame(src=STA, dst=AP, bssid=BSSID, payload=payload, add_radiotap=False)
    cnf = sae_confirm_frame(src=AP, dst=STA, bssid=BSSID, payload=b"\x04", add_radiotap=False)

    assert is_sae_auth(cmt)
    assert sae_is_commit(cmt)
    assert not sae_is_confirm(cmt)
    assert get_sae_payload(cmt) == payload

    assert is_sae_auth(cnf)
    assert not sae_is_commit(cnf)
    assert sae_is_confirm(cnf)
    assert get_sae_payload(cnf) == b"\x04"

    # Double-check Dot11Auth fields are correct
    a = cmt.getlayer(Dot11Auth)
    assert a.algo == 8 and a.seqnum == 1 and a.status == 0
