# SPDX-License-Identifier: GPL-2.0-or-later
from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap
from scapy.modules.wifi_sae import (
    sae_commit_frame, sae_confirm_frame,
    is_sae_auth, sae_is_commit, sae_is_confirm, get_sae_payload,
    AUTH_ALGO_SAE
)

STA = "02:00:00:00:00:01"
AP  = "02:00:00:00:aa:bb"
BSS = AP

def test_sae_commit_builder_fields():
    payload = b"\x00\x13\x01\x02"  # arbitrary bytes
    pkt = sae_commit_frame(src=STA, dst=AP, bssid=BSS, payload=payload, add_radiotap=False)
    assert pkt[Dot11].type == 0
    assert pkt[Dot11].subtype == 11
    assert pkt[Dot11].addr1 == AP
    assert pkt[Dot11].addr2 == STA
    assert pkt[Dot11].addr3 == BSS
    assert pkt[Dot11Auth].algo == AUTH_ALGO_SAE
    assert pkt[Dot11Auth].seqnum == 1
    assert get_sae_payload(pkt) == payload

def test_sae_confirm_builder_fields():
    payload = b"\xab\xcd\xef"
    pkt = sae_confirm_frame(src=AP, dst=STA, bssid=BSS, payload=payload, add_radiotap=False)
    assert pkt[Dot11].addr1 == STA
    assert pkt[Dot11].addr2 == AP
    assert pkt[Dot11].addr3 == BSS
    assert pkt[Dot11Auth].algo == AUTH_ALGO_SAE
    assert pkt[Dot11Auth].seqnum == 2
    assert get_sae_payload(pkt) == payload

def test_predicates_and_payload():
    c_payload = b"\x01" * 8
    f_payload = b"\x02" * 16
    c = sae_commit_frame(STA, AP, BSS, c_payload, add_radiotap=True)
    f = sae_confirm_frame(AP, STA, BSS, f_payload, add_radiotap=True)

    assert is_sae_auth(c)
    assert sae_is_commit(c)
    assert not sae_is_confirm(c)
    assert get_sae_payload(c) == c_payload

    assert is_sae_auth(f)
    assert sae_is_confirm(f)
    assert not sae_is_commit(f)
    assert get_sae_payload(f) == f_payload
