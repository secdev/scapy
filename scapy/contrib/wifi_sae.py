# SPDX-License-Identifier: GPL-2.0-or-later
"""
wifi_sae: WPA3/SAE (802.11-2016/2020) helpers.

These helpers craft & recognize SAE Authentication frames without
implementing SAE crypto. They rely on Dot11Auth(algo=8) with seqnum:
  - 1: SAE Commit
  - 2: SAE Confirm

They are intentionally light-weight and avoid touching hot dissector paths.
"""

from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap
from scapy.packet import Raw

# 802.11 Authentication Algorithm Numbers (subset)
AUTH_ALGO_OPEN = 0
AUTH_ALGO_SAE = 8  # WPA3 SAE

# 802.11 Management subtype for Authentication frames
DOT11_TYPE_MGMT = 0
DOT11_SUBTYPE_AUTH = 11


def _mk_dot11(dst, src, bssid):
    """
    Build a Dot11 header for a mgmt Authentication exchange:
    - STA -> AP: addr1=AP(dst), addr2=STA(src), addr3=BSSID(AP)
    - AP  -> STA: addr1=STA(dst), addr2=AP(src), addr3=BSSID(AP)
    """
    return Dot11(
        type=DOT11_TYPE_MGMT,
        subtype=DOT11_SUBTYPE_AUTH,
        addr1=dst,
        addr2=src,
        addr3=bssid,
    )


def _wrap_radiotap(pkt, add_radiotap):
    return RadioTap() / pkt if add_radiotap else pkt


def _attach_payload(pkt, payload):
    """Attach raw SAE bytes as packet payload (works across Scapy versions)."""
    if payload:
        return pkt / Raw(payload)
    return pkt


def sae_commit_frame(src, dst, bssid, payload=b"", *, add_radiotap=True):
    """
    Build a WPA3/SAE *Commit* Authentication frame.
    """
    dot11 = _mk_dot11(dst, src, bssid)
    auth = Dot11Auth(algo=AUTH_ALGO_SAE, seqnum=1, status=0)
    return _wrap_radiotap(_attach_payload(dot11 / auth, payload), add_radiotap)


def sae_confirm_frame(src, dst, bssid, payload=b"", *, add_radiotap=True):
    """
    Build a WPA3/SAE *Confirm* Authentication frame.
    """
    dot11 = _mk_dot11(dst, src, bssid)
    auth = Dot11Auth(algo=AUTH_ALGO_SAE, seqnum=2, status=0)
    return _wrap_radiotap(_attach_payload(dot11 / auth, payload), add_radiotap)


def is_sae_auth(pkt):
    """Return True if packet is an 802.11 Authentication using SAE (algo=8)."""
    a = pkt.getlayer(Dot11Auth)
    return bool(a and a.algo == AUTH_ALGO_SAE)


def sae_is_commit(pkt):
    """Return True if SAE Authentication with seqnum == 1 (Commit)."""
    a = pkt.getlayer(Dot11Auth)
    return bool(a and a.algo == AUTH_ALGO_SAE and a.seqnum == 1)


def sae_is_confirm(pkt):
    """Return True if SAE Authentication with seqnum == 2 (Confirm)."""
    a = pkt.getlayer(Dot11Auth)
    return bool(a and a.algo == AUTH_ALGO_SAE and a.seqnum == 2)


def get_sae_payload(pkt):
    """
    Return the raw SAE payload bytes, or b"" if not present/not SAE.

    We read bytes from the Dot11Auth payload, which is version-agnostic:
    some Scapy versions expose an `info` field, others expect extra bytes
    as a raw payload.
    """
    a = pkt.getlayer(Dot11Auth)
    if not a or a.algo != AUTH_ALGO_SAE:
        return b""
    try:
        return bytes(a.payload) if a.payload else b""
    except Exception:
        return b""
