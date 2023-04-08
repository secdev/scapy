# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Leonard Crestez <cdleonard@gmail.com>

# scapy.contrib.description = TCP-AO Signature Calculation
# scapy.contrib.status = loads

"""Packet-processing utilities implementing RFC5925 and RFC5926"""

import logging
from scapy.compat import orb
from scapy.layers.inet import IP, TCP
from scapy.layers.inet import tcp_pseudoheader
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.pton_ntop import inet_pton
import socket
import struct

from typing import (
    Union,
)

logger = logging.getLogger(__name__)


def _hmac_sha1_digest(key, msg):
    # type: (bytes, bytes) -> bytes
    import hmac
    import hashlib

    return hmac.new(key, msg, hashlib.sha1).digest()


def _cmac_aes_digest(key, msg):
    # type: (bytes, bytes) -> bytes
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.backends import default_backend

    backend = default_backend()
    c = cmac.CMAC(algorithms.AES(key), backend=backend)
    c.update(bytes(msg))
    return c.finalize()


class TCPAOAlg:
    @classmethod
    def kdf(cls, master_key, context):
        # type: (bytes, bytes) -> bytes
        raise NotImplementedError()

    @classmethod
    def mac(cls, traffic_key, context):
        # type: (bytes, bytes) -> bytes
        raise NotImplementedError()

    maclen = -1


class TCPAOAlg_HMAC_SHA1(TCPAOAlg):
    @classmethod
    def kdf(cls, master_key, context):
        # type: (bytes, bytes) -> bytes
        input = b"\x01" + b"TCP-AO" + context + b"\x00\xa0"
        return _hmac_sha1_digest(master_key, input)

    @classmethod
    def mac(cls, traffic_key, message):
        # type: (bytes, bytes) -> bytes
        return _hmac_sha1_digest(traffic_key, message)[:12]

    maclen = 12


class TCPAOAlg_CMAC_AES(TCPAOAlg):
    @classmethod
    def kdf(self, master_key, context):
        # type: (bytes, bytes) -> bytes
        if len(master_key) == 16:
            key = master_key
        else:
            key = _cmac_aes_digest(b"\x00" * 16, master_key)
        return _cmac_aes_digest(key, b"\x01TCP-AO" + context + b"\x00\x80")

    @classmethod
    def mac(self, traffic_key, message):
        # type: (bytes, bytes) -> bytes
        return _cmac_aes_digest(traffic_key, message)[:12]

    maclen = 12


def get_alg(name):
    # type: (str) -> TCPAOAlg
    if name.upper() == "HMAC-SHA-1-96":
        return TCPAOAlg_HMAC_SHA1()
    elif name.upper() == "AES-128-CMAC-96":
        return TCPAOAlg_CMAC_AES()
    else:
        raise ValueError("Bad TCP AuthOpt algorithms {}".format(name))


def _get_ipvx_src(u):
    # type: (Union[IP, IPv6]) -> bytes
    if isinstance(u, IP):
        return inet_pton(socket.AF_INET, u.src)
    elif isinstance(u, IPv6):
        return inet_pton(socket.AF_INET6, u.src)
    else:
        raise Exception("Neither IP nor IPv6 found on packet")


def _get_ipvx_dst(u):
    # type: (Union[IP, IPv6]) -> bytes
    if isinstance(u, IP):
        return inet_pton(socket.AF_INET, u.dst)
    elif isinstance(u, IPv6):
        return inet_pton(socket.AF_INET6, u.dst)
    else:
        raise Exception("Neither IP nor IPv6 found on packet")


def build_context(
    saddr,  # type: bytes
    daddr,  # type: bytes
    sport,  # type: int
    dport,  # type: int
    src_isn,  # type: int
    dst_isn,  # type: int
):
    # type: (...) -> bytes
    """Build context bytes as specified by RFC5925 section 5.2"""
    if len(saddr) != len(daddr) or (len(saddr) != 4 and len(saddr) != 16):
        raise ValueError("saddr and daddr must be 4-byte or 16-byte addresses")
    return (
        saddr +
        daddr +
        struct.pack(
            "!HHII",
            sport,
            dport,
            src_isn,
            dst_isn,
        )
    )


def build_context_from_packet(
    p,  # type: Packet
    src_isn,  # type: int
    dst_isn,  # type: int
):
    # type: (...) -> bytes
    """Build context bytes as specified by RFC5925 section 5.2"""
    tcp = p[TCP]
    return build_context(
        _get_ipvx_src(tcp.underlayer),
        _get_ipvx_dst(tcp.underlayer),
        tcp.sport,
        tcp.dport,
        src_isn,
        dst_isn,
    )


def build_message_from_packet(p, include_options=True, sne=0):
    # type: (Packet, bool, int) -> bytes
    """Build message bytes as described by RFC5925 section 5.1"""
    result = bytearray()
    result += struct.pack("!I", sne)
    result += tcp_pseudoheader(p[TCP])

    # tcp header with checksum set to zero
    th_bytes = bytes(p[TCP])
    result += th_bytes[:16]
    result += b"\x00\x00"
    result += th_bytes[18:20]

    # Even if include_options=False the TCP-AO option itself is still included
    # with the MAC set to all-zeros. This means we need to parse TCP options.
    pos = 20
    th = p[TCP]
    doff = th.dataofs
    if doff is None:
        opt_len = len(th.get_field("options").i2m(th, th.options))
        doff = 5 + ((opt_len + 3) // 4)
    tcphdr_optend = doff * 4
    while pos < tcphdr_optend:
        optnum = orb(th_bytes[pos])
        pos += 1
        if optnum == 0 or optnum == 1:
            if include_options:
                result += bytearray([optnum])
            continue

        optlen = orb(th_bytes[pos])
        pos += 1
        if pos + optlen - 2 > tcphdr_optend:
            logger.info("bad tcp option %d optlen %d beyond end-of-header",
                        optnum, optlen)
            break
        if optlen < 2:
            logger.info("bad tcp option %d optlen %d less than two",
                        optnum, optlen)
            break
        if optnum == 29:
            if optlen < 4:
                logger.info("bad tcp option %d optlen %d", optnum, optlen)
                break
            result += th_bytes[pos - 2: pos + 2]
            result += (optlen - 4) * b"\x00"
        elif include_options:
            result += th_bytes[pos - 2: pos + optlen - 2]
        pos += optlen - 2
    result += bytes(p[TCP].payload)
    return result


def calc_tcpao_traffic_key(p, alg, master_key, sisn, disn):
    # type: (Packet, TCPAOAlg, bytes, int, int) -> bytes
    """Calculate TCP-AO traffic-key from packet and initial sequence numbers

    This is constant for an established connection.
    """
    return alg.kdf(master_key, build_context_from_packet(p, sisn, disn))


def calc_tcpao_mac(p, alg, traffic_key, include_options=True, sne=0):
    # type: (Packet, TCPAOAlg, bytes, bool, int) -> bytes
    """Calculate TCP-AO MAC from packet and traffic key"""
    return alg.mac(traffic_key, build_message_from_packet(
        p, include_options=include_options, sne=sne
    ))


def sign_tcpao(
    p,
    alg,
    traffic_key,
    keyid=0,
    rnextkeyid=0,
    include_options=True,
    sne=0,
):
    # type: (Packet, TCPAOAlg, bytes, int, int, bool, int) -> None
    """Calculate TCP-AO option value and insert into packet"""
    th = p[TCP]
    keyids = struct.pack("BB", keyid, rnextkeyid)
    th.options = th.options + [('AO', keyids + alg.maclen * b"\x00")]
    message_bytes = calc_tcpao_mac(
        p, alg, traffic_key, include_options=include_options, sne=sne)
    mac = alg.mac(traffic_key, message_bytes)
    th.options[-1] = ('AO', keyids + mac)
