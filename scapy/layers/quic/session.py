# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2025 Jackson Sippe

"""
QUIC session handler.
"""

import socket
import struct

from scapy.config import conf
from scapy.error import log_runtime
from scapy.packet import Packet
from scapy.pton_ntop import inet_pton
from scapy.layers.inet import UDP
from scapy.layers.tls.session import tlsSession

class quicSession(tlsSession):
    """
    QUIC session handler.
    This class is used to manage QUIC sessions, including handling
    QUIC packets and frames.

    For now, it extends the tlsSession class as QUIC currently
    uses TLS 1.3. In the future, it may be extended to modern
    transport security protocols.
    """

    def __init__(self, ipsrc=None, ipdst=None,
                 sport=None, dport=None,
                  connection_end="server",
                   wcs=None, rcs=None):
        super().__init__(ipsrc=ipsrc, ipdst=ipdst,
                         sport=sport, dport=dport,
                         connection_end=connection_end,
                         wcs=wcs, rcs=rcs)
        # Initialize any additional attributes for QUIC session management
    
        # Get infos from underlayer

    def set_underlayer(self, _underlayer):
        if isinstance(_underlayer, UDP):
            udp = _underlayer
            self.sport = udp.sport
            self.dport = udp.dport
            try:
                self.ipsrc = udp.underlayer.src
                self.ipdst = udp.underlayer.dst
            except AttributeError:
                pass

class _GenericQUICSessionInheritance(Packet):
    """
    This class is used to inherit from the QUIC session class
    without directly extending it. It allows for generic handling
    of QUIC sessions.
    """
    __slots__ = ["quic_session"]
    name = "Dummy Generic QUIC Packet"
    fields_desc = []  # Define any fields if necessary

    def __init__(self, _pkt="", post_transform=None, _internal=0,
                 _underlayer=None, quic_session=None, **fields):
        try:
            setme = self.quic_session is None
        except Exception:
            setme = True
        newses = False
        if setme:
            if quic_session is None:
                newses = True
                self.quic_session = quicSession()
            else:
                self.quic_session = quic_session
        
        # self.rcs_snap_init = self.quic_session.rcs.snapshot()
        # self.wcs_snap_init = self.quic_session.wcs.snapshot()

        if isinstance(_underlayer, UDP):
            self.quic_session.set_underlayer(_underlayer)

            if conf.quic_session_enable:
                if newses:
                    s = conf.quic_sessions.find(self.quic_session)
                    if s:
                        if s.dport == self.quic_session.dport:
                            self.quic_session = s
                        else:
                            self.quic_session = s.mirror()
                    else:
                        conf.quic_sessions.add(self.quic_session)

        Packet.__init__(self, _pkt=_pkt, post_transform=post_transform,
                        _internal=_internal, _underlayer=_underlayer,
                        **fields)

    

class _quic_sessions(object):
    def __init__(self):
        self.sessions = {}
    
    def add(self, session):
        s = self.find(session)
        if s:
            log_runtime.info("QUIC: previous session shall not be overwritten")
            return
        
        h = session.hash()
        if h in self.sessions:
            self.sessions[h].append(session)
        else:
            self.sessions[h] = [session]
    
    def find(self, session):
        try:
            h = session.hash()
        except Exception:
            return None
        if h in self.sessions:
            for k in self.sessions[h]:
                if k.eq(session):
                    if conf.debug_quic:
                        log_runtime.info("QUIC: found session matching %s", k)
                    return k
        if conf.debug_quic:
            log_runtime.info("QUIC: did not find session matching %s", session)
        return None

conf.quic_sessions = _quic_sessions()