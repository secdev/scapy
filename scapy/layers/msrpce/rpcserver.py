# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
DCE/RPC server as per [MS-RPCE]
"""

import socket
import threading
from collections import deque

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.data import MTU
from scapy.volatile import RandShort

from scapy.layers.dcerpc import (
    DceRpc5,
    DceRpcSession,
    DceRpc5Bind,
    DceRpc5BindAck,
    DceRpc5BindNak,
    DceRpc5Auth3,
    DceRpc5AlterContext,
    DceRpc5AlterContextResp,
    DceRpc5Result,
    DceRpc5Request,
    DceRpc5Response,
    DceRpc5TransferSyntax,
    DceRpc5PortAny,
    CommonAuthVerifier,
    DCE_RPC_INTERFACES,
    DCERPC_Transport,
    RPC_C_AUTHN_LEVEL,
)

# RPC
from scapy.layers.msrpce.ept import (
    ept_map_Request,
    ept_map_Response,
    twr_p_t,
    protocol_tower_t,
    prot_and_addr_t,
)


class _DCERPC_Server_metaclass(type):
    def __new__(cls, name, bases, dct):
        dct.setdefault(
            "dcerpc_commands",
            {x.dcerpc_command: x for x in dct.values() if hasattr(x, "dcerpc_command")},
        )
        return type.__new__(cls, name, bases, dct)


class DCERPC_Server(metaclass=_DCERPC_Server_metaclass):
    def __init__(
        self,
        transport,
        ndr64=False,
        verb=True,
        local_ip=None,
        port=None,
        portmap=None,
        **kwargs,
    ):
        self.transport = transport
        self.session = DceRpcSession(**kwargs)
        self.queue = deque()
        self.ndr64 = ndr64
        if ndr64:
            self.ndr_name = "NDR64"
        else:
            self.ndr_name = "NDR 2.0"
        # For endpoint mapper. TODO: improve separation/handling of SMB/IP etc
        self.local_ip = local_ip
        self.port = port
        self.portmap = portmap or {}
        self.verb = verb

    def loop(self, sock):
        while True:
            pkt = sock.recv(MTU)
            if not pkt:
                break
            self.recv(pkt)
            # send all possible responses
            while True:
                resp = self.get_response()
                if not resp:
                    break
                sock.send(bytes(resp))

    @staticmethod
    def answer(reqcls):
        """
        A decorator that registers a DCE/RPC responder to a command.
        See the DCE/RPC documentation.

        :param reqcls: the DCE/RPC packet class to respond to
        """

        def deco(func):
            func.dcerpc_command = reqcls
            return func

        return deco

    def extend(self, server_cls):
        """
        Extend a DCE/RPC server into another
        """
        self.dcerpc_commands.update(server_cls.dcerpc_commands)

    def make_reply(self, req):
        cls = req[DceRpc5Request].payload.__class__
        if cls in self.dcerpc_commands:
            # call handler
            return self.dcerpc_commands[cls](self, req)
        return None

    @classmethod
    def spawn(cls, transport, iface=None, port=135, bg=False, **kwargs):
        """
        Spawn a DCE/RPC server

        :param transport: one of DCERPC_Transport
        :param iface: the interface to spawn it on (default: conf.iface)
        :param port: the port to spawn it on (for IP_TCP or the SMB server)
        :param bg: background mode? (default: False)
        """
        if transport == DCERPC_Transport.NCACN_IP_TCP:
            # IP/TCP case
            ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_ip = get_if_addr(iface or conf.iface)
            try:
                ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
            ssock.bind((local_ip, port))
            ssock.listen(5)
            sockets = []
            if kwargs.get("verb", True):
                print(
                    conf.color_theme.green(
                        "Server %s started. Waiting..." % cls.__name__
                    )
                )

            def _run():
                # Wait for clients forever
                try:
                    while True:
                        clientsocket, address = ssock.accept()
                        sockets.append(clientsocket)
                        print(
                            conf.color_theme.gold(
                                "\u2503 Connection received from %s" % repr(address)
                            )
                        )
                        server = cls(
                            DCERPC_Transport.NCACN_IP_TCP,
                            local_ip=local_ip,
                            port=port,
                            **kwargs,
                        )
                        threading.Thread(
                            target=server.loop, args=(clientsocket,)
                        ).start()
                except KeyboardInterrupt:
                    print("X Exiting.")
                    ssock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    print("X Server closed.")
                finally:
                    for sock in sockets:
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                            sock.close()
                        except Exception:
                            pass
                    ssock.close()

            if bg:
                # Background
                threading.Thread(target=_run).start()
                return ssock
            else:
                # Non-background
                _run()
        elif transport == DCERPC_Transport.NCACN_NP:
            # SMB case
            from scapy.layers.smbserver import SMB_Server

            kwargs.setdefault("shares", [])  # do not expose files by default
            return SMB_Server.spawn(
                iface=iface or conf.iface,
                port=port,
                bg=bg,
                # Important: pass the DCE/RPC server
                DCERPC_SERVER_CLS=cls,
                # SMB parameters
                **kwargs,
            )
        else:
            raise ValueError("Unsupported transport :(")

    def recv(self, data):
        if isinstance(data, bytes):
            req = DceRpc5(data)
        else:
            req = data
        # If the packet has padding, it contains several fragments
        pad = None
        if conf.padding_layer in req:
            pad = req[conf.padding_layer].load
            req[conf.padding_layer].underlayer.remove_payload()
        # Ask the DCE/RPC session to process it (match interface, etc.)
        req = self.session.in_pkt(req)
        hdr = DceRpc5(
            endian=req.endian,
            encoding=req.encoding,
            float=req.float,
            call_id=req.call_id,
        )
        # Now process the packet based on the DCE/RPC type
        if DceRpc5Bind in req or DceRpc5AlterContext in req or DceRpc5Auth3 in req:
            # Log
            if self.verb:
                print(
                    conf.color_theme.opening(
                        "<< %s" % req.payload.__class__.__name__
                        + (
                            " (with %s%s)"
                            % (
                                self.session.ssp.__class__.__name__,
                                (
                                    f" - {self.session.auth_level.name}"
                                    if self.session.auth_level is not None
                                    else ""
                                ),
                            )
                            if self.session.ssp
                            else ""
                        )
                    )
                )
            if not self.session.rpc_bind_interface:
                # The session did not find a matching interface !
                self.queue.extend(self.session.out_pkt(hdr / DceRpc5BindNak()))
                if self.verb:
                    print(conf.color_theme.fail("! DceRpc5BindNak (unknown interface)"))
            else:
                auth_value, status = None, 0
                if (
                    self.session.ssp
                    and req.auth_verifier
                    and req.auth_verifier.auth_value
                ):
                    (
                        self.session.sspcontext,
                        auth_value,
                        status,
                    ) = self.session.ssp.GSS_Accept_sec_context(
                        self.session.sspcontext, req.auth_verifier.auth_value
                    )
                    self.session.auth_level = RPC_C_AUTHN_LEVEL(
                        req.auth_verifier.auth_level
                    )
                    self.session.auth_context_id = req.auth_verifier.auth_context_id
                    if DceRpc5Auth3 in req:
                        # Auth 3 stops here (no server response) !
                        if status != 0:
                            print(conf.color_theme.fail("! DceRpc5Auth3 failed"))
                        if pad is not None:
                            self.recv(pad)
                        return
                    # auth_verifier here contains the SSP nego packets
                    # (whereas it usually contains the verifiers)
                    if auth_value is not None:
                        hdr.auth_verifier = CommonAuthVerifier(
                            auth_type=req.auth_verifier.auth_type,
                            auth_level=req.auth_verifier.auth_level,
                            auth_context_id=req.auth_verifier.auth_context_id,
                            auth_value=auth_value,
                        )

                def get_result(ctx):
                    name = ctx.transfer_syntaxes[0].sprintf("%if_uuid%")
                    if name == self.ndr_name:
                        # Acceptance
                        return DceRpc5Result(
                            result=0,
                            reason=0,
                            transfer_syntax=DceRpc5TransferSyntax(
                                if_uuid=ctx.transfer_syntaxes[0].if_uuid,
                                if_version=ctx.transfer_syntaxes[0].if_version,
                            ),
                        )
                    elif name == "Bind Time Feature Negotiation":
                        return DceRpc5Result(
                            result=3,
                            reason=3,
                            transfer_syntax=DceRpc5TransferSyntax(
                                if_uuid="NULL",
                                if_version=0,
                            ),
                        )
                    else:
                        # Reject
                        return DceRpc5Result(
                            result=2,
                            reason=2,
                            transfer_syntax=DceRpc5TransferSyntax(
                                if_uuid="NULL",
                                if_version=0,
                            ),
                        )

                results = [get_result(x) for x in req.context_elem]
                if self.port is None:
                    # Piped
                    port_spec = (
                        b"\\\\PIPE\\\\%s\0"
                        % self.session.rpc_bind_interface.name.encode()
                    )
                else:
                    # IP
                    port_spec = str(self.port).encode() + b"\x00"
                if DceRpc5Bind in req:
                    cls = DceRpc5BindAck
                else:
                    cls = DceRpc5AlterContextResp
                self.queue.extend(
                    self.session.out_pkt(
                        hdr
                        / cls(
                            assoc_group_id=RandShort(),
                            sec_addr=DceRpc5PortAny(
                                port_spec=port_spec,
                            ),
                            results=results,
                        ),
                    )
                )
                if self.verb:
                    print(
                        conf.color_theme.success(
                            f">> {cls.__name__} {self.session.rpc_bind_interface.name}"
                            f" is on port '{port_spec.decode()}' using {self.ndr_name}"
                        )
                    )
        elif DceRpc5Request in req:
            if self.verb:
                print(
                    conf.color_theme.opening(
                        "<< REQUEST: %s"
                        % req[DceRpc5Request].payload.__class__.__name__
                    )
                )
            # Can be any RPC request !
            resp = self.make_reply(req)
            if resp:
                self.queue.extend(
                    self.session.out_pkt(
                        hdr
                        / DceRpc5Response(
                            alloc_hint=len(resp),
                            cont_id=req.cont_id,
                        )
                        / resp,
                    )
                )
                if self.verb:
                    print(
                        conf.color_theme.success(
                            ">> RESPONSE: %s" % (resp.__class__.__name__)
                        )
                    )
        # If there was padding, process the second frag
        if pad is not None:
            self.recv(pad)

    def get_response(self):
        try:
            return self.queue.popleft()
        except IndexError:
            return None

    # Endpoint mapper

    @answer.__func__(ept_map_Request)  # hack for Python <= 3.9
    def ept_map(self, req):
        """
        Answer to ept_map_Request.
        """
        if self.transport != DCERPC_Transport.NCACN_IP_TCP:
            raise ValueError("Unimplemented")

        tower = protocol_tower_t(
            req[ept_map_Request].valueof("map_tower.tower_octet_string")
        )
        uuid = tower.floors[0].uuid
        if_version = (tower.floors[0].rhs << 16) | tower.floors[0].version

        # Check for results in our portmap
        port = None
        if (uuid, if_version) in DCE_RPC_INTERFACES:
            interface = DCE_RPC_INTERFACES[(uuid, if_version)]
            if interface in self.portmap:
                port = self.portmap[interface]

        if port is not None:
            # Found result
            resp_tower = twr_p_t(
                tower_octet_string=bytes(
                    protocol_tower_t(
                        floors=[
                            tower.floors[0],  # UUID
                            tower.floors[1],  # NDR version
                            tower.floors[2],  # RPC version
                            prot_and_addr_t(
                                lhs_length=1,
                                protocol_identifier="NCACN_IP_TCP",
                                rhs_length=2,
                                rhs=port,
                            ),
                            prot_and_addr_t(
                                lhs_length=1,
                                protocol_identifier="IP",
                                rhs_length=4,
                                rhs=self.local_ip or "0.0.0.0",
                            ),
                        ]
                    )
                )
            )
            resp = ept_map_Response(ITowers=[resp_tower], ndr64=self.ndr64)
            resp.ITowers.max_count = req.max_towers  # ugh
        else:
            # No result found
            pass
        return resp
