# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
DCE/RPC server as per [MS-RPCE]
"""

import socket
import uuid
import threading
from collections import deque

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.data import MTU
from scapy.volatile import RandShort

from scapy.layers.dcerpc import (
    CommonAuthVerifier,
    DCE_RPC_INTERFACES,
    DCERPC_Transport,
    DceRpc5,
    DceRpc5AlterContext,
    DceRpc5AlterContextResp,
    DceRpc5Auth3,
    DceRpc5Bind,
    DceRpc5BindAck,
    DceRpc5BindNak,
    DceRpc5Fault,
    DceRpc5PortAny,
    DceRpc5Request,
    DceRpc5Response,
    DceRpc5Result,
    DceRpc5TransferSyntax,
    DceRpcInterface,
    DceRpcSession,
    NDRPacket,
    RPC_C_AUTHN_LEVEL,
)
from scapy.layers.gssapi import (
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
)

# RPC
from scapy.layers.msrpce.ept import (
    ept_map_Request,
    ept_map_Response,
    twr_p_t,
    protocol_tower_t,
    prot_and_addr_t,
)

# Typing
from typing import (
    Dict,
    Callable,
    Optional,
    Tuple,
)


class _DCERPC_Server_metaclass(type):
    # This value is calculated for each DCE/RPC server, and contains
    # the callables sorted by interface+opnum
    dcerpc_commands: Dict[Tuple[uuid.UUID, int], Callable] = {}

    def __new__(cls, name, bases, dct):
        dct.setdefault(
            "dcerpc_commands",
            {x.dcerpc_command: x for x in dct.values() if hasattr(x, "dcerpc_command")},
        )
        return type.__new__(cls, name, bases, dct)


class DCERPC_Fault(Exception):
    def __init__(self, status):
        self.status = status


class DCERPC_Server(metaclass=_DCERPC_Server_metaclass):
    """
    DCE/RPC server

    :param transport: the DCERPC_Transport to bind this server on
    :param ndr64: whether to use NDR64 or not (default: conf.ndr64)
    :param verb: verbose mode

    Other optional parameters:

    :param min_auth_level: the minimum RPC_C_AUTHN_LEVEL to allow.
                           (NONE allows anonymous access)
    """

    def __init__(
        self,
        transport: DCERPC_Transport,
        ndr64: Optional[bool] = None,
        verb: bool = True,
        min_auth_level: RPC_C_AUTHN_LEVEL = RPC_C_AUTHN_LEVEL.NONE,
        # endpoint mapper only
        local_ip: str = None,
        port: int = None,
        portmap: Dict[DceRpcInterface, int] = None,
        **kwargs,
    ):
        self.transport = transport
        self.dcerpc_commands = self.dcerpc_commands.copy()
        if ndr64 is None:
            ndr64 = conf.ndr64
        self.ndr64 = ndr64
        self.min_auth_level = min_auth_level

        # For endpoint mapper. TODO: improve separation/handling of SMB/IP etc
        self.local_ip = local_ip
        self.port = port
        self.portmap = portmap or {}
        self.verb = verb

        # Session specific
        self.session = DceRpcSession(**kwargs)
        self.authenticated = False
        self.queue = deque()

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
            if not issubclass(reqcls, NDRPacket):
                raise ValueError("Cannot answer a non NDRPacket class !")
            try:
                func.dcerpc_command = reqcls.intf, reqcls.opnum
            except AttributeError:
                raise ValueError(
                    "NDRPacket class isn't registered or isn't a request !"
                )
            return func

        return deco

    def extend(self, server_cls):
        """
        Extend a DCE/RPC server into another
        """
        self.dcerpc_commands.update(server_cls.dcerpc_commands)

    def make_reply(self, req):
        """
        Make a response to the DCE/RPC request.

        This finds whether a callback has been registered for this particular packet,
        and call it if available.
        """
        opnum = req[DceRpc5Request].opnum
        if self.session.rpc_bind_interface is None:
            return None
        intf = self.session.rpc_bind_interface.uuid
        if (intf, opnum) in self.dcerpc_commands:
            # call handler
            return self.dcerpc_commands[(intf, opnum)](self, req)
        return None

    @staticmethod
    def _run_client(server, clientsocket, sockets):
        try:
            server.loop(clientsocket)
        finally:
            clientsocket.close()
            sockets.remove(clientsocket)

    @classmethod
    def spawn(cls, transport, iface=None, port=135, bg=False, **kwargs):
        """
        Spawn a DCE/RPC server

        :param transport: one of DCERPC_Transport
        :param iface: the interface to spawn it on (default: conf.iface)
        :param port: the port to spawn it on (for IP_TCP or the SMB server)
        :param bg: background mode? (default: False)
        :param ndr64: whether NDR64 is supported or not (default: conf.ndr64).
            This attribute will be overwritten if the client doesn't support it.
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
                            target=cls._run_client,
                            args=(server, clientsocket, sockets),
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

            min_auth_level = kwargs.pop(
                "min_auth_level", RPC_C_AUTHN_LEVEL.PKT_INTEGRITY
            )
            if min_auth_level >= RPC_C_AUTHN_LEVEL.PKT_PRIVACY:
                kwargs.setdefault("REQUIRE_ENCRYPTION", True)
            elif min_auth_level <= RPC_C_AUTHN_LEVEL.PKT:
                kwargs.setdefault("REQUIRE_SIGNATURE", False)

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

    def _send_fault(self, hdr, req, status):
        """
        Internal: return a DCE/RPC Fault
        """
        hdr.pfc_flags += "PFC_DID_NOT_EXECUTE"
        self.queue.extend(
            hdr
            / DceRpc5Fault(
                status=status,
                cont_id=req.cont_id,
            )
        )

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
                    # SSPI
                    (
                        self.session.sspcontext,
                        auth_value,
                        status,
                    ) = self.session.ssp.GSS_Accept_sec_context(
                        self.session.sspcontext, req.auth_verifier.auth_value
                    )

                    if DceRpc5Auth3 in req:
                        # Auth 3 stops here (no server response) !
                        if status == GSS_S_COMPLETE:
                            self.authenticated = True
                        else:
                            print(conf.color_theme.fail("! DceRpc5Auth3 failed"))
                            self.session.auth_level = RPC_C_AUTHN_LEVEL.NONE
                        if pad is not None:
                            self.recv(pad)
                        return

                    # Check auth status
                    if status not in [GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED]:
                        self._send_fault(hdr, req, status=5)
                        if self.verb:
                            print(
                                conf.color_theme.fail(
                                    "! GSS_Accept_sec_context failed: %s" % status
                                )
                            )
                        return

                    # Store session context
                    self.session.auth_context_id = req.auth_verifier.auth_context_id
                    self.session.auth_level = RPC_C_AUTHN_LEVEL(
                        req.auth_verifier.auth_level
                    )
                    if self.session.auth_level < self.min_auth_level:
                        self._send_fault(hdr, req, status=5)
                        if self.verb:
                            print(
                                conf.color_theme.fail(
                                    "! auth_level %s < min_auth_level %s."
                                    % (
                                        self.session.auth_level,
                                        self.min_auth_level,
                                    )
                                )
                            )
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

                    # Mark as authenticated if successful.
                    if status == GSS_S_COMPLETE:
                        self.authenticated = True
                elif not self.authenticated:
                    # Trying to do unauthenticated bind.
                    if self.min_auth_level == RPC_C_AUTHN_LEVEL.NONE:
                        self.session.auth_level = RPC_C_AUTHN_LEVEL.NONE
                    else:
                        self._send_fault(hdr, req, status=5)
                        if self.verb:
                            print(
                                conf.color_theme.fail(
                                    "! Anonymous bind is not allowed."
                                )
                            )
                        return

                # Detect if the client requested NDR64 and the server agrees
                self.ndr64 = self.ndr64 and any(
                    ctx.transfer_syntaxes[0].sprintf("%if_uuid%") == "NDR64"
                    for ctx in req.context_elem
                )

                # Process bind contexts and answer to them
                results = []
                for ctx in req.context_elem:
                    # Get name
                    name = ctx.transfer_syntaxes[0].sprintf("%if_uuid%")
                    if (
                        # NDR64
                        (name == "NDR64" and self.ndr64)
                        or
                        # NDR 2.0
                        (name == "NDR 2.0" and not self.ndr64)
                    ):
                        # Acceptance
                        results.append(
                            DceRpc5Result(
                                result=0,
                                reason=0,
                                transfer_syntax=DceRpc5TransferSyntax(
                                    if_uuid=ctx.transfer_syntaxes[0].if_uuid,
                                    if_version=ctx.transfer_syntaxes[0].if_version,
                                ),
                            )
                        )
                    elif name == "Bind Time Feature Negotiation":
                        # Handle Bind Time Feature
                        results.append(
                            DceRpc5Result(
                                result=3,
                                reason=3,
                                transfer_syntax=DceRpc5TransferSyntax(
                                    if_uuid="NULL",
                                    if_version=0,
                                ),
                            )
                        )
                    else:
                        # Reject
                        results.append(
                            DceRpc5Result(
                                result=2,
                                reason=2,
                                transfer_syntax=DceRpc5TransferSyntax(
                                    if_uuid="NULL",
                                    if_version=0,
                                ),
                            )
                        )

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
                            assoc_group_id=int(RandShort()),
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
                            f" is on port '{port_spec.decode()}' using "
                            + ("NDR64" if self.ndr64 else "NDR32")
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

            # Check auth
            if not self.authenticated and self.min_auth_level != RPC_C_AUTHN_LEVEL.NONE:
                self._send_fault(hdr, req, status=5)
                return

            # Can be any RPC request !
            try:
                resp = self.make_reply(req)
                if not resp:
                    # nca_s_op_rng_error
                    raise DCERPC_Fault(0x1C010002)

                # Send response
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
            except DCERPC_Fault as ex:
                if self.verb:
                    print(conf.color_theme.fail("! %s" % ex.status))

                # Return a Fault
                self._send_fault(hdr, req, status=ex.status)

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
            # No result found: nca_s_unk_if
            raise DCERPC_Fault(0x1C010003)
        return resp
