# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
DCE/RPC client as per [MS-RPCE]
"""

import uuid
import socket

from scapy.config import conf
from scapy.error import log_runtime

from scapy.layers.dcerpc import (
    _DCE_RPC_ERROR_CODES,
    ComInterface,
    CommonAuthVerifier,
    DCE_C_AUTHN_LEVEL,
    DCERPC_Transport,
    DceRpc5,
    DceRpc5AbstractSyntax,
    DceRpc5AlterContext,
    DceRpc5AlterContextResp,
    DceRpc5Auth3,
    DceRpc5Bind,
    DceRpc5BindAck,
    DceRpc5BindNak,
    DceRpc5Context,
    DceRpc5Fault,
    DceRpc5Request,
    DceRpc5Response,
    DceRpc5TransferSyntax,
    DceRpcInterface,
    DceRpcSecVT,
    DceRpcSecVTCommand,
    DceRpcSecVTPcontext,
    DceRpcSession,
    DceRpcSocket,
    find_dcerpc_interface,
    NDRContextHandle,
    NDRPointer,
    RPC_C_IMP_LEVEL,
)
from scapy.layers.gssapi import (
    SSP,
    GSS_S_FAILURE,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_C_FLAGS,
)
from scapy.layers.smb2 import STATUS_ERREF
from scapy.layers.smbclient import (
    SMB_RPC_SOCKET,
)

# RPC
from scapy.layers.msrpce.ept import (
    ept_map_Request,
    ept_map_Response,
    twr_p_t,
    protocol_tower_t,
    prot_and_addr_t,
    UUID,
)

# Typing
from typing import (
    Optional,
    Union,
)


class DCERPC_Client(object):
    """
    A basic DCE/RPC client

    :param transport: the transport to use.
    :param ndr64: should ask for NDR64 when binding (default conf.ndr64)
    :param ndrendian: the endianness to use (default little)
    :param verb: enable verbose logging (default True)
    :param auth_level: the DCE_C_AUTHN_LEVEL to use
    :param impersonation_type: the RPC_C_IMP_LEVEL to use
    """

    def __init__(
        self,
        transport: DCERPC_Transport,
        ndr64: Optional[bool] = None,
        ndrendian: str = "little",
        verb: bool = True,
        auth_level: Optional[DCE_C_AUTHN_LEVEL] = None,
        impersonation_type: RPC_C_IMP_LEVEL = RPC_C_IMP_LEVEL.DEFAULT,
        **kwargs,
    ):
        self.sock = None
        self.transport = transport
        assert isinstance(
            transport, DCERPC_Transport
        ), "transport must be from DCERPC_Transport"

        # Counters
        self.call_id = 0
        self.next_cont_id = 0  # next available context id
        self.next_auth_contex_id = 0  # next available auth context id

        # Session parameters
        if ndr64 is None:
            ndr64 = conf.ndr64
        self.ndr64: bool = ndr64
        self.ndrendian = ndrendian
        self.verb = verb
        self.host: str = None
        self.port: int = -1
        self.ssp = kwargs.pop("ssp", None)  # type: SSP
        self.sspcontext = None
        if auth_level is not None:
            self.auth_level = auth_level
        elif self.ssp is not None:
            self.auth_level = DCE_C_AUTHN_LEVEL.CONNECT
        else:
            self.auth_level = DCE_C_AUTHN_LEVEL.NONE
        if impersonation_type == RPC_C_IMP_LEVEL.DEFAULT:
            # Same default as windows
            impersonation_type = RPC_C_IMP_LEVEL.IDENTIFY
        self.impersonation_type = impersonation_type
        self._first_time_on_interface = True
        self.contexts = {}
        self.dcesockargs = kwargs
        self.dcesockargs["transport"] = self.transport

    @classmethod
    def from_smblink(cls, smbcli, smb_kwargs={}, **kwargs):
        """
        Build a DCERPC_Client from a SMB_Client.smblink directly
        """
        client = DCERPC_Client(DCERPC_Transport.NCACN_NP, **kwargs)
        sock = client.smbrpcsock = SMB_RPC_SOCKET(smbcli, **smb_kwargs)
        client.sock = DceRpcSocket(
            sock,
            DceRpc5,
            ssp=client.ssp,
            auth_level=client.auth_level,
            **client.dcesockargs,
        )
        return client

    @property
    def session(self) -> DceRpcSession:
        return self.sock.session

    def connect(
        self,
        host,
        endpoint: Union[int, str] = None,
        port: Optional[int] = None,
        interface=None,
        timeout=5,
        smb_kwargs={},
    ):
        """
        Initiate a connection.

        :param host: the host to connect to
        :param endpoint: (optional) the port/smb pipe to connect to
        :param interface: (optional) if endpoint isn't provided, uses the endpoint
            mapper to find the appropriate endpoint for that interface.
        :param timeout: (optional) the connection timeout (default 5)
        :param port: (optional) the port to connect to. (useful for SMB)
        """
        if endpoint is None and interface is not None:
            # Figure out the endpoint using the endpoint mapper

            if self.transport == DCERPC_Transport.NCACN_IP_TCP and port is None:
                # IP/TCP
                # ask the endpoint mapper (port 135) for the IP:PORT
                endpoints = get_endpoint(
                    host,
                    interface,
                    ndrendian=self.ndrendian,
                    verb=self.verb,
                )
                if endpoints:
                    _, endpoint = endpoints[0]
                else:
                    raise ValueError(
                        "Could not find an available endpoint for that interface !"
                    )
            elif self.transport == DCERPC_Transport.NCACN_NP:
                # SMB
                # ask the endpoint mapper (over SMB) for the namedpipe
                endpoints = get_endpoint(
                    host,
                    interface,
                    transport=self.transport,
                    ndrendian=self.ndrendian,
                    verb=self.verb,
                    smb_kwargs=smb_kwargs,
                )
                if endpoints:
                    endpoint = endpoints[0].lstrip("\\pipe\\")
                else:
                    return

        # Assign the default port if no port is provided
        if port is None:
            if self.transport == DCERPC_Transport.NCACN_IP_TCP:  # IP/TCP
                port = endpoint or 135
            elif self.transport == DCERPC_Transport.NCACN_NP:  # SMB
                port = 445
            else:
                raise ValueError(
                    "Can't guess the port for transport: %s" % self.transport
                )

        # Start socket and connect
        self.host = host
        self.port = port
        sock = socket.socket()
        sock.settimeout(timeout)
        if self.verb:
            print(
                "\u2503 Connecting to %s on port %s via %s..."
                % (host, port, repr(self.transport))
            )
        sock.connect((host, port))
        if self.verb:
            print(
                conf.color_theme.green(
                    "\u2514 Connected from %s" % repr(sock.getsockname())
                )
            )

        if self.transport == DCERPC_Transport.NCACN_NP:  # SMB
            # If the endpoint is provided, connect to it.
            if endpoint is not None:
                self.open_smbpipe(endpoint)

            # We pack the socket into a SMB_RPC_SOCKET
            sock = self.smbrpcsock = SMB_RPC_SOCKET.from_tcpsock(
                sock, ssp=self.ssp, **smb_kwargs
            )
            self.sock = DceRpcSocket(sock, DceRpc5, **self.dcesockargs)
        elif self.transport == DCERPC_Transport.NCACN_IP_TCP:
            self.sock = DceRpcSocket(
                sock,
                DceRpc5,
                ssp=self.ssp,
                auth_level=self.auth_level,
                **self.dcesockargs,
            )

    def close(self):
        """
        Close the DCE/RPC client.
        """
        if self.verb:
            print("X Connection closed\n")
        self.sock.close()

    def sr1(self, pkt, **kwargs):
        """
        Send/Receive a DCE/RPC message.

        The DCE/RPC header is added automatically.
        """
        self.call_id += 1
        pkt = (
            DceRpc5(
                call_id=self.call_id,
                pfc_flags="PFC_FIRST_FRAG+PFC_LAST_FRAG",
                endian=self.ndrendian,
                auth_verifier=kwargs.pop("auth_verifier", None),
                vt_trailer=kwargs.pop("vt_trailer", None),
            )
            / pkt
        )
        if "pfc_flags" in kwargs:
            pkt.pfc_flags = kwargs.pop("pfc_flags")
        if "objectuuid" in kwargs:
            pkt.pfc_flags += "PFC_OBJECT_UUID"
            pkt.object = kwargs.pop("objectuuid")
        return self.sock.sr1(pkt, verbose=0, **kwargs)

    def send(self, pkt, **kwargs):
        """
        Send a DCE/RPC message.

        The DCE/RPC header is added automatically.
        """
        self.call_id += 1
        pkt = (
            DceRpc5(
                call_id=self.call_id,
                pfc_flags="PFC_FIRST_FRAG+PFC_LAST_FRAG",
                endian=self.ndrendian,
                auth_verifier=kwargs.pop("auth_verifier", None),
                vt_trailer=kwargs.pop("vt_trailer", None),
            )
            / pkt
        )
        if "pfc_flags" in kwargs:
            pkt.pfc_flags = kwargs.pop("pfc_flags")
        if "objectuuid" in kwargs:
            pkt.pfc_flags += "PFC_OBJECT_UUID"
            pkt.object = kwargs.pop("objectuuid")
        return self.sock.send(pkt, **kwargs)

    def sr1_req(self, pkt, **kwargs):
        """
        Send/Receive a DCE/RPC request.

        :param pkt: the inner DCE/RPC message, without any header.
        """
        if self.verb:
            if "objectuuid" in kwargs:
                # COM
                print(
                    conf.color_theme.opening(
                        ">> REQUEST (COM): %s" % pkt.payload.__class__.__name__
                    )
                )
            else:
                print(
                    conf.color_theme.opening(">> REQUEST: %s" % pkt.__class__.__name__)
                )
        # Add sectrailer if first time talking on this interface
        vt_trailer = b""
        if (
            self._first_time_on_interface
            and self.transport != DCERPC_Transport.NCACN_NP
        ):
            # In the first request after a bind, Windows sends a trailer to verify
            # that the negotiated transfer/interface wasn't altered.
            self._first_time_on_interface = False
            vt_trailer = DceRpcSecVT(
                commands=[
                    DceRpcSecVTCommand(SEC_VT_COMMAND_END=1)
                    / DceRpcSecVTPcontext(
                        InterfaceId=self.session.rpc_bind_interface.uuid,
                        TransferSyntax="NDR64" if self.ndr64 else "NDR 2.0",
                        TransferVersion=1 if self.ndr64 else 2,
                    )
                ]
            )

        # Optional: force opnum
        opnum = {}
        if "opnum" in kwargs:
            opnum["opnum"] = kwargs.pop("opnum")

        # Send/receive
        resp = self.sr1(
            DceRpc5Request(
                cont_id=self.session.cont_id,
                alloc_hint=len(pkt) + len(vt_trailer),
                **opnum,
            )
            / pkt,
            vt_trailer=vt_trailer,
            **kwargs,
        )

        # Parse result
        result = None
        if DceRpc5Response in resp:
            if self.verb:
                if "objectuuid" in kwargs:
                    # COM
                    print(
                        conf.color_theme.success(
                            "<< RESPONSE (COM): %s"
                            % (resp[DceRpc5Response].payload.payload.__class__.__name__)
                        )
                    )
                else:
                    print(
                        conf.color_theme.success(
                            "<< RESPONSE: %s"
                            % (resp[DceRpc5Response].payload.__class__.__name__)
                        )
                    )
            result = resp[DceRpc5Response].payload
        elif DceRpc5Fault in resp:
            if self.verb:
                print(conf.color_theme.success("<< FAULT"))
                # If [MS-EERR] is loaded, show the extended info
                if resp[DceRpc5Fault].payload and not isinstance(
                    resp[DceRpc5Fault].payload, conf.raw_layer
                ):
                    resp[DceRpc5Fault].payload.show()
            result = resp
        if self.verb and getattr(resp, "status", 0) != 0:
            if resp.status in _DCE_RPC_ERROR_CODES:
                print(conf.color_theme.fail(f"! {_DCE_RPC_ERROR_CODES[resp.status]}"))
            elif resp.status in STATUS_ERREF:
                print(conf.color_theme.fail(f"! {STATUS_ERREF[resp.status]}"))
            else:
                print(conf.color_theme.fail("! Failure"))
                resp.show()
        return result

    def _get_bind_context(self, interface):
        """
        Internal: get the bind DCE/RPC context.
        """
        if interface in self.contexts:
            # We have already found acceptable contexts for this interface,
            # reuse that.
            return self.contexts[interface]

        # NDR 2.0
        contexts = [
            DceRpc5Context(
                cont_id=self.next_cont_id,
                abstract_syntax=DceRpc5AbstractSyntax(
                    if_uuid=interface.uuid,
                    if_version=interface.if_version,
                ),
                transfer_syntaxes=[
                    DceRpc5TransferSyntax(
                        # NDR 2.0 32-bit
                        if_uuid="NDR 2.0",
                        if_version=2,
                    )
                ],
            ),
        ]
        self.next_cont_id += 1

        # NDR64
        if self.ndr64:
            contexts.append(
                DceRpc5Context(
                    cont_id=self.next_cont_id,
                    abstract_syntax=DceRpc5AbstractSyntax(
                        if_uuid=interface.uuid,
                        if_version=interface.if_version,
                    ),
                    transfer_syntaxes=[
                        DceRpc5TransferSyntax(
                            # NDR64
                            if_uuid="NDR64",
                            if_version=1,
                        )
                    ],
                )
            )
            self.next_cont_id += 1

        # BindTimeFeatureNegotiationBitmask
        contexts.append(
            DceRpc5Context(
                cont_id=self.next_cont_id,
                abstract_syntax=DceRpc5AbstractSyntax(
                    if_uuid=interface.uuid,
                    if_version=interface.if_version,
                ),
                transfer_syntaxes=[
                    DceRpc5TransferSyntax(
                        if_uuid=uuid.UUID("6cb71c2c-9812-4540-0300-000000000000"),
                        if_version=1,
                    )
                ],
            )
        )
        self.next_cont_id += 1

        # Store contexts for this interface
        self.contexts[interface] = contexts

        return contexts

    def _check_bind_context(self, interface, contexts) -> bool:
        """
        Internal: check the answer DCE/RPC bind context, and update them.
        """
        for i, ctx in enumerate(contexts):
            if ctx.result == 0:
                # Context was accepted. Remove all others from cache
                self.contexts[interface] = [self.contexts[interface][i]]
                return True

        return False

    def _bind(
        self, interface: Union[DceRpcInterface, ComInterface], reqcls, respcls
    ) -> bool:
        """
        Internal: used to send a bind/alter request
        """
        # Build a security context: [MS-RPCE] 3.3.1.5.2
        if self.verb:
            print(
                conf.color_theme.opening(
                    ">> %s on %s" % (reqcls.__name__, interface)
                    + (" (with %s)" % self.ssp.__class__.__name__ if self.ssp else "")
                )
            )

        # Do we need an authenticated bind
        if not self.ssp or (
            self.sspcontext is not None
            or self.transport == DCERPC_Transport.NCACN_NP
            and self.auth_level < DCE_C_AUTHN_LEVEL.PKT_INTEGRITY
        ):
            # NCACN_NP = SMB without INTEGRITY/PRIVACY does not bind the RPC securely,
            # again as it has already authenticated during the SMB Session Setup
            resp = self.sr1(
                reqcls(context_elem=self._get_bind_context(interface)),
                auth_verifier=None,
            )
            status = GSS_S_COMPLETE
        else:
            # Perform authentication
            self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                self.sspcontext,
                req_flags=(
                    # SSPs need to be instantiated with some special flags
                    # for DCE/RPC usages.
                    GSS_C_FLAGS.GSS_C_DCE_STYLE
                    | GSS_C_FLAGS.GSS_C_REPLAY_FLAG
                    | GSS_C_FLAGS.GSS_C_SEQUENCE_FLAG
                    | GSS_C_FLAGS.GSS_C_MUTUAL_FLAG
                    | (
                        GSS_C_FLAGS.GSS_C_INTEG_FLAG
                        if self.auth_level >= DCE_C_AUTHN_LEVEL.PKT_INTEGRITY
                        else 0
                    )
                    | (
                        GSS_C_FLAGS.GSS_C_CONF_FLAG
                        if self.auth_level >= DCE_C_AUTHN_LEVEL.PKT_PRIVACY
                        else 0
                    )
                    | (
                        GSS_C_FLAGS.GSS_C_IDENTIFY_FLAG
                        if self.impersonation_type <= RPC_C_IMP_LEVEL.IDENTIFY
                        else 0
                    )
                    | (
                        GSS_C_FLAGS.GSS_C_DELEG_FLAG
                        if self.impersonation_type == RPC_C_IMP_LEVEL.DELEGATE
                        else 0
                    )
                ),
                target_name="host/" + self.host,
            )

            if status not in [GSS_S_CONTINUE_NEEDED, GSS_S_COMPLETE]:
                # Authentication failed.
                self.sspcontext.clifailure()
                return False

            resp = self.sr1(
                reqcls(context_elem=self._get_bind_context(interface)),
                auth_verifier=(
                    None
                    if not self.sspcontext
                    else CommonAuthVerifier(
                        auth_type=self.ssp.auth_type,
                        auth_level=self.auth_level,
                        auth_context_id=self.session.auth_context_id,
                        auth_value=token,
                    )
                ),
                pfc_flags=(
                    "PFC_FIRST_FRAG+PFC_LAST_FRAG"
                    + (
                        # If the SSP supports "Header Signing", advertise it
                        "+PFC_SUPPORT_HEADER_SIGN"
                        if self.ssp is not None and self.session.support_header_signing
                        else ""
                    )
                ),
            )

            # Check that the answer looks valid and contexts were accepted
            if respcls not in resp or not self._check_bind_context(
                interface, resp.results
            ):
                token = None
                status = GSS_S_FAILURE
            else:
                # Call the underlying SSP
                self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                    self.sspcontext,
                    input_token=resp.auth_verifier.auth_value,
                    target_name="host/" + self.host,
                )

            if status in [GSS_S_CONTINUE_NEEDED, GSS_S_COMPLETE]:
                # Authentication should continue, in two ways:
                # - through DceRpc5Auth3 (e.g. NTLM)
                # - through DceRpc5AlterContext (e.g. Kerberos)
                if token and self.ssp.LegsAmount(self.sspcontext) % 2 == 1:
                    # AUTH 3 for certain SSPs (e.g. NTLM)
                    # "The server MUST NOT respond to an rpc_auth_3 PDU"
                    self.send(
                        DceRpc5Auth3(),
                        auth_verifier=CommonAuthVerifier(
                            auth_type=self.ssp.auth_type,
                            auth_level=self.auth_level,
                            auth_context_id=self.session.auth_context_id,
                            auth_value=token,
                        ),
                    )
                    status = GSS_S_COMPLETE
                else:
                    while token:
                        respcls = DceRpc5AlterContextResp
                        resp = self.sr1(
                            DceRpc5AlterContext(
                                context_elem=self._get_bind_context(interface)
                            ),
                            auth_verifier=CommonAuthVerifier(
                                auth_type=self.ssp.auth_type,
                                auth_level=self.auth_level,
                                auth_context_id=self.session.auth_context_id,
                                auth_value=token,
                            ),
                        )
                        if respcls not in resp:
                            status = GSS_S_FAILURE
                            break
                        if resp.auth_verifier is None:
                            status = GSS_S_COMPLETE
                            break
                        self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                            self.sspcontext,
                            input_token=resp.auth_verifier.auth_value,
                            target_name="host/" + self.host,
                        )
            else:
                log_runtime.error("GSS_Init_sec_context failed with %s !" % status)

        # Check context acceptance
        if (
            status == GSS_S_COMPLETE
            and respcls in resp
            and self._check_bind_context(interface, resp.results)
        ):
            self.call_id = 0  # reset call id
            port = resp.sec_addr.port_spec.decode()
            ndr = self.session.ndr64 and "NDR64" or "NDR32"
            self.ndr64 = self.session.ndr64
            if self.verb:
                print(
                    conf.color_theme.success(
                        f"<< {respcls.__name__} port '{port}' using {ndr}"
                    )
                )
            self.session.sspcontext = self.sspcontext
            self._first_time_on_interface = True
            return True
        else:
            if self.verb:
                if DceRpc5BindNak in resp:
                    err_msg = resp.sprintf(
                        "reject_reason: %DceRpc5BindNak.provider_reject_reason%"
                    )
                    print(conf.color_theme.fail("! Bind_nak (%s)" % err_msg))
                    if DceRpc5BindNak in resp:
                        if resp[DceRpc5BindNak].payload and not isinstance(
                            resp[DceRpc5BindNak].payload, conf.raw_layer
                        ):
                            resp[DceRpc5BindNak].payload.show()
                elif DceRpc5Fault in resp:
                    if getattr(resp, "status", 0) != 0:
                        if resp.status in _DCE_RPC_ERROR_CODES:
                            print(
                                conf.color_theme.fail(
                                    f"! {_DCE_RPC_ERROR_CODES[resp.status]}"
                                )
                            )
                        elif resp.status in STATUS_ERREF:
                            print(
                                conf.color_theme.fail(f"! {STATUS_ERREF[resp.status]}")
                            )
                        else:
                            print(conf.color_theme.fail("! Failure"))
                            resp.show()
                    if DceRpc5Fault in resp:
                        if resp[DceRpc5Fault].payload and not isinstance(
                            resp[DceRpc5Fault].payload, conf.raw_layer
                        ):
                            resp[DceRpc5Fault].payload.show()
                else:
                    print(conf.color_theme.fail("! Failure"))
                    resp.show()
            return False

    def bind(self, interface: Union[DceRpcInterface, ComInterface]) -> bool:
        """
        Bind the client to an interface

        :param interface: the DceRpcInterface object
        """
        return self._bind(interface, DceRpc5Bind, DceRpc5BindAck)

    def alter_context(self, interface: Union[DceRpcInterface, ComInterface]) -> bool:
        """
        Alter context: post-bind context negotiation

        :param interface: the DceRpcInterface object
        """
        return self._bind(interface, DceRpc5AlterContext, DceRpc5AlterContextResp)

    def bind_or_alter(self, interface: Union[DceRpcInterface, ComInterface]) -> bool:
        """
        Bind the client to an interface or alter the context if already bound

        :param interface: the DceRpcInterface object
        """
        if not self.session.rpc_bind_interface:
            # No interface is bound
            return self.bind(interface)
        elif self.session.rpc_bind_interface != interface:
            # An interface is already bound
            return self.alter_context(interface)
        return True

    def open_smbpipe(self, name: str):
        """
        Open a certain filehandle with the SMB automaton.

        :param name: the name of the pipe
        """
        self.ipc_tid = self.smbrpcsock.tree_connect("IPC$")
        self.smbrpcsock.open_pipe(name)

    def close_smbpipe(self):
        """
        Close the previously opened pipe
        """
        self.smbrpcsock.set_TID(self.ipc_tid)
        self.smbrpcsock.close_pipe()
        self.smbrpcsock.tree_disconnect()

    def connect_and_bind(
        self,
        host: str,
        interface: DceRpcInterface,
        port: Optional[int] = None,
        timeout: int = 5,
        smb_kwargs={},
    ):
        """
        Asks the Endpoint Mapper what address to use to connect to the interface,
        then uses connect() followed by a bind()

        :param host: the host to connect to
        :param interface: the DceRpcInterface object
        :param port: (optional, NCACN_NP only) the port to connect to
        :param timeout: (optional) the connection timeout (default 5)
        """
        # Connect to the interface using the endpoint mapper
        self.connect(
            host=host,
            interface=interface,
            port=port,
            timeout=timeout,
            smb_kwargs=smb_kwargs,
        )

        # Bind in RPC
        self.bind(interface)

    def epm_map(self, interface):
        """
        Calls ept_map (the EndPoint Manager)
        """
        if self.ndr64:
            ndr_uuid = "NDR64"
            ndr_version = 1
        else:
            ndr_uuid = "NDR 2.0"
            ndr_version = 2
        pkt = self.sr1_req(
            ept_map_Request(
                obj=NDRPointer(
                    referent_id=1,
                    value=UUID(
                        Data1=0,
                        Data2=0,
                        Data3=0,
                        Data4=None,
                    ),
                ),
                map_tower=NDRPointer(
                    referent_id=2,
                    value=twr_p_t(
                        tower_octet_string=bytes(
                            protocol_tower_t(
                                floors=[
                                    prot_and_addr_t(
                                        lhs_length=19,
                                        protocol_identifier=0xD,
                                        uuid=interface.uuid,
                                        version=interface.major_version,
                                        rhs_length=2,
                                        rhs=interface.minor_version,
                                    ),
                                    prot_and_addr_t(
                                        lhs_length=19,
                                        protocol_identifier=0xD,
                                        uuid=ndr_uuid,
                                        version=ndr_version,
                                        rhs_length=2,
                                        rhs=0,
                                    ),
                                    prot_and_addr_t(
                                        lhs_length=1,
                                        protocol_identifier="RPC connection-oriented protocol",  # noqa: E501
                                        rhs_length=2,
                                        rhs=0,
                                    ),
                                    {
                                        DCERPC_Transport.NCACN_IP_TCP: (
                                            prot_and_addr_t(
                                                lhs_length=1,
                                                protocol_identifier="NCACN_IP_TCP",
                                                rhs_length=2,
                                                rhs=135,
                                            )
                                        ),
                                        DCERPC_Transport.NCACN_NP: (
                                            prot_and_addr_t(
                                                lhs_length=1,
                                                protocol_identifier="NCACN_NP",
                                                rhs_length=2,
                                                rhs=b"0\x00",
                                            )
                                        ),
                                    }[self.transport],
                                    {
                                        DCERPC_Transport.NCACN_IP_TCP: (
                                            prot_and_addr_t(
                                                lhs_length=1,
                                                protocol_identifier="IP",
                                                rhs_length=4,
                                                rhs="0.0.0.0",
                                            )
                                        ),
                                        DCERPC_Transport.NCACN_NP: (
                                            prot_and_addr_t(
                                                lhs_length=1,
                                                protocol_identifier="NCACN_NB",
                                                rhs_length=10,
                                                rhs=b"127.0.0.1\x00",
                                            )
                                        ),
                                    }[self.transport],
                                ],
                            )
                        ),
                    ),
                ),
                entry_handle=NDRContextHandle(
                    attributes=0,
                    uuid=b"\x00" * 16,
                ),
                max_towers=500,
                ndr64=self.ndr64,
                ndrendian=self.ndrendian,
            )
        )
        if pkt and ept_map_Response in pkt:
            status = pkt[ept_map_Response].status
            # [MS-RPCE] sect 2.2.1.2.5
            if status == 0x00000000:
                towers = [
                    protocol_tower_t(x.value.tower_octet_string)
                    for x in pkt[ept_map_Response].ITowers.value[0].value
                ]
                # Let's do some checks to know we know what we're doing
                endpoints = []
                for t in towers:
                    if t.floors[0].uuid != interface.uuid:
                        if self.verb:
                            print(
                                conf.color_theme.fail(
                                    "! Server answered with a different interface."
                                )
                            )
                        raise ValueError
                    if t.floors[1].sprintf("%uuid%") != ndr_uuid:
                        if self.verb:
                            print(
                                conf.color_theme.fail(
                                    "! Server answered with a different NDR version."
                                )
                            )
                        raise ValueError
                    if self.transport == DCERPC_Transport.NCACN_IP_TCP:
                        endpoints.append((t.floors[4].rhs, t.floors[3].rhs))
                    elif self.transport == DCERPC_Transport.NCACN_NP:
                        endpoints.append(t.floors[3].rhs.rstrip(b"\x00").decode())
                return endpoints
            elif status == 0x16C9A0D6:
                if self.verb:
                    pkt.show()
                    print(
                        conf.color_theme.fail(
                            "! Server errored: 'There are no elements that satisfy"
                            " the specified search criteria'."
                        )
                    )
                raise ValueError
        print(conf.color_theme.fail("! Failure."))
        if pkt:
            pkt.show()
        raise ValueError("EPM Map failed")


def get_endpoint(
    ip,
    interface,
    transport=DCERPC_Transport.NCACN_IP_TCP,
    ndrendian="little",
    verb=True,
    ssp=None,
    smb_kwargs={},
):
    """
    Call the endpoint mapper on a remote IP to find an interface

    :param ip:
    :param interface:
    :param mode:
    :param verb:
    :param ssp:

    :return: a list of connection tuples for this interface
    """
    client = DCERPC_Client(
        transport,
        # EPM only works with NDR32
        ndr64=False,
        ndrendian=ndrendian,
        verb=verb,
        ssp=ssp,
    )

    if transport == DCERPC_Transport.NCACN_IP_TCP:
        endpoint = 135
    elif transport == DCERPC_Transport.NCACN_NP:
        endpoint = "epmapper"
    else:
        raise ValueError("Unknown transport value !")

    client.connect(ip, endpoint=endpoint, smb_kwargs=smb_kwargs)

    client.bind(find_dcerpc_interface("ept"))
    endpoints = client.epm_map(interface)

    client.close()
    return endpoints
