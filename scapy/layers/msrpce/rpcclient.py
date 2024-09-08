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

from scapy.layers.dcerpc import (
    DceRpc5,
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
    DceRpc5AbstractSyntax,
    DceRpc5TransferSyntax,
    DceRpcSocket,
    DCERPC_Transport,
    find_dcerpc_interface,
    CommonAuthVerifier,
    DCE_C_AUTHN_LEVEL,
    # NDR
    NDRPointer,
    NDRContextHandle,
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


class DCERPC_Client(object):
    """
    A basic DCE/RPC client

    :param ndr64: Should ask for NDR64 when binding (default False)
    """

    def __init__(self, transport, ndr64=False, ndrendian="little", verb=True, **kwargs):
        self.sock = None
        self.transport = transport
        assert isinstance(
            transport, DCERPC_Transport
        ), "transport must be from DCERPC_Transport"
        self.call_id = 0
        self.cont_id = 0
        self.ndr64 = ndr64
        self.ndrendian = ndrendian
        self.verb = verb
        self.auth_level = kwargs.pop("auth_level", DCE_C_AUTHN_LEVEL.NONE)
        self.auth_context_id = kwargs.pop("auth_context_id", 0)
        self.ssp = kwargs.pop("ssp", None)  # type: SSP
        self.sspcontext = None
        self.dcesockargs = kwargs

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
            auth_context_id=client.auth_context_id,
            **client.dcesockargs,
        )
        return client

    def connect(self, ip, port=None, timeout=5, smb_kwargs={}):
        """
        Initiate a connection
        """
        if port is None:
            if self.transport == DCERPC_Transport.NCACN_IP_TCP:  # IP/TCP
                port = 135
            elif self.transport == DCERPC_Transport.NCACN_NP:  # SMB
                port = 445
            else:
                raise ValueError(
                    "Can't guess the port for transport: %s" % self.transport
                )
        sock = socket.socket()
        sock.settimeout(timeout)
        if self.verb:
            print(
                "\u2503 Connecting to %s on port %s via %s..."
                % (ip, port, repr(self.transport))
            )
        sock.connect((ip, port))
        if self.verb:
            print(
                conf.color_theme.green(
                    "\u2514 Connected from %s" % repr(sock.getsockname())
                )
            )
        if self.transport == DCERPC_Transport.NCACN_NP:  # SMB
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
                auth_context_id=self.auth_context_id,
                **self.dcesockargs,
            )

    def close(self):
        if self.verb:
            print("X Connection closed\n")
        self.sock.close()

    def sr1(self, pkt, **kwargs):
        self.call_id += 1
        pkt = (
            DceRpc5(
                call_id=self.call_id,
                pfc_flags="PFC_FIRST_FRAG+PFC_LAST_FRAG",
                endian=self.ndrendian,
                auth_verifier=kwargs.pop("auth_verifier", None),
            )
            / pkt
        )
        if "pfc_flags" in kwargs:
            pkt.pfc_flags = kwargs.pop("pfc_flags")
        return self.sock.sr1(pkt, verbose=0, **kwargs)

    def send(self, pkt, **kwargs):
        self.call_id += 1
        pkt = (
            DceRpc5(
                call_id=self.call_id,
                pfc_flags="PFC_FIRST_FRAG+PFC_LAST_FRAG",
                endian=self.ndrendian,
                auth_verifier=kwargs.pop("auth_verifier", None),
            )
            / pkt
        )
        if "pfc_flags" in kwargs:
            pkt.pfc_flags = kwargs.pop("pfc_flags")
        return self.sock.send(pkt, **kwargs)

    def sr1_req(self, pkt, **kwargs):
        if self.verb:
            print(conf.color_theme.opening(">> REQUEST: %s" % pkt.__class__.__name__))
        # Send/receive
        resp = self.sr1(
            DceRpc5Request(cont_id=self.cont_id, alloc_hint=len(pkt)) / pkt,
            **kwargs,
        )
        if DceRpc5Response in resp:
            if self.verb:
                print(
                    conf.color_theme.success(
                        "<< RESPONSE: %s"
                        % (resp[DceRpc5Response].payload.__class__.__name__)
                    )
                )
            return resp[DceRpc5Response].payload
        else:
            if self.verb:
                if DceRpc5Fault in resp:
                    if resp[DceRpc5Fault].payload and not isinstance(
                        resp[DceRpc5Fault].payload, conf.raw_layer
                    ):
                        resp[DceRpc5Fault].payload.show()
                    if resp.status == 0x00000005:
                        print(conf.color_theme.fail("! nca_s_fault_access_denied"))
                    elif resp.status == 0x00000721:
                        print(
                            conf.color_theme.fail(
                                "! nca_s_fault_sec_pkg_error "
                                "(error in checksum/encryption)"
                            )
                        )
                    else:
                        print(
                            conf.color_theme.fail(
                                "! %s" % STATUS_ERREF.get(resp.status, "Failure")
                            )
                        )
                        resp.show()
                return
            return resp

    def get_bind_context(self, interface):
        return [
            DceRpc5Context(
                cont_id=0,
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
        ] + (
            [
                DceRpc5Context(
                    cont_id=1,
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
                ),
                DceRpc5Context(
                    cont_id=2,
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
                ),
            ]
            if self.ndr64
            else []
        )

    def _bind(self, interface, reqcls, respcls):
        # Build a security context: [MS-RPCE] 3.3.1.5.2
        if self.verb:
            print(
                conf.color_theme.opening(
                    ">> %s on %s" % (reqcls.__name__, interface)
                    + (" (with %s)" % self.ssp.__class__.__name__ if self.ssp else "")
                )
            )
        if not self.ssp or (
            self.transport == DCERPC_Transport.NCACN_NP
            and self.auth_level < DCE_C_AUTHN_LEVEL.PKT_INTEGRITY
        ):
            # NCACN_NP = SMB without INTEGRITY/PRIVACY does not bind the RPC securely,
            # again as it has already authenticated during the SMB Session Setup
            resp = self.sr1(
                reqcls(context_elem=self.get_bind_context(interface)),
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
                ),
            )
            if status not in [GSS_S_CONTINUE_NEEDED, GSS_S_COMPLETE]:
                # Authentication failed.
                self.sspcontext.clifailure()
                return False
            resp = self.sr1(
                reqcls(context_elem=self.get_bind_context(interface)),
                auth_verifier=(
                    None
                    if not self.sspcontext
                    else CommonAuthVerifier(
                        auth_type=self.ssp.auth_type,
                        auth_level=self.auth_level,
                        auth_context_id=self.auth_context_id,
                        auth_value=token,
                    )
                ),
                pfc_flags=(
                    "PFC_FIRST_FRAG+PFC_LAST_FRAG"
                    + (
                        # If the SSP supports "Header Signing", advertise it
                        "+PFC_SUPPORT_HEADER_SIGN"
                        if self.ssp is not None
                        and self.sock.session.support_header_signing
                        else ""
                    )
                ),
            )
            if respcls not in resp:
                token = None
                status = GSS_S_FAILURE
            else:
                # Call the underlying SSP
                self.sspcontext, token, status = self.ssp.GSS_Init_sec_context(
                    self.sspcontext, val=resp.auth_verifier.auth_value
                )
            if status in [GSS_S_CONTINUE_NEEDED, GSS_S_COMPLETE]:
                # Authentication should continue
                if token and self.ssp.LegsAmount(self.sspcontext) % 2 == 1:
                    # AUTH 3 for certain SSPs (e.g. NTLM)
                    # "The server MUST NOT respond to an rpc_auth_3 PDU"
                    self.send(
                        DceRpc5Auth3(),
                        auth_verifier=CommonAuthVerifier(
                            auth_type=self.ssp.auth_type,
                            auth_level=self.auth_level,
                            auth_context_id=self.auth_context_id,
                            auth_value=token,
                        ),
                    )
                    status = GSS_S_COMPLETE
                else:
                    # Authentication can continue in two ways:
                    # - through DceRpc5Auth3 (e.g. NTLM)
                    # - through DceRpc5AlterContext (e.g. Kerberos)
                    while token:
                        respcls = DceRpc5AlterContextResp
                        resp = self.sr1(
                            DceRpc5AlterContext(
                                context_elem=self.get_bind_context(interface)
                            ),
                            auth_verifier=CommonAuthVerifier(
                                auth_type=self.ssp.auth_type,
                                auth_level=self.auth_level,
                                auth_context_id=self.auth_context_id,
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
                            self.sspcontext, val=resp.auth_verifier.auth_value
                        )
        # Check context acceptance
        if (
            status == GSS_S_COMPLETE
            and respcls in resp
            and any(x.result == 0 for x in resp.results[: int(self.ndr64) + 1])
        ):
            self.call_id = 0  # reset call id
            port = resp.sec_addr.port_spec.decode()
            ndr = self.sock.session.ndr64 and "NDR64" or "NDR32"
            self.cont_id = int(self.sock.session.ndr64)  # ctx 0 for NDR32, 1 for NDR64
            if self.verb:
                print(
                    conf.color_theme.success(
                        f"<< {respcls.__name__} port '{port}' using {ndr}"
                    )
                )
            self.sock.session.sspcontext = self.sspcontext
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
                    if resp.status == 0x00000005:
                        print(conf.color_theme.fail("! nca_s_fault_access_denied"))
                    elif resp.status == 0x00000721:
                        print(
                            conf.color_theme.fail(
                                "! nca_s_fault_sec_pkg_error "
                                "(error in checksum/encryption)"
                            )
                        )
                    else:
                        print(
                            conf.color_theme.fail(
                                "! %s" % STATUS_ERREF.get(resp.status, "Failure")
                            )
                        )
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

    def bind(self, interface):
        """
        Bind the client to an interface
        """
        return self._bind(interface, DceRpc5Bind, DceRpc5BindAck)

    def alter_context(self, interface):
        """
        Alter context: post-bind context negotiation
        """
        return self._bind(interface, DceRpc5AlterContext, DceRpc5AlterContextResp)

    def bind_or_alter(self, interface):
        """
        Bind the client to an interface or alter the context if already bound
        """
        if not self.sock.session.rpc_bind_interface:
            # No interface is bound
            self.bind(interface)
        else:
            # An interface is already bound
            self.alter_context(interface)

    def open_smbpipe(self, name):
        """
        Open a certain filehandle with the SMB automaton
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
        ip,
        interface,
        port=None,
        smb_kwargs={},
    ):
        """
        Asks the Endpoint Mapper what address to use to connect to the interface,
        then uses connect() followed by a bind()
        """
        if self.transport == DCERPC_Transport.NCACN_IP_TCP:
            # IP/TCP
            # 1. ask the endpoint mapper (port 135) for the IP:PORT
            endpoints = get_endpoint(
                ip,
                interface,
                ndrendian=self.ndrendian,
                verb=self.verb,
            )
            if endpoints:
                ip, port = endpoints[0]
            else:
                return
            # 2. Connect to that IP:PORT
            self.connect(ip, port=port)
        elif self.transport == DCERPC_Transport.NCACN_NP:
            # SMB
            # 1. ask the endpoint mapper (over SMB) for the namedpipe
            endpoints = get_endpoint(
                ip,
                interface,
                transport=self.transport,
                ndrendian=self.ndrendian,
                verb=self.verb,
                smb_kwargs=smb_kwargs,
            )
            if endpoints:
                pipename = endpoints[0].lstrip("\\pipe\\")
            else:
                return
            # 2. connect to the SMB server
            self.connect(ip, port=port, smb_kwargs=smb_kwargs)
            # 3. open the new named pipe
            self.open_smbpipe(pipename)
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
    smb_kwargs={},
):
    """
    Call the endpoint mapper on a remote IP to find an interface

    :param ip:
    :param interface:
    :param mode:
    :param verb:

    :return: a list of connection tuples for this interface
    """
    client = DCERPC_Client(
        transport,
        ndr64=False,
        ndrendian=ndrendian,
        verb=verb,
    )  # EPM only works with NDR32
    client.connect(ip, smb_kwargs=smb_kwargs)
    if transport == DCERPC_Transport.NCACN_NP:  # SMB
        client.open_smbpipe("epmapper")
    client.bind(find_dcerpc_interface("ept"))
    endpoints = client.epm_map(interface)
    client.close()
    return endpoints
