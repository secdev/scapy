# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
SMB 1 / 2 Client Automaton
"""

from scapy.automaton import ATMT, Automaton
from scapy.layers.ntlm import (
    NTLM_AUTHENTICATE,
    NTLM_AUTHENTICATE_V2,
    NTLM_NEGOTIATE,
    NTLM_Client,
)
from scapy.packet import Raw
from scapy.volatile import RandUUID

from scapy.layers.netbios import NBTSession
from scapy.layers.gssapi import (
    GSSAPI_BLOB,
    SPNEGO_MechListMIC,
    SPNEGO_MechType,
    SPNEGO_Token,
    SPNEGO_negToken,
    SPNEGO_negTokenInit,
    SPNEGO_negTokenResp,
)
from scapy.layers.smb import (
    SMB_Header,
    SMB_Dialect,
    SMBNegotiate_Request,
    SMBNegotiate_Response_Security,
    SMBNegotiate_Response_Extended_Security,
    SMBSession_Null,
    SMBSession_Setup_AndX_Request,
    SMBSession_Setup_AndX_Request_Extended_Security,
    SMBSession_Setup_AndX_Response,
    SMBSession_Setup_AndX_Response_Extended_Security,
    SMBTree_Connect_AndX,
)
from scapy.layers.smb2 import (
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Negotiate_Protocol_Response,
    SMB2_Session_Setup_Request,
    SMB2_Session_Setup_Response,
    SMB2_Tree_Connect_Request,
)
from scapy.layers.smbserver import NTLM_SMB_Server


class NTLM_SMB_Client(NTLM_Client, Automaton):
    port = 445
    cls = NBTSession
    kwargs_cls = {
        NTLM_SMB_Server: {"CLIENT_PROVIDES_NEGOEX": True, "ECHO": True}
    }

    def __init__(self, *args, **kwargs):
        self.EXTENDED_SECURITY = kwargs.pop("EXTENDED_SECURITY", True)
        self.ALLOW_SMB2 = kwargs.pop("ALLOW_SMB2", True)
        self.REAL_HOSTNAME = kwargs.pop("REAL_HOSTNAME", None)
        self.RETURN_SOCKET = kwargs.pop("RETURN_SOCKET", None)
        self.RUN_SCRIPT = kwargs.pop("RUN_SCRIPT", None)
        self.SMB2 = False
        super(NTLM_SMB_Client, self).__init__(*args, **kwargs)

    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    @ATMT.condition(BEGIN)
    def continue_smb2(self):
        kwargs = self.wait_server()
        self.CONTINUE_SMB2 = kwargs.pop("CONTINUE_SMB2", False)
        self.SMB2_INIT_PARAMS = kwargs.pop("SMB2_INIT_PARAMS", {})
        if self.CONTINUE_SMB2:
            self.SMB2 = True
            self.smb_header = NBTSession() / SMB2_Header(
                PID=0xfeff
            )
            raise self.SMB2_NEGOTIATE()

    @ATMT.condition(BEGIN, prio=1)
    def send_negotiate(self):
        raise self.SENT_NEGOTIATE()

    @ATMT.action(send_negotiate)
    def on_negotiate(self):
        self.smb_header = NBTSession() / SMB_Header(
            Flags2=(
                "LONG_NAMES+EAS+NT_STATUS+UNICODE+"
                "SMB_SECURITY_SIGNATURE+EXTENDED_SECURITY"
            ),
            TID=0xFFFF,
            PIDLow=0xFEFF,
            UID=0,
            MID=0
        )
        if self.EXTENDED_SECURITY:
            self.smb_header.Flags2 += "EXTENDED_SECURITY"
        pkt = self.smb_header.copy() / SMBNegotiate_Request(
            Dialects=[SMB_Dialect(DialectString=x) for x in [
                "PC NETWORK PROGRAM 1.0", "LANMAN1.0",
                "Windows for Workgroups 3.1a", "LM1.2X002", "LANMAN2.1",
                "NT LM 0.12"
            ] + (["SMB 2.002", "SMB 2.???"] if self.ALLOW_SMB2 else [])
            ],
        )
        if not self.EXTENDED_SECURITY:
            pkt.Flags2 -= "EXTENDED_SECURITY"
        pkt[SMB_Header].Flags2 = pkt[SMB_Header].Flags2 - \
            "SMB_SECURITY_SIGNATURE" + \
            "SMB_SECURITY_SIGNATURE_REQUIRED+IS_LONG_NAME"
        self.send(pkt)

    @ATMT.state()
    def SENT_NEGOTIATE(self):
        pass

    @ATMT.receive_condition(SENT_NEGOTIATE)
    def receive_negotiate_response(self, pkt):
        if SMBNegotiate_Response_Security in pkt or\
                SMBNegotiate_Response_Extended_Security in pkt or\
                SMB2_Negotiate_Protocol_Response in pkt:
            self.set_srv(
                "ServerTime",
                pkt.ServerTime
            )
            self.set_srv(
                "SecurityMode",
                pkt.SecurityMode
            )
            if SMB2_Negotiate_Protocol_Response in pkt:
                # SMB2
                self.SMB2 = True  # We are using SMB2 to talk to the server
                self.smb_header = NBTSession() / SMB2_Header(
                    PID=0xfeff
                )
            else:
                # SMB1
                self.set_srv(
                    "ServerTimeZone",
                    pkt.ServerTimeZone
                )
        if SMBNegotiate_Response_Extended_Security in pkt or\
                SMB2_Negotiate_Protocol_Response in pkt:
            # Extended SMB1 / SMB2
            negoex_tuple = self._get_token(
                pkt.SecurityBlob
            )
            self.set_srv(
                "GUID",
                pkt.GUID
            )
            self.received_ntlm_token(negoex_tuple)
            if SMB2_Negotiate_Protocol_Response in pkt and \
                    pkt.DialectRevision in [0x02ff, 0x03ff]:
                # There will be a second negotiate protocol request
                self.smb_header.MID += 1
                raise self.SMB2_NEGOTIATE()
            else:
                raise self.NEGOTIATED()
        elif SMBNegotiate_Response_Security in pkt:
            # Non-extended SMB1
            self.set_srv("Challenge", pkt.Challenge)
            self.set_srv("DomainName", pkt.DomainName)
            self.set_srv("ServerName", pkt.ServerName)
            self.received_ntlm_token((None, None, None, None))
            raise self.NEGOTIATED()

    @ATMT.state()
    def SMB2_NEGOTIATE(self):
        pass

    @ATMT.condition(SMB2_NEGOTIATE)
    def send_negotiate_smb2(self):
        raise self.SENT_NEGOTIATE()

    @ATMT.action(send_negotiate_smb2)
    def on_negotiate_smb2(self):
        pkt = self.smb_header.copy() / SMB2_Negotiate_Protocol_Request(
            # Only ask for SMB 2.0.2 because it has the lowest security
            Dialects=[0x0202],
            Capabilities=(
                "DFS+Leasing+LargeMTU+MultiChannel+"
                "PersistentHandles+DirectoryLeasing+Encryption"
            ),
            SecurityMode=0,
            ClientGUID=self.SMB2_INIT_PARAMS.get("ClientGUID", RandUUID()),
        )
        self.send(pkt)

    @ATMT.state()
    def NEGOTIATED(self):
        pass

    @ATMT.condition(NEGOTIATED)
    def should_send_setup_andx_request(self):
        ntlm_tuple = self.get_token()
        raise self.SENT_SETUP_ANDX_REQUEST().action_parameters(ntlm_tuple)

    @ATMT.state()
    def SENT_SETUP_ANDX_REQUEST(self):
        pass

    @ATMT.action(should_send_setup_andx_request)
    def send_setup_andx_request(self, ntlm_tuple):
        ntlm_token, negResult, MIC, rawToken = ntlm_tuple
        self.smb_header.MID = self.get("MID")
        self.smb_header.TID = self.get("TID")
        if self.SMB2:
            self.smb_header.AsyncId = self.get("AsyncId")
            self.smb_header.SessionId = self.get("SessionId")
        else:
            self.smb_header.UID = self.get("UID", 0)
        if self.SMB2 or self.EXTENDED_SECURITY:
            # SMB1 extended / SMB2
            if self.SMB2:
                # SMB2
                pkt = self.smb_header.copy() / SMB2_Session_Setup_Request(
                    Capabilities="DFS",
                    SecurityMode=0,
                )
                pkt.CreditsRequested = 33
            else:
                # SMB1 extended
                pkt = self.smb_header.copy() / \
                    SMBSession_Setup_AndX_Request_Extended_Security(
                        ServerCapabilities=(
                            "UNICODE+NT_SMBS+STATUS32+LEVEL_II_OPLOCKS+"
                            "DYNAMIC_REAUTH+EXTENDED_SECURITY"
                        ),
                        VCNumber=self.get("VCNumber"),
                        NativeOS=b"",
                        NativeLanMan=b""
                )
            pkt.SecuritySignature = self.get("SecuritySignature")
            if isinstance(ntlm_token, NTLM_NEGOTIATE):
                if rawToken:
                    pkt.SecurityBlob = ntlm_token
                else:
                    pkt.SecurityBlob = GSSAPI_BLOB(
                        innerContextToken=SPNEGO_negToken(
                            token=SPNEGO_negTokenInit(
                                mechTypes=[
                                    # NTLMSSP
                                    SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.10")],  # noqa: E501
                                mechToken=SPNEGO_Token(
                                    value=ntlm_token
                                )
                            )
                        )
                    )
            elif isinstance(ntlm_token, (NTLM_AUTHENTICATE,
                                         NTLM_AUTHENTICATE_V2)):
                pkt.SecurityBlob = SPNEGO_negToken(
                    token=SPNEGO_negTokenResp(
                        negResult=negResult,
                    )
                )
                # Token may be missing (e.g. STATUS_MORE_PROCESSING_REQUIRED)
                if ntlm_token:
                    pkt.SecurityBlob.token.responseToken = SPNEGO_Token(
                        value=ntlm_token
                    )
                if MIC and not self.DROP_MIC:  # Drop the MIC?
                    pkt.SecurityBlob.token.mechListMIC = SPNEGO_MechListMIC(
                        value=MIC
                    )
        else:
            # Non-extended security
            pkt = self.smb_header.copy() / SMBSession_Setup_AndX_Request(
                ServerCapabilities="UNICODE+NT_SMBS+STATUS32+LEVEL_II_OPLOCKS",
                VCNumber=self.get("VCNumber"),
                NativeOS=b"",
                NativeLanMan=b"",
                OEMPassword=b"\0" * 24,
                UnicodePassword=ntlm_token,
                PrimaryDomain=self.get("PrimaryDomain"),
                AccountName=self.get("AccountName"),
            ) / SMBTree_Connect_AndX(
                Flags="EXTENDED_RESPONSE",
                Password=b"\0",
            )
            pkt.PrimaryDomain = self.get("PrimaryDomain")
            pkt.AccountName = self.get("AccountName")
            pkt.Path = (
                "\\\\%s\\" % self.REAL_HOSTNAME +
                self.get("Path")[2:].split("\\", 1)[1]
            )
            pkt.Service = self.get("Service")
        self.send(pkt)

    @ATMT.receive_condition(SENT_SETUP_ANDX_REQUEST)
    def receive_setup_andx_response(self, pkt):
        if SMBSession_Null in pkt or \
                SMBSession_Setup_AndX_Response_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Response in pkt:
            # SMB1
            self.set_srv("Status", pkt[SMB_Header].Status)
            self.set_srv(
                "UID",
                pkt[SMB_Header].UID
            )
            self.set_srv(
                "MID",
                pkt[SMB_Header].MID
            )
            self.set_srv(
                "TID",
                pkt[SMB_Header].TID
            )
            if SMBSession_Null in pkt:
                # Likely an error
                self.received_ntlm_token((None, None, None, None))
                raise self.NEGOTIATED()
            elif SMBSession_Setup_AndX_Response_Extended_Security in pkt or \
                    SMBSession_Setup_AndX_Response in pkt:
                self.set_srv(
                    "NativeOS",
                    pkt.getfieldval(
                        "NativeOS")
                )
                self.set_srv(
                    "NativeLanMan",
                    pkt.getfieldval(
                        "NativeLanMan")
                )
        if SMB2_Session_Setup_Response in pkt:
            # SMB2
            self.set_srv("Status", pkt.Status)
            self.set_srv("SecuritySignature", pkt.SecuritySignature)
            self.set_srv("MID", pkt.MID)
            self.set_srv("TID", pkt.TID)
            self.set_srv("AsyncId", pkt.AsyncId)
            self.set_srv("SessionId", pkt.SessionId)
        if SMBSession_Setup_AndX_Response_Extended_Security in pkt or \
                SMB2_Session_Setup_Response in pkt:
            # SMB1 extended / SMB2
            _, negResult, _, _ = ntlm_tuple = self._get_token(
                pkt.SecurityBlob
            )
            if negResult == 0:  # Authenticated
                self.received_ntlm_token(ntlm_tuple)
                raise self.AUTHENTICATED()
            else:
                self.received_ntlm_token(ntlm_tuple)
                raise self.NEGOTIATED().action_parameters(pkt)
        elif SMBSession_Setup_AndX_Response_Extended_Security in pkt:
            # SMB1 non-extended
            pass

    @ATMT.state()
    def AUTHENTICATED(self):
        pass

    @ATMT.condition(AUTHENTICATED, prio=0)
    def authenticated_post_actions(self):
        if self.RETURN_SOCKET:
            raise self.SOCKET_MODE()
        if self.RUN_SCRIPT:
            raise self.DO_RUN_SCRIPT()

    @ATMT.receive_condition(AUTHENTICATED, prio=1)
    def receive_packet(self, pkt):
        raise self.AUTHENTICATED().action_parameters(pkt)

    @ATMT.action(receive_packet)
    def pass_packet(self, pkt):
        self.echo(pkt)

    @ATMT.state(final=1)
    def DO_RUN_SCRIPT(self):
        # This is an example script, mostly unimplemented...
        # Tree connect
        self.smb_header.MID += 1
        self.send(
            self.smb_header.copy() /
            SMB2_Tree_Connect_Request(
                Buffer=[('Path', '\\\\%s\\IPC$' % self.REAL_HOSTNAME)]
            )
        )
        # Create srvsvc
        self.smb_header.MID += 1
        pkt = self.smb_header.copy()
        pkt.Command = "SMB2_CREATE"
        pkt /= Raw(load=b'9\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9f\x01\x12\x00\x00\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00x\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00s\x00r\x00v\x00s\x00v\x00c\x00')  # noqa: E501
        self.send(pkt)
        # ... run something?
        self.end()

    @ATMT.state()
    def SOCKET_MODE(self):
        pass

    @ATMT.receive_condition(SOCKET_MODE)
    def incoming_data_received(self, pkt):
        raise self.SOCKET_MODE().action_parameters(pkt)

    @ATMT.action(incoming_data_received)
    def receive_data(self, pkt):
        self.oi.smbpipe.send(bytes(pkt))

    @ATMT.ioevent(SOCKET_MODE, name="smbpipe", as_supersocket="smblink")
    def outgoing_data_received(self, fd):
        raise self.ESTABLISHED().action_parameters(fd.recv())

    @ATMT.action(outgoing_data_received)
    def send_data(self, d):
        self.smb_header.MID += 1
        self.send(self.smb_header.copy() / d)
