# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
SMB 1 / 2 Server Automaton
"""

import time

from scapy.automaton import ATMT, Automaton
from scapy.layers.ntlm import (
    NTLM_CHALLENGE,
    NTLM_Server,
)
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
    SMB2_FILEID,
    SMB2_Close_Request,
    SMB2_Close_Response,
    SMB2_Create_Request,
    SMB2_Create_Response,
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Negotiate_Protocol_Response,
    SMB2_Query_Info_Request,
    SMB2_Query_Info_Response,
    SMB2_Read_Request,
    SMB2_Read_Response,
    SMB2_Session_Setup_Request,
    SMB2_Session_Setup_Response,
    SMB2_IOCTL_Request,
    SMB2_Error_Response,
    SMB2_Tree_Connect_Request,
    SMB2_Tree_Connect_Response,
    FileStandardInformation,
    SMB2_Write_Request,
    SMB2_Write_Response,
)


class NTLM_SMB_Server(NTLM_Server, Automaton):
    port = 445
    cls = NBTSession

    def __init__(self, *args, **kwargs):
        self.CLIENT_PROVIDES_NEGOEX = kwargs.pop(
            "CLIENT_PROVIDES_NEGOEX", False)
        self.ECHO = kwargs.pop("ECHO", False)
        self.SERVE_FILES = kwargs.pop("SERVE_FILES", [])
        self.ANONYMOUS_LOGIN = kwargs.pop("ANONYMOUS_LOGIN", False)
        self.GUEST_LOGIN = kwargs.pop("GUEST_LOGIN", False)
        self.PASS_NEGOEX = kwargs.pop("PASS_NEGOEX", False)
        self.EXTENDED_SECURITY = kwargs.pop("EXTENDED_SECURITY", True)
        self.ALLOW_SMB2 = kwargs.pop("ALLOW_SMB2", True)
        self.REQUIRE_SIGNATURE = kwargs.pop("REQUIRE_SIGNATURE", False)
        self.REAL_HOSTNAME = kwargs.pop(
            "REAL_HOSTNAME", None)  # Compulsory for SMB1 !!!
        assert self.ALLOW_SMB2 or \
            self.REAL_HOSTNAME, "SMB1 requires REAL_HOSTNAME !"
        # Session information
        self.SMB2 = False
        self.Dialect = None
        super(NTLM_SMB_Server, self).__init__(*args, **kwargs)

    def send(self, pkt):
        if self.Dialect and self.SigningSessionKey:
            if isinstance(pkt.payload, SMB2_Header):
                # Sign SMB2 !
                smb = pkt[SMB2_Header]
                smb.Flags += "SMB2_FLAGS_SIGNED"
                smb.sign(self.Dialect, self.SigningSessionKey)
        return super(NTLM_SMB_Server, self).send(pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        self.authenticated = False
        assert \
            not self.ECHO or self.cli_atmt, \
            "Cannot use ECHO without binding to a client !"
        assert \
            not (self.cli_atmt and self.SERVE_FILES), \
            "Cannot use SERVE_FILES if a client is bound !"

    @ATMT.receive_condition(BEGIN)
    def received_negotiate(self, pkt):
        if SMBNegotiate_Request in pkt:
            if self.cli_atmt:
                self.start_client()
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.receive_condition(BEGIN)
    def received_negotiate_smb2_begin(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            self.SMB2 = True
            if self.cli_atmt:
                self.start_client(
                    CONTINUE_SMB2=True,
                    SMB2_INIT_PARAMS={
                        "ClientGUID": pkt.ClientGUID
                    }
                )
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2_begin)
    def on_negotiate_smb2_begin(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.action(received_negotiate)
    def on_negotiate(self, pkt):
        if self.CLIENT_PROVIDES_NEGOEX:
            negoex_token, _, _, _ = self.get_token(negoex=True)
        else:
            negoex_token = None
        if not self.SMB2 and not self.get("GUID", 0):
            self.EXTENDED_SECURITY = False
        # Build negotiate response
        DialectIndex = None
        DialectRevision = None
        if SMB2_Negotiate_Protocol_Request in pkt:
            # SMB2
            DialectRevisions = pkt[SMB2_Negotiate_Protocol_Request].Dialects
            DialectRevisions.sort()
            DialectRevision = DialectRevisions[0]
            if DialectRevision >= 0x300:  # SMB3
                raise ValueError(
                    "SMB client requires SMB3 which is unimplemented.")
        else:
            DialectIndexes = [
                x.DialectString for x in pkt[SMBNegotiate_Request].Dialects
            ]
            if self.ALLOW_SMB2:
                # Find a value matching SMB2, fallback to SMB1
                for key, rev in [(b"SMB 2.???", 0x02ff),
                                 (b"SMB 2.002", 0x0202)]:
                    try:
                        DialectIndex = DialectIndexes.index(key)
                        DialectRevision = rev
                        self.SMB2 = True
                        break
                    except ValueError:
                        pass
                else:
                    DialectIndex = DialectIndexes.index(b"NT LM 0.12")
            else:
                # Enforce SMB1
                DialectIndex = DialectIndexes.index(b"NT LM 0.12")
        if DialectRevision and DialectRevision & 0xff != 0xff:
            # Version isn't SMB X.???
            self.Dialect = DialectRevision
        cls = None
        if self.SMB2:
            # SMB2
            cls = SMB2_Negotiate_Protocol_Response
            self.smb_header = NBTSession() / SMB2_Header(
                CreditsRequested=1,
            )
            if SMB2_Negotiate_Protocol_Request in pkt:
                self.smb_header.MID = pkt.MID
                self.smb_header.TID = pkt.TID
                self.smb_header.AsyncId = pkt.AsyncId
                self.smb_header.SessionId = pkt.SessionId
        else:
            # SMB1
            self.smb_header = NBTSession() / SMB_Header(
                Flags="REPLY+CASE_INSENSITIVE+CANONICALIZED_PATHS",
                Flags2=(
                    "LONG_NAMES+EAS+NT_STATUS+SMB_SECURITY_SIGNATURE+"
                    "UNICODE+EXTENDED_SECURITY"
                ),
                TID=pkt.TID,
                MID=pkt.MID,
                UID=pkt.UID,
                PIDLow=pkt.PIDLow
            )
            if self.EXTENDED_SECURITY:
                cls = SMBNegotiate_Response_Extended_Security
            else:
                cls = SMBNegotiate_Response_Security
        if self.SMB2:
            # SMB2
            resp = self.smb_header.copy() / cls(
                DialectRevision=DialectRevision,
                Capabilities="DFS",
                SecurityMode=3 if self.REQUIRE_SIGNATURE else 0,
                # self.get("SecurityMode", 1),
                ServerTime=self.get("ServerTime", time.time() + 11644473600),
                ServerStartTime=0,
                MaxTransactionSize=65536,
                MaxReadSize=65536,
                MaxWriteSize=65536,
            )
        else:
            # SMB1
            resp = self.smb_header.copy() / cls(
                DialectIndex=DialectIndex,
                ServerCapabilities=(
                    "UNICODE+LARGE_FILES+NT_SMBS+RPC_REMOTE_APIS+STATUS32+"
                    "LEVEL_II_OPLOCKS+LOCK_AND_READ+NT_FIND+"
                    "LWIO+INFOLEVEL_PASSTHRU+LARGE_READX+LARGE_WRITEX"
                ),
                SecurityMode=(
                    3 if self.REQUIRE_SIGNATURE
                    else self.get("SecurityMode", 1)),
                ServerTime=self.get("ServerTime"),
                ServerTimeZone=self.get("ServerTimeZone")
            )
            if self.EXTENDED_SECURITY:
                resp.ServerCapabilities += "EXTENDED_SECURITY"
        if self.EXTENDED_SECURITY or self.SMB2:
            # Extended SMB1 / SMB2
            # Add security blob
            resp.SecurityBlob = GSSAPI_BLOB(
                innerContextToken=SPNEGO_negToken(
                    token=SPNEGO_negTokenInit(
                        mechTypes=[
                            # NEGOEX - Optional. See below
                            # NTLMSSP
                            SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.10")],

                    )
                )
            )
            resp.GUID = self.get("GUID", RandUUID())
            if self.PASS_NEGOEX:  # NEGOEX handling
                # NOTE: NegoEX has an effect on how the SecurityContext is
                # initialized, as detailed in [MS-AUTHSOD] sect 3.3.2
                # But the format that the Exchange token uses appears not to
                # be documented :/
                resp.SecurityBlob.innerContextToken.token.mechTypes.insert(
                    0,
                    # NEGOEX
                    SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.30"),
                )
                resp.SecurityBlob.innerContextToken.token.mechToken = SPNEGO_Token(  # noqa: E501
                    value=negoex_token
                )
        else:
            # Non-extended SMB1
            resp.Challenge = self.get("Challenge")
            resp.DomainName = self.get("DomainName")
            resp.ServerName = self.get("ServerName")
            resp.Flags2 -= "EXTENDED_SECURITY"
        if not self.SMB2:
            resp[SMB_Header].Flags2 = resp[SMB_Header].Flags2 - \
                "SMB_SECURITY_SIGNATURE" + \
                "SMB_SECURITY_SIGNATURE_REQUIRED+IS_LONG_NAME"
        self.send(resp)

    @ATMT.state()
    def NEGOTIATED(self):
        pass

    @ATMT.receive_condition(NEGOTIATED)
    def received_negotiate_smb2(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2)
    def on_negotiate_smb2(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.receive_condition(NEGOTIATED)
    def receive_setup_andx_request(self, pkt):
        if SMBSession_Setup_AndX_Request_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Request in pkt:
            # SMB1
            if SMBSession_Setup_AndX_Request_Extended_Security in pkt:
                # Extended
                ntlm_tuple = self._get_token(
                    pkt.SecurityBlob
                )
            else:
                # Non-extended
                self.set_cli("AccountName", pkt.AccountName)
                self.set_cli("PrimaryDomain",
                             pkt.PrimaryDomain)
                self.set_cli("Path", pkt.Path)
                self.set_cli("Service", pkt.Service)
                ntlm_tuple = self._get_token(
                    pkt[SMBSession_Setup_AndX_Request].UnicodePassword
                )
            self.set_cli("VCNumber", pkt.VCNumber)
            self.set_cli("SecuritySignature", pkt.SecuritySignature)
            self.set_cli("UID", pkt.UID)
            self.set_cli("MID", pkt.MID)
            self.set_cli("TID", pkt.TID)
            self.received_ntlm_token(ntlm_tuple)
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt)
        elif SMB2_Session_Setup_Request in pkt:
            # SMB2
            ntlm_tuple = self._get_token(pkt.SecurityBlob)
            self.set_cli("SecuritySignature", pkt.SecuritySignature)
            self.set_cli("MID", pkt.MID)
            self.set_cli("TID", pkt.TID)
            self.set_cli("AsyncId", pkt.AsyncId)
            self.set_cli("SessionId", pkt.SessionId)
            self.set_cli("SecurityMode", pkt.SecurityMode)
            self.received_ntlm_token(ntlm_tuple)
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt)

    @ATMT.state()
    def RECEIVED_SETUP_ANDX_REQUEST(self):
        pass

    @ATMT.action(receive_setup_andx_request)
    def on_setup_andx_request(self, pkt):
        ntlm_token, negResult, MIC, rawToken = ntlm_tuple = self.get_token()
        # rawToken == whether the GSSAPI ASN.1 wrapper is used
        # typically, when a SMB session **falls back** to NTLM, no
        # wrapper is used
        if SMBSession_Setup_AndX_Request_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Request in pkt or\
                SMB2_Session_Setup_Request in pkt:
            if SMB2_Session_Setup_Request in pkt:
                # SMB2
                self.smb_header.MID = self.get(
                    "MID", self.smb_header.MID + 1)
                self.smb_header.TID = self.get(
                    "TID", self.smb_header.TID)
                if self.smb_header.Flags.SMB2_FLAGS_ASYNC_COMMAND:
                    self.smb_header.AsyncId = self.get(
                        "AsyncId", self.smb_header.AsyncId)
                self.smb_header.SessionId = self.get(
                    "SessionId", self.smb_header.SessionId)
            else:
                # SMB1
                self.smb_header.UID = self.get("UID")
                self.smb_header.MID = self.get("MID")
                self.smb_header.TID = self.get("TID")
            if ntlm_tuple == (None, None, None, None):
                # Error
                if SMB2_Session_Setup_Request in pkt:
                    # SMB2
                    resp = self.smb_header.copy() / \
                        SMB2_Session_Setup_Response()
                else:
                    # SMB1
                    resp = self.smb_header.copy() / SMBSession_Null()
                resp.Status = self.get("Status", 0xc000006d)
            else:
                # Negotiation
                if SMBSession_Setup_AndX_Request_Extended_Security in pkt or\
                        SMB2_Session_Setup_Request in pkt:
                    # SMB1 extended / SMB2
                    if SMB2_Session_Setup_Request in pkt:
                        # SMB2
                        resp = self.smb_header.copy() / \
                            SMB2_Session_Setup_Response()
                        if self.GUEST_LOGIN:
                            resp.SessionFlags = "IS_GUEST"
                        if self.ANONYMOUS_LOGIN:
                            resp.SessionFlags = "IS_NULL"
                    else:
                        # SMB1 extended
                        resp = self.smb_header.copy() / \
                            SMBSession_Setup_AndX_Response_Extended_Security(
                                NativeOS=self.get("NativeOS"),
                                NativeLanMan=self.get("NativeLanMan")
                        )
                        if self.GUEST_LOGIN:
                            resp.Action = "SMB_SETUP_GUEST"
                    if not ntlm_token:
                        # No token (e.g. accepted)
                        resp.SecurityBlob = SPNEGO_negToken(
                            token=SPNEGO_negTokenResp(
                                negResult=negResult,
                            )
                        )
                        if MIC and not self.DROP_MIC:  # Drop the MIC?
                            resp.SecurityBlob.token.mechListMIC = SPNEGO_MechListMIC(  # noqa: E501
                                value=MIC
                            )
                        if negResult == 0:
                            self.authenticated = True
                    elif isinstance(ntlm_token, NTLM_CHALLENGE) \
                            and not rawToken:
                        resp.SecurityBlob = SPNEGO_negToken(
                            token=SPNEGO_negTokenResp(
                                negResult=1,
                                supportedMech=SPNEGO_MechType(
                                    # NTLMSSP
                                    oid="1.3.6.1.4.1.311.2.2.10"),
                                responseToken=SPNEGO_Token(
                                    value=ntlm_token
                                )
                            )
                        )
                    else:
                        # Token is raw or unknown
                        resp.SecurityBlob = ntlm_token
                elif SMBSession_Setup_AndX_Request in pkt:
                    # Non-extended
                    resp = self.smb_header.copy() / \
                        SMBSession_Setup_AndX_Response(
                            NativeOS=self.get("NativeOS"),
                            NativeLanMan=self.get("NativeLanMan")
                    )
                resp.Status = self.get(
                    "Status", 0x0 if self.authenticated else 0xc0000016)
        self.send(resp)

    @ATMT.condition(RECEIVED_SETUP_ANDX_REQUEST)
    def wait_for_next_request(self):
        if self.authenticated:
            raise self.AUTHENTICATED()
        else:
            raise self.NEGOTIATED()

    @ATMT.state()
    def AUTHENTICATED(self):
        """Dev: overload this"""
        pass

    @ATMT.condition(AUTHENTICATED, prio=0)
    def should_serve(self):
        if self.SERVE_FILES:
            # Serve files
            raise self.SERVING()

    @ATMT.condition(AUTHENTICATED, prio=1)
    def should_end(self):
        if not self.ECHO:
            # Close connection
            raise self.END()

    @ATMT.receive_condition(AUTHENTICATED, prio=2)
    def receive_packet_echo(self, pkt):
        if self.ECHO:
            raise self.AUTHENTICATED().action_parameters(pkt)

    def _response_validate_negotiate_info(self):
        pkt = self.smb_header.copy() / \
            SMB2_Error_Response(ErrorData=b"\xff")
        pkt.Status = "STATUS_NOT_SUPPORTED"
        pkt.Command = "SMB2_IOCTL"
        self.send(pkt)

    @ATMT.action(receive_packet_echo)
    def pass_packet(self, pkt):
        # Pre-process some of the data if possible
        pkt.show()
        if not self.SMB2:
            # SMB1 - no signature (disabled by our implementation)
            if SMBTree_Connect_AndX in pkt and self.REAL_HOSTNAME:
                pkt.LENGTH = None
                pkt.ByteCount = None
                pkt.Path = (
                    "\\\\%s\\" % self.REAL_HOSTNAME +
                    pkt.Path[2:].split("\\", 1)[1]
                )
        else:
            self.smb_header.MID += 1
            # SMB2
            if SMB2_IOCTL_Request in pkt and pkt.CtlCode == 0x00140204:
                # FSCTL_VALIDATE_NEGOTIATE_INFO
                # This is a security measure asking the server to validate
                # what flags were negotiated during the SMBNegotiate exchange.
                # This packet is ALWAYS signed, and expects a signed response.

                # https://docs.microsoft.com/en-us/archive/blogs/openspecification/smb3-secure-dialect-negotiation
                # > "Down-level servers (pre-Windows 2012) will return
                # > STATUS_NOT_SUPPORTED or STATUS_INVALID_DEVICE_REQUEST
                # > since they do not allow or implement
                # > FSCTL_VALIDATE_NEGOTIATE_INFO.
                # > The client should accept the
                # > response provided it's properly signed".

                # Since we can't sign the response, modern clients will abort
                # the connection after receiving this, despite our best
                # efforts...
                self._response_validate_negotiate_info()
                return
        self.echo(pkt)

    @ATMT.state()
    def SERVING(self):
        """
        Main state when serving files
        """
        pass

    @ATMT.receive_condition(SERVING)
    def receive_tree_connect(self, pkt):
        if SMB2_Tree_Connect_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_tree_connect)
    def send_tree_connect_response(self, pkt):
        self.smb_header.TID = 0x1
        self.smb_header.MID = pkt.MID
        self.send(self.smb_header / SMB2_Tree_Connect_Response(
            ShareType="PIPE",
            ShareFlags="AUTO_CACHING+NO_CACHING",
            Capabilities=0,
            MaximalAccess="+".join(
                ['FILE_LIST_DIRECTORY',
                 'FILE_ADD_FILE',
                 'FILE_ADD_SUBDIRECTORY',
                 'FILE_READ_EA',
                 'FILE_WRITE_EA',
                 'FILE_TRAVERSE',
                 'FILE_DELETE_CHILD',
                 'FILE_READ_ATTRIBUTES',
                 'FILE_WRITE_ATTRIBUTES',
                 'DELETE',
                 'READ_CONTROL',
                 'WRITE_DAC',
                 'WRITE_OWNER',
                 'SYNCHRONIZE',
                 'ACCESS_SYSTEM_SECURITY'])
        ))

    @ATMT.receive_condition(SERVING)
    def receive_ioctl(self, pkt):
        if SMB2_IOCTL_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_ioctl)
    def send_ioctl_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self._response_validate_negotiate_info()

    @ATMT.receive_condition(SERVING)
    def receive_create_file(self, pkt):
        if SMB2_Create_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_create_file)
    def send_create_file_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self.send(
            self.smb_header.copy() / SMB2_Create_Response(
                FileId=SMB2_FILEID(Persistent=0x4000000012,
                                   Volatile=0x4000000001)
            )
        )

    @ATMT.receive_condition(SERVING)
    def receive_query_info(self, pkt):
        if SMB2_Query_Info_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_query_info)
    def send_query_info_response(self, pkt):
        self.smb_header.MID = pkt.MID
        if pkt.InfoType == 0x01:  # SMB2_0_INFO_FILE
            if pkt.FileInfoClass == 0x05:  # FileStandardInformation
                self.send(
                    self.smb_header.copy() / SMB2_Query_Info_Response(
                        Buffer=[('Output',
                                 FileStandardInformation(
                                     AllocationSize=4096,
                                     DeletePending=1))]
                    )
                )

    @ATMT.state()
    def PIPE_WRITTEN(self):
        pass

    @ATMT.receive_condition(SERVING)
    def receive_write_request(self, pkt):
        if SMB2_Write_Request in pkt:
            fi = pkt.FileId
            if fi.Persistent == 0x4000000012 and fi.Volatile == 0x4000000001:
                # The srvsvc file
                raise self.PIPE_WRITTEN().action_parameters(pkt)
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_write_request)
    def send_write_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self.send(
            self.smb_header.copy() / SMB2_Write_Response(
                Count=len(pkt.Data)
            )
        )

    @ATMT.receive_condition(PIPE_WRITTEN)
    def receive_read_request(self, pkt):
        if SMB2_Read_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_read_request)
    def send_read_response(self, pkt):
        self.smb_header.MID = pkt.MID
        # TODO - implement pipe logic
        self.send(
            self.smb_header.copy() / SMB2_Read_Response()
        )

    @ATMT.receive_condition(SERVING)
    def receive_close_request(self, pkt):
        if SMB2_Close_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_close_request)
    def send_close_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self.send(
            self.smb_header.copy() / SMB2_Close_Response()
        )

    @ATMT.state(final=1)
    def END(self):
        self.end()
