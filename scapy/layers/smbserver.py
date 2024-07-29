# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
SMB 2 Server Automaton

This provides a [MS-SMB2] server that can:
- serve files
- host a DCE/RPC server

This is a Scapy Automaton that is supposedly easily extendable.

.. note::
    You will find more complete documentation for this layer over at
    `SMB <https://scapy.readthedocs.io/en/latest/layers/smb.html#server>`_
"""

import hashlib
import pathlib
import socket
import struct
import time

from scapy.arch import get_if_addr
from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.error import log_runtime, log_interactive
from scapy.volatile import RandUUID

from scapy.layers.dcerpc import (
    DCERPC_Transport,
    NDRUnion,
)
from scapy.layers.gssapi import (
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_S_CREDENTIALS_EXPIRED,
)
from scapy.layers.msrpce.rpcserver import DCERPC_Server
from scapy.layers.ntlm import (
    NTLMSSP,
)
from scapy.layers.smb import (
    SMBNegotiate_Request,
    SMBNegotiate_Response_Extended_Security,
    SMBNegotiate_Response_Security,
    SMBSession_Null,
    SMBSession_Setup_AndX_Request,
    SMBSession_Setup_AndX_Request_Extended_Security,
    SMBSession_Setup_AndX_Response,
    SMBSession_Setup_AndX_Response_Extended_Security,
    SMBTree_Connect_AndX,
    SMB_Header,
)
from scapy.layers.smb2 import (
    DFS_REFERRAL_ENTRY1,
    DFS_REFERRAL_V3,
    DirectTCP,
    FILE_BOTH_DIR_INFORMATION,
    FILE_FULL_DIR_INFORMATION,
    FILE_ID_BOTH_DIR_INFORMATION,
    FILE_NAME_INFORMATION,
    FileAllInformation,
    FileAlternateNameInformation,
    FileBasicInformation,
    FileEaInformation,
    FileFsAttributeInformation,
    FileFsSizeInformation,
    FileFsVolumeInformation,
    FileIdBothDirectoryInformation,
    FileInternalInformation,
    FileNetworkOpenInformation,
    FileStandardInformation,
    FileStreamInformation,
    NETWORK_INTERFACE_INFO,
    SECURITY_DESCRIPTOR,
    SMB2_Cancel_Request,
    SMB2_Change_Notify_Request,
    SMB2_Change_Notify_Response,
    SMB2_Close_Request,
    SMB2_Close_Response,
    SMB2_Create_Context,
    SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2,
    SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE,
    SMB2_CREATE_QUERY_ON_DISK_ID,
    SMB2_Create_Request,
    SMB2_Create_Response,
    SMB2_Echo_Request,
    SMB2_Echo_Response,
    SMB2_Encryption_Capabilities,
    SMB2_Error_Response,
    SMB2_FILEID,
    SMB2_Header,
    SMB2_IOCTL_Network_Interface_Info,
    SMB2_IOCTL_Request,
    SMB2_IOCTL_RESP_GET_DFS_Referral,
    SMB2_IOCTL_Response,
    SMB2_IOCTL_Validate_Negotiate_Info_Response,
    SMB2_Negotiate_Context,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Negotiate_Protocol_Response,
    SMB2_Preauth_Integrity_Capabilities,
    SMB2_Query_Directory_Request,
    SMB2_Query_Directory_Response,
    SMB2_Query_Info_Request,
    SMB2_Query_Info_Response,
    SMB2_Read_Request,
    SMB2_Read_Response,
    SMB2_Session_Logoff_Request,
    SMB2_Session_Logoff_Response,
    SMB2_Session_Setup_Request,
    SMB2_Session_Setup_Response,
    SMB2_Set_Info_Request,
    SMB2_Set_Info_Response,
    SMB2_Signing_Capabilities,
    SMB2_Tree_Connect_Request,
    SMB2_Tree_Connect_Response,
    SMB2_Tree_Disconnect_Request,
    SMB2_Tree_Disconnect_Response,
    SMB2_Write_Request,
    SMB2_Write_Response,
    SMBStreamSocket,
    SOCKADDR_STORAGE,
    SRVSVC_SHARE_TYPES,
)
from scapy.layers.spnego import SPNEGOSSP

# Import DCE/RPC
from scapy.layers.msrpce.raw.ms_srvs import (
    LPSERVER_INFO_101,
    LPSHARE_ENUM_STRUCT,
    LPSHARE_INFO_1,
    NetrServerGetInfo_Request,
    NetrServerGetInfo_Response,
    NetrShareEnum_Request,
    NetrShareEnum_Response,
    NetrShareGetInfo_Request,
    NetrShareGetInfo_Response,
    SHARE_INFO_1_CONTAINER,
)
from scapy.layers.msrpce.raw.ms_wkst import (
    LPWKSTA_INFO_100,
    NetrWkstaGetInfo_Request,
    NetrWkstaGetInfo_Response,
)


class SMBShare:
    """
    A class used to define a share, used by SMB_Server

    :param name: the share name
    :param path: the path the the folder hosted by the share
    :param type: (optional) share type per [MS-SRVS] sect 2.2.2.4
    :param remark: (optional) a description of the share
    """

    def __init__(self, name, path=".", type=None, remark=""):
        # Set the default type
        if type is None:
            type = 0  # DISKTREE
            if name.endswith("$"):
                type &= 0x80000000  # SPECIAL
        # Lower case the name for resolution
        self._name = name.lower()
        # Resolve path
        self.path = pathlib.Path(path).resolve()
        # props
        self.name = name
        self.type = type
        self.remark = remark

    def __repr__(self):
        type = SRVSVC_SHARE_TYPES[self.type & 0x0FFFFFFF]
        if self.type & 0x80000000:
            type = "SPECIAL+" + type
        if self.type & 0x40000000:
            type = "TEMPORARY+" + type
        return "<SMBShare %s [%s]%s = %s>" % (
            self.name,
            type,
            self.remark and (" '%s'" % self.remark) or "",
            str(self.path),
        )


# The SMB Automaton


class SMB_Server(Automaton):
    """
    SMB server automaton

    :param shares: the shares to serve. By default, share nothing.
                   Note that IPC$ is appended.
    :param ssp: the SSP to use

    All other options (in caps) are optional, and SMB specific:

    :param ANONYMOUS_LOGIN: mark the clients as anonymous
    :param GUEST_LOGIN: mark the clients as guest
    :param REQUIRE_SIGNATURE: set 'Require Signature'
    :param MAX_DIALECT: maximum SMB dialect. Defaults to 0x0311 (3.1.1)
    :param TREE_SHARE_FLAGS: flags to announce on Tree_Connect_Response
    :param TREE_CAPABILITIES: capabilities to announce on Tree_Connect_Response
    :param TREE_MAXIMAL_ACCESS: maximal access to announce on Tree_Connect_Response
    :param FILE_MAXIMAL_ACCESS: maximal access to announce in MxAc Create Context
    """

    pkt_cls = DirectTCP
    socketcls = SMBStreamSocket

    def __init__(self, shares=[], ssp=None, verb=True, readonly=True, *args, **kwargs):
        self.verb = verb
        if "sock" not in kwargs:
            raise ValueError(
                "SMB_Server cannot be started directly ! Use SMB_Server.spawn"
            )
        # Various SMB server arguments
        self.ANONYMOUS_LOGIN = kwargs.pop("ANONYMOUS_LOGIN", False)
        self.GUEST_LOGIN = kwargs.pop("GUEST_LOGIN", None)
        self.EXTENDED_SECURITY = kwargs.pop("EXTENDED_SECURITY", True)
        self.USE_SMB1 = kwargs.pop("USE_SMB1", False)
        self.REQUIRE_SIGNATURE = kwargs.pop("REQUIRE_SIGNATURE", False)
        self.MAX_DIALECT = kwargs.pop("MAX_DIALECT", 0x0311)
        self.TREE_SHARE_FLAGS = kwargs.pop(
            "TREE_SHARE_FLAGS", "FORCE_LEVELII_OPLOCK+RESTRICT_EXCLUSIVE_OPENS"
        )
        self.TREE_CAPABILITIES = kwargs.pop("TREE_CAPABILITIES", 0)
        self.TREE_MAXIMAL_ACCESS = kwargs.pop(
            "TREE_MAXIMAL_ACCESS",
            "+".join(
                [
                    "FILE_READ_DATA",
                    "FILE_WRITE_DATA",
                    "FILE_APPEND_DATA",
                    "FILE_READ_EA",
                    "FILE_WRITE_EA",
                    "FILE_EXECUTE",
                    "FILE_DELETE_CHILD",
                    "FILE_READ_ATTRIBUTES",
                    "FILE_WRITE_ATTRIBUTES",
                    "DELETE",
                    "READ_CONTROL",
                    "WRITE_DAC",
                    "WRITE_OWNER",
                    "SYNCHRONIZE",
                ]
            ),
        )
        self.FILE_MAXIMAL_ACCESS = kwargs.pop(
            # Read-only
            "FILE_MAXIMAL_ACCESS",
            "+".join(
                [
                    "FILE_READ_DATA",
                    "FILE_READ_EA",
                    "FILE_EXECUTE",
                    "FILE_READ_ATTRIBUTES",
                    "READ_CONTROL",
                    "SYNCHRONIZE",
                ]
            ),
        )
        self.LOCAL_IPS = kwargs.pop(
            "LOCAL_IPS", [get_if_addr(kwargs.get("iface", conf.iface) or conf.iface)]
        )
        self.DOMAIN_REFERRALS = kwargs.pop("DOMAIN_REFERRALS", [])
        if self.USE_SMB1:
            log_runtime.warning("Serving SMB1 is not supported :/")
        self.readonly = readonly
        # We don't want to update the parent shares argument
        self.shares = shares.copy()
        # Append the IPC$ share
        self.shares.append(
            SMBShare(
                name="IPC$",
                type=0x80000003,  # SPECIAL+IPC
                remark="Remote IPC",
            )
        )
        # Initialize the DCE/RPC server for SMB
        self.rpc_server = SMB_DCERPC_Server(
            DCERPC_Transport.NCACN_NP,
            shares=self.shares,
            verb=self.verb,
        )
        # Extend it if another DCE/RPC server is provided
        if "DCERPC_SERVER_CLS" in kwargs:
            self.rpc_server.extend(kwargs.pop("DCERPC_SERVER_CLS"))
        # Internal Session information
        self.SMB2 = False
        self.NegotiateCapabilities = None
        self.GUID = RandUUID()._fix()
        # Compounds are handled on receiving by the StreamSocket,
        # and on aggregated in a CompoundQueue to be sent in one go
        self.NextCompound = False
        self.CompoundedHandle = None
        # SSP provider
        if ssp is None:
            # No SSP => fallback on NTLM with guest
            ssp = SPNEGOSSP(
                [
                    NTLMSSP(
                        USE_MIC=False,
                        DO_NOT_CHECK_LOGIN=True,
                    ),
                ]
            )
            if self.GUEST_LOGIN is None:
                self.GUEST_LOGIN = True
        # Initialize
        Automaton.__init__(self, *args, **kwargs)
        # Set session options
        self.session.ssp = ssp
        self.session.SecurityMode = kwargs.pop(
            "SECURITY_MODE",
            3 if self.REQUIRE_SIGNATURE else bool(ssp),
        )

    @property
    def session(self):
        # session shorthand
        return self.sock.session

    def vprint(self, s=""):
        """
        Verbose print (if enabled)
        """
        if self.verb:
            if conf.interactive:
                log_interactive.info("> %s", s)
            else:
                print("> %s" % s)

    def send(self, pkt):
        return super(SMB_Server, self).send(pkt, Compounded=self.NextCompound)

    @ATMT.state(initial=1)
    def BEGIN(self):
        self.authenticated = False

    @ATMT.receive_condition(BEGIN)
    def received_negotiate(self, pkt):
        if SMBNegotiate_Request in pkt:
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.receive_condition(BEGIN)
    def received_negotiate_smb2_begin(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            self.SMB2 = True
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2_begin)
    def on_negotiate_smb2_begin(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.action(received_negotiate)
    def on_negotiate(self, pkt):
        self.session.sspcontext, spnego_token = self.session.ssp.NegTokenInit2()
        # Build negotiate response
        DialectIndex = None
        DialectRevision = None
        if SMB2_Negotiate_Protocol_Request in pkt:
            # SMB2
            DialectRevisions = pkt[SMB2_Negotiate_Protocol_Request].Dialects
            DialectRevisions = [x for x in DialectRevisions if x <= self.MAX_DIALECT]
            DialectRevisions.sort(reverse=True)
            if DialectRevisions:
                DialectRevision = DialectRevisions[0]
        else:
            # SMB1
            DialectIndexes = [
                x.DialectString for x in pkt[SMBNegotiate_Request].Dialects
            ]
            if self.USE_SMB1:
                # Enforce SMB1
                DialectIndex = DialectIndexes.index(b"NT LM 0.12")
            else:
                # Find a value matching SMB2, fallback to SMB1
                for key, rev in [(b"SMB 2.???", 0x02FF), (b"SMB 2.002", 0x0202)]:
                    try:
                        DialectIndex = DialectIndexes.index(key)
                        DialectRevision = rev
                        self.SMB2 = True
                        break
                    except ValueError:
                        pass
                else:
                    DialectIndex = DialectIndexes.index(b"NT LM 0.12")
        if DialectRevision and DialectRevision & 0xFF != 0xFF:
            # Version isn't SMB X.???
            self.session.Dialect = DialectRevision
        cls = None
        if self.SMB2:
            # SMB2
            cls = SMB2_Negotiate_Protocol_Response
            self.smb_header = DirectTCP() / SMB2_Header(
                Flags="SMB2_FLAGS_SERVER_TO_REDIR",
                CreditRequest=1,
                CreditCharge=1,
            )
            if SMB2_Negotiate_Protocol_Request in pkt:
                self.update_smbheader(pkt)
        else:
            # SMB1
            self.smb_header = DirectTCP() / SMB_Header(
                Flags="REPLY+CASE_INSENSITIVE+CANONICALIZED_PATHS",
                Flags2=(
                    "LONG_NAMES+EAS+NT_STATUS+SMB_SECURITY_SIGNATURE+"
                    "UNICODE+EXTENDED_SECURITY"
                ),
                TID=pkt.TID,
                MID=pkt.MID,
                UID=pkt.UID,
                PIDLow=pkt.PIDLow,
            )
            if self.EXTENDED_SECURITY:
                cls = SMBNegotiate_Response_Extended_Security
            else:
                cls = SMBNegotiate_Response_Security
        if DialectRevision is None and DialectIndex is None:
            # No common dialect found.
            if self.SMB2:
                resp = self.smb_header.copy() / SMB2_Error_Response()
                resp.Command = "SMB2_NEGOTIATE"
            else:
                resp = self.smb_header.copy() / SMBSession_Null()
                resp.Command = "SMB_COM_NEGOTIATE"
            resp.Status = "STATUS_NOT_SUPPORTED"
            self.send(resp)
            return
        if self.SMB2:  # SMB2
            # Capabilities: [MS-SMB2] 3.3.5.4
            self.NegotiateCapabilities = "+".join(
                [
                    "DFS",
                    "LEASING",
                    "LARGE_MTU",
                ]
            )
            if DialectRevision >= 0x0300:
                # "if Connection.Dialect belongs to the SMB 3.x dialect family,
                # the server supports..."
                self.NegotiateCapabilities += "+" + "+".join(
                    [
                        "MULTI_CHANNEL",
                        "PERSISTENT_HANDLES",
                        "DIRECTORY_LEASING",
                    ]
                )
            if DialectRevision in [0x0300, 0x0302]:
                # "if Connection.Dialect is "3.0" or "3.0.2""...
                # Note: 3.1.1 uses the ENCRYPT_DATA flag in Tree Connect Response
                self.NegotiateCapabilities += "+ENCRYPTION"
            # Build response
            resp = self.smb_header.copy() / cls(
                DialectRevision=DialectRevision,
                SecurityMode=self.session.SecurityMode,
                ServerTime=(time.time() + 11644473600) * 1e7,
                ServerStartTime=0,
                MaxTransactionSize=65536,
                MaxReadSize=65536,
                MaxWriteSize=65536,
                Capabilities=self.NegotiateCapabilities,
            )
            # SMB >= 3.0.0
            if DialectRevision >= 0x0300:
                # [MS-SMB2] sect 3.3.5.3.1 note 253
                resp.MaxTransactionSize = 0x800000
                resp.MaxReadSize = 0x800000
                resp.MaxWriteSize = 0x800000
            # SMB 3.1.1
            if DialectRevision >= 0x0311:
                resp.NegotiateContexts = [
                    # Preauth capabilities
                    SMB2_Negotiate_Context()
                    / SMB2_Preauth_Integrity_Capabilities(
                        # SHA-512 by default
                        HashAlgorithms=[self.session.PreauthIntegrityHashId],
                        Salt=self.session.Salt,
                    ),
                    # Encryption capabilities
                    SMB2_Negotiate_Context()
                    / SMB2_Encryption_Capabilities(
                        # AES-128-CCM by default
                        Ciphers=[self.session.CipherId],
                    ),
                    # Signing capabilities
                    SMB2_Negotiate_Context()
                    / SMB2_Signing_Capabilities(
                        # AES-128-CCM by default
                        SigningAlgorithms=[self.session.SigningAlgorithmId],
                    ),
                ]
        else:
            # SMB1
            resp = self.smb_header.copy() / cls(
                DialectIndex=DialectIndex,
                ServerCapabilities=(
                    "UNICODE+LARGE_FILES+NT_SMBS+RPC_REMOTE_APIS+STATUS32+"
                    "LEVEL_II_OPLOCKS+LOCK_AND_READ+NT_FIND+"
                    "LWIO+INFOLEVEL_PASSTHRU+LARGE_READX+LARGE_WRITEX"
                ),
                SecurityMode=self.session.SecurityMode,
                ServerTime=(time.time() + 11644473600) * 1e7,
                ServerTimeZone=0x3C,
            )
            if self.EXTENDED_SECURITY:
                resp.ServerCapabilities += "EXTENDED_SECURITY"
        if self.EXTENDED_SECURITY or self.SMB2:
            # Extended SMB1 / SMB2
            resp.GUID = self.GUID
            # Add security blob
            resp.SecurityBlob = spnego_token
        else:
            # Non-extended SMB1
            # FIXME never tested.
            resp.SecurityBlob = spnego_token
            resp.Flags2 -= "EXTENDED_SECURITY"
        if not self.SMB2:
            resp[SMB_Header].Flags2 = (
                resp[SMB_Header].Flags2
                - "SMB_SECURITY_SIGNATURE"
                + "SMB_SECURITY_SIGNATURE_REQUIRED+IS_LONG_NAME"
            )
        if SMB2_Header in pkt:
            # If required, compute sessions
            self.session.computeSMBConnectionPreauth(
                bytes(pkt[SMB2_Header]),  # nego request
                bytes(resp[SMB2_Header]),  # nego response
            )
        self.send(resp)

    @ATMT.state()
    def NEGOTIATED(self):
        pass

    def update_smbheader(self, pkt):
        """
        Called when receiving a SMB2 packet to update the current smb_header
        """
        # [MS-SMB2] sect 3.2.5.1.4 - always grant client its credits
        self.smb_header.CreditRequest = pkt.CreditRequest
        # [MS-SMB2] sect 3.3.4.1
        # "the server SHOULD set the CreditCharge field in the SMB2 header
        # of the response to the CreditCharge value in the SMB2 header of the request."
        self.smb_header.CreditCharge = pkt.CreditCharge
        # If the packet has a NextCommand, set NextCompound to True
        self.NextCompound = bool(pkt.NextCommand)
        # [MS-SMB2] sect 3.3.5.2.7.2
        # Add SMB2_FLAGS_RELATED_OPERATIONS to the response if present
        if pkt.Flags.SMB2_FLAGS_RELATED_OPERATIONS:
            self.smb_header.Flags += "SMB2_FLAGS_RELATED_OPERATIONS"
        else:
            self.smb_header.Flags -= "SMB2_FLAGS_RELATED_OPERATIONS"
        # [MS-SMB2] sect 2.2.1.2 - Priority
        if (self.session.Dialect or 0) >= 0x0311:
            self.smb_header.Flags &= 0xFF8F
            self.smb_header.Flags |= int(pkt.Flags) & 0x70
        # Update IDs
        self.smb_header.SessionId = pkt.SessionId
        self.smb_header.TID = pkt.TID
        self.smb_header.MID = pkt.MID
        self.smb_header.PID = pkt.PID

    @ATMT.receive_condition(NEGOTIATED)
    def received_negotiate_smb2(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2)
    def on_negotiate_smb2(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.receive_condition(NEGOTIATED)
    def receive_setup_andx_request(self, pkt):
        if (
            SMBSession_Setup_AndX_Request_Extended_Security in pkt
            or SMBSession_Setup_AndX_Request in pkt
        ):
            # SMB1
            if SMBSession_Setup_AndX_Request_Extended_Security in pkt:
                # Extended
                ssp_blob = pkt.SecurityBlob
            else:
                # Non-extended
                ssp_blob = pkt[SMBSession_Setup_AndX_Request].UnicodePassword
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt, ssp_blob)
        elif SMB2_Session_Setup_Request in pkt:
            # SMB2
            ssp_blob = pkt.SecurityBlob
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt, ssp_blob)

    @ATMT.state()
    def RECEIVED_SETUP_ANDX_REQUEST(self):
        pass

    @ATMT.action(receive_setup_andx_request)
    def on_setup_andx_request(self, pkt, ssp_blob):
        self.session.sspcontext, tok, status = self.session.ssp.GSS_Accept_sec_context(
            self.session.sspcontext, ssp_blob
        )
        self.update_smbheader(pkt)
        if SMB2_Session_Setup_Request in pkt:
            # SMB2
            self.smb_header.SessionId = 0x0001000000000015
        if status not in [GSS_S_CONTINUE_NEEDED, GSS_S_COMPLETE]:
            # Error
            if SMB2_Session_Setup_Request in pkt:
                # SMB2
                resp = self.smb_header.copy() / SMB2_Session_Setup_Response()
                # Set security blob (if any)
                resp.SecurityBlob = tok
            else:
                # SMB1
                resp = self.smb_header.copy() / SMBSession_Null()
            # Map some GSS return codes to NTStatus
            if status == GSS_S_CREDENTIALS_EXPIRED:
                resp.Status = "STATUS_PASSWORD_EXPIRED"
            else:
                resp.Status = "STATUS_LOGON_FAILURE"
            # Reset Session preauth (SMB 3.1.1)
            self.session.SessionPreauthIntegrityHashValue = None
        else:
            # Negotiation
            if (
                SMBSession_Setup_AndX_Request_Extended_Security in pkt
                or SMB2_Session_Setup_Request in pkt
            ):
                # SMB1 extended / SMB2
                if SMB2_Session_Setup_Request in pkt:
                    # SMB2
                    resp = self.smb_header.copy() / SMB2_Session_Setup_Response()
                    if self.GUEST_LOGIN:
                        resp.SessionFlags = "IS_GUEST"
                    if self.ANONYMOUS_LOGIN:
                        resp.SessionFlags = "IS_NULL"
                else:
                    # SMB1 extended
                    resp = (
                        self.smb_header.copy()
                        / SMBSession_Setup_AndX_Response_Extended_Security(
                            NativeOS="Windows 4.0",
                            NativeLanMan="Windows 4.0",
                        )
                    )
                    if self.GUEST_LOGIN:
                        resp.Action = "SMB_SETUP_GUEST"
                # Set security blob
                resp.SecurityBlob = tok
            elif SMBSession_Setup_AndX_Request in pkt:
                # Non-extended
                resp = self.smb_header.copy() / SMBSession_Setup_AndX_Response(
                    NativeOS="Windows 4.0",
                    NativeLanMan="Windows 4.0",
                )
            resp.Status = 0x0 if (status == GSS_S_COMPLETE) else 0xC0000016
        # We have a response. If required, compute sessions
        if status == GSS_S_CONTINUE_NEEDED:
            # the setup session response is used in hash
            self.session.computeSMBSessionPreauth(
                bytes(pkt[SMB2_Header]),  # session setup request
                bytes(resp[SMB2_Header]),  # session setup response
            )
        else:
            # the setup session response is not used in hash
            self.session.computeSMBSessionPreauth(
                bytes(pkt[SMB2_Header]),  # session setup request
            )
        if status == GSS_S_COMPLETE:
            # Authentication was successful
            self.session.computeSMBSessionKey()
            self.authenticated = True
        # and send
        self.send(resp)

    @ATMT.condition(RECEIVED_SETUP_ANDX_REQUEST)
    def wait_for_next_request(self):
        if self.authenticated:
            self.vprint(
                "User authenticated %s!" % (self.GUEST_LOGIN and " as guest" or "")
            )
            raise self.AUTHENTICATED()
        else:
            raise self.NEGOTIATED()

    @ATMT.state()
    def AUTHENTICATED(self):
        """Dev: overload this"""
        pass

    # DEV: add a condition on AUTHENTICATED with prio=0

    @ATMT.condition(AUTHENTICATED, prio=1)
    def should_serve(self):
        # Serve files
        self.current_trees = {}
        self.current_handles = {}
        self.enumerate_index = {}  # used for query directory enumeration
        self.tree_id = 0
        self.base_time_t = self.current_smb_time()
        raise self.SERVING()

    def _ioctl_error(self, Status="STATUS_NOT_SUPPORTED"):
        pkt = self.smb_header.copy() / SMB2_Error_Response(ErrorData=b"\xff")
        pkt.Status = Status
        pkt.Command = "SMB2_IOCTL"
        self.send(pkt)

    @ATMT.state(final=1)
    def END(self):
        self.end()

    # SERVE FILES

    def current_tree(self):
        """
        Return the current tree name
        """
        return self.current_trees[self.smb_header.TID]

    def root_path(self):
        """
        Return the root path of the current tree
        """
        curtree = self.current_tree()
        try:
            share_path = next(x.path for x in self.shares if x._name == curtree.lower())
        except StopIteration:
            return None
        return pathlib.Path(share_path).resolve()

    @ATMT.state()
    def SERVING(self):
        """
        Main state when serving files
        """
        pass

    @ATMT.receive_condition(SERVING)
    def receive_logoff_request(self, pkt):
        if SMB2_Session_Logoff_Request in pkt:
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(receive_logoff_request)
    def send_logoff_response(self, pkt):
        self.update_smbheader(pkt)
        self.send(self.smb_header.copy() / SMB2_Session_Logoff_Response())

    @ATMT.receive_condition(SERVING)
    def receive_setup_andx_request_in_serving(self, pkt):
        self.receive_setup_andx_request(pkt)

    @ATMT.receive_condition(SERVING)
    def is_smb1_tree(self, pkt):
        if SMBTree_Connect_AndX in pkt:
            # Unsupported
            log_runtime.warning("Tree request in SMB1: unimplemented. Quit")
            raise self.END()

    @ATMT.receive_condition(SERVING)
    def receive_tree_connect(self, pkt):
        if SMB2_Tree_Connect_Request in pkt:
            tree_name = pkt[SMB2_Tree_Connect_Request].Path.split("\\")[-1]
            raise self.SERVING().action_parameters(pkt, tree_name)

    @ATMT.action(receive_tree_connect)
    def send_tree_connect_response(self, pkt, tree_name):
        self.update_smbheader(pkt)
        # Check the tree name against the shares we're serving
        if not any(x._name == tree_name.lower() for x in self.shares):
            # Unknown tree
            resp = self.smb_header.copy() / SMB2_Error_Response()
            resp.Command = "SMB2_TREE_CONNECT"
            resp.Status = "STATUS_BAD_NETWORK_NAME"
            self.send(resp)
            return
        # Add tree to current trees
        if tree_name not in self.current_trees:
            self.tree_id += 1
            self.smb_header.TID = self.tree_id
        self.current_trees[self.smb_header.TID] = tree_name
        self.vprint("Tree Connect on: %s" % tree_name)
        self.send(
            self.smb_header
            / SMB2_Tree_Connect_Response(
                ShareType="PIPE" if self.current_tree() == "IPC$" else "DISK",
                ShareFlags="AUTO_CACHING+NO_CACHING"
                if self.current_tree() == "IPC$"
                else self.TREE_SHARE_FLAGS,
                Capabilities=0
                if self.current_tree() == "IPC$"
                else self.TREE_CAPABILITIES,
                MaximalAccess=self.TREE_MAXIMAL_ACCESS,
            )
        )

    @ATMT.receive_condition(SERVING)
    def receive_ioctl(self, pkt):
        if SMB2_IOCTL_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_ioctl)
    def send_ioctl_response(self, pkt):
        self.update_smbheader(pkt)
        if pkt.CtlCode == 0x11C017:
            # FSCTL_PIPE_TRANSCEIVE
            self.rpc_server.recv(pkt.Input.load)
            self.send(
                self.smb_header.copy()
                / SMB2_IOCTL_Response(
                    CtlCode=0x11C017,
                    FileId=pkt[SMB2_IOCTL_Request].FileId,
                    Buffer=[("Output", self.rpc_server.get_response())],
                )
            )
        elif pkt.CtlCode == 0x00140204 and self.session.sspcontext.SessionKey:
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

            if (self.session.Dialect or 0) < 0x0300:
                # SMB < 3 isn't supposed to support FSCTL_VALIDATE_NEGOTIATE_INFO
                self._ioctl_error(Status="STATUS_FILE_CLOSED")
                return

            # SMB3
            self.send(
                self.smb_header.copy()
                / SMB2_IOCTL_Response(
                    CtlCode=0x00140204,
                    FileId=pkt[SMB2_IOCTL_Request].FileId,
                    Buffer=[
                        (
                            "Output",
                            SMB2_IOCTL_Validate_Negotiate_Info_Response(
                                GUID=self.GUID,
                                DialectRevision=self.session.Dialect,
                                SecurityMode=self.session.SecurityMode,
                                Capabilities=self.NegotiateCapabilities,
                            ),
                        )
                    ],
                )
            )
        elif pkt.CtlCode == 0x001401FC:
            # FSCTL_QUERY_NETWORK_INTERFACE_INFO
            self.send(
                self.smb_header.copy()
                / SMB2_IOCTL_Response(
                    CtlCode=0x001401FC,
                    FileId=pkt[SMB2_IOCTL_Request].FileId,
                    Output=SMB2_IOCTL_Network_Interface_Info(
                        interfaces=[
                            NETWORK_INTERFACE_INFO(
                                SockAddr_Storage=SOCKADDR_STORAGE(
                                    Family=0x0002,
                                    IPv4Adddress=x,
                                )
                            )
                            for x in self.LOCAL_IPS
                        ]
                    ),
                )
            )
        elif pkt.CtlCode == 0x00060194:
            # FSCTL_DFS_GET_REFERRALS
            if (
                self.DOMAIN_REFERRALS
                and not pkt[SMB2_IOCTL_Request].Input.RequestFileName
            ):
                # Requesting domain referrals
                self.send(
                    self.smb_header.copy()
                    / SMB2_IOCTL_Response(
                        CtlCode=0x00060194,
                        FileId=pkt[SMB2_IOCTL_Request].FileId,
                        Output=SMB2_IOCTL_RESP_GET_DFS_Referral(
                            ReferralEntries=[
                                DFS_REFERRAL_V3(
                                    ReferralEntryFlags="NameListReferral",
                                    TimeToLive=600,
                                )
                                for _ in self.DOMAIN_REFERRALS
                            ],
                            ReferralBuffer=[
                                DFS_REFERRAL_ENTRY1(SpecialName=name)
                                for name in self.DOMAIN_REFERRALS
                            ],
                        ),
                    )
                )
                return
            resp = self.smb_header.copy() / SMB2_Error_Response()
            resp.Command = "SMB2_IOCTL"
            resp.Status = "STATUS_FS_DRIVER_REQUIRED"
            self.send(resp)
        else:
            # Among other things, FSCTL_VALIDATE_NEGOTIATE_INFO
            self._ioctl_error(Status="STATUS_NOT_SUPPORTED")

    @ATMT.receive_condition(SERVING)
    def receive_create_file(self, pkt):
        if SMB2_Create_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    PIPES_TABLE = {
        "srvsvc": SMB2_FILEID(Persistent=0x4000000012, Volatile=0x4000000001),
        "wkssvc": SMB2_FILEID(Persistent=0x4000000013, Volatile=0x4000000002),
        "NETLOGON": SMB2_FILEID(Persistent=0x4000000014, Volatile=0x4000000003),
    }

    # special handle in case of compounded requests ([MS-SMB2] 3.2.4.1.4)
    # that points to the chained opened file handle
    LAST_HANDLE = SMB2_FILEID(
        Persistent=0xFFFFFFFFFFFFFFFF, Volatile=0xFFFFFFFFFFFFFFFF
    )

    def current_smb_time(self):
        return (
            FileNetworkOpenInformation().get_field("CreationTime").i2m(None, None)
            - 864000000000  # one day ago
        )

    def make_file_id(self, fname):
        """
        Generate deterministic FileId based on the fname
        """
        hash = hashlib.md5((fname or "").encode()).digest()
        return 0x4000000000 | struct.unpack("<I", hash[:4])[0]

    def lookup_file(self, fname, durable_handle=None, create=False, createOptions=None):
        """
        Lookup the file and build it's SMB2_FILEID
        """
        root = self.root_path()
        if isinstance(fname, pathlib.Path):
            path = fname
            fname = path.name
        else:
            path = root / (fname or "").replace("\\", "/")
        path = path.resolve()
        # Word of caution: this check ONLY works because root and path have been
        # resolve(). Be careful
        # Note: symbolic links are currently unsupported.
        if root not in path.parents and path != root:
            raise FileNotFoundError
        if path.is_reserved():
            raise FileNotFoundError
        if not path.exists():
            if create and createOptions:
                if createOptions.FILE_DIRECTORY_FILE:
                    # Folder creation
                    path.mkdir()
                    self.vprint("Created folder:" + fname)
                else:
                    # File creation
                    path.touch()
                    self.vprint("Created file:" + fname)
            else:
                raise FileNotFoundError
        if durable_handle is None:
            handle = SMB2_FILEID(
                Persistent=self.make_file_id(fname) + self.smb_header.MID,
            )
        else:
            # We were given a durable handle. Use it
            handle = durable_handle
        attrs = {
            "CreationTime": self.base_time_t,
            "LastAccessTime": self.base_time_t,
            "LastWriteTime": self.base_time_t,
            "ChangeTime": self.base_time_t,
            "EndOfFile": 0,
            "AllocationSize": 0,
        }
        path_stat = path.stat()
        attrs["EndOfFile"] = attrs["AllocationSize"] = path_stat.st_size
        if fname is None:
            # special case
            attrs["FileAttributes"] = "+".join(
                [
                    "FILE_ATTRIBUTE_HIDDEN",
                    "FILE_ATTRIBUTE_SYSTEM",
                    "FILE_ATTRIBUTE_DIRECTORY",
                ]
            )
        elif path.is_dir():
            attrs["FileAttributes"] = "FILE_ATTRIBUTE_DIRECTORY"
        else:
            attrs["FileAttributes"] = "FILE_ATTRIBUTE_ARCHIVE"
        self.current_handles[handle] = (
            path,  # file path
            attrs,  # file attributes
        )
        self.enumerate_index[handle] = 0
        return handle

    def set_compounded_handle(self, handle):
        """
        Mark a handle as the current one being compounded.
        """
        self.CompoundedHandle = handle

    def get_file_id(self, pkt):
        """
        Return the FileId attribute of pkt, accounting for compounded requests.
        """
        fid = pkt.FileId
        if fid == self.LAST_HANDLE:
            return self.CompoundedHandle
        return fid

    def lookup_folder(self, handle, filter, offset, cls):
        """
        Lookup a folder handle
        """
        path = self.current_handles[handle][0]
        self.vprint("Query directory: " + str(path))
        self.current_handles[handle][1]["LastAccessTime"] = self.current_smb_time()
        if not path.is_dir():
            raise NotADirectoryError
        return sorted(
            [
                cls(FileName=x.name, **self.current_handles[self.lookup_file(x)][1])
                for x in path.glob(filter)
                # Note: symbolic links are unsupported because it's hard to check
                # for path traversal on them.
                if not x.is_symlink()
            ]
            + [
                cls(
                    FileAttributes=("FILE_ATTRIBUTE_DIRECTORY"),
                    FileName=".",
                )
            ]
            + (
                [
                    cls(
                        FileAttributes=("FILE_ATTRIBUTE_DIRECTORY"),
                        FileName="..",
                    )
                ]
                if path.resolve() != self.root_path()
                else []
            ),
            key=lambda x: x.FileName,
        )[offset:]

    @ATMT.action(receive_create_file)
    def send_create_file_response(self, pkt):
        """
        Handle CreateFile request

        See [MS-SMB2] 3.3.5.9 ()
        """
        self.update_smbheader(pkt)
        if pkt[SMB2_Create_Request].NameLen:
            fname = pkt[SMB2_Create_Request].Name
        else:
            fname = None
        if fname:
            self.vprint("Opened: " + fname)
        if self.current_tree() == "IPC$":
            # Special IPC$ case: opening a pipe
            FILE_ID = self.PIPES_TABLE.get(fname, None)
            if FILE_ID:
                attrs = {
                    "CreationTime": 0,
                    "LastAccessTime": 0,
                    "LastWriteTime": 0,
                    "ChangeTime": 0,
                    "EndOfFile": 0,
                    "AllocationSize": 4096,
                }
                self.current_handles[FILE_ID] = (
                    fname,
                    attrs,
                )
                self.send(
                    self.smb_header.copy()
                    / SMB2_Create_Response(
                        OplockLevel=pkt.RequestedOplockLevel,
                        FileId=FILE_ID,
                        **attrs,
                    )
                )
            else:
                # NOT_FOUND
                resp = self.smb_header.copy() / SMB2_Error_Response()
                resp.Command = "SMB2_CREATE"
                resp.Status = "STATUS_OBJECT_NAME_NOT_FOUND"
                self.send(resp)
            return
        else:
            # Check if there is a Durable Handle Reconnect Request
            durable_handle = None
            if pkt[SMB2_Create_Request].CreateContextsLen:
                try:
                    durable_handle = next(
                        x.Data.FileId
                        for x in pkt[SMB2_Create_Request].CreateContexts
                        if x.Name == b"DH2C"
                    )
                except StopIteration:
                    pass
            # Lookup file handle
            try:
                handle = self.lookup_file(fname, durable_handle=durable_handle)
            except FileNotFoundError:
                # NOT_FOUND
                if pkt[SMB2_Create_Request].CreateDisposition in [
                    0x00000002,  # FILE_CREATE
                    0x00000005,  # FILE_OVERWRITE_IF
                ]:
                    if self.readonly:
                        resp = self.smb_header.copy() / SMB2_Error_Response()
                        resp.Command = "SMB2_CREATE"
                        resp.Status = "STATUS_ACCESS_DENIED"
                        self.send(resp)
                        return
                    else:
                        # Create file
                        handle = self.lookup_file(
                            fname,
                            durable_handle=durable_handle,
                            create=True,
                            createOptions=pkt[SMB2_Create_Request].CreateOptions,
                        )
                else:
                    resp = self.smb_header.copy() / SMB2_Error_Response()
                    resp.Command = "SMB2_CREATE"
                    resp.Status = "STATUS_OBJECT_NAME_NOT_FOUND"
                    self.send(resp)
                    return
            # Store compounded handle
            self.set_compounded_handle(handle)
            # Build response
            attrs = self.current_handles[handle][1]
            resp = self.smb_header.copy() / SMB2_Create_Response(
                OplockLevel=pkt.RequestedOplockLevel,
                FileId=handle,
                **attrs,
            )
            # Handle the various chain elements
            if pkt[SMB2_Create_Request].CreateContextsLen:
                CreateContexts = []
                # Note: failing to provide context elements when the client asks for
                # them will make the windows implementation fall into a weird
                # "the-server-is-dumb" mode. So provide them 'quoi qu'il en coûte'.
                for elt in pkt[SMB2_Create_Request].CreateContexts:
                    if elt.Name == b"QFid":
                        # [MS-SMB2] sect 3.3.5.9.9
                        CreateContexts.append(
                            SMB2_Create_Context(
                                Name=b"QFid",
                                Data=SMB2_CREATE_QUERY_ON_DISK_ID(
                                    DiskFileId=self.make_file_id(fname),
                                    VolumeId=0xBA39CD11,
                                ),
                            )
                        )
                    elif elt.Name == b"MxAc":
                        # [MS-SMB2] sect 3.3.5.9.5
                        CreateContexts.append(
                            SMB2_Create_Context(
                                Name=b"MxAc",
                                Data=SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE(
                                    QueryStatus=0,
                                    MaximalAccess=self.FILE_MAXIMAL_ACCESS,
                                ),
                            )
                        )
                    elif elt.Name == b"DH2Q":
                        # [MS-SMB2] sect 3.3.5.9.10
                        if "FILE_ATTRIBUTE_DIRECTORY" in attrs["FileAttributes"]:
                            continue
                        CreateContexts.append(
                            SMB2_Create_Context(
                                Name=b"DH2Q",
                                Data=SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2(
                                    Timeout=180000
                                ),
                            )
                        )
                    elif elt.Name == b"RqLs":
                        # [MS-SMB2] sect 3.3.5.9.11
                        # TODO: hmm, we are probably supposed to do something here
                        CreateContexts.append(
                            SMB2_Create_Context(
                                Name=b"RqLs",
                                Data=elt.Data,
                            )
                        )
                resp.CreateContexts = CreateContexts
        self.send(resp)

    @ATMT.receive_condition(SERVING)
    def receive_change_notify_info(self, pkt):
        if SMB2_Change_Notify_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_change_notify_info)
    def send_change_notify_info_response(self, pkt):
        # [MS-SMB2] sect 3.3.5.19
        # "If the underlying object store does not support change notifications, the
        # server MUST fail this request with STATUS_NOT_SUPPORTED."
        self.update_smbheader(pkt)
        resp = self.smb_header.copy() / SMB2_Error_Response()
        resp.Command = "SMB2_CHANGE_NOTIFY"
        # ScapyFS doesn't support notifications
        resp.Status = "STATUS_NOT_SUPPORTED"
        self.send(resp)

    @ATMT.receive_condition(SERVING)
    def receive_query_directory_info(self, pkt):
        if SMB2_Query_Directory_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_query_directory_info)
    def send_query_directory_response(self, pkt):
        self.update_smbheader(pkt)
        if not pkt.FileNameLen:
            # this is broken.
            return
        query = pkt.FileName
        fid = self.get_file_id(pkt)
        # Check for handled FileInformationClass
        # 0x02: FileFullDirectoryInformation
        # 0x03: FileBothDirectoryInformation
        # 0x25: FileIdBothDirectoryInformation
        if pkt.FileInformationClass not in [0x02, 0x03, 0x25]:
            # Unknown FileInformationClass
            resp = self.smb_header.copy() / SMB2_Error_Response()
            resp.Command = "SMB2_QUERY_DIRECTORY"
            resp.Status = "STATUS_INVALID_INFO_CLASS"
            self.send(resp)
            return
        # Handle SMB2_RESTART_SCANS
        if pkt[SMB2_Query_Directory_Request].Flags.SMB2_RESTART_SCANS:
            self.enumerate_index[fid] = 0
        # Lookup the files
        try:
            files = self.lookup_folder(
                fid,
                query,
                self.enumerate_index[fid],
                {
                    0x02: FILE_FULL_DIR_INFORMATION,
                    0x03: FILE_BOTH_DIR_INFORMATION,
                    0x25: FILE_ID_BOTH_DIR_INFORMATION,
                }[pkt.FileInformationClass],
            )
        except NotADirectoryError:
            resp = self.smb_header.copy() / SMB2_Error_Response()
            resp.Command = "SMB2_QUERY_DIRECTORY"
            resp.Status = "STATUS_INVALID_PARAMETER"
            self.send(resp)
            return
        if not files:
            # No more files !
            self.enumerate_index[fid] = 0
            resp = self.smb_header.copy() / SMB2_Error_Response()
            resp.Command = "SMB2_QUERY_DIRECTORY"
            resp.Status = "STATUS_NO_MORE_FILES"
            self.send(resp)
            return
        # Handle SMB2_RETURN_SINGLE_ENTRY
        if pkt[SMB2_Query_Directory_Request].Flags.SMB2_RETURN_SINGLE_ENTRY:
            files = files[:1]
        # Increment index
        self.enumerate_index[fid] += len(files)
        # Build response based on the FileInformationClass
        fileinfo = FileIdBothDirectoryInformation(
            files=files,
        )
        self.send(
            self.smb_header.copy()
            / SMB2_Query_Directory_Response(Buffer=[("Output", fileinfo)])
        )

    @ATMT.receive_condition(SERVING)
    def receive_query_info(self, pkt):
        if SMB2_Query_Info_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_query_info)
    def send_query_info_response(self, pkt):
        self.update_smbheader(pkt)
        # [MS-FSCC] + [MS-SMB2] sect 2.2.37 / 3.3.5.20.1
        fid = self.get_file_id(pkt)
        if pkt.InfoType == 0x01:  # SMB2_0_INFO_FILE
            if pkt.FileInfoClass == 0x05:  # FileStandardInformation
                attrs = self.current_handles[fid][1]
                fileinfo = FileStandardInformation(
                    EndOfFile=attrs["EndOfFile"],
                    AllocationSize=attrs["AllocationSize"],
                )
            elif pkt.FileInfoClass == 0x06:  # FileInternalInformation
                pth = self.current_handles[fid][0]
                fileinfo = FileInternalInformation(
                    IndexNumber=hash(pth) & 0xFFFFFFFFFFFFFFFF,
                )
            elif pkt.FileInfoClass == 0x07:  # FileEaInformation
                fileinfo = FileEaInformation()
            elif pkt.FileInfoClass == 0x12:  # FileAllInformation
                attrs = self.current_handles[fid][1]
                fileinfo = FileAllInformation(
                    BasicInformation=FileBasicInformation(
                        CreationTime=attrs["CreationTime"],
                        LastAccessTime=attrs["LastAccessTime"],
                        LastWriteTime=attrs["LastWriteTime"],
                        ChangeTime=attrs["ChangeTime"],
                        FileAttributes=attrs["FileAttributes"],
                    ),
                    StandardInformation=FileStandardInformation(
                        EndOfFile=attrs["EndOfFile"],
                        AllocationSize=attrs["AllocationSize"],
                    ),
                )
            elif pkt.FileInfoClass == 0x15:  # FileAlternateNameInformation
                pth = self.current_handles[fid][0]
                fileinfo = FileAlternateNameInformation(
                    FileName=pth.name,
                )
            elif pkt.FileInfoClass == 0x16:  # FileStreamInformation
                attrs = self.current_handles[fid][1]
                fileinfo = FileStreamInformation(
                    StreamSize=attrs["EndOfFile"],
                    StreamAllocationSize=attrs["AllocationSize"],
                )
            elif pkt.FileInfoClass == 0x22:  # FileNetworkOpenInformation
                attrs = self.current_handles[fid][1]
                fileinfo = FileNetworkOpenInformation(
                    **attrs,
                )
            elif pkt.FileInfoClass == 0x30:  # FileNormalizedNameInformation
                pth = self.current_handles[fid][0]
                fileinfo = FILE_NAME_INFORMATION(
                    FileName=pth.name,
                )
            else:
                log_runtime.warning(
                    "Unimplemented: %s"
                    % pkt[SMB2_Query_Info_Request].sprintf("%InfoType% %FileInfoClass%")
                )
                return
        elif pkt.InfoType == 0x02:  # SMB2_0_INFO_FILESYSTEM
            # [MS-FSCC] sect 2.5
            if pkt.FileInfoClass == 0x01:  # FileFsVolumeInformation
                fileinfo = FileFsVolumeInformation()
            elif pkt.FileInfoClass == 0x03:  # FileFsSizeInformation
                fileinfo = FileFsSizeInformation()
            elif pkt.FileInfoClass == 0x05:  # FileFsAttributeInformation
                fileinfo = FileFsAttributeInformation(
                    FileSystemAttributes=0x88000F,
                )
            elif pkt.FileInfoClass == 0x07:  # FileEaInformation
                fileinfo = FileEaInformation()
            else:
                log_runtime.warning(
                    "Unimplemented: %s"
                    % pkt[SMB2_Query_Info_Request].sprintf("%InfoType% %FileInfoClass%")
                )
                return
        elif pkt.InfoType == 0x03:  # SMB2_0_INFO_SECURITY
            # [MS-FSCC] 2.4.6
            fileinfo = SECURITY_DESCRIPTOR()
            # TODO: fill it
            if pkt.AdditionalInformation.OWNER_SECURITY_INFORMATION:
                pass
            if pkt.AdditionalInformation.GROUP_SECURITY_INFORMATION:
                pass
            if pkt.AdditionalInformation.DACL_SECURITY_INFORMATION:
                pass
            if pkt.AdditionalInformation.SACL_SECURITY_INFORMATION:
                pass
            # Observed:
            if (
                pkt.AdditionalInformation.OWNER_SECURITY_INFORMATION
                or pkt.AdditionalInformation.SACL_SECURITY_INFORMATION
                or pkt.AdditionalInformation.GROUP_SECURITY_INFORMATION
                or pkt.AdditionalInformation.DACL_SECURITY_INFORMATION
            ):
                pkt = self.smb_header.copy() / SMB2_Error_Response(ErrorData=b"\xff")
                pkt.Status = "STATUS_ACCESS_DENIED"
                pkt.Command = "SMB2_QUERY_INFO"
                self.send(pkt)
                return
            if pkt.AdditionalInformation.ATTRIBUTE_SECURITY_INFORMATION:
                fileinfo.Control = 0x8800
        self.send(
            self.smb_header.copy()
            / SMB2_Query_Info_Response(Buffer=[("Output", fileinfo)])
        )

    @ATMT.receive_condition(SERVING)
    def receive_set_info_request(self, pkt):
        if SMB2_Set_Info_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_set_info_request)
    def send_set_info_response(self, pkt):
        self.update_smbheader(pkt)
        self.send(self.smb_header.copy() / SMB2_Set_Info_Response())

    @ATMT.receive_condition(SERVING)
    def receive_write_request(self, pkt):
        if SMB2_Write_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_write_request)
    def send_write_response(self, pkt):
        self.update_smbheader(pkt)
        resp = SMB2_Write_Response(Count=len(pkt.Data))
        fid = self.get_file_id(pkt)
        if self.current_tree() == "IPC$":
            if fid in self.PIPES_TABLE.values():
                # A pipe
                self.rpc_server.recv(pkt.Data)
        else:
            if self.readonly:
                # Read only !
                resp = SMB2_Error_Response()
                resp.Command = "SMB2_WRITE"
                resp.Status = "ERROR_FILE_READ_ONLY"
            else:
                # Write file
                pth, _ = self.current_handles[fid]
                length = pkt[SMB2_Write_Request].DataLen
                off = pkt[SMB2_Write_Request].Offset
                self.vprint("Writing %s bytes at %s" % (length, off))
                with open(pth, "r+b") as fd:
                    fd.seek(off)
                    resp.Count = fd.write(pkt[SMB2_Write_Request].Data)
        self.send(self.smb_header.copy() / resp)

    @ATMT.receive_condition(SERVING)
    def receive_read_request(self, pkt):
        if SMB2_Read_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_read_request)
    def send_read_response(self, pkt):
        self.update_smbheader(pkt)
        resp = SMB2_Read_Response()
        fid = self.get_file_id(pkt)
        if self.current_tree() == "IPC$":
            # Read output from DCE/RPC server
            r = self.rpc_server.get_response()
            resp.Data = bytes(r)
        else:
            # Read file and send content
            pth, _ = self.current_handles[fid]
            length = pkt[SMB2_Read_Request].Length
            off = pkt[SMB2_Read_Request].Offset
            self.vprint("Reading %s bytes at %s" % (length, off))
            with open(pth, "rb") as fd:
                fd.seek(off)
                resp.Data = fd.read(length)
        self.send(self.smb_header.copy() / resp)

    @ATMT.receive_condition(SERVING)
    def receive_close_request(self, pkt):
        if SMB2_Close_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_close_request)
    def send_close_response(self, pkt):
        self.update_smbheader(pkt)
        if self.current_tree() != "IPC$":
            fid = self.get_file_id(pkt)
            pth, attrs = self.current_handles[fid]
            if pth:
                self.vprint("Closed: " + str(pth))
            del self.current_handles[fid]
            del self.enumerate_index[fid]
            self.send(
                self.smb_header.copy()
                / SMB2_Close_Response(
                    Flags=pkt[SMB2_Close_Request].Flags,
                    **attrs,
                )
            )
        else:
            self.send(self.smb_header.copy() / SMB2_Close_Response())

    @ATMT.receive_condition(SERVING)
    def receive_tree_disconnect_request(self, pkt):
        if SMB2_Tree_Disconnect_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_tree_disconnect_request)
    def send_tree_disconnect_response(self, pkt):
        self.update_smbheader(pkt)
        try:
            del self.current_trees[self.smb_header.TID]  # clear tree
            resp = self.smb_header.copy() / SMB2_Tree_Disconnect_Response()
        except KeyError:
            resp = self.smb_header.copy() / SMB2_Error_Response()
            resp.Command = "SMB2_TREE_DISCONNECT"
            resp.Status = "STATUS_NETWORK_NAME_DELETED"
        self.send(resp)

    @ATMT.receive_condition(SERVING)
    def receive_cancel_request(self, pkt):
        if SMB2_Cancel_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_cancel_request)
    def send_notify_cancel_response(self, pkt):
        self.update_smbheader(pkt)
        resp = self.smb_header.copy() / SMB2_Change_Notify_Response()
        resp.Status = "STATUS_CANCELLED"
        self.send(resp)

    @ATMT.receive_condition(SERVING)
    def receive_echo_request(self, pkt):
        if SMB2_Echo_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_echo_request)
    def send_echo_reply(self, pkt):
        self.update_smbheader(pkt)
        self.send(self.smb_header.copy() / SMB2_Echo_Response())


# DCE/RPC server for SMB


class SMB_DCERPC_Server(DCERPC_Server):
    """
    DCE/RPC server than handles the minimum RPCs for SMB to work:
    """

    def __init__(self, *args, **kwargs):
        self.shares = kwargs.pop("shares")
        super(SMB_DCERPC_Server, self).__init__(*args, **kwargs)

    @DCERPC_Server.answer(NetrShareEnum_Request)
    def netr_share_enum(self, req):
        """
        NetrShareEnum [MS-SRVS]
        "retrieves information about each shared resource on a server."
        """
        nbEntries = len(self.shares)
        return NetrShareEnum_Response(
            InfoStruct=LPSHARE_ENUM_STRUCT(
                Level=1,
                ShareInfo=NDRUnion(
                    tag=1,
                    value=SHARE_INFO_1_CONTAINER(
                        Buffer=[
                            # Add shares
                            LPSHARE_INFO_1(
                                shi1_netname=x.name,
                                shi1_type=x.type,
                                shi1_remark=x.remark,
                            )
                            for x in self.shares
                        ],
                        EntriesRead=nbEntries,
                    ),
                ),
            ),
            TotalEntries=nbEntries,
            ndr64=self.ndr64,
        )

    @DCERPC_Server.answer(NetrWkstaGetInfo_Request)
    def netr_wksta_getinfo(self, req):
        """
        NetrWkstaGetInfo [MS-SRVS]
        "returns information about the configuration of a workstation."
        """
        return NetrWkstaGetInfo_Response(
            WkstaInfo=NDRUnion(
                tag=100,
                value=LPWKSTA_INFO_100(
                    wki100_platform_id=500,  # NT
                    wki100_ver_major=5,
                ),
            ),
            ndr64=self.ndr64,
        )

    @DCERPC_Server.answer(NetrServerGetInfo_Request)
    def netr_server_getinfo(self, req):
        """
        NetrServerGetInfo [MS-WKST]
        "retrieves current configuration information for CIFS and
        SMB Version 1.0 servers."
        """
        return NetrServerGetInfo_Response(
            ServerInfo=NDRUnion(
                tag=101,
                value=LPSERVER_INFO_101(
                    sv101_platform_id=500,  # NT
                    sv101_name=req.ServerName.value.value[0].value,
                    sv101_version_major=6,
                    sv101_version_minor=1,
                    sv101_type=1,  # Workstation
                ),
            ),
            ndr64=self.ndr64,
        )

    @DCERPC_Server.answer(NetrShareGetInfo_Request)
    def netr_share_getinfo(self, req):
        """
        NetrShareGetInfo [MS-SRVS]
        "retrieves information about a particular shared resource on a server."
        """
        return NetrShareGetInfo_Response(
            ShareInfo=NDRUnion(
                tag=1,
                value=LPSHARE_INFO_1(
                    shi1_netname=req.NetName.value[0].value,
                    shi1_type=0,
                    shi1_remark=b"",
                ),
            ),
            ndr64=self.ndr64,
        )


# Util


class smbserver:
    r"""
    Spawns a simple smbserver

    smbserver parameters:

        :param shares: the list of shares to announce. Note that IPC$ is appended.
                       By default, a 'Scapy' share on './'
        :param port:  (optional) the port to bind on, default 445
        :param iface:  (optional) the interface to bind on, default conf.iface
        :param readonly: (optional) whether the server is read-only or not. default True
        :param ssp: (optional) the SSP to use. See the examples below.
                    Default NTLM with guest

    Many more SMB-specific parameters are available in help(SMB_Server)
    """

    def __init__(
        self,
        shares=None,
        iface: str = None,
        port: int = 445,
        verb: int = 2,
        readonly: bool = True,
        # SMB arguments
        ssp=None,
        **kwargs,
    ):
        # Default Share
        if shares is None:
            shares = [
                SMBShare(
                    name="Scapy", path=".", remark="Scapy's SMB server default share"
                )
            ]
        # Verb
        if verb >= 2:
            log_runtime.info("-- Scapy %s SMB Server --" % conf.version)
            log_runtime.info(
                "SSP: %s. Read-Only: %s. Serving %s shares:"
                % (
                    conf.color_theme.yellow(ssp or "NTLM (guest)"),
                    (
                        conf.color_theme.yellow("YES")
                        if readonly
                        else conf.color_theme.format("NO", "bg_red+white")
                    ),
                    conf.color_theme.red(len(shares)),
                )
            )
            for share in shares:
                log_runtime.info(" * %s" % share)
        # Start SMB Server
        self.srv = SMB_Server.spawn(
            # TCP server
            port=port,
            iface=iface or conf.loopback_name,
            verb=verb,
            # SMB server
            ssp=ssp,
            shares=shares,
            readonly=readonly,
            # SMB arguments
            **kwargs,
        )

    def close(self):
        """
        Close the smbserver if started in background mode (bg=True)
        """
        if self.srv:
            try:
                self.srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.srv.close()


if __name__ == "__main__":
    from scapy.utils import AutoArgparse

    AutoArgparse(smbserver)
