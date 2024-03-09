# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
SMB 1 / 2 Client Automaton
"""

import io
import os
import pathlib
import socket
import time
import threading

from scapy.automaton import ATMT, Automaton, ObjectPipe
from scapy.base_classes import Net
from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.fields import UTCTimeField
from scapy.supersocket import SuperSocket
from scapy.utils import (
    CLIUtil,
    pretty_list,
    human_size,
    valid_ip,
    valid_ip6,
)
from scapy.volatile import RandUUID

from scapy.layers.dcerpc import NDRUnion, find_dcerpc_interface
from scapy.layers.gssapi import (
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
)
from scapy.layers.inet6 import Net6
from scapy.layers.kerberos import (
    KerberosSSP,
    krb_as_and_tgs,
    _parse_upn,
)
from scapy.layers.msrpce.raw.ms_srvs import (
    LPSHARE_ENUM_STRUCT,
    NetrShareEnum_Request,
    NetrShareEnum_Response,
    SHARE_INFO_1_CONTAINER,
)
from scapy.layers.ntlm import (
    NTLMSSP,
    MD4le,
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
    SMB_Dialect,
    SMB_Header,
)
from scapy.layers.smb2 import (
    DirectTCP,
    FileAllInformation,
    FileIdBothDirectoryInformation,
    SMB2_Change_Notify_Request,
    SMB2_Change_Notify_Response,
    SMB2_Close_Request,
    SMB2_Close_Response,
    SMB2_Create_Request,
    SMB2_Create_Response,
    SMB2_Error_Response,
    SMB2_Header,
    SMB2_IOCTL_Request,
    SMB2_IOCTL_Response,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Negotiate_Protocol_Response,
    SMB2_Query_Directory_Request,
    SMB2_Query_Directory_Response,
    SMB2_Query_Info_Request,
    SMB2_Query_Info_Response,
    SMB2_Read_Request,
    SMB2_Read_Response,
    SMB2_Session_Setup_Request,
    SMB2_Session_Setup_Response,
    SMB2_Tree_Connect_Request,
    SMB2_Tree_Connect_Response,
    SMB2_Tree_Disconnect_Request,
    SMB2_Tree_Disconnect_Response,
    SMB2_Write_Request,
    SMB2_Write_Response,
    SMBStreamSocket,
    SRVSVC_SHARE_TYPES,
    STATUS_ERREF,
)
from scapy.layers.spnego import SPNEGOSSP


class SMB_Client(Automaton):
    port = 445
    cls = DirectTCP

    def __init__(self, sock, ssp=None, *args, **kwargs):
        # Various SMB client arguments
        self.EXTENDED_SECURITY = kwargs.pop("EXTENDED_SECURITY", True)
        self.USE_SMB1 = kwargs.pop("USE_SMB1", False)
        self.REQUIRE_SIGNATURE = kwargs.pop("REQUIRE_SIGNATURE", False)
        self.SecurityMode = kwargs.pop(
            "SECURITY_MODE",
            3 if self.REQUIRE_SIGNATURE else int(bool(ssp)),
        )
        self.RETRY = kwargs.pop("RETRY", 0)  # optionally: retry n times session setup
        self.SMB2 = kwargs.pop("SMB2", False)  # optionally: start directly in SMB2
        self.DIALECTS = [
            0x0202
        ]  # XXX: add support for credit charge so we can upgrade this
        # Internal Session information
        self.Authenticated = False
        self.Dialect = None
        self.IsGuest = False
        self.ErrorStatus = None
        if ssp is None:
            # We got no SSP. Assuming the server allows anonymous
            ssp = SPNEGOSSP(
                [
                    NTLMSSP(
                        UPN="guest",
                        HASHNT=b"",
                    )
                ]
            )
        self.ssp = ssp
        self.sspcontext = None
        Automaton.__init__(
            self,
            recvsock=lambda **kwargs: sock,
            ll=lambda **kwargs: sock,
            *args,
            **kwargs,
        )
        if self.is_atmt_socket:
            self.smb_sock_ready = threading.Event()

    @classmethod
    def from_tcpsock(cls, sock, **kwargs):
        return cls.smblink(
            None,
            SMBStreamSocket(sock, DirectTCP),
            **kwargs,
        )

    def send(self, pkt):
        if self.Authenticated and self.sspcontext.SessionKey:
            if isinstance(pkt.payload, SMB2_Header):
                # Sign SMB2 !
                smb = pkt[SMB2_Header]
                smb.Flags += "SMB2_FLAGS_SIGNED"
                smb.sign(self.Dialect, self.sspcontext.SessionKey)
        # TODO: compute creditscharge
        # currently the client is stuck on 2.0.2 because of that
        return super(SMB_Client, self).send(pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        pass

    @ATMT.condition(BEGIN)
    def continue_smb2(self):
        if self.SMB2:  # Directly started in SMB2
            self.smb_header = DirectTCP() / SMB2_Header(PID=0xFEFF)
            raise self.SMB2_NEGOTIATE()

    @ATMT.condition(BEGIN, prio=1)
    def send_negotiate(self):
        raise self.SENT_NEGOTIATE()

    @ATMT.action(send_negotiate)
    def on_negotiate(self):
        self.smb_header = DirectTCP() / SMB_Header(
            Flags2=(
                "LONG_NAMES+EAS+NT_STATUS+UNICODE+"
                "SMB_SECURITY_SIGNATURE+EXTENDED_SECURITY"
            ),
            TID=0xFFFF,
            PIDLow=0xFEFF,
            UID=0,
            MID=0,
        )
        if self.EXTENDED_SECURITY:
            self.smb_header.Flags2 += "EXTENDED_SECURITY"
        pkt = self.smb_header.copy() / SMBNegotiate_Request(
            Dialects=[
                SMB_Dialect(DialectString=x)
                for x in [
                    "PC NETWORK PROGRAM 1.0",
                    "LANMAN1.0",
                    "Windows for Workgroups 3.1a",
                    "LM1.2X002",
                    "LANMAN2.1",
                    "NT LM 0.12",
                ]
                + (["SMB 2.002", "SMB 2.???"] if not self.USE_SMB1 else [])
            ],
        )
        if not self.EXTENDED_SECURITY:
            pkt.Flags2 -= "EXTENDED_SECURITY"
        pkt[SMB_Header].Flags2 = (
            pkt[SMB_Header].Flags2
            - "SMB_SECURITY_SIGNATURE"
            + "SMB_SECURITY_SIGNATURE_REQUIRED+IS_LONG_NAME"
        )
        self.send(pkt)

    @ATMT.state()
    def SENT_NEGOTIATE(self):
        pass

    @ATMT.receive_condition(SENT_NEGOTIATE)
    def receive_negotiate_response(self, pkt):
        if (
            SMBNegotiate_Response_Security in pkt
            or SMBNegotiate_Response_Extended_Security in pkt
            or SMB2_Negotiate_Protocol_Response in pkt
        ):
            if SMB2_Negotiate_Protocol_Response in pkt:
                # SMB2
                self.SMB2 = True  # We are using SMB2 to talk to the server
                self.smb_header = DirectTCP() / SMB2_Header(PID=0xFEFF)
        if (
            SMBNegotiate_Response_Extended_Security in pkt
            or SMB2_Negotiate_Protocol_Response in pkt
        ):
            # Extended SMB1 / SMB2
            try:
                ssp_blob = pkt.SecurityBlob  # eventually SPNEGO server initiation
            except AttributeError:
                ssp_blob = None
            if self.SMB2:
                self.smb_header.MID += 1
            if (
                SMB2_Negotiate_Protocol_Response in pkt
                and pkt.DialectRevision & 0xFF == 0xFF
            ):
                # Version is SMB X.???
                raise self.SMB2_NEGOTIATE()
            else:
                if SMB2_Negotiate_Protocol_Response in pkt:
                    self.Dialect = pkt.DialectRevision
                raise self.NEGOTIATED(ssp_blob)
        elif SMBNegotiate_Response_Security in pkt:
            # Non-extended SMB1
            # Never tested. FIXME. probably broken
            raise self.NEGOTIATED(pkt.Challenge)

    @ATMT.state()
    def SMB2_NEGOTIATE(self):
        pass

    @ATMT.condition(SMB2_NEGOTIATE)
    def send_negotiate_smb2(self):
        raise self.SENT_NEGOTIATE()

    @ATMT.action(send_negotiate_smb2)
    def on_negotiate_smb2(self):
        pkt = self.smb_header.copy() / SMB2_Negotiate_Protocol_Request(
            Dialects=self.DIALECTS,
            Capabilities="DFS",
            SecurityMode=self.SecurityMode,
            ClientGUID=RandUUID()._fix(),
        )
        self.send(pkt)

    @ATMT.state()
    def NEGOTIATED(self, ssp_blob=None):
        ssp_tuple = self.ssp.GSS_Init_sec_context(self.sspcontext, ssp_blob)
        return ssp_tuple

    # DEV: add a condition on NEGOTIATED with prio=0

    @ATMT.condition(NEGOTIATED, prio=1)
    def should_send_setup_andx_request(self, ssp_tuple):
        _, _, negResult = ssp_tuple
        if negResult not in [GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED]:
            raise ValueError("Internal error: the SSP completed with an error.")
        raise self.SENT_SETUP_ANDX_REQUEST().action_parameters(ssp_tuple)

    @ATMT.state()
    def SENT_SETUP_ANDX_REQUEST(self):
        pass

    @ATMT.action(should_send_setup_andx_request)
    def send_setup_andx_request(self, ssp_tuple):
        self.sspcontext, token, negResult = ssp_tuple
        self.smb_header.MID += 1
        if self.SMB2 and negResult == GSS_S_CONTINUE_NEEDED:
            # New session: force 0
            self.SessionId = 0
        if self.SMB2 or self.EXTENDED_SECURITY:
            # SMB1 extended / SMB2
            if self.SMB2:
                # SMB2
                pkt = self.smb_header.copy() / SMB2_Session_Setup_Request(
                    Capabilities="DFS",
                    SecurityMode=self.SecurityMode,
                )
            else:
                # SMB1 extended
                pkt = (
                    self.smb_header.copy()
                    / SMBSession_Setup_AndX_Request_Extended_Security(
                        ServerCapabilities=(
                            "UNICODE+NT_SMBS+STATUS32+LEVEL_II_OPLOCKS+"
                            "DYNAMIC_REAUTH+EXTENDED_SECURITY"
                        ),
                        NativeOS=b"",
                        NativeLanMan=b"",
                    )
                )
            pkt.SecurityBlob = token
        else:
            # Non-extended security.
            pkt = self.smb_header.copy() / SMBSession_Setup_AndX_Request(
                ServerCapabilities="UNICODE+NT_SMBS+STATUS32+LEVEL_II_OPLOCKS",
                NativeOS=b"",
                NativeLanMan=b"",
                OEMPassword=b"\0" * 24,
                UnicodePassword=token,
            )
        self.send(pkt)

    @ATMT.receive_condition(SENT_SETUP_ANDX_REQUEST)
    def receive_setup_andx_response(self, pkt):
        if (
            SMBSession_Null in pkt
            or SMBSession_Setup_AndX_Response_Extended_Security in pkt
            or SMBSession_Setup_AndX_Response in pkt
        ):
            # SMB1
            if SMBSession_Null in pkt:
                # Likely an error
                raise self.NEGOTIATED()
        # Logging
        if pkt.Status != 0 and pkt.Status != 0xC0000016:
            # Not SUCCESS nor MORE_PROCESSING_REQUIRED: log
            self.ErrorStatus = pkt.sprintf("%SMB2_Header.Status%")
            self.debug(
                lvl=1,
                msg=conf.color_theme.red(
                    pkt.sprintf("SMB Session Setup Response: %SMB2_Header.Status%")
                ),
            )
        # Cases depending on the response packet
        if (
            SMBSession_Setup_AndX_Response_Extended_Security in pkt
            or SMB2_Session_Setup_Response in pkt
        ):
            # The server assigns us a SessionId
            self.smb_header.SessionId = pkt.SessionId
            # SMB1 extended / SMB2
            if pkt.Status == 0:  # Authenticated
                if SMB2_Session_Setup_Response in pkt and (pkt.SessionFlags.IS_GUEST):
                    # We were 'authenticated' in GUEST
                    self.IsGuest = True
                raise self.AUTHENTICATED(pkt.SecurityBlob)
            else:
                # Ongoing auth
                raise self.NEGOTIATED(pkt.SecurityBlob)
        elif SMBSession_Setup_AndX_Response_Extended_Security in pkt:
            # SMB1 non-extended
            pass
        elif SMB2_Error_Response in pkt:
            # Authentication failure
            self.sspcontext = None
            if not self.RETRY:
                raise self.AUTH_FAILED()
            self.debug(lvl=2, msg="RETRY: %s" % self.RETRY)
            self.RETRY -= 1
            raise self.NEGOTIATED()

    @ATMT.state(final=1)
    def AUTH_FAILED(self):
        self.smb_sock_ready.set()

    @ATMT.state()
    def AUTHENTICATED(self, ssp_blob=None):
        self.sspcontext, _, status = self.ssp.GSS_Init_sec_context(
            self.sspcontext, ssp_blob
        )
        if status != GSS_S_COMPLETE:
            raise ValueError("Internal error: the SSP completed with an error.")
        if self.IsGuest:
            # When authenticated in Guest, the sessionkey the client has is invalid
            self.sspcontext.SessionKey = None
        self.Authenticated = True

    # DEV: add a condition on AUTHENTICATED with prio=0

    @ATMT.condition(AUTHENTICATED, prio=1)
    def authenticated_post_actions(self):
        raise self.SOCKET_BIND()

    # Plain SMB Socket

    @ATMT.state()
    def SOCKET_BIND(self):
        self.smb_sock_ready.set()

    @ATMT.condition(SOCKET_BIND)
    def start_smb_socket(self):
        raise self.SOCKET_MODE_SMB()

    @ATMT.state()
    def SOCKET_MODE_SMB(self):
        pass

    @ATMT.receive_condition(SOCKET_MODE_SMB)
    def incoming_data_received_smb(self, pkt):
        raise self.SOCKET_MODE_SMB().action_parameters(pkt)

    @ATMT.action(incoming_data_received_smb)
    def receive_data_smb(self, pkt):
        if not pkt.Flags.SMB2_FLAGS_ASYNC_COMMAND:
            # PID and TID are not set when ASYNC
            self.smb_header.TID = pkt.TID
            self.smb_header.PID = pkt.PID
        resp = pkt[SMB2_Header].payload
        if isinstance(resp, SMB2_Error_Response):
            if pkt.Status == 0x00000103:  # STATUS_PENDING
                # answer is coming later.. just wait...
                return
            if pkt.Status == 0x0000010B:  # STATUS_NOTIFY_CLEANUP
                # this is a notify cleanup. ignore
                return
        # Add the status to the response as metadata
        resp.NTStatus = pkt.sprintf("%SMB2_Header.Status%")
        self.oi.smbpipe.send(resp)

    @ATMT.ioevent(SOCKET_MODE_SMB, name="smbpipe", as_supersocket="smblink")
    def outgoing_data_received_smb(self, fd):
        raise self.SOCKET_MODE_SMB().action_parameters(fd.recv())

    @ATMT.action(outgoing_data_received_smb)
    def send_data(self, d):
        self.smb_header.MID += 1
        self.send(self.smb_header.copy() / d)


class SMB_SOCKET(SuperSocket):
    """
    Mid-level wrapper over SMB_Client.smblink that provides some basic SMB
    client functions, such as tree connect, directory query, etc.
    """

    def __init__(self, smbsock, use_ioctl=True, timeout=3):
        self.ins = smbsock
        self.timeout = timeout
        if not self.ins.atmt.smb_sock_ready.wait(timeout=timeout):
            raise TimeoutError(
                "The SMB handshake timed out ! (enable debug=1 for logs)"
            )
        if self.ins.atmt.ErrorStatus:
            raise Scapy_Exception(
                "SMB Session Setup failed: %s" % self.ins.atmt.ErrorStatus
            )

    @classmethod
    def from_tcpsock(cls, sock, **kwargs):
        """
        Wraps the tcp socket in a SMB_Client.smblink first, then into the
        SMB_SOCKET/SMB_RPC_SOCKET
        """
        return cls(
            use_ioctl=kwargs.pop("use_ioctl", True),
            timeout=kwargs.pop("timeout", 3),
            smbsock=SMB_Client.from_tcpsock(sock, **kwargs),
        )

    def set_TID(self, TID):
        """
        Set the TID (Tree ID).
        This can be called before sending a packet
        """
        self.ins.atmt.smb_header.TID = TID

    def get_TID(self):
        """
        Get the current TID from the underlying socket
        """
        return self.ins.atmt.smb_header.TID

    def tree_connect(self, name):
        """
        Send a TreeConnect request
        """
        resp = self.ins.sr1(
            SMB2_Tree_Connect_Request(
                Buffer=[
                    (
                        "Path",
                        "\\\\%s\\%s"
                        % (
                            self.ins.atmt.sspcontext.ServerHostname,
                            name,
                        ),
                    )
                ]
            ),
            verbose=False,
            timeout=self.timeout,
        )
        if not resp:
            raise ValueError("TreeConnect timed out !")
        if SMB2_Tree_Connect_Response not in resp:
            raise ValueError("Failed TreeConnect ! %s" % resp.NTStatus)
        return self.get_TID()

    def tree_disconnect(self):
        """
        Send a TreeDisconnect request
        """
        resp = self.ins.sr1(
            SMB2_Tree_Disconnect_Request(),
            verbose=False,
            timeout=self.timeout,
        )
        if not resp:
            raise ValueError("TreeDisconnect timed out !")
        if SMB2_Tree_Disconnect_Response not in resp:
            raise ValueError("Failed TreeDisconnect ! %s" % resp.NTStatus)

    def create_request(
        self,
        name,
        mode="r",
        type="pipe",
        extra_create_options=[],
        extra_desired_access=[],
    ):
        """
        Open a file/pipe by its name

        :param name: the name of the file or named pipe. e.g. 'srvsvc'
        """
        ShareAccess = []
        DesiredAccess = []
        # Common params depending on the access
        if "r" in mode:
            ShareAccess.append("FILE_SHARE_READ")
            DesiredAccess.extend(["FILE_READ_DATA", "FILE_READ_ATTRIBUTES"])
        if "w" in mode:
            ShareAccess.append("FILE_SHARE_WRITE")
            DesiredAccess.extend(["FILE_WRITE_DATA", "FILE_WRITE_ATTRIBUTES"])
        if "d" in mode:
            ShareAccess.append("FILE_SHARE_DELETE")
        # Params depending on the type
        FileAttributes = []
        CreateOptions = []
        CreateDisposition = "FILE_OPEN"
        if type == "folder":
            FileAttributes.append("FILE_ATTRIBUTE_DIRECTORY")
            CreateOptions.append("FILE_DIRECTORY_FILE")
        elif type in ["file", "pipe"]:
            CreateOptions = ["FILE_NON_DIRECTORY_FILE"]
            if "r" in mode:
                DesiredAccess.extend(["FILE_READ_EA", "READ_CONTROL", "SYNCHRONIZE"])
            if "w" in mode:
                CreateDisposition = "FILE_OVERWRITE_IF"
                DesiredAccess.append("FILE_WRITE_EA")
            if "d" in mode:
                DesiredAccess.append("DELETE")
                CreateOptions.append("FILE_DELETE_ON_CLOSE")
            if type == "file":
                FileAttributes.append("FILE_ATTRIBUTE_NORMAL")
        elif type:
            raise ValueError("Unknown type: %s" % type)
        # Extra options
        if extra_create_options:
            CreateOptions.extend(extra_create_options)
        if extra_desired_access:
            DesiredAccess.extend(extra_desired_access)
        # Request
        resp = self.ins.sr1(
            SMB2_Create_Request(
                ImpersonationLevel="Impersonation",
                DesiredAccess="+".join(DesiredAccess),
                CreateDisposition=CreateDisposition,
                CreateOptions="+".join(CreateOptions),
                ShareAccess="+".join(ShareAccess),
                FileAttributes="+".join(FileAttributes),
                Name=name,
            ),
            verbose=0,
            timeout=self.timeout,
        )
        if not resp:
            raise ValueError("CreateRequest timed out !")
        if SMB2_Create_Response not in resp:
            raise ValueError("Failed CreateRequest ! %s" % resp.NTStatus)
        return resp[SMB2_Create_Response].FileId

    def close_request(self, FileId):
        """
        Close the FileId
        """
        pkt = SMB2_Close_Request(FileId=FileId)
        resp = self.ins.sr1(pkt, verbose=0, timeout=self.timeout)
        if not resp:
            raise ValueError("CloseRequest timed out !")
        if SMB2_Close_Response not in resp:
            raise ValueError("Failed CloseRequest ! %s" % resp.NTStatus)

    def read_request(self, FileId, Length, Offset=0):
        """
        Read request
        """
        resp = self.ins.sr1(
            SMB2_Read_Request(
                FileId=FileId,
                Length=Length,
                Offset=Offset,
            ),
            verbose=0,
            timeout=self.timeout,
        )
        if not resp:
            raise ValueError("ReadRequest timed out !")
        if SMB2_Read_Response not in resp:
            raise ValueError("Failed ReadRequest ! %s" % resp.NTStatus)
        return resp.Data

    def write_request(self, Data, FileId, Offset=0):
        """
        Write request
        """
        resp = self.ins.sr1(
            SMB2_Write_Request(
                FileId=FileId,
                Data=Data,
                Offset=Offset,
            ),
            verbose=0,
            timeout=self.timeout,
        )
        if not resp:
            raise ValueError("WriteRequest timed out !")
        if SMB2_Write_Response not in resp:
            raise ValueError("Failed WriteRequest ! %s" % resp.NTStatus)
        return resp.Count

    def query_directory(self, FileId, FileName="*"):
        """
        Query the Directory with FileId
        """
        results = []
        Flags = "SMB2_RESTART_SCANS"
        while True:
            pkt = SMB2_Query_Directory_Request(
                FileInformationClass="FileIdBothDirectoryInformation",
                FileId=FileId,
                FileName=FileName,
                Flags=Flags,
            )
            resp = self.ins.sr1(pkt, verbose=0, timeout=self.timeout)
            Flags = 0  # only the first one is RESTART_SCANS
            if not resp:
                raise ValueError("QueryDirectory timed out !")
            if SMB2_Error_Response in resp:
                break
            elif SMB2_Query_Directory_Response not in resp:
                raise ValueError("Failed QueryDirectory ! %s" % resp.NTStatus)
            res = FileIdBothDirectoryInformation(resp.Output)
            results.extend(
                [
                    (
                        x.FileName,
                        x.FileAttributes,
                        x.EndOfFile,
                        x.LastWriteTime,
                    )
                    for x in res.files
                ]
            )
        return results

    def query_info(self, FileId, InfoType, FileInfoClass, AdditionalInformation=0):
        """
        Query the Info
        """
        pkt = SMB2_Query_Info_Request(
            InfoType=InfoType,
            FileInfoClass=FileInfoClass,
            OutputBufferLength=65535,
            FileId=FileId,
            AdditionalInformation=AdditionalInformation,
        )
        resp = self.ins.sr1(pkt, verbose=0, timeout=self.timeout)
        if not resp:
            raise ValueError("QueryInfo timed out !")
        if SMB2_Query_Info_Response not in resp:
            raise ValueError("Failed QueryInfo ! %s" % resp.NTStatus)
        return resp.Output

    def changenotify(self, FileId):
        """
        Register change notify
        """
        pkt = SMB2_Change_Notify_Request(
            Flags="SMB2_WATCH_TREE",
            OutputBufferLength=65535,
            FileId=FileId,
            CompletionFilter=0x0FFF,
        )
        # we can wait forever, not a problem in this one
        resp = self.ins.sr1(pkt, verbose=0, chainCC=True)
        if SMB2_Change_Notify_Response not in resp:
            raise ValueError("Failed ChangeNotify ! %s" % resp.NTStatus)
        return resp.Output


class SMB_RPC_SOCKET(ObjectPipe, SMB_SOCKET):
    """
    Extends SMB_SOCKET (which is a wrapper over SMB_Client.smblink) to send
    DCE/RPC messages (bind, reqs, etc.)

    This is usable as a normal SuperSocket (sr1, etc.) and performs the
    wrapping of the DCE/RPC messages into SMB2_Write/Read packets.
    """

    def __init__(self, smbsock, use_ioctl=True, timeout=3):
        self.use_ioctl = use_ioctl
        ObjectPipe.__init__(self, "SMB_RPC_SOCKET")
        SMB_SOCKET.__init__(self, smbsock, timeout=timeout)

    def open_pipe(self, name):
        self.PipeFileId = self.create_request(name, mode="rw", type="pipe")

    def close_pipe(self):
        self.close_request(self.PipeFileId)
        self.PipeFileId = None

    def send(self, x):
        """
        Internal ObjectPipe function.
        """
        # Reminder: this class is an ObjectPipe, it's just a queue
        if self.use_ioctl:
            # Use IOCTLRequest
            pkt = SMB2_IOCTL_Request(
                FileId=self.PipeFileId,
                Flags="SMB2_0_IOCTL_IS_FSCTL",
                CtlCode="FSCTL_PIPE_TRANSCEIVE",
            )
            pkt.Input = bytes(x)
            resp = self.ins.sr1(pkt, verbose=0)
            if SMB2_IOCTL_Response not in resp:
                raise ValueError("Failed reading IOCTL_Response ! %s" % resp.NTStatus)
            data = bytes(resp.Output)
            # Handle BUFFER_OVERFLOW (big DCE/RPC response)
            while resp.NTStatus == "STATUS_BUFFER_OVERFLOW":
                # Retrieve DCE/RPC full size
                resp = self.ins.sr1(
                    SMB2_Read_Request(
                        FileId=self.PipeFileId,
                    ),
                    verbose=0
                )
                data += resp.Data
            super(SMB_RPC_SOCKET, self).send(data)
        else:
            # Use WriteRequest/ReadRequest
            pkt = SMB2_Write_Request(
                FileId=self.PipeFileId,
            )
            pkt.Data = bytes(x)
            # We send the Write Request
            resp = self.ins.sr1(pkt, verbose=0)
            if SMB2_Write_Response not in resp:
                raise ValueError("Failed sending WriteResponse ! %s" % resp.NTStatus)
            # We send a Read Request afterwards
            resp = self.ins.sr1(
                SMB2_Read_Request(
                    FileId=self.PipeFileId,
                ),
                verbose=0,
            )
            if SMB2_Read_Response not in resp:
                raise ValueError("Failed reading ReadResponse ! %s" % resp.NTStatus)
            data = bytes(resp.Data)
            # Handle BUFFER_OVERFLOW (big DCE/RPC response)
            while resp.NTStatus == "STATUS_BUFFER_OVERFLOW":
                # Retrieve DCE/RPC full size
                resp = self.ins.sr1(
                    SMB2_Read_Request(
                        FileId=self.PipeFileId,
                    ),
                    verbose=0
                )
                data += resp.Data
            super(SMB_RPC_SOCKET, self).send(data)

    def close(self):
        SMB_SOCKET.close(self)
        ObjectPipe.close(self)


@conf.commands.register
class smbclient(CLIUtil):
    r"""
    A simple smbclient CLI

    :param target: can be a hostname, the IPv4 or the IPv6 to connect to
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param guest: use guest mode (over NTLM)
    :param ssp: if provided, use this SSP for auth.
    :param kerberos: if available, whether to use Kerberos or not
    :param kerberos_required: require kerberos
    :param port: the TCP port. default 445
    :param password: (string) if provided, used for auth
    :param HashNt: (bytes) if provided, used for auth (NTLM)
    :param ST: if provided, the service ticket to use (Kerberos)
    :param KEY: if provided, the session key associated to the ticket (Kerberos)
    :param cli: CLI mode (default True). False to use for scripting
    """

    def __init__(
        self,
        target: str,
        UPN: str = None,
        password: str = None,
        guest: bool = False,
        kerberos: bool = True,
        kerberos_required: bool = False,
        HashNt: str = None,
        port: int = 445,
        timeout: int = 2,
        debug: int = 0,
        ssp=None,
        ST=None,
        KEY=None,
        cli=True,
    ):
        if cli:
            self._depcheck()
        hostname = None
        # Check if target is a hostname / Check IP
        if ":" in target:
            family = socket.AF_INET6
            if not valid_ip6(target):
                hostname = target
            target = str(Net6(target))
        else:
            family = socket.AF_INET
            if not valid_ip(target):
                hostname = target
            target = str(Net(target))
        assert UPN or ssp or guest, "Either UPN, ssp or guest must be provided !"
        # Do we need to build a SSP?
        if ssp is None:
            # Create the SSP (only if not guest mode)
            if not guest:
                # Check UPN
                try:
                    _, realm = _parse_upn(UPN)
                    if realm == ".":
                        # Local
                        kerberos = False
                except ValueError:
                    # not a UPN: NTLM
                    kerberos = False
                # Do we need to ask the password?
                if HashNt is None and password is None and ST is None:
                    # yes.
                    from prompt_toolkit import prompt

                    password = prompt("Password: ", is_password=True)
                ssps = []
                # Kerberos
                if kerberos and hostname:
                    if ST is None:
                        resp = krb_as_and_tgs(
                            upn=UPN,
                            spn="host/%s" % hostname,
                            password=password,
                            debug=debug,
                        )
                        if resp is not None:
                            ST, KEY = resp.tgsrep.ticket, resp.sessionkey
                    if ST:
                        ssps.append(KerberosSSP(UPN=UPN, ST=ST, KEY=KEY, debug=debug))
                    elif kerberos_required:
                        raise ValueError(
                            "Kerberos required but target isn't a hostname !"
                        )
                elif kerberos_required:
                    raise ValueError(
                        "Kerberos required but domain not specified in the UPN, "
                        "or target isn't a hostname !"
                    )
                # NTLM
                if not kerberos_required:
                    if HashNt is None and password is not None:
                        HashNt = MD4le(password)
                    ssps.append(NTLMSSP(UPN=UPN, HASHNT=HashNt))
                # Build the SSP
                ssp = SPNEGOSSP(ssps)
            else:
                # Guest mode
                ssp = None
        # Open socket
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        # SMB MTU: TODO negociate
        self.MaxReadSize = self.MaxWriteSize = 65536
        self.extra_create_options = []
        # Wrap with the automaton
        self.timeout = timeout
        self.sock = SMB_Client.from_tcpsock(
            sock,
            ssp=ssp,
            debug=debug,
        )
        try:
            # Wrap with SMB_SOCKET
            self.smbsock = SMB_SOCKET(self.sock)
            # Wait for either the atmt to fail, or the smb_sock_ready to timeout
            _t = time.time()
            while True:
                if self.sock.atmt.smb_sock_ready.is_set():
                    # yay
                    break
                if not self.sock.atmt.isrunning():
                    status = self.sock.atmt.get("Status")
                    raise Scapy_Exception(
                        "%s with status %s"
                        % (
                            self.sock.atmt.state.state,
                            STATUS_ERREF.get(status, hex(status)),
                        )
                    )
                if time.time() - _t > timeout:
                    self.sock.close()
                    raise TimeoutError("The SMB handshake timed out.")
                time.sleep(0.1)
        except Exception:
            # Something bad happened, end the socket/automaton
            self.sock.close()
            raise

        # For some usages, we will also need the RPC wrapper
        from scapy.layers.msrpce.rpcclient import DCERPC_Client

        self.rpcclient = DCERPC_Client.from_smblink(self.sock, ndr64=False, verb=False)
        # We have a valid smb connection !
        print(
            "SMB authentication successful using %s%s !"
            % (
                repr(self.sock.atmt.sspcontext),
                " as GUEST" if self.sock.atmt.IsGuest else "",
            )
        )
        # Now define some variables for our CLI
        self.pwd = pathlib.PureWindowsPath("/")
        self.localpwd = pathlib.Path(".").resolve()
        self.current_tree = None
        self.ls_cache = {}  # cache the listing of the current directory
        # Start CLI
        if cli:
            self.loop(debug=debug)

    def ps1(self):
        return r"smb: \%s> " % self.normalize_path(self.pwd)

    def close(self):
        print("Connection closed")
        self.smbsock.close()

    def _require_share(self, silent=False):
        if self.current_tree is None:
            if not silent:
                print("No share selected ! Try 'shares' then 'use'.")
            return True

    def collapse_path(self, path):
        # the amount of pathlib.wtf you need to do to resolve .. on all platforms
        # is ridiculous
        return pathlib.PureWindowsPath(os.path.normpath(path.as_posix()))

    def normalize_path(self, path):
        """
        Normalize path for CIFS usage
        """
        return str(self.collapse_path(path)).lstrip("\\")

    @CLIUtil.addcommand()
    def shares(self):
        """
        List the shares available
        """
        # One of the 'hardest' considering it's an RPC
        self.rpcclient.open_smbpipe("srvsvc")
        self.rpcclient.bind(find_dcerpc_interface("srvsvc"))
        req = NetrShareEnum_Request(
            InfoStruct=LPSHARE_ENUM_STRUCT(
                Level=1,
                ShareInfo=NDRUnion(
                    tag=1,
                    value=SHARE_INFO_1_CONTAINER(Buffer=None),
                ),
            ),
            PreferedMaximumLength=0xFFFFFFFF,
        )
        resp = self.rpcclient.sr1_req(req, timeout=self.timeout)
        self.rpcclient.close_smbpipe()
        if not isinstance(resp, NetrShareEnum_Response):
            raise ValueError("NetrShareEnum_Request failed !")
        results = []
        for share in resp.valueof("InfoStruct.ShareInfo.Buffer"):
            shi1_type = share.valueof("shi1_type") & 0x0FFFFFFF
            results.append(
                (
                    share.valueof("shi1_netname").decode(),
                    SRVSVC_SHARE_TYPES.get(shi1_type, shi1_type),
                    share.valueof("shi1_remark").decode(),
                )
            )
        return results

    @CLIUtil.addoutput(shares)
    def shares_output(self, results):
        """
        Print the output of 'shares'
        """
        print(pretty_list(results, [("ShareName", "ShareType", "Comment")]))

    @CLIUtil.addcommand()
    def use(self, share):
        """
        Open a share
        """
        self.current_tree = self.smbsock.tree_connect(share)
        self.pwd = pathlib.PureWindowsPath("/")
        self.ls_cache.clear()

    def _parsepath(self, arg, remote=True):
        """
        Parse a path. Returns the parent folder and file name
        """
        # Find parent directory if it exists
        elt = (pathlib.PureWindowsPath if remote else pathlib.Path)(arg)
        eltpar = (pathlib.PureWindowsPath if remote else pathlib.Path)(".")
        eltname = elt.name
        if arg.endswith("/") or arg.endswith("\\"):
            eltpar = elt
            eltname = ""
        elif elt.parent and elt.parent.name:
            eltpar = elt.parent
        return eltpar, eltname

    def _fs_complete(self, arg, cond=None):
        """
        Return a listing of the remote files for completion purposes
        """
        if cond is None:
            cond = lambda _: True
        eltpar, eltname = self._parsepath(arg)
        # ls in that directory
        try:
            files = self.ls(parent=eltpar)
        except ValueError:
            return []
        return [
            str(eltpar / x[0])
            for x in files
            if (
                x[0].lower().startswith(eltname.lower())
                and x[0] not in [".", ".."]
                and cond(x[1])
            )
        ]

    def _dir_complete(self, arg):
        """
        Return a directories of remote files for completion purposes
        """
        results = self._fs_complete(
            arg,
            cond=lambda x: x.FILE_ATTRIBUTE_DIRECTORY,
        )
        if len(results) == 1 and results[0].startswith(arg):
            # skip through folders
            return [results[0] + "\\"]
        return results

    @CLIUtil.addcommand(spaces=True)
    def ls(self, parent=None):
        """
        List the files in the remote directory
        -t: sort by timestamp
        -S: sort by size
        """
        if self._require_share():
            return
        # Get pwd of the ls
        pwd = self.pwd
        if parent is not None:
            pwd /= parent
        pwd = self.normalize_path(pwd)
        # Poll the cache
        if self.ls_cache and pwd in self.ls_cache:
            return self.ls_cache[pwd]
        self.smbsock.set_TID(self.current_tree)
        # Open folder
        fileId = self.smbsock.create_request(
            pwd,
            type="folder",
            extra_create_options=self.extra_create_options,
        )
        # Query the folder
        files = self.smbsock.query_directory(fileId)
        # Close the folder
        self.smbsock.close_request(fileId)
        self.ls_cache[pwd] = files  # Store cache
        return files

    @CLIUtil.addoutput(ls)
    def ls_output(self, results, *, t=False, S=False):
        """
        Print the output of 'ls'
        """
        fld = UTCTimeField(
            "", None, fmt="<Q", epoch=[1601, 1, 1, 0, 0, 0], custom_scaling=1e7
        )
        if t:
            # Sort by time
            results.sort(key=lambda x: -x[3])
        if S:
            # Sort by size
            results.sort(key=lambda x: -x[2])
        results = [
            (
                x[0],
                "+".join(y.lstrip("FILE_ATTRIBUTE_") for y in str(x[1]).split("+")),
                human_size(x[2]),
                fld.i2repr(None, x[3]),
            )
            for x in results
        ]
        print(
            pretty_list(
                results,
                [("FileName", "FileAttributes", "EndOfFile", "LastWriteTime")],
                sortBy=None,
            )
        )

    @CLIUtil.addcomplete(ls)
    def ls_complete(self, folder):
        """
        Auto-complete ls
        """
        if self._require_share(silent=True):
            return []
        return self._dir_complete(folder)

    @CLIUtil.addcommand(spaces=True)
    def cd(self, folder):
        """
        Change the remote current directory
        """
        if self._require_share():
            return
        if not folder:
            # show mode
            return str(self.pwd)
        self.pwd /= folder
        self.pwd = self.collapse_path(self.pwd)
        self.ls_cache.clear()

    @CLIUtil.addcomplete(cd)
    def cd_complete(self, folder):
        """
        Auto-complete cd
        """
        if self._require_share(silent=True):
            return []
        return self._dir_complete(folder)

    def _lfs_complete(self, arg, cond):
        """
        Return a listing of local files for completion purposes
        """
        eltpar, eltname = self._parsepath(arg, remote=False)
        eltpar = self.localpwd / eltpar
        return [
            str(x.relative_to(self.localpwd))
            for x in eltpar.glob("*")
            if (x.name.lower().startswith(eltname.lower()) and cond(x))
        ]

    @CLIUtil.addoutput(cd)
    def cd_output(self, result):
        """
        Print the output of 'cd'
        """
        if result:
            print(result)

    @CLIUtil.addcommand()
    def lls(self):
        """
        List the files in the local directory
        """
        return list(self.localpwd.glob("*"))

    @CLIUtil.addoutput(lls)
    def lls_output(self, results):
        """
        Print the output of 'lls'
        """
        results = [
            (
                x.name,
                human_size(stat.st_size),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
            )
            for x, stat in ((x, x.stat()) for x in results)
        ]
        print(
            pretty_list(results, [("FileName", "File Size", "Last Modification Time")])
        )

    @CLIUtil.addcommand(spaces=True)
    def lcd(self, folder):
        """
        Change the local current directory
        """
        if not folder:
            # show mode
            return str(self.localpwd)
        self.localpwd /= folder
        self.localpwd = self.localpwd.resolve()

    @CLIUtil.addcomplete(lcd)
    def lcd_complete(self, folder):
        """
        Auto-complete lcd
        """
        return self._lfs_complete(folder, lambda x: x.is_dir())

    @CLIUtil.addoutput(lcd)
    def lcd_output(self, result):
        """
        Print the output of 'lcd'
        """
        if result:
            print(result)

    def _get_file(self, file, fd):
        """
        Gets the file bytes from a remote host
        """
        # Get pwd of the ls
        fpath = self.pwd / file
        self.smbsock.set_TID(self.current_tree)
        # Open file
        fileId = self.smbsock.create_request(
            self.normalize_path(fpath),
            type="file",
            extra_create_options=self.extra_create_options,
        )
        # Get the file size
        info = FileAllInformation(
            self.smbsock.query_info(
                FileId=fileId,
                InfoType="SMB2_0_INFO_FILE",
                FileInfoClass="FileAllInformation",
            )
        )
        length = info.StandardInformation.EndOfFile
        offset = 0
        # Read the file
        while length:
            lengthRead = min(self.MaxReadSize, length)
            fd.write(
                self.smbsock.read_request(fileId, Length=lengthRead, Offset=offset)
            )
            offset += lengthRead
            length -= lengthRead
        # Close the file
        self.smbsock.close_request(fileId)
        return offset

    def _send_file(self, fname, fd):
        """
        Send the file bytes to a remote host
        """
        # Get destination file
        fpath = self.pwd / fname
        self.smbsock.set_TID(self.current_tree)
        # Open file
        fileId = self.smbsock.create_request(
            self.normalize_path(fpath),
            type="file",
            mode="w",
            extra_create_options=self.extra_create_options,
        )
        # Send the file
        offset = 0
        while True:
            data = fd.read(self.MaxWriteSize)
            if not data:
                # end of file
                break
            offset += self.smbsock.write_request(
                Data=data,
                FileId=fileId,
                Offset=offset,
            )
        # Close the file
        self.smbsock.close_request(fileId)
        return offset

    def _getr(self, directory, _root, _verb=True):
        """
        Internal recursive function to get a directory

        :param directory: the remote directory to get
        :param _root: locally, the directory to store any found files
        """
        size = 0
        if not _root.exists():
            _root.mkdir()
        # ls the directory
        for x in self.ls(parent=directory):
            if x[0] in [".", ".."]:
                # Discard . and ..
                continue
            remote = directory / x[0]
            local = _root / x[0]
            try:
                if x[1].FILE_ATTRIBUTE_DIRECTORY:
                    # Sub-directory
                    size += self._getr(remote, local)
                else:
                    # Sub-file
                    size += self.get(remote, local)[1]
                if _verb:
                    print(remote)
            except ValueError as ex:
                if _verb:
                    print(conf.color_theme.red(remote), "->", str(ex))
        return size

    @CLIUtil.addcommand(spaces=True, globsupport=True)
    def get(self, file, _dest=None, _verb=True, *, r=False):
        """
        Retrieve a file
        -r: recursively download a directory
        """
        if self._require_share():
            return
        if r:
            dirpar, dirname = self._parsepath(file)
            return file, self._getr(
                dirpar / dirname,  # Remotely
                _root=self.localpwd / dirname,  # Locally
                _verb=_verb,
            )
        else:
            fname = pathlib.PureWindowsPath(file).name
            # Write the buffer
            if _dest is None:
                _dest = self.localpwd / fname
            with _dest.open("wb") as fd:
                size = self._get_file(file, fd)
            return fname, size

    @CLIUtil.addoutput(get)
    def get_output(self, info):
        """
        Print the output of 'get'
        """
        print("Retrieved '%s' of size %s" % (info[0], human_size(info[1])))

    @CLIUtil.addcomplete(get)
    def get_complete(self, file):
        """
        Auto-complete get
        """
        if self._require_share(silent=True):
            return []
        return self._fs_complete(file)

    @CLIUtil.addcommand(spaces=True, globsupport=True)
    def cat(self, file):
        """
        Print a file
        """
        if self._require_share():
            return
        # Write the buffer to buffer
        buf = io.BytesIO()
        self._get_file(file, buf)
        return buf.getvalue()

    @CLIUtil.addoutput(cat)
    def cat_output(self, result):
        """
        Print the output of 'cat'
        """
        print(result.decode(errors="backslashreplace"))

    @CLIUtil.addcomplete(cat)
    def cat_complete(self, file):
        """
        Auto-complete cat
        """
        if self._require_share(silent=True):
            return []
        return self._fs_complete(file)

    @CLIUtil.addcommand(spaces=True)
    def put(self, file):
        """
        Upload a file
        """
        if self._require_share():
            return
        local_file = self.localpwd / file
        if local_file.is_dir():
            # Directory
            raise ValueError("put on dir not impl")
        else:
            fname = pathlib.Path(file).name
            with local_file.open("rb") as fd:
                size = self._send_file(fname, fd)
        self.ls_cache.clear()
        return fname, size

    @CLIUtil.addcommand(spaces=True)
    def rm(self, file):
        """
        Delete a file
        """
        if self._require_share():
            return
        # Get pwd of the ls
        fpath = self.pwd / file
        self.smbsock.set_TID(self.current_tree)
        # Open file
        fileId = self.smbsock.create_request(
            self.normalize_path(fpath),
            type="file",
            mode="d",
            extra_create_options=self.extra_create_options,
        )
        # Close the file
        self.smbsock.close_request(fileId)
        self.ls_cache.clear()
        return fpath.name

    @CLIUtil.addcomplete(rm)
    def rm_complete(self, file):
        """
        Auto-complete rm
        """
        if self._require_share(silent=True):
            return []
        return self._fs_complete(file)


if __name__ == "__main__":
    from scapy.utils import AutoArgparse
    AutoArgparse(smbclient)
