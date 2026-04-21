# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
SSP for implicit authentication on Windows
"""

import ctypes
import ctypes.wintypes
import enum

from scapy.layers.gssapi import (
    GSS_C_FLAGS,
    GSS_S_FLAGS,
    GSS_C_NO_CHANNEL_BINDINGS,
    GssChannelBindings,
    GSSAPI_BLOB,
    SSP,
    GSS_S_BAD_NAME,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_S_DEFECTIVE_CREDENTIAL,
    GSS_S_DEFECTIVE_TOKEN,
    GSS_S_FAILURE,
    GSS_S_UNAUTHORIZED,
    GSS_S_UNAVAILABLE,
)

# Typing imports
from typing import (
    Optional,
)

# Windows bindings

SECPKG_CRED_INBOUND = 0x00000001
SECPKG_CRED_OUTBOUND = 0x00000002
SECPKG_CRED_BOTH = 0x00000003

SECPKG_ATTR_SESSION_KEY = 9
SECPKG_ATTR_SERVER_FLAGS = 14


class SecPkgContext_SessionKey(ctypes.Structure):
    _fields_ = [
        ("SessionKeyLength", ctypes.wintypes.ULONG),
        ("SessionKey", ctypes.wintypes.LPBYTE),
    ]


class SecPkgContext_Flags(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.wintypes.ULONG),
    ]


SECURITY_NETWORK_DREP = 0


class SEC_CODES(enum.IntEnum):
    """
    Windows sspi.h return codes
    """

    SEC_E_OK = 0x00000000
    SEC_I_CONTINUE_NEEDED = 0x00090312
    SEC_I_COMPLETE_AND_CONTINUE = 0x00090314
    SEC_E_INSUFFICIENT_MEMORY = 0x80090300
    SEC_E_INTERNAL_ERROR = 0x80090304
    SEC_E_INVALID_HANDLE = 0x80090301
    SEC_E_INVALID_TOKEN = 0x80090308
    SEC_E_LOGON_DENIED = 0x8009030C
    SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311
    SEC_E_NO_CREDENTIALS = 0x8009030E
    SEC_E_TARGET_UNKNOWN = 0x80090303
    SEC_E_UNSUPPORTED_FUNCTION = 0x80090302
    SEC_E_WRONG_PRINCIPAL = 0x80090322

    @staticmethod
    def to_GSS(code: int):
        if code in _GSS_REG_TRANSLATION:
            return _GSS_REG_TRANSLATION[code]
        else:
            return code


_GSS_REG_TRANSLATION = {
    SEC_CODES.SEC_E_OK: GSS_S_COMPLETE,
    SEC_CODES.SEC_I_CONTINUE_NEEDED: GSS_S_CONTINUE_NEEDED,
    SEC_CODES.SEC_I_COMPLETE_AND_CONTINUE: GSS_S_CONTINUE_NEEDED,
    SEC_CODES.SEC_E_INSUFFICIENT_MEMORY: GSS_S_FAILURE,
    SEC_CODES.SEC_E_INTERNAL_ERROR: GSS_S_FAILURE,
    SEC_CODES.SEC_E_INVALID_HANDLE: GSS_S_DEFECTIVE_CREDENTIAL,
    SEC_CODES.SEC_E_INVALID_TOKEN: GSS_S_DEFECTIVE_TOKEN,
    SEC_CODES.SEC_E_LOGON_DENIED: GSS_S_UNAUTHORIZED,
    SEC_CODES.SEC_E_NO_AUTHENTICATING_AUTHORITY: GSS_S_UNAVAILABLE,
    SEC_CODES.SEC_E_NO_CREDENTIALS: GSS_S_DEFECTIVE_CREDENTIAL,
    SEC_CODES.SEC_E_TARGET_UNKNOWN: GSS_S_BAD_NAME,
    SEC_CODES.SEC_E_UNSUPPORTED_FUNCTION: GSS_S_UNAVAILABLE,
    SEC_CODES.SEC_E_WRONG_PRINCIPAL: GSS_S_BAD_NAME,
}


class SECURITY_INTEGER(ctypes.Structure):
    _fields_ = [
        ("LowPart", ctypes.wintypes.ULONG),
        ("HighPart", ctypes.wintypes.LONG),
    ]


class SecHandle(ctypes.Structure):
    _fields_ = [
        ("dwLower", ctypes.POINTER(ctypes.wintypes.ULONG)),
        ("dwUpper", ctypes.POINTER(ctypes.wintypes.ULONG)),
    ]


_winapi_AcquireCredentialsHandle = ctypes.windll.secur32.AcquireCredentialsHandleW
_winapi_AcquireCredentialsHandle.restype = ctypes.wintypes.DWORD
_winapi_AcquireCredentialsHandle.argtypes = [
    ctypes.wintypes.LPWSTR,  # pszPrincipal
    ctypes.wintypes.LPWSTR,  # pszPackage
    ctypes.wintypes.ULONG,  # fCredentialUse
    ctypes.c_void_p,  # pvLogonID
    ctypes.c_void_p,  # pAuthData
    ctypes.c_void_p,  # pGetKeyFn
    ctypes.c_void_p,  # pvGetKeyArgument
    ctypes.POINTER(SecHandle),  # phCredential,
    ctypes.POINTER(SECURITY_INTEGER),  # ptsExpiry
]


class SecBuffer(ctypes.Structure):
    _fields_ = [
        ("cbBuffer", ctypes.wintypes.ULONG),
        ("BufferType", ctypes.wintypes.ULONG),
        ("pvBuffer", ctypes.c_void_p),
    ]


SECBUFFER_VERSION = 0
SECBUFFER_TOKEN = 2
SECBUFFER_CHANNEL_BINDINGS = 14


class SecBufferDesc(ctypes.Structure):
    _fields_ = [
        ("ulVersion", ctypes.wintypes.ULONG),
        ("cBuffers", ctypes.wintypes.ULONG),
        ("pBuffers", ctypes.POINTER(ctypes.POINTER(SecBuffer))),
    ]


_winapi_InitializeSecurityContext = ctypes.windll.secur32.InitializeSecurityContextW
_winapi_InitializeSecurityContext.restype = ctypes.wintypes.DWORD
_winapi_InitializeSecurityContext.argtypes = [
    ctypes.POINTER(SecHandle),  # phCredential
    ctypes.POINTER(SecHandle),  # phContext (NULL on first call)
    ctypes.wintypes.LPCWSTR,  # pszTargetName
    ctypes.wintypes.ULONG,  # fContextReq
    ctypes.wintypes.ULONG,  # Reserved1 (must be 0)
    ctypes.wintypes.ULONG,  # TargetDataRep (e.g. SECURITY_NATIVE_DREP)
    ctypes.POINTER(SecBufferDesc),  # pInput (can be NULL)
    ctypes.wintypes.ULONG,  # Reserved2 (must be 0)
    ctypes.POINTER(SecHandle),  # phNewContext
    ctypes.POINTER(SecBufferDesc),  # pOutput
    ctypes.POINTER(ctypes.wintypes.ULONG),  # pfContextAttr
    ctypes.POINTER(SECURITY_INTEGER),  # ptsExpiry
]

_winapi_AcceptSecurityContext = ctypes.windll.secur32.AcceptSecurityContext
_winapi_AcceptSecurityContext.restype = ctypes.wintypes.DWORD
_winapi_AcceptSecurityContext.argtypes = [
    ctypes.POINTER(SecHandle),  # phCredential
    ctypes.POINTER(SecHandle),  # phContext (NULL on first call)
    ctypes.POINTER(SecBufferDesc),  # pInput
    ctypes.wintypes.ULONG,  # fContextReq
    ctypes.wintypes.ULONG,  # TargetDataRep (e.g. SECURITY_NATIVE_DREP)
    ctypes.POINTER(SecHandle),  # phNewContext
    ctypes.POINTER(SecBufferDesc),  # pOutput
    ctypes.POINTER(ctypes.wintypes.ULONG),  # pfContextAttr
    ctypes.POINTER(SECURITY_INTEGER),  # ptsExpiry
]

_winapi_FreeContextBuffer = ctypes.windll.secur32.FreeContextBuffer
_winapi_FreeContextBuffer.restype = ctypes.wintypes.DWORD
_winapi_FreeContextBuffer.argtypes = [ctypes.c_void_p]

_winapi_QueryContextAttributesW = ctypes.windll.secur32.QueryContextAttributesW
_winapi_QueryContextAttributesW.restype = ctypes.wintypes.DWORD
_winapi_QueryContextAttributesW.argtypes = [
    ctypes.POINTER(SecHandle),
    ctypes.wintypes.ULONG,
    ctypes.c_void_p,
]

_winapi_SspiGetTargetHostName = ctypes.windll.secur32.SspiGetTargetHostName
_winapi_SspiGetTargetHostName.restype = ctypes.wintypes.DWORD
_winapi_SspiGetTargetHostName.argtypes = [
    ctypes.wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.wintypes.LPWSTR),
]


# Types


class ISC_REQ_FLAGS(enum.IntFlag):
    """
    ISC_REQ Flags per sspi.h
    """

    ISC_REQ_DELEGATE = 0x00000001
    ISC_REQ_MUTUAL_AUTH = 0x00000002
    ISC_REQ_REPLAY_DETECT = 0x00000004
    ISC_REQ_SEQUENCE_DETECT = 0x00000008
    ISC_REQ_CONFIDENTIALITY = 0x00000010
    ISC_REQ_USE_SESSION_KEY = 0x00000020
    ISC_REQ_PROMPT_FOR_CREDS = 0x00000040
    ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080
    ISC_REQ_ALLOCATE_MEMORY = 0x00000100
    ISC_REQ_USE_DCE_STYLE = 0x00000200
    ISC_REQ_DATAGRAM = 0x00000400
    ISC_REQ_CONNECTION = 0x00000800
    ISC_REQ_CALL_LEVEL = 0x00001000
    ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000
    ISC_REQ_EXTENDED_ERROR = 0x00004000
    ISC_REQ_STREAM = 0x00008000
    ISC_REQ_INTEGRITY = 0x00010000
    ISC_REQ_IDENTIFY = 0x00020000
    ISC_REQ_NULL_SESSION = 0x00040000
    ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000
    ISC_REQ_RESERVED1 = 0x00100000
    ISC_REQ_FRAGMENT_TO_FIT = 0x00200000
    ISC_REQ_FORWARD_CREDENTIALS = 0x00400000
    ISC_REQ_NO_INTEGRITY = 0x00800000
    ISC_REQ_USE_HTTP_STYLE = 0x01000000
    ISC_REQ_UNVERIFIED_TARGET_NAME = 0x20000000
    ISC_REQ_CONFIDENTIALITY_ONLY = 0x40000000
    ISC_REQ_MESSAGES = 0x0000000100000000
    ISC_REQ_DEFERRED_CRED_VALIDATION = 0x0000000200000000
    ISC_REQ_NO_POST_HANDSHAKE_AUTH = 0x0000000400000000
    ISC_REQ_REUSE_SESSION_TICKETS = 0x0000000800000000
    ISC_REQ_EXPLICIT_SESSION = 0x0000001000000000

    @staticmethod
    def from_GSS(flags: GSS_C_FLAGS) -> "ISC_REQ_FLAGS":
        """
        Convert GSS_C_FLAGS into ISC_REQ_FLAGS
        """
        result = 0
        for gssf, iscf in _GSS_ISC_TRANSLATION.items():
            if flags & gssf:
                result |= iscf
        return ISC_REQ_FLAGS(result)

    @staticmethod
    def to_GSS(flags: "ISC_REQ_FLAGS") -> GSS_C_FLAGS:
        """
        Convert ISC_REQ_FLAGS into GSS_C_FLAGS
        """
        result = 0
        for gssf, iscf in _GSS_ISC_TRANSLATION.items():
            if flags & iscf:
                result |= gssf
        return GSS_C_FLAGS(result)


_GSS_ISC_TRANSLATION = {
    GSS_C_FLAGS.GSS_C_DELEG_FLAG: ISC_REQ_FLAGS.ISC_REQ_DELEGATE,
    GSS_C_FLAGS.GSS_C_MUTUAL_FLAG: ISC_REQ_FLAGS.ISC_REQ_MUTUAL_AUTH,
    GSS_C_FLAGS.GSS_C_REPLAY_FLAG: ISC_REQ_FLAGS.ISC_REQ_REPLAY_DETECT,
    GSS_C_FLAGS.GSS_C_SEQUENCE_FLAG: ISC_REQ_FLAGS.ISC_REQ_SEQUENCE_DETECT,
    GSS_C_FLAGS.GSS_C_CONF_FLAG: ISC_REQ_FLAGS.ISC_REQ_CONFIDENTIALITY,
    GSS_C_FLAGS.GSS_C_INTEG_FLAG: ISC_REQ_FLAGS.ISC_REQ_INTEGRITY,
    GSS_C_FLAGS.GSS_C_DCE_STYLE: ISC_REQ_FLAGS.ISC_REQ_USE_DCE_STYLE,
    GSS_C_FLAGS.GSS_C_IDENTIFY_FLAG: ISC_REQ_FLAGS.ISC_REQ_IDENTIFY,
    GSS_C_FLAGS.GSS_C_EXTENDED_ERROR_FLAG: ISC_REQ_FLAGS.ISC_REQ_EXTENDED_ERROR,
}


class ASC_REQ_FLAGS(enum.IntFlag):
    ASC_REQ_DELEGATE = 0x00000001
    ASC_REQ_MUTUAL_AUTH = 0x00000002
    ASC_REQ_REPLAY_DETECT = 0x00000004
    ASC_REQ_SEQUENCE_DETECT = 0x00000008
    ASC_REQ_CONFIDENTIALITY = 0x00000010
    ASC_REQ_USE_SESSION_KEY = 0x00000020
    ASC_REQ_SESSION_TICKET = 0x00000040
    ASC_REQ_ALLOCATE_MEMORY = 0x00000100
    ASC_REQ_USE_DCE_STYLE = 0x00000200
    ASC_REQ_DATAGRAM = 0x00000400
    ASC_REQ_CONNECTION = 0x00000800
    ASC_REQ_CALL_LEVEL = 0x00001000
    ASC_REQ_FRAGMENT_SUPPLIED = 0x00002000
    ASC_REQ_EXTENDED_ERROR = 0x00008000
    ASC_REQ_STREAM = 0x00010000
    ASC_REQ_INTEGRITY = 0x00020000
    ASC_REQ_LICENSING = 0x00040000
    ASC_REQ_IDENTIFY = 0x00080000
    ASC_REQ_ALLOW_NULL_SESSION = 0x00100000
    ASC_REQ_ALLOW_NON_USER_LOGONS = 0x00200000
    ASC_REQ_ALLOW_CONTEXT_REPLAY = 0x00400000
    ASC_REQ_FRAGMENT_TO_FIT = 0x00800000
    ASC_REQ_NO_TOKEN = 0x01000000
    ASC_REQ_PROXY_BINDINGS = 0x04000000
    ASC_REQ_ALLOW_MISSING_BINDINGS = 0x10000000

    @staticmethod
    def from_GSS(flags: GSS_C_FLAGS) -> "ASC_REQ_FLAGS":
        """
        Convert GSS_C_FLAGS into ASC_REQ_FLAGS
        """
        result = 0
        for gssf, ascf in _GSS_ASC_TRANSLATION.items():
            if flags & gssf:
                result |= ascf
        return ASC_REQ_FLAGS(result)

    @staticmethod
    def to_GSS(flags: "ASC_REQ_FLAGS") -> GSS_C_FLAGS:
        """
        Convert ASC_REQ_FLAGS into GSS_C_FLAGS
        """
        result = 0
        for gssf, ascf in _GSS_ASC_TRANSLATION.items():
            if flags & ascf:
                result |= gssf
        return GSS_C_FLAGS(result)


_GSS_ASC_TRANSLATION = {
    GSS_C_FLAGS.GSS_C_DELEG_FLAG: ASC_REQ_FLAGS.ASC_REQ_DELEGATE,
    GSS_C_FLAGS.GSS_C_MUTUAL_FLAG: ASC_REQ_FLAGS.ASC_REQ_MUTUAL_AUTH,
    GSS_C_FLAGS.GSS_C_REPLAY_FLAG: ASC_REQ_FLAGS.ASC_REQ_REPLAY_DETECT,
    GSS_C_FLAGS.GSS_C_SEQUENCE_FLAG: ASC_REQ_FLAGS.ASC_REQ_SEQUENCE_DETECT,
    GSS_C_FLAGS.GSS_C_CONF_FLAG: ASC_REQ_FLAGS.ASC_REQ_CONFIDENTIALITY,
    GSS_C_FLAGS.GSS_C_INTEG_FLAG: ASC_REQ_FLAGS.ASC_REQ_INTEGRITY,
    GSS_C_FLAGS.GSS_C_DCE_STYLE: ASC_REQ_FLAGS.ASC_REQ_USE_DCE_STYLE,
    GSS_C_FLAGS.GSS_C_IDENTIFY_FLAG: ASC_REQ_FLAGS.ASC_REQ_IDENTIFY,
    GSS_C_FLAGS.GSS_C_EXTENDED_ERROR_FLAG: ASC_REQ_FLAGS.ASC_REQ_EXTENDED_ERROR,
    GSS_S_FLAGS.GSS_S_ALLOW_MISSING_BINDINGS: ASC_REQ_FLAGS.ASC_REQ_ALLOW_MISSING_BINDINGS,  # noqa: E501
}


# The SSP


class WinSSP(SSP):
    """
    Use a native Windows SSP through SSPI

    :param Package: the SSP to use
    """

    class STATE(SSP.STATE):
        NEGOTIATING = 1
        COMPLETED = 2

    class CONTEXT(SSP.CONTEXT):
        __slots__ = [
            "state",
            "Credential",
            "Package",
            "phContext",
            "ptsExpiry",
            "SessionKey",
            "ServerHostname",
        ]

        def __init__(
            self,
            Package: str,
            CredentialUse: int,
            req_flags: Optional["GSS_C_FLAGS | GSS_S_FLAGS"] = None,
        ):
            self.Credential = SecHandle()
            self.phContext = None
            self.ptsExpiry = SECURITY_INTEGER()
            self.Package = Package
            self.state = WinSSP.STATE.NEGOTIATING
            self.ServerHostname = None

            status = _winapi_AcquireCredentialsHandle(
                None,
                Package,
                CredentialUse,
                None,
                None,
                None,
                None,
                ctypes.byref(self.Credential),
                ctypes.byref(self.ptsExpiry),
            )
            if status != SEC_CODES.SEC_E_OK:
                raise OSError(f"AcquireCredentialsHandle failed: {hex(status)}")

            super(WinSSP.CONTEXT, self).__init__(
                req_flags=req_flags,
            )

        def QuerySessionKey(self):
            """
            Query the session key
            """
            Buffer = SecPkgContext_SessionKey()

            status = _winapi_QueryContextAttributesW(
                self.phContext,
                SECPKG_ATTR_SESSION_KEY,
                ctypes.byref(Buffer),
            )
            if status != SEC_CODES.SEC_E_OK:
                raise ValueError(f"QueryContextAttributesW failed with: {hex(status)}")

            SessionKeyBuf = ctypes.cast(
                Buffer.SessionKey,
                ctypes.POINTER(ctypes.wintypes.BYTE * Buffer.SessionKeyLength),
            )
            self.SessionKey = bytes(SessionKeyBuf.contents)

        def QueryNegotiatedFlags(self):
            """
            Query the negotiated flags.
            """
            Buffer = SecPkgContext_Flags()

            status = _winapi_QueryContextAttributesW(
                self.phContext,
                SECPKG_ATTR_SERVER_FLAGS,
                ctypes.byref(Buffer),
            )
            if status != SEC_CODES.SEC_E_OK:
                raise ValueError(f"QueryContextAttributesW failed with: {hex(status)}")

            self.flags = ISC_REQ_FLAGS.to_GSS(Buffer.Flags)

        def __repr__(self):
            return "[Native SSP: %s]" % self.Package

    def __init__(self, Package: str = "Negotiate"):
        self.Package = Package
        super(WinSSP, self).__init__()

    def GSS_Init_sec_context(
        self,
        Context: CONTEXT,
        input_token=None,
        target_name: Optional[str] = None,
        req_flags: Optional[GSS_C_FLAGS] = None,
        chan_bindings: GssChannelBindings = GSS_C_NO_CHANNEL_BINDINGS,
    ):
        # Get context
        if not Context:
            Context = self.CONTEXT(
                self.Package,
                SECPKG_CRED_OUTBOUND,
                req_flags=req_flags,
            )

        if Context.state == self.STATE.COMPLETED:
            # SSPI and GSSAPI count completion differently, so we might
            # be called one time for nothing. Return that we completed properly.
            return Context, None, GSS_S_COMPLETE

        # Create and populate the input buffers
        InputBuffers = []
        if input_token:
            input_token = bytes(input_token)
            InputBuffers.append(
                SecBuffer(
                    len(input_token),
                    SECBUFFER_TOKEN,
                    ctypes.cast(
                        ctypes.create_string_buffer(input_token), ctypes.c_void_p
                    ),
                )
            )
        if chan_bindings != GSS_C_NO_CHANNEL_BINDINGS:
            raise NotImplementedError("Channel bindings !")
        if InputBuffers:
            InputBuffers = ctypes.ARRAY(SecBuffer, len(InputBuffers))(*InputBuffers)
            Input = SecBufferDesc(
                SECBUFFER_VERSION,
                len(InputBuffers),
                ctypes.cast(
                    ctypes.byref(InputBuffers),
                    ctypes.POINTER(ctypes.POINTER(SecBuffer)),
                ),
            )
        else:
            Input = None

        # Create the output buffers (empty for now)
        OutputBuffers = ctypes.ARRAY(SecBuffer, 1)(
            *[
                SecBuffer(
                    ctypes.wintypes.ULONG(0),
                    ctypes.wintypes.ULONG(SECBUFFER_TOKEN),
                    ctypes.c_void_p(),
                )
            ]
        )
        Output = SecBufferDesc(
            SECBUFFER_VERSION,
            len(OutputBuffers),
            ctypes.cast(
                ctypes.byref(OutputBuffers), ctypes.POINTER(ctypes.POINTER(SecBuffer))
            ),
        )

        # Prepare other arguments
        phNewContext = Context.phContext or SecHandle()
        pfContextAttr = ctypes.wintypes.ULONG()
        if target_name:
            TargetName = ctypes.cast(
                ctypes.create_string_buffer(
                    target_name.encode("utf-16le") + b"\x00\x00"
                ),
                ctypes.wintypes.LPCWSTR,
            )

            HostName = ctypes.wintypes.LPWSTR()
            status = _winapi_SspiGetTargetHostName(TargetName, ctypes.byref(HostName))
            if status == SEC_CODES.SEC_E_OK:
                Context.ServerHostname = HostName.value
        else:
            TargetName = None

        # Call SSPI
        status = _winapi_InitializeSecurityContext(
            ctypes.byref(Context.Credential),
            Context.phContext if Context.phContext else None,
            TargetName,
            ISC_REQ_FLAGS.from_GSS(Context.flags)
            | ISC_REQ_FLAGS.ISC_REQ_ALLOCATE_MEMORY,
            0,
            SECURITY_NETWORK_DREP,
            Input and ctypes.byref(Input),
            0,
            ctypes.byref(phNewContext),
            ctypes.byref(Output),
            ctypes.byref(pfContextAttr),
            ctypes.byref(Context.ptsExpiry),
        )

        # Find the output token, if any
        output_token = None
        if status in [
            SEC_CODES.SEC_E_OK,
            SEC_CODES.SEC_I_CONTINUE_NEEDED,
            SEC_CODES.SEC_I_COMPLETE_AND_CONTINUE,
        ]:
            if Context.phContext is None:
                Context.phContext = phNewContext

            for OutputBuffer in OutputBuffers:
                if (
                    OutputBuffer.BufferType == SECBUFFER_TOKEN
                    and OutputBuffer.cbBuffer != 0
                ):
                    buf = ctypes.cast(
                        OutputBuffer.pvBuffer,
                        ctypes.POINTER(ctypes.wintypes.BYTE * OutputBuffer.cbBuffer),
                    )
                    output_token = GSSAPI_BLOB(bytes(buf.contents))
                    break

        # If we succeeded, query the session key
        if status in [SEC_CODES.SEC_E_OK, SEC_CODES.SEC_I_COMPLETE_AND_CONTINUE]:
            Context.QuerySessionKey()
            Context.QueryNegotiatedFlags()
            Context.state = self.STATE.COMPLETED

        # Free things we did not create (won't be freed by GC)
        for OutputBuffer in OutputBuffers:
            if OutputBuffer.pvBuffer is not None:
                _winapi_FreeContextBuffer(OutputBuffer.pvBuffer)

        return Context, output_token, SEC_CODES.to_GSS(status)

    def GSS_Accept_sec_context(
        self,
        Context: CONTEXT,
        input_token=None,
        req_flags: Optional[GSS_S_FLAGS] = GSS_S_FLAGS.GSS_S_ALLOW_MISSING_BINDINGS,
        chan_bindings: GssChannelBindings = GSS_C_NO_CHANNEL_BINDINGS,
    ):
        # Get context
        if not Context:
            Context = self.CONTEXT(
                self.Package,
                SECPKG_CRED_INBOUND,
                req_flags=req_flags,
            )

        # Create and populate the input buffers
        InputBuffers = []
        if input_token:
            input_token = bytes(input_token)
            InputBuffers.append(
                SecBuffer(
                    len(input_token),
                    SECBUFFER_TOKEN,
                    ctypes.cast(
                        ctypes.create_string_buffer(input_token), ctypes.c_void_p
                    ),
                )
            )
        if chan_bindings != GSS_C_NO_CHANNEL_BINDINGS:
            raise NotImplementedError("Channel bindings !")
        if InputBuffers:
            InputBuffers = ctypes.ARRAY(SecBuffer, len(InputBuffers))(*InputBuffers)
            Input = SecBufferDesc(
                SECBUFFER_VERSION,
                len(InputBuffers),
                ctypes.cast(
                    ctypes.byref(InputBuffers),
                    ctypes.POINTER(ctypes.POINTER(SecBuffer)),
                ),
            )
        else:
            Input = None

        # Create the output buffers (empty for now)
        OutputBuffers = ctypes.ARRAY(SecBuffer, 1)(
            *[
                SecBuffer(
                    ctypes.wintypes.ULONG(0),
                    ctypes.wintypes.ULONG(SECBUFFER_TOKEN),
                    ctypes.c_void_p(),
                )
            ]
        )
        Output = SecBufferDesc(
            SECBUFFER_VERSION,
            len(OutputBuffers),
            ctypes.cast(
                ctypes.byref(OutputBuffers), ctypes.POINTER(ctypes.POINTER(SecBuffer))
            ),
        )

        # Prepare other arguments
        phNewContext = Context.phContext or SecHandle()
        pfContextAttr = ctypes.wintypes.ULONG()

        # Call SSPI
        status = _winapi_AcceptSecurityContext(
            ctypes.byref(Context.Credential),
            Context.phContext if Context.phContext else None,
            Input and ctypes.byref(Input),
            ASC_REQ_FLAGS.from_GSS(Context.flags)
            | ASC_REQ_FLAGS.ASC_REQ_ALLOCATE_MEMORY,
            SECURITY_NETWORK_DREP,
            ctypes.byref(phNewContext),
            ctypes.byref(Output),
            ctypes.byref(pfContextAttr),
            ctypes.byref(Context.ptsExpiry),
        )

        # Find the output token, if any
        output_token = None
        if status in [
            SEC_CODES.SEC_E_OK,
            SEC_CODES.SEC_I_CONTINUE_NEEDED,
            SEC_CODES.SEC_I_COMPLETE_AND_CONTINUE,
        ]:
            if Context.phContext is None:
                Context.phContext = phNewContext

            for OutputBuffer in OutputBuffers:
                if (
                    OutputBuffer.BufferType == SECBUFFER_TOKEN
                    and OutputBuffer.cbBuffer != 0
                ):
                    buf = ctypes.cast(
                        OutputBuffer.pvBuffer,
                        ctypes.POINTER(ctypes.wintypes.BYTE * OutputBuffer.cbBuffer),
                    )
                    output_token = GSSAPI_BLOB(bytes(buf.contents))
                    break

        # If we succeeded, query the session key
        if status in [SEC_CODES.SEC_E_OK, SEC_CODES.SEC_I_COMPLETE_AND_CONTINUE]:
            Context.QuerySessionKey()
            Context.QueryNegotiatedFlags()
            Context.state = self.STATE.COMPLETED

        # Free things we did not create (won't be freed by GC)
        for OutputBuffer in OutputBuffers:
            if OutputBuffer.pvBuffer is not None:
                _winapi_FreeContextBuffer(OutputBuffer.pvBuffer)

        return Context, output_token, SEC_CODES.to_GSS(status)
