# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-NRPC] Netlogon Remote Protocol

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f
"""

import os
import struct
import time

from scapy.config import conf, crypto_validator
from scapy.layers.dcerpc import (
    find_dcerpc_interface,
    DCE_C_AUTHN_LEVEL,
    NL_AUTH_MESSAGE,
    NL_AUTH_SIGNATURE,
)
from scapy.layers.gssapi import (
    GSS_C_FLAGS,
    GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED,
    GSS_S_FAILURE,
)
from scapy.layers.ntlm import RC4, RC4K, RC4Init, SSP

from scapy.layers.msrpce.rpcclient import DCERPC_Client, DCERPC_Transport
from scapy.layers.msrpce.raw.ms_nrpc import (
    NetrServerAuthenticate3_Request,
    NetrServerAuthenticate3_Response,
    NetrServerReqChallenge_Request,
    NetrServerReqChallenge_Response,
    NETLOGON_SECURE_CHANNEL_TYPE,
    PNETLOGON_AUTHENTICATOR,
    PNETLOGON_CREDENTIAL,
)


if conf.crypto_valid:
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from scapy.libs.rfc3961 import DES
else:
    hashes = hmac = Cipher = algorithms = modes = DES = None


# Typing imports
from typing import (
    Optional,
)


# --- RFC


# [MS-NRPC] sect 3.1.4.3.1
@crypto_validator
def ComputeSessionKeyAES(NTOWFv1Hash, ClientChallenge, ServerChallenge):
    M4SS = NTOWFv1Hash
    h = hmac.HMAC(M4SS, hashes.SHA256())
    h.update(ClientChallenge)
    h.update(ServerChallenge)
    return h.finalize()[:16]


# [MS-NRPC] sect 3.1.4.3.2
@crypto_validator
def ComputeSessionKeyStrongKey(NTOWFv1Hash, ClientChallenge, ServerChallenge):
    M4SS = NTOWFv1Hash
    digest = hashes.Hash(hashes.MD5())
    digest.update(b"\x00\x00\x00\x00")
    digest.update(ClientChallenge)
    digest.update(ServerChallenge)
    h = hmac.HMAC(M4SS, hashes.MD5())
    h.update(digest.finalize())
    return h.finalize()


# [MS-NRPC] sect 3.1.4.4.1
@crypto_validator
def ComputeNetlogonCredentialAES(Input, Sk):
    cipher = Cipher(algorithms.AES(Sk), mode=modes.CFB(b"\x00" * 16))
    encryptor = cipher.encryptor()
    return encryptor.update(Input) + encryptor.finalize()


# [MS-NRPC] sect 3.1.4.4.2
def InitLMKey(KeyIn):
    KeyOut = bytearray(b"\x00" * 8)
    KeyOut[0] = KeyIn[0] >> 0x01
    KeyOut[1] = ((KeyIn[0] & 0x01) << 6) | (KeyIn[1] >> 2)
    KeyOut[2] = ((KeyIn[1] & 0x03) << 5) | (KeyIn[2] >> 3)
    KeyOut[3] = ((KeyIn[2] & 0x07) << 4) | (KeyIn[3] >> 4)
    KeyOut[4] = ((KeyIn[3] & 0x0F) << 3) | (KeyIn[4] >> 5)
    KeyOut[5] = ((KeyIn[4] & 0x1F) << 2) | (KeyIn[5] >> 6)
    KeyOut[6] = ((KeyIn[5] & 0x3F) << 1) | (KeyIn[6] >> 7)
    KeyOut[7] = KeyIn[6] & 0x7F
    for i in range(8):
        KeyOut[i] = (KeyOut[i] << 1) & 0xFE
    return KeyOut


@crypto_validator
def ComputeNetlogonCredentialDES(Input, Sk):
    k3 = InitLMKey(Sk[0:7])
    k4 = InitLMKey(Sk[7:14])
    output1 = Cipher(DES(k3), modes.ECB()).encryptor().update(Input)
    return Cipher(DES(k4), modes.ECB()).encryptor().update(output1)


# [MS-NRPC] sect 3.1.4.5
def _credentialAddition(cred, i):
    return (
        struct.pack(
            "<I",
            (i + struct.unpack("<I", cred[:4])[0]) & 0xFFFFFFFF,
        )
        + cred[4:]
    )


def NewAuthenticatorAndCredential(ClientStoredCredential, Sk):
    ts = int(time.time())
    ClientStoredCredential = _credentialAddition(ClientStoredCredential, ts)
    return (
        PNETLOGON_AUTHENTICATOR(
            Credential=PNETLOGON_CREDENTIAL(
                data=ComputeNetlogonCredentialDES(
                    ClientStoredCredential,
                    Sk,
                ),
            ),
            Timestamp=ts,
        ),
        ClientStoredCredential,
    )


# [MS-NRPC] sect 3.3.4.2.1


def ComputeCopySeqNumber(ClientSequenceNumber, client):
    low = struct.pack(">L", ClientSequenceNumber & 0xFFFFFFFF)
    high = struct.pack(
        ">L",
        ((ClientSequenceNumber >> 32) & 0xFFFFFFFF) | (0x80000000 if client else 0),
    )
    return low + high


@crypto_validator
def ComputeNetlogonSignature(nl_auth_sig, message, SessionKey, Confounder=None):
    digest = hashes.Hash(hashes.MD5())
    digest.update(b"\x00\x00\x00\x00")
    digest.update(nl_auth_sig[:8])
    if Confounder:
        digest.update(Confounder)
    digest.update(message)
    h = hmac.HMAC(SessionKey, hashes.MD5())
    h.update(digest.finalize())
    return h.finalize()


@crypto_validator
def ComputeNetlogonSealingKey(SessionKey, CopySeqNumber):
    XorKey = bytes(bytearray((x ^ 0xF0) for x in bytearray(SessionKey)))
    h = hmac.HMAC(XorKey, hashes.MD5())
    h.update(b"\x00\x00\x00\x00")
    h = hmac.HMAC(h.finalize(), hashes.MD5())
    h.update(CopySeqNumber)
    return h.finalize()


@crypto_validator
def ComputeNetlogonSequenceNumberKey(SessionKey, Checksum):
    h = hmac.HMAC(SessionKey, hashes.MD5())
    h.update(b"\x00\x00\x00\x00")
    h = hmac.HMAC(h.finalize(), hashes.MD5())
    h.update(Checksum)
    return h.finalize()


# --- SSP


class NetlogonSSP(SSP):
    auth_type = 0x44  # Netlogon

    class STATE(SSP.STATE):
        INIT = 1
        CLI_SENT_NL = 2
        SRV_SENT_NL = 3

    class CONTEXT(SSP.CONTEXT):
        __slots__ = [
            "ClientSequenceNumber",
            "IsClient",
            "AES",
        ]

        def __init__(self, IsClient, req_flags=None):
            self.state = NetlogonSSP.STATE.INIT
            self.IsClient = IsClient
            self.ClientSequenceNumber = 0
            self.AES = False
            super(NetlogonSSP.CONTEXT, self).__init__(req_flags=req_flags)

    def __init__(self, SessionKey, computername, domainname, **kwargs):
        self.SessionKey = SessionKey
        self.computername = computername
        self.domainname = domainname
        super(NetlogonSSP, self).__init__(**kwargs)

    def _secure(self, Context, msgs, Seal):
        """
        Internal function used by GSS_WrapEx and GSS_GetMICEx
        """
        # Concatenate the ToSign
        ToSign = b"".join(x.data for x in msgs if x.sign)

        # [MS-NRPC] 3.3.4.2.1, AES not negotiated
        signature = NL_AUTH_SIGNATURE(
            SignatureAlgorithm=0x0077,
            SealAlgorithm=0x007A if Seal else 0xFFFF,
        )
        Confounder = None
        if Seal:
            Confounder = os.urandom(8)
        SequenceNumber = ComputeCopySeqNumber(
            Context.ClientSequenceNumber, Context.IsClient
        )
        Context.ClientSequenceNumber += 1
        signature.Checksum = ComputeNetlogonSignature(
            bytes(signature), ToSign, self.SessionKey, Confounder
        )[:8]
        if Seal:
            # 3.3.4.2.1 pt 8
            EncryptionKey = ComputeNetlogonSealingKey(self.SessionKey, SequenceNumber)
            # Encrypt Confounder and data
            handle = RC4Init(EncryptionKey)
            signature.Confounder = RC4(handle, Confounder)
            # DOC IS WRONG !
            # > The server MUST initialize RC4 only once, before encrypting
            # > the Confounder field.
            # But, this fails ! as Samba put it:
            # > For RC4, Windows resets the cipherstate after encrypting
            # > the confounder, thus defeating the purpose of the confounder
            handle = RC4Init(EncryptionKey)
            for msg in msgs:
                if msg.conf_req_flag:
                    msg.data = RC4(handle, msg.data)
        # 3.3.4.2.1 pt 9
        EncryptionKey = ComputeNetlogonSequenceNumberKey(
            self.SessionKey, signature.Checksum
        )
        signature.SequenceNumber = RC4K(EncryptionKey, SequenceNumber)

        return (
            msgs,
            signature,
        )

    def _unsecure(self, Context, msgs, signature, Seal):
        """
        Internal function used by GSS_UnwrapEx and GSS_VerifyMICEx
        """
        assert isinstance(signature, NL_AUTH_SIGNATURE)

        # [MS-NRPC] sect 3.3.4.2.2 AES not negotiated
        # 3.3.4.2.2 pt 5
        EncryptionKey = ComputeNetlogonSequenceNumberKey(
            self.SessionKey, signature.Checksum
        )
        SequenceNumber = RC4K(EncryptionKey, signature.SequenceNumber)
        # 3.3.4.2.2 pt 6/7
        CopySeqNumber = ComputeCopySeqNumber(
            Context.ClientSequenceNumber, not Context.IsClient
        )
        Context.ClientSequenceNumber += 1
        if SequenceNumber != CopySeqNumber:
            raise ValueError("ERROR: SequenceNumber don't match")
        Confounder = None
        if Seal:
            # 3.3.4.2.2 pt 9
            EncryptionKey = ComputeNetlogonSealingKey(self.SessionKey, SequenceNumber)
            Confounder = RC4K(EncryptionKey, signature.Confounder)
            for msg in msgs:
                if msg.conf_req_flag:
                    msg.data = RC4K(EncryptionKey, msg.data)

        # Concatenate the ToSign
        ToSign = b"".join(x.data for x in msgs if x.sign)

        # 3.3.4.2.2 pt 10/11
        Checksum = ComputeNetlogonSignature(
            bytes(signature), ToSign, self.SessionKey, Confounder
        )[:8]
        if signature.Checksum != Checksum:
            raise ValueError("ERROR: Checksum don't match")
        return msgs

    def GSS_WrapEx(self, Context, msgs, qop_req=0):
        return self._secure(Context, msgs, True)

    def GSS_GetMICEx(self, Context, msgs, qop_req=0):
        return self._secure(Context, msgs, False)[1]

    def GSS_UnwrapEx(self, Context, msgs, signature):
        return self._unsecure(Context, msgs, signature, True)

    def GSS_VerifyMICEx(self, Context, msgs, signature):
        self._unsecure(Context, msgs, signature, False)

    def GSS_Init_sec_context(
        self, Context, val=None, req_flags: Optional[GSS_C_FLAGS] = None
    ):
        if Context is None:
            Context = self.CONTEXT(True, req_flags=req_flags)

        if Context.state == self.STATE.INIT:
            Context.state = self.STATE.CLI_SENT_NL
            return (
                Context,
                NL_AUTH_MESSAGE(
                    MessageType=0,
                    Flags=3,
                    NetbiosDomainName=self.domainname,
                    NetbiosComputerName=self.computername,
                ),
                GSS_S_CONTINUE_NEEDED,
            )
        else:
            return Context, None, GSS_S_COMPLETE

    def GSS_Accept_sec_context(self, Context, val=None):
        if Context is None:
            Context = self.CONTEXT(False, req_flags=0)

        if Context.state == self.STATE.INIT:
            Context.state = self.STATE.SRV_SENT_NL
            return (
                Context,
                NL_AUTH_MESSAGE(
                    MessageType=1,
                    Flags=0,
                ),
                GSS_S_COMPLETE,
            )
        else:
            # Invalid state
            return Context, None, GSS_S_FAILURE

    def MaximumSignatureLength(self, Context: CONTEXT):
        """
        Returns the Maximum Signature length.

        This will be used in auth_len in DceRpc5, and is necessary for
        PFC_SUPPORT_HEADER_SIGN to work properly.
        """
        # len(NL_AUTH_SIGNATURE())
        if Context.AES:
            return 48
        else:
            return 32


# --- Utils


class NetlogonClient(DCERPC_Client):
    def __init__(
        self,
        auth_level=DCE_C_AUTHN_LEVEL.NONE,
        domainname=None,
        computername=None,
        verb=True,
    ):
        self.interface = find_dcerpc_interface("logon")
        self.ndr64 = False  # Netlogon doesn't work with NDR64
        self.SessionKey = None
        self.domainname = domainname
        self.computername = computername
        self.ClientStoredCredential = None
        super(NetlogonClient, self).__init__(
            DCERPC_Transport.NCACN_IP_TCP,
            auth_level=auth_level,
            ndr64=self.ndr64,
            verb=verb,
        )

    def connect_and_bind(self, remoteIP):
        super(NetlogonClient, self).connect_and_bind(remoteIP, self.interface)

    def alter_context(self):
        return super(NetlogonClient, self).alter_context(self.interface)

    def create_authenticator(self):
        auth, self.ClientStoredCredential = NewAuthenticatorAndCredential(
            self.ClientStoredCredential, self.SessionKey
        )
        return auth

    def validate_authenticator(self, auth):
        self.ClientStoredCredential = _credentialAddition(
            self.ClientStoredCredential, 1
        )
        tempcred = ComputeNetlogonCredentialDES(
            self.ClientStoredCredential, self.SessionKey
        )
        assert (
            tempcred == auth.Credential.data
        ), "Server netlogon authenticator is wrong !"

    def setSessionKey(self, SessionKey):
        self.SessionKey = SessionKey
        self.ssp = self.sock.session.ssp = NetlogonSSP(
            SessionKey=self.SessionKey,
            domainname=self.domainname,
            computername=self.computername,
        )

    def negotiate_sessionkey(self, secretHash):
        # Flow documented in 3.1.4 Session-Key Negotiation
        # and sect 3.4.5.2 for specific calls
        clientChall = b"12345678"
        # Step 1: NetrServerReqChallenge
        netr_server_req_chall_response = self.sr1_req(
            NetrServerReqChallenge_Request(
                PrimaryName=None,
                ComputerName=self.computername,
                ClientChallenge=PNETLOGON_CREDENTIAL(
                    data=clientChall,
                ),
                ndr64=self.ndr64,
                ndrendian=self.ndrendian,
            )
        )
        if (
            NetrServerReqChallenge_Response not in netr_server_req_chall_response
            or netr_server_req_chall_response.status != 0
        ):
            print(conf.color_theme.fail("! Failure."))
            netr_server_req_chall_response.show()
            return False
        # Step 2: NetrServerAuthenticate3
        serverChall = netr_server_req_chall_response.ServerChallenge.data
        SessionKey = ComputeSessionKeyStrongKey(secretHash, clientChall, serverChall)
        self.ClientStoredCredential = ComputeNetlogonCredentialDES(
            clientChall, SessionKey
        )
        netr_server_auth3_response = self.sr1_req(
            NetrServerAuthenticate3_Request(
                PrimaryName=None,
                AccountName=self.computername + "$",
                SecureChannelType=NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                ComputerName=self.computername,
                ClientCredential=PNETLOGON_CREDENTIAL(
                    data=self.ClientStoredCredential,
                ),
                NegotiateFlags=0x600FFFFF,
                ndr64=self.ndr64,
                ndrendian=self.ndrendian,
            )
        )
        if (
            NetrServerAuthenticate3_Response not in netr_server_auth3_response
            or netr_server_auth3_response.status != 0
        ):
            if netr_server_auth3_response.status == 0xC0000022:
                print(conf.color_theme.fail("! STATUS_ACCESS_DENIED"))
            elif netr_server_auth3_response.status == 0xC000018B:
                print(conf.color_theme.fail("! STATUS_NO_TRUST_SAM_ACCOUNT"))
            else:
                print(conf.color_theme.fail("! Failure."))
                netr_server_auth3_response.show()
            return False
        # Check Server Credential
        if (
            netr_server_auth3_response.ServerCredential.data
            != ComputeNetlogonCredentialDES(serverChall, SessionKey)
        ):
            print(conf.color_theme.fail("! Invalid ServerCredential."))
            return False
        # SessionKey negotiated !
        self.setSessionKey(SessionKey)
        return True
