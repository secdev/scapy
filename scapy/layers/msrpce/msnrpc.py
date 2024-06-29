# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-NRPC] Netlogon Remote Protocol

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f
"""

import enum
import os
import struct
import time

from scapy.config import conf, crypto_validator
from scapy.fields import FlagValue, FlagsField
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

from scapy.layers.msrpce.rpcclient import (
    DCERPC_Client,
    DCERPC_Transport,
    STATUS_ERREF,
)
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

# [MS-NRPC] sect 3.1.4.2
_negotiateFlags = {
    # Not used. MUST be ignored on receipt.
    0x00000001: "A",
    # B: BDCs persistently try to update their database to the PDC's
    # version after they get a notification indicating that their
    # database is out-of-date.
    0x00000002: "BDCContinuousUpdate",
    # C: Supports RC4 encryption.
    0x00000004: "RC4",
    # Not used. MUST be ignored on receipt.
    0x00000008: "D",
    # E: Supports BDCs handling CHANGELOGs.
    0x00000010: "BDCChangelog",
    # F: Supports restarting of full synchronization between DCs.
    0x00000020: "RestartingDCSync",
    # G: Does not require ValidationLevel 2 fornongeneric passthrough.
    0x00000040: "NoValidationLevel2",
    # H: Supports the NetrDatabaseRedo (Opnum 17) functionality
    0x00000080: "DatabaseRedo",
    # I: Supports refusal of password changes.
    0x00000100: "RefusalPasswordChange",
    # J: Supports the NetrLogonSendToSam (Opnum 32) functionality.
    0x00000200: "SendToSam",
    # K: Supports generic pass-through authentication.
    0x00000400: "Generic-passthrough",
    # L: Supports concurrent RPC calls.
    0x00000800: "ConcurrentRPC",
    # M: Supports avoiding of user account database replication.
    0x00001000: "AvoidRepliAccountDB",
    # N: Supports avoiding of Security Authority database replication.
    0x00002000: "AvoidRepliAuthorityDB",
    # O: Supports strong keys.
    0x00004000: "StrongKeys",
    # P: Supports transitive trusts.
    0x00008000: "TransitiveTrust",
    # Not used. MUST be ignored on receipt.
    0x00010000: "Q",
    # R: Supports the NetrServerPasswordSet2 functionality.
    0x00020000: "ServerPasswordSet2",
    # S: Supports the NetrLogonGetDomainInfo functionality.
    0x00040000: "GetDomainInfo",
    # T: Supports cross-forest trusts.
    0x00080000: "CrossForestTrust",
    # U: The server ignores the NT4Emulator ADM element.
    0x00100000: "NoNT4Emul",
    # V: Supports RODC pass-through to different domains.
    0x00200000: "RODC-passthrough",
    # W: Supports Advanced Encryption Standard (AES) encryption and SHA2 hashing.
    0x01000000: "AES",
    # Supports Kerberos as the security support provider for secure channel setup.
    0x20000000: "Kerberos",
    # Y: Supports Secure RPC.
    0x40000000: "SecureRPC",
    # Not used. MUST be ignored on receipt.
    0x80000000: "Z",
}
_negotiateFlags = FlagsField("", 0, -32, _negotiateFlags).names


# [MS-NRPC] sect 3.1.4.3.1
@crypto_validator
def ComputeSessionKeyAES(HashNt, ClientChallenge, ServerChallenge):
    M4SS = HashNt
    h = hmac.HMAC(M4SS, hashes.SHA256())
    h.update(ClientChallenge)
    h.update(ServerChallenge)
    return h.finalize()[:16]


# [MS-NRPC] sect 3.1.4.3.2
@crypto_validator
def ComputeSessionKeyStrongKey(HashNt, ClientChallenge, ServerChallenge):
    M4SS = HashNt
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
    cipher = Cipher(algorithms.AES(Sk), mode=modes.CFB8(b"\x00" * 16))
    encryptor = cipher.encryptor()
    return encryptor.update(Input)


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


# [MS-NRPC] sect 3.3.4.2.1


def ComputeCopySeqNumber(ClientSequenceNumber, client):
    low = struct.pack(">L", ClientSequenceNumber & 0xFFFFFFFF)
    high = struct.pack(
        ">L",
        ((ClientSequenceNumber >> 32) & 0xFFFFFFFF) | (0x80000000 if client else 0),
    )
    return low + high


@crypto_validator
def ComputeNetlogonChecksumAES(nl_auth_sig, message, SessionKey, Confounder=None):
    h = hmac.HMAC(SessionKey, hashes.SHA256())
    h.update(nl_auth_sig[:8])
    if Confounder:
        h.update(Confounder)
    h.update(message)
    return h.finalize()


@crypto_validator
def ComputeNetlogonChecksumMD5(nl_auth_sig, message, SessionKey, Confounder=None):
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
def ComputeNetlogonSealingKeyAES(SessionKey):
    return bytes(bytearray((x ^ 0xF0) for x in bytearray(SessionKey)))


@crypto_validator
def ComputeNetlogonSealingKeyRC4(SessionKey, CopySeqNumber):
    XorKey = bytes(bytearray((x ^ 0xF0) for x in bytearray(SessionKey)))
    h = hmac.HMAC(XorKey, hashes.MD5())
    h.update(b"\x00\x00\x00\x00")
    h = hmac.HMAC(h.finalize(), hashes.MD5())
    h.update(CopySeqNumber)
    return h.finalize()


@crypto_validator
def ComputeNetlogonSequenceNumberKeyMD5(SessionKey, Checksum):
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

        def __init__(self, IsClient, req_flags=None, AES=True):
            self.state = NetlogonSSP.STATE.INIT
            self.IsClient = IsClient
            self.ClientSequenceNumber = 0
            self.AES = AES
            super(NetlogonSSP.CONTEXT, self).__init__(req_flags=req_flags)

    def __init__(self, SessionKey, computername, domainname, AES=True, **kwargs):
        self.SessionKey = SessionKey
        self.AES = AES
        self.computername = computername
        self.domainname = domainname
        super(NetlogonSSP, self).__init__(**kwargs)

    def _secure(self, Context, msgs, Seal):
        """
        Internal function used by GSS_WrapEx and GSS_GetMICEx

        [MS-NRPC] 3.3.4.2.1
        """
        # Concatenate the ToSign
        ToSign = b"".join(x.data for x in msgs if x.sign)

        Confounder = None
        if Seal:
            Confounder = os.urandom(8)

        if Context.AES:
            # 1. If AES is negotiated
            signature = NL_AUTH_SIGNATURE(
                SignatureAlgorithm=0x0013,
                SealAlgorithm=0x001A if Seal else 0xFFFF,
            )
        else:
            # 2. If AES is not negotiated
            signature = NL_AUTH_SIGNATURE(
                SignatureAlgorithm=0x0077,
                SealAlgorithm=0x007A if Seal else 0xFFFF,
            )
        # 3. Pad filled with 0xff (OK)
        # 4. Flags with 0x00 (OK)
        # 5. SequenceNumber
        SequenceNumber = ComputeCopySeqNumber(
            Context.ClientSequenceNumber, Context.IsClient
        )
        # 6. The ClientSequenceNumber MUST be incremented by 1
        Context.ClientSequenceNumber += 1
        # 7. Signature
        if Context.AES:
            signature.Checksum = ComputeNetlogonChecksumAES(
                bytes(signature), ToSign, self.SessionKey, Confounder
            )[:8]
        else:
            signature.Checksum = ComputeNetlogonChecksumMD5(
                bytes(signature), ToSign, self.SessionKey, Confounder
            )[:8]
        # 8. If the Confidentiality option is requested, the Confounder field and
        # the data MUST be encrypted
        if Seal:
            if Context.AES:
                EncryptionKey = ComputeNetlogonSealingKeyAES(self.SessionKey)
            else:
                EncryptionKey = ComputeNetlogonSealingKeyRC4(
                    self.SessionKey, SequenceNumber
                )
            # Encrypt Confounder and data
            if Context.AES:
                IV = SequenceNumber * 2
                encryptor = Cipher(
                    algorithms.AES(EncryptionKey), mode=modes.CFB8(IV)
                ).encryptor()
                # Confounder
                signature.Confounder = encryptor.update(Confounder)
                # data
                for msg in msgs:
                    if msg.conf_req_flag:
                        msg.data = encryptor.update(msg.data)
            else:
                handle = RC4Init(EncryptionKey)
                # Confounder
                signature.Confounder = RC4(handle, Confounder)
                # DOC IS WRONG !
                # > The server MUST initialize RC4 only once, before encrypting
                # > the Confounder field.
                # But, this fails ! as Samba put it:
                # > For RC4, Windows resets the cipherstate after encrypting
                # > the confounder, thus defeating the purpose of the confounder
                handle = RC4Init(EncryptionKey)
                # data
                for msg in msgs:
                    if msg.conf_req_flag:
                        msg.data = RC4(handle, msg.data)
        # 9. The SequenceNumber MUST be encrypted.
        if Context.AES:
            EncryptionKey = self.SessionKey
            IV = signature.Checksum * 2
            cipher = Cipher(algorithms.AES(EncryptionKey), mode=modes.CFB8(IV))
            encryptor = cipher.encryptor()
            signature.SequenceNumber = encryptor.update(SequenceNumber)
        else:
            EncryptionKey = ComputeNetlogonSequenceNumberKeyMD5(
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

        [MS-NRPC] 3.3.4.2.2
        """
        assert isinstance(signature, NL_AUTH_SIGNATURE)

        # 1. The SignatureAlgorithm bytes MUST be verified
        if (Context.AES and signature.SignatureAlgorithm != 0x0013) or (
            not Context.AES and signature.SignatureAlgorithm != 0x0077
        ):
            raise ValueError("Invalid SignatureAlgorithm !")

        # 5. The SequenceNumber MUST be decrypted.
        if Context.AES:
            EncryptionKey = self.SessionKey
            IV = signature.Checksum * 2
            cipher = Cipher(algorithms.AES(EncryptionKey), mode=modes.CFB8(IV))
            decryptor = cipher.decryptor()
            SequenceNumber = decryptor.update(signature.SequenceNumber)
        else:
            EncryptionKey = ComputeNetlogonSequenceNumberKeyMD5(
                self.SessionKey, signature.Checksum
            )
            SequenceNumber = RC4K(EncryptionKey, signature.SequenceNumber)
        # 6. A local copy of SequenceNumber MUST be computed
        CopySeqNumber = ComputeCopySeqNumber(
            Context.ClientSequenceNumber, not Context.IsClient
        )
        # 7. The SequenceNumber MUST be compared to CopySeqNumber
        if SequenceNumber != CopySeqNumber:
            raise ValueError("ERROR: SequenceNumber don't match")
        # 8. ClientSequenceNumber MUST be incremented.
        Context.ClientSequenceNumber += 1
        # 9. If the Confidentiality option is requested, the Confounder and the
        # data MUST be decrypted.
        Confounder = None
        if Seal:
            if Context.AES:
                EncryptionKey = ComputeNetlogonSealingKeyAES(self.SessionKey)
            else:
                EncryptionKey = ComputeNetlogonSealingKeyRC4(
                    self.SessionKey, SequenceNumber
                )
            # Decrypt Confounder and data
            if Context.AES:
                IV = SequenceNumber * 2
                decryptor = Cipher(
                    algorithms.AES(EncryptionKey), mode=modes.CFB8(IV)
                ).decryptor()
                # Confounder
                Confounder = decryptor.update(signature.Confounder)
                # data
                for msg in msgs:
                    if msg.conf_req_flag:
                        msg.data = decryptor.update(msg.data)
            else:
                # Confounder
                EncryptionKey = ComputeNetlogonSealingKeyRC4(
                    self.SessionKey, SequenceNumber
                )
                Confounder = RC4K(EncryptionKey, signature.Confounder)
                # data
                handle = RC4Init(EncryptionKey)
                for msg in msgs:
                    if msg.conf_req_flag:
                        msg.data = RC4(handle, msg.data)

        # Concatenate the ToSign
        ToSign = b"".join(x.data for x in msgs if x.sign)

        # 10/11. Signature
        if Context.AES:
            Checksum = ComputeNetlogonChecksumAES(
                bytes(signature), ToSign, self.SessionKey, Confounder
            )[:8]
        else:
            Checksum = ComputeNetlogonChecksumMD5(
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
            Context = self.CONTEXT(True, req_flags=req_flags, AES=self.AES)

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
            Context = self.CONTEXT(False, req_flags=0, AES=self.AES)

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
        if Context.flags & GSS_C_FLAGS.GSS_C_CONF_FLAG:
            if Context.AES:
                return 56
            else:
                return 32
        else:
            if Context.AES:
                return 48
            else:
                return 24


# --- Utils


class NETLOGON_SECURE_CHANNEL_METHOD(enum.Enum):
    NetrServerAuthenticate3 = 1
    NetrServerAuthenticateKerberos = 2


class NetlogonClient(DCERPC_Client):
    """
    A subclass of DCERPC_Client that supports establishing a Netlogon secure channel
    using the Netlogon SSP, and handling Netlogon authenticators.

    This class therefore only supports the 'logon' rpc.

    :param auth_level: one of DCE_C_AUTHN_LEVEL

    :param verb: verbosity control.
    :param supportAES: advertise AES support in the Netlogon session.

    Example::

        >>> cli = NetlogonClient()
        >>> cli.connect_and_bind("192.168.0.100")
        >>> cli.establishSecureChannel(
        ...     domainname="DOMAIN", computername="WIN10",
        ...     HashNT=bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ... )
    """

    def __init__(
        self,
        auth_level=DCE_C_AUTHN_LEVEL.NONE,
        verb=True,
        supportAES=True,
        **kwargs,
    ):
        self.interface = find_dcerpc_interface("logon")
        self.ndr64 = False  # Netlogon doesn't work with NDR64
        self.SessionKey = None
        self.ClientStoredCredential = None
        self.supportAES = supportAES
        super(NetlogonClient, self).__init__(
            DCERPC_Transport.NCACN_IP_TCP,
            auth_level=auth_level,
            ndr64=self.ndr64,
            verb=verb,
            **kwargs,
        )

    def connect_and_bind(self, remoteIP):
        """
        This calls DCERPC_Client's connect_and_bind to bind the 'logon' interface.
        """
        super(NetlogonClient, self).connect_and_bind(remoteIP, self.interface)

    def alter_context(self):
        return super(NetlogonClient, self).alter_context(self.interface)

    def create_authenticator(self):
        """
        Create a NETLOGON_AUTHENTICATOR
        """
        # [MS-NRPC] sect 3.1.4.5
        ts = int(time.time())
        self.ClientStoredCredential = _credentialAddition(
            self.ClientStoredCredential, ts
        )
        return PNETLOGON_AUTHENTICATOR(
            Credential=PNETLOGON_CREDENTIAL(
                data=(
                    ComputeNetlogonCredentialAES(
                        self.ClientStoredCredential,
                        self.SessionKey,
                    )
                    if self.supportAES
                    else ComputeNetlogonCredentialDES(
                        self.ClientStoredCredential,
                        self.SessionKey,
                    )
                ),
            ),
            Timestamp=ts,
        )

    def validate_authenticator(self, auth):
        """
        Validate a NETLOGON_AUTHENTICATOR

        :param auth: the NETLOGON_AUTHENTICATOR object
        """
        # [MS-NRPC] sect 3.1.4.5
        self.ClientStoredCredential = _credentialAddition(
            self.ClientStoredCredential, 1
        )
        if self.supportAES:
            tempcred = ComputeNetlogonCredentialAES(
                self.ClientStoredCredential, self.SessionKey
            )
        else:
            tempcred = ComputeNetlogonCredentialDES(
                self.ClientStoredCredential, self.SessionKey
            )
        if tempcred != auth.Credential.data:
            raise ValueError("Server netlogon authenticator is wrong !")

    def establishSecureChannel(
        self,
        computername: str,
        domainname: str,
        HashNt: bytes,
        mode=NETLOGON_SECURE_CHANNEL_METHOD.NetrServerAuthenticate3,
        secureChannelType=NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
    ):
        """
        Function to establish the Netlogon Secure Channel.

        This uses NetrServerAuthenticate3 to negotiate the session key, then creates a
        NetlogonSSP that uses that session key and alters the DCE/RPC session to use it.

        :param mode: one of NETLOGON_SECURE_CHANNEL_METHOD. This defines which method
                     to use to establish the secure channel.
        :param computername: the netbios computer account name that is used to establish
                             the secure channel. (e.g. WIN10)
        :param domainname: the netbios domain name to connect to (e.g. DOMAIN)
        :param HashNt: the HashNT of the computer account.
        """
        # Flow documented in 3.1.4 Session-Key Negotiation
        # and sect 3.4.5.2 for specific calls
        clientChall = os.urandom(8)
        # Step 1: NetrServerReqChallenge
        netr_server_req_chall_response = self.sr1_req(
            NetrServerReqChallenge_Request(
                PrimaryName=None,
                ComputerName=computername,
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
            print(
                conf.color_theme.fail(
                    "! %s"
                    % STATUS_ERREF.get(netr_server_req_chall_response.status, "Failure")
                )
            )
            netr_server_req_chall_response.show()
            raise ValueError
        # Calc NegotiateFlags
        NegotiateFlags = FlagValue(
            0x602FFFFF,  # sensible default (Windows)
            names=_negotiateFlags,
        )
        if self.supportAES:
            NegotiateFlags += "AES"
        # We are either using NetrServerAuthenticate3 or NetrServerAuthenticateKerberos
        if mode == NETLOGON_SECURE_CHANNEL_METHOD.NetrServerAuthenticate3:
            # We use the legacy NetrServerAuthenticate3 function (NetlogonSSP)
            # Step 2: Build the session key
            serverChall = netr_server_req_chall_response.ServerChallenge.data
            if self.supportAES:
                SessionKey = ComputeSessionKeyAES(HashNt, clientChall, serverChall)
                self.ClientStoredCredential = ComputeNetlogonCredentialAES(
                    clientChall, SessionKey
                )
            else:
                SessionKey = ComputeSessionKeyStrongKey(
                    HashNt, clientChall, serverChall
                )
                self.ClientStoredCredential = ComputeNetlogonCredentialDES(
                    clientChall, SessionKey
                )
            netr_server_auth3_response = self.sr1_req(
                NetrServerAuthenticate3_Request(
                    PrimaryName=None,
                    AccountName=computername + "$",
                    SecureChannelType=secureChannelType,
                    ComputerName=computername,
                    ClientCredential=PNETLOGON_CREDENTIAL(
                        data=self.ClientStoredCredential,
                    ),
                    NegotiateFlags=int(NegotiateFlags),
                    ndr64=self.ndr64,
                    ndrendian=self.ndrendian,
                )
            )
            if (
                NetrServerAuthenticate3_Response not in netr_server_auth3_response
                or netr_server_auth3_response.status != 0
            ):
                NegotiatedFlags = None
                if NetrServerAuthenticate3_Response in netr_server_auth3_response:
                    NegotiatedFlags = FlagValue(
                        netr_server_auth3_response.NegotiateFlags,
                        names=_negotiateFlags,
                    )
                    if NegotiateFlags != NegotiatedFlags:
                        print(
                            conf.color_theme.fail(
                                "! Unsupported server flags: %s"
                                % (NegotiatedFlags ^ NegotiateFlags)
                            )
                        )
                print(
                    conf.color_theme.fail(
                        "! %s"
                        % STATUS_ERREF.get(netr_server_auth3_response.status, "Failure")
                    )
                )
                if netr_server_auth3_response.status not in STATUS_ERREF:
                    netr_server_auth3_response.show()
                raise ValueError
            # Check Server Credential
            if self.supportAES:
                if (
                    netr_server_auth3_response.ServerCredential.data
                    != ComputeNetlogonCredentialAES(serverChall, SessionKey)
                ):
                    print(conf.color_theme.fail("! Invalid ServerCredential."))
                    raise ValueError
            else:
                if (
                    netr_server_auth3_response.ServerCredential.data
                    != ComputeNetlogonCredentialDES(serverChall, SessionKey)
                ):
                    print(conf.color_theme.fail("! Invalid ServerCredential."))
                    raise ValueError
            # SessionKey negotiated !
            self.SessionKey = SessionKey
            # Create the NetlogonSSP and assign it to the local client
            self.ssp = self.sock.session.ssp = NetlogonSSP(
                SessionKey=self.SessionKey,
                AES=self.supportAES,
                domainname=domainname,
                computername=computername,
            )
        elif mode == NETLOGON_SECURE_CHANNEL_METHOD.NetrServerAuthenticateKerberos:
            NegotiateFlags += "Kerberos"
            # TODO
            raise NotImplementedError
        # Finally alter context (to use the SSP)
        self.alter_context()
