# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-EERR] ExtendedError Remote Data Structure
"""

# Wireshark does not know how to read this !

import uuid

from scapy.fields import UTCTimeField
from scapy.packet import Packet, bind_layers

from scapy.layers.dcerpc import (
    DceRpc5Fault,
    DceRpc5BindNak,
    NDRSerializeType1PacketField,
)
from scapy.layers.msrpce.raw.ms_eerr import (
    ExtendedErrorInfo,
    EEComputerNamePresent,
)
from scapy.layers.smb2 import STATUS_ERREF

# Encapsulation packets

# https://learn.microsoft.com/en-us/windows/win32/rpc/understanding-extended-error-information

EERR_GENERATING_COMPONENT = {
    # The component owning the manager routine for the particular RPC call
    1: "Application",
    # The RPC run time
    2: "Runtime",
    # The security provider for this call.
    3: "Security Provider",
    # The NPFS file system
    4: "NPFS",
    # The Redirector
    5: "RDR",
    # The named pipe system.
    # This can be either NPFS or RDR, but in many cases the RPC run time
    # does not know who performed the requested the operation, and in such
    # cases NMP is returned.
    6: "NMP",
    # The IO system or a driver used by the IO system.
    # This can be either NPFS, RDR, or a Winsock provider.
    7: "IO",
    # The Winsock provider
    8: "Winsock",
    # The Authorization APIs.
    9: "Authz code",
    # The Local Procedure Call facility.
    10: "LPC",
}

EERR_FLAGS = {
    1: "EEInfoPreviousRecordsMissing",
    2: "EEInfoNextRecordsMissing",
}

# https://learn.microsoft.com/en-us/windows/win32/rpc/extended-error-information-detection-locations

EERR_DETECTION_LOCATIONS = {
    10: "DealWithLRPCRequest10",
    11: "DealWithLRPCRequest20",
    12: "WithLRPCRequest30",
    13: "WithLRPCRequest40",
    20: "LrpcMessageToRpcMessage10",
    21: "LrpcMessageToRpcMessage20",
    22: "LrpcMessageToRpcMessage30",
    30: "DealWithRequestMessage10",
    31: "DealWithRequestMessage20",
    32: "DealWithRequestMessage30",
    40: "CheckSecurity10",
    50: "DealWithBindMessage10",
    51: "DealWithBindMessage20",
    52: "DealWithBindMessage30",
    53: "DealWithBindMessage40",
    54: "DealWithBindMessage50",
    55: "DealWithBindMessage60",
    60: "FindServerCredentials10",
    61: "FindServerCredentials20",
    62: "FindServerCredentials30",
    70: "AcceptFirstTime10",
    71: "AcceptThirdLeg10",
    72: "AcceptThirdLeg20",
    73: "AcceptFirstTime20",
    74: "AcceptThirdLeg40",
    80: "AssociationRequested10",
    81: "AssociationRequested20",
    82: "AssociationRequested30",
    90: "CompleteSecurityToken10",
    91: "CompleteSecurityToken20",
    100: "AcquireCredentialsForClient10",
    101: "AcquireCredentialsForClient20",
    102: "AcquireCredentialsForClient30",
    110: "InquireDefaultPrincName10",
    111: "InquireDefaultPrincName20",
    120: "SignOrSeal10",
    130: "VerifyOrUnseal10",
    131: "VerifyOrUnseal20",
    140: "InitializeFirstTime10",
    141: "InitializeFirstTime20",
    142: "InitializeFirstTime30",
    150: "InitializeThirdLeg10",
    151: "InitializeThirdLeg20",
    152: "InitializeThirdLeg30",
    153: "InitializeThirdLeg40",
    154: "InitializeThirdLeg50",
    155: "InitializeThirdLeg60",
    160: "ImpersonateClient10",
    170: "DispatchToStub10",
    171: "DispatchToStub20",
    180: "DispatchToStubWorker10",
    181: "DispatchToStubWorker20",
    182: "DispatchToStubWorker30",
    183: "DispatchToStubWorker40",
    190: "NMPOpen10",
    191: "NMPOpen20",
    192: "NMPOpen30",
    193: "NMPOpen40",
    200: "NMPSyncSend10",
    210: "NMPSyncSendReceive10",
    220: "NMPSyncSendReceive20",
    221: "NMPSyncSendReceive30",
    230: "COSend10",
    240: "COSubmitRead10",
    250: "COSubmitSyncRead10",
    251: "COSubmitSyncRead20",
    260: "COSyncRecv10",
    270: "WSCheckForShutdowns10",
    271: "WSCheckForShutdowns20",
    272: "WSCheckForShutdowns30",
    273: "WSCheckForShutdowns40",
    274: "WSCheckForShutdowns50",
    280: "WSSyncSend10",
    281: "WSSyncSend20",
    282: "WSSyncSend30",
    290: "WSSyncRecv10",
    291: "WSSyncRecv20",
    292: "WSSyncRecv30",
    300: "WSServerListenCommon10",
    301: "WSServerListenCommon20",
    302: "WSServerListenCommon30",
    310: "WSOpen10",
    311: "WSOpen20",
    312: "WSOpen30",
    313: "WSOpen40",
    314: "WSOpen50",
    315: "WSOpen60",
    316: "WSOpen70",
    317: "WSOpen80",
    318: "WSOpen90",
    320: "NextAddress10",
    321: "NextAddress20",
    322: "NextAddress30",
    323: "NextAddress40",
    330: "WSBind10",
    331: "WSBind20",
    332: "WSBind30",
    333: "WSBind40",
    334: "WSBind50",
    335: "WSBind45",
    340: "IPBuildAddressVector10",
    350: "GetStatusForTimeout10",
    351: "GetStatusForTimeout20",
    360: "OSF_CCONNECTION__SendFragment10",
    361: "OSF_CCONNECTION__SendFragment20",
    370: "OSF_CCALL__ReceiveReply10",
    371: "OSF_CCALL__ReceiveReply20",
    380: "OSF_CCALL__FastSendReceive10",
    381: "OSF_CCALL__FastSendReceive20",
    382: "OSF_CCALL__FastSendReceive30",
    390: "LRPC_BINDING_HANDLE__AllocateCCall10",
    391: "LRPC_BINDING_HANDLE__AllocateCCall20",
    400: "LRPC_ADDRESS__ServerSetupAddress10",
    410: "LRPC_ADDRESS__HandleInvalidAssociationReference10",
    420: "InitializeAuthzSupportIfNecessary10",
    421: "InitializeAuthzSupportIfNecessary20",
    430: "CreateDummyResourceManagerIfNecessary10",
    431: "CreateDummyResourceManagerIfNecessary20",
    440: "LRPC_SCALL__GetAuthorizationContext10",
    441: "LRPC_SCALL__GetAuthorizationContext20",
    442: "LRPC_SCALL__GetAuthorizationContext30",
    450: "SCALL__DuplicateAuthzContext10",
    460: "SCALL__CreateAndSaveAuthzContextFromToken10",
    470: "SECURITY_CONTEXT__GetAccessToken10",
    471: "SECURITY_CONTEXT__GetAccessToken20",
    480: "OSF_SCALL__GetAuthorizationContext10",
    500: "EpResolveEndpoint10",
    501: "EpResolveEndpoint20",
    510: "OSF_SCALL__GetBuffer10",
    520: "LRPC_SCALL__ImpersonateClient10",
    530: "SetMaximumLengths10",
    540: "LRPC_CASSOCIATION__ActuallyDoBinding10",
    541: "LRPC_CASSOCIATION__ActuallyDoBinding20",
    542: "LRPC_CASSOCIATION__ActuallyDoBinding30",
    543: "LRPC_CASSOCIATION__ActuallyDoBinding40",
    550: "LRPC_CASSOCIATION__CreateBackConnection10",
    551: "LRPC_CASSOCIATION__CreateBackConnection20",
    552: "LRPC_CASSOCIATION__CreateBackConnection30",
    560: "LRPC_CASSOCIATION__OpenLpcPort10",
    561: "LRPC_CASSOCIATION__OpenLpcPort20",
    562: "LRPC_CASSOCIATION__OpenLpcPort30",
    563: "LRPC_CASSOCIATION__OpenLpcPort40",
    570: "RegisterEntries10",
    571: "RegisterEntries20",
    580: "NDRSContextUnmarshall2_10",
    581: "NDRSContextUnmarshall2_20",
    582: "NDRSContextUnmarshall2_30",
    583: "NDRSContextUnmarshall2_40",
    584: "NDRSContextUnmarshall2_50",
    590: "NDRSContextMarshall2_10",
    600: "WinsockDatagramSend10",
    601: "WinsockDatagramSend20",
    610: "WinsockDatagramReceive10",
    620: "WinsockDatagramSubmitReceive10",
    630: "DG_CCALL__CancelAsyncCall10",
    640: "DG_CCALL__DealWithTimeout10",
    641: "DG_CCALL__DealWithTimeout20",
    642: "DG_CCALL__DealWithTimeout30",
    650: "DG_CCALL__DispatchPacket10",
    660: "DG_CCALL__ReceiveSinglePacket10",
    661: "DG_CCALL__ReceiveSinglePacket20",
    662: "DG_CCALL__ReceiveSinglePacket30",
    670: "WinsockDatagramResolve10",
    680: "WinsockDatagramCreate10",
    690: "TCP_QueryLocalAddress10",
    691: "TCP_QueryLocalAddress20",
    700: "OSF_CASSOCIATION__ProcessBindAckOrNak10",
    701: "OSF_CASSOCIATION__ProcessBindAckOrNak20",
    710: "MatchMsPrincipalName10",
    720: "CompareRdnElement10",
    730: "MatchFullPathPrincipalName10",
    731: "MatchFullPathPrincipalName20",
    732: "MatchFullPathPrincipalName30",
    733: "MatchFullPathPrincipalName40",
    734: "MatchFullPathPrincipalName50",
    740: "RpcCertGeneratePrincipalName10",
    741: "RpcCertGeneratePrincipalName20",
    742: "RpcCertGeneratePrincipalName30",
    750: "RpcCertVerifyContext10",
    751: "RpcCertVerifyContext20",
    752: "RpcCertVerifyContext30",
    753: "RpcCertVerifyContext40",
    761: "OSF_BINDING_HANDLE__NegotiateTransferSyntax10",
    # END OF DOC
    # below is reverse engineered
    770: "RpcpErrorAddRecord",
    780: "RpcpLookupAccountSid",
    800: "OSF_SCONNECTION__AcceptFirstTime",
    810: "OSF_SCONNECTION__AcceptThirdLeg",
    820: "OSF_BINDING_HANDLE__AcquireTokenForTransport",
    821: "OSF_BINDING_HANDLE__AcquireCredentialsForTokenIfNecessary",
    835: "LRPC_CASSOCIATION__CompleteBind",
    840: "LRPC_BASE_BINDING_HANDLE__BaseBindingCopy",
    860: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    861: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    862: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    864: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    865: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    867: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    868: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    869: "LRPC_BASE_BINDING_HANDLE__SetAuthInformation",
    880: "LRPC_BASE_BINDING_HANDLE__ResolveEndpoint",
    881: "LRPC_BASE_BINDING_HANDLE__ResolveEndpoint",
    882: "LRPC_BASE_BINDING_HANDLE__ResolveEndpoint",
    883: "LRPC_BASE_BINDING_HANDLE__ResolveEndpoint",
    900: "LRPC_BASE_BINDING_HANDLE__SubmitResolveEndpointRequest",
    910: "LRPC_BASE_BINDING_HANDLE__NormalizeServerSid",
    912: "LRPC_BASE_BINDING_HANDLE__NormalizeServerSid",
    913: "LRPC_BASE_BINDING_HANDLE__NormalizeServerSid",
    920: "LRPC_BASE_BINDING_HANDLE__DriveStateForward",
    921: "LRPC_BASE_BINDING_HANDLE__DriveStateForward",
    930: "LRPC_BINDING_HANDLE__PrepareBindingHandle",
    931: "LRPC_BINDING_HANDLE__PrepareBindingHandle",
    946: "?0LRPC_FAST_BINDING_HANDLE",
    950: "LRPC_BASE_CCALL__AsyncReceive",
    960: "LRPC_BINDING_HANDLE__NegotiateTransferSyntax",
    972: "LRPC_BASE_CCALL__UnpackResponse",
    974: "LRPC_BASE_CCALL__UnpackResponse",
    978: "LRPC_BASE_CCALL__UnpackResponse",
    980: "LRPC_BASE_CCALL__HandleReply",
    990: "LRPC_BASE_CCALL__HandleReply",
    1000: "LRPC_BASE_CCALL__AlpcSend",
    1010: "LRPC_BASE_CCALL__DoSendReceive",
    1020: "LRPC_BASE_CCALL__GetBuffer",
    1030: "LRPC_BASE_CCALL__DoAsyncSend",
    1040: "LRPC_BIND_CCALL__NotifyBHStateChange",
    1050: "LRPC_BIND_CCALL__AttemptRetry",
    1060: "CLIENT_IO_PROVIDER__SyncWait",
    1070: "CLIENT_IO_PROVIDER__Register",
    1100: "AlpcAllocateSectionAndView",
    1120: "CaptureThreadToken",
    1140: "RpcpDuplicateTokenEx",
    1150: "GetMachineAccountSidWorker",
    1160: "LRPC_BASE_BINDING_HANDLE__DriveStateForward",
    1170: "LPC_NORMALIZED_SID__IterateAndVerify",
    1100: "AlpcAllocateSectionAndView",
    1120: "CaptureThreadToken",
    1140: "RpcpDuplicateTokenEx",
    1150: "GetMachineAccountSidWorker",
    1160: "LRPC_BASE_BINDING_HANDLE__DriveStateForward",
    1170: "LPC_NORMALIZED_SID__IterateAndVerify",
    1171: "LPC_NORMALIZED_SID__IterateAndVerify",
    1180: "LRPC_SASSOCIATION__GetClientName",
    1190: "LRPC_SASSOCIATION__AddBinding",
    1200: "AlpcAllocateView",
    1210: "LRPC_SASSOCIATION__ImpersonateClient",
    1215: "LRPC_SASSOCIATION__ImpersonateClientContainer",
    1230: "LRPC_SCALL__SaveClientToken",
    1232: "LRPC_SCALL__SaveClientToken",
    1240: "LRPC_SCONTEXT__GetUserNameW",
    1260: "LRPC_SCONTEXT__LookupUser",
    1270: "LRPC_BINDING_HANDLE__NegotiateTransferSyntax",
    1280: "LRPC_SCALL__SendReceive",
    1290: "LRPC_CCALL__HandleCallbackSequence",
    1300: "LRPC_SCALL__QueueOrDispatchCall",
    1310: "LRPC_ADDRESS__GetCurrentModifiedId",
    1320: "RPC_INTERFACE__DoSecurityCallbackHelper",
    1321: "RPC_INTERFACE__DoSecurityCallbackHelper",
    1322: "RPC_INTERFACE__DoSecurityCallbackHelper",
    1324: "RPC_INTERFACE__EnforceInterfaceSecurityDescriptor",
    1325: "RPC_INTERFACE__EnforceInterfaceSecurityDescriptor",
    1326: "RPC_INTERFACE__EnforceInterfaceSecurityDescriptor",
    1330: "SCALL__CompleteAsyncSecurityCallback",
    1340: "LRPC_BASE_CCALL__ReallocPipeBuffer",
    1360: "LRPC_ADDRESS__GetClientSid",
    1440: "RpcpErrorAddRecord",
    1441: "RpcpErrorAddRecord",
    1442: "TCPOrHTTP_Open",
    1450: "I_RpcRecordCalloutFailure",
    1451: "RpcpErrorAddRecord",
    1452: "I_RpcRecordCalloutFailure",
    1460: "OSF_CCONNECTION__SendBindPacket",
    1461: "OSF_CCONNECTION__SendBindPacket",
    1462: "OSF_CCONNECTION__SendBindPacket",
    1463: "OSF_CCONNECTION__SendBindPacket",
    1464: "OSF_CCONNECTION__SendBindPacket",
    1465: "OSF_CCONNECTION__SendBindPacket",
    1466: "OSF_CCONNECTION__SendBindPacket",
    1467: "OSF_CCONNECTION__SendBindPacket",
    1468: "OSF_CCONNECTION__SendBindPacket",
    1469: "OSF_CCONNECTION__SendBindPacket",
    1471: "LRPC_BASE_CCALL__HandlePipeChunk",
    1474: "LRPC_BASE_CCALL__HandlePipeChunk",
    1480: "LRPC_CASSOCIATION__AlpcCreateReservedMessage",
    1491: "LRPC_CASSOCIATION__AskForReservedMessage",
    1492: "LRPC_CASSOCIATION__AskForReservedMessage",
    1500: "LRPC_BASE_CCALL__CancelAsyncCall",
    1502: "LRPC_BASE_CCALL__HandlePipeFault",
    1510: "LRPC_BASE_CCALL__HandlePipePull",
    1520: "LRPC_SCALL__NotifyAssociationClosePending",
    1530: "LRPC_SCALL__AbortAsyncCall",
    1540: "BindToEpMapper",
    1550: "LRPC_BASE_CCALL__Send",
    1560: "LRPC_BASE_CCALL__Receive",
    1570: "LRPC_SASSOCIATION__NotifyAllActiveCalls",
    1580: "LRPC_SASSOCIATION__CleanupSparsePipes",
    1590: "LRPC_CCALL__CallbackSendReceive",
    1600: "LRPC_CALLBACK__SendReceiveLoop",
    1601: "LRPC_CALLBACK__SendReceiveLoop",
    1602: "LRPC_CALLBACK__SendReceiveLoop",
    1610: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1611: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1612: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1613: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1614: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1616: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1617: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1619: "OSF_SCALL__DoSecurityCallbackAndAccessCheck",
    1641: "LRPC_SCAUSAL_FLOW__MaybeQueueCall",
    1642: "LRPC_SCAUSAL_FLOW__MaybeQueueCall",
    1650: "LRPC_FAST_BIND_CCALL__ActualCancelCall",
    1660: "LRPC_FAST_BINDING_HANDLE__Bind",
    1670: "LRPC_CAUSAL_FLOW__SendNextCalls",
    1700: "CO_ConnectionThreadPoolCallback",
    1701: "CO_ConnectionThreadPoolCallback",
    1704: "CO_AddressThreadPoolCallback",
    1705: "CO_AddressThreadPoolCallback",
    1710: "OSF_CCONNECTION__ConnectionAborted",
    1720: "OSF_CCONNECTION__ProcessReceiveComplete",
    1730: "OSF_CCONNECTION__ProcessSendComplete",
    1740: "OSF_BINDING_HANDLE__AllocateCCall",
    1741: "OSF_BINDING_HANDLE__AllocateCCall",
    1750: "ProcessFaultPacket",
    3050: "OSF_CCONNECTION__AddCall",
    3080: "SECURITY_CONTEXT__GetWireIdForSnego",
    3081: "SECURITY_CONTEXT__GetWireIdForSnego",
    4000: "OSF_SCALL__FwFilter",
    4001: "OSF_SCALL__FwFilter",
    4002: "OSF_SCALL__FwFilter",
    4020: "LRPC_SCALL__ReallocPipeBuffer",
    4030: "LRPC_BASE_CCALL__HandleCancelMessage",
    4040: "LRPC_SCAUSAL_FLOW__RecordGapInFlow",
    4060: "NMP_BuildDefaultDaclForPipe",
    4061: "NMP_BuildDefaultDaclForPipe",
    4070: "NMP_SetSecurity",
    4072: "NMP_SetSecurity",
    4073: "NMP_BuildDefaultDaclForPipe",
    4077: "NMP_SetSecurity",
    4078: "NMP_SetSecurity",
    4200: "WS_ClientBind",
    4210: "OSF_SCALL__ProcessReceivedPDU",
    4222: "OSF_SCALL__EatAuthInfoFromPacket",
    4230: "RpcpConvertToLongRunning",
    4240: "LRPC_BASE_BINDING_HANDLE__EnableAsyncIfNecessary",
    4253: "LRPC_SYSTEM_HANDLE_DATA__AddSystemHandle",
    4256: "LRPC_SYSTEM_HANDLE_DATA__GetSystemHandle",
    4257: "LRPC_SYSTEM_HANDLE_DATA__GetSystemHandle",
    4272: "RpcpSystemHandleTypeSpecificWork",
    4273: "RpcpSystemHandleTypeSpecificWork",
    4274: "RpcpSystemHandleTypeSpecificWork",
    4291: "HVSOCKET_SetSocketOptions",
}


class DceRpc5ExtendedErrorInfo(Packet):
    fields_desc = [
        NDRSerializeType1PacketField(
            "extended_error",
            ExtendedErrorInfo(),
            ExtendedErrorInfo,
            ptr_pack=True,
        )
    ]

    def show(self) -> None:
        """
        Print stacktrace
        """
        # Get a list of ErrorInfo
        cur = self.extended_error
        errors = [cur]
        while cur and cur.Next:
            cur = cur.Next.value
            errors.append(cur)
        # Concatenate the ErrorInfos
        timefld = UTCTimeField(
            "",
            None,
            fmt="<Q",
            epoch=[1601, 1, 1, 0, 0, 0],
            custom_scaling=1e7,
            strf="%d/%m/%Y %H:%M:%S.%f",
        )
        print("# Extended Error Information")
        for err in errors:
            print("PID:", err.ProcessID, "-", timefld.i2repr(None, err.TimeStamp))
            if err.ComputerName.Type == EEComputerNamePresent.eecnpPresent:
                print(
                    " | ComputerName:",
                    err.ComputerName.value.value.valueof("pString").decode("utf-16le"),
                )
            print(
                " | Generating Component:",
                EERR_GENERATING_COMPONENT.get(
                    err.GeneratingComponent, err.GeneratingComponent
                ),
            )
            print(" | Status:", STATUS_ERREF.get(err.Status, err.Status))
            print(
                " | DetectionLocation:",
                EERR_DETECTION_LOCATIONS.get(
                    err.DetectionLocation, err.DetectionLocation
                ),
            )
            print(" | Flags", EERR_FLAGS.get(err.Flags, err.Flags))
            print(
                " | Params: ",
                repr([(x.sprintf("%Type%"), x.value.value) for x in err.Params]),
            )


# Bind to fault PDU
bind_layers(DceRpc5Fault, DceRpc5ExtendedErrorInfo, reserved=1)

# Bind to nak PDU
bind_layers(
    DceRpc5BindNak,
    DceRpc5ExtendedErrorInfo,
    signature=uuid.UUID("90740320-fad0-11d3-82d7-009027b130ab"),
)
