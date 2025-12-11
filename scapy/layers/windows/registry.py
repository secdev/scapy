"""
This file implements Windows Registry related high level functions.
It provides easy to use functions to manipulate the registry.
If you want to tweak low level fields see directly scapy.layers.msrpce.raw.ms_rrp.
Otherwise, this module should hopefully provide everything you need.
"""

from enum import StrEnum, IntEnum, IntFlag
from typing import Generator, Optional

from scapy.packet import Packet
from scapy.error import log_runtime

from scapy.layers.windows.win_security import AccessRights, SECURITY_DESCRIPTOR
from scapy.layers.msrpce.rpcclient import DCERPC_Client
from scapy.layers.dcerpc import (
    NDRConformantArray,
    NDRPointer,
    NDRVaryingArray,
)

# pylint: disable-next=import-error, no-name-in-module
from scapy.layers.msrpce.raw.ms_rrp import (
    OpenClassesRoot_Request,
    OpenLocalMachine_Request,
    OpenCurrentUser_Request,
    OpenUsers_Request,
    OpenCurrentConfig_Request,
    OpenPerformanceData_Request,
    OpenPerformanceText_Request,
    OpenPerformanceNlsText_Request,
    BaseRegOpenKey_Request,
    BaseRegEnumKey_Request,
    BaseRegEnumValue_Request,
    BaseRegCloseKey_Request,
    BaseRegQueryValue_Request,
    BaseRegGetVersion_Request,
    BaseRegQueryInfoKey_Request,
    BaseRegQueryInfoKey_Response,
    BaseRegGetKeySecurity_Request,
    BaseRegSaveKey_Request,
    BaseRegSetValue_Request,
    BaseRegCreateKey_Request,
    BaseRegDeleteKey_Request,
    BaseRegDeleteValue_Request,
    PRPC_SECURITY_DESCRIPTOR,
    PRPC_SECURITY_ATTRIBUTES,
    RPC_UNICODE_STRING,
    NDRContextHandle,
)


class RootKeys(StrEnum):
    """
    Standard root keys for the Windows registry
    """

    # Registry root keys
    # These constants are used to specify the root keys of the Windows registry.
    # The root keys are the top-level keys in the registry hierarchy.

    # Registry entries subordinate to this key define types (or classes) of documents and the
    # properties associated with those types.
    # The subkeys of the HKEY_CLASSES_ROOT key are a merged view of the following two subkeys:
    HKEY_CLASSES_ROOT = "HKCR"

    # Registry entries subordinate to this key define the preferences of the current user.
    # These preferences include the settings of environment variables, data on program groups,
    # colors, printers, network connections, and application preferences.
    # The HKEY_CURRENT_USER root key is a subkey of the HKEY_USERS root key, as described in
    # section 3.1.1.8.
    HKEY_CURRENT_USER = "HKCU"

    # Registry entries subordinate to this key define the physical state of the computer,
    # including data on the bus type, system memory, and installed hardware and software.
    HKEY_LOCAL_MACHINE = "HKLM"

    # This key contains information on the current hardware profile of the local computer.
    # HKEY_CURRENT_CONFIG is an alias for
    # HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current
    HKEY_CURRENT_CONFIG = "HKCC"

    # This key define the default user configuration for new users on the local computer and the
    # user configuration for the current user.
    HKEY_USERS = "HKU"

    # Registry entries subordinate to this key allow access to performance data.
    HKEY_PERFORMANCE_DATA = "HKPD"

    # Registry entries subordinate to this key reference the text strings that describe counters
    # in U.S. English.
    HKEY_PERFORMANCE_TEXT = "HKPT"

    # Registry entries subordinate to this key reference the text strings that describe
    # counters in the local language of the area in which the computer is running.
    HKEY_PERFORMANCE_NLSTEXT = "HKPN"

    def __new__(cls, value):
        # 1. Strip and uppercase the raw input
        normalized = value.strip().upper()
        # 2. Create the enum member with the normalized value
        obj = str.__new__(cls, normalized)
        obj._value_ = normalized
        return obj

    @classmethod
    def from_value(cls, value: str):
        """Convert a string to a RootKeys enum member."""
        value = value.strip().upper()
        match value:
            case "HKEY_CLASSES_ROOT":
                value = RootKeys.HKEY_CLASSES_ROOT.value
            case "HKEY_CURRENT_USER":
                value = RootKeys.HKEY_CURRENT_USER.value
            case "HKEY_LOCAL_MACHINE":
                value = RootKeys.HKEY_LOCAL_MACHINE.value
            case "HKEY_CURRENT_CONFIG":
                value = RootKeys.HKEY_CURRENT_CONFIG.value
            case "HKEY_USERS":
                value = RootKeys.HKEY_USERS.value
            case "HKEY_PERFORMANCE_DATA":
                value = RootKeys.HKEY_PERFORMANCE_DATA.value
            case "HKEY_PERFORMANCE_TEXT":
                value = RootKeys.HKEY_PERFORMANCE_TEXT.value
            case "HKEY_PERFORMANCE_NLSTEXT":
                value = RootKeys.HKEY_PERFORMANCE_NLSTEXT.value

        try:
            return cls(value)
        except ValueError:
            print(f"Unknown root key: {value}.")


class ErrorCodes(IntEnum):
    """
    Error codes for registry operations
    """

    ERROR_SUCCESS = 0x00000000
    ERROR_FILE_NOT_FOUND = 0x00000002
    ERROR_PATH_NOT_FOUND = 0x00000003
    ERROR_ACCESS_DENIED = 0x00000005
    ERROR_INVALID_HANDLE = 0x00000006
    ERROR_NOT_SAME_DEVICE = 0x00000011
    ERROR_WRITE_PROTECT = 0x00000013
    ERROR_INVALID_PARAMETER = 0x00000057
    ERROR_CALL_NOT_IMPLEMENTED = 0x00000057
    ERROR_INVALID_NAME = 0x0000007B
    ERROR_BAD_PATHNAME = 0x000000A1
    ERROR_ALREADY_EXISTS = 0x000000B7
    ERROR_NO_MORE_ITEMS = 0x00000103
    ERROR_NOACCESS = 0x000003E6
    ERROR_SUBKEY_NOT_FOUND = 0x000006F7
    ERROR_INSUFFICIENT_BUFFER = 0x0000007A
    ERROR_MORE_DATA = 0x000000EA

    def __str__(self) -> str:
        """
        Return the string representation of the error code.
        :return: The string representation of the error code.
        """

        return self.name


class RegOptions(IntFlag):
    """
    Registry options for registry keys
    """

    REG_OPTION_NON_VOLATILE = 0x00000000
    REG_OPTION_VOLATILE = 0x00000001
    REG_OPTION_CREATE_LINK = 0x00000002
    REG_OPTION_BACKUP_RESTORE = 0x00000004
    REG_OPTION_OPEN_LINK = 0x00000008
    REG_OPTION_DONT_VIRTUALIZE = 0x00000010


class RegType(IntEnum):
    """
    Registry value types
    """

    # These constants are used to specify the type of a registry value.

    REG_SZ = 1  # Unicode string
    REG_EXPAND_SZ = 2  # Unicode string with environment variable expansion
    REG_BINARY = 3  # Binary data
    REG_DWORD = 4  # 32-bit unsigned integer
    REG_DWORD_BIG_ENDIAN = 5  # 32-bit unsigned integer in big-endian format
    REG_LINK = 6  # Symbolic link
    REG_MULTI_SZ = 7  # Multiple Unicode strings
    REG_QWORD = 11  # 64-bit unsigned integer
    UNK = 99999  # fallback default

    @classmethod
    def _missing_(cls, value):
        log_runtime.info(f"Unknown registry type: {value}, using UNK")
        unk = cls.UNK
        unk.real_value = value
        return unk

    def __new__(cls, value, real_value=None):
        obj = int.__new__(cls, value)
        obj._value_ = value
        if real_value is None:
            real_value = value
        obj.real_value = real_value
        return obj

    @classmethod
    def fromvalue(cls, value: str | int) -> "RegType":
        """Convert a string to a RegType enum member.
        :param value: The string representation of the registry type.
        :return: The corresponding RegType enum member.
        """

        if isinstance(value, int):
            try:
                return cls(value)
            except ValueError:
                log_runtime.info(f"Unknown registry type: {value}, using UNK")
                return cls.UNK

        value = value.strip().upper()
        try:
            return cls(int(value))
        except (ValueError, KeyError):
            log_runtime.info(f"Unknown registry type: {value}, using UNK")
        return cls.UNK


class RegEntry:
    """
    RegEntry to properly parse the data based on the type.

        :param reg_value: the name of the registry value (str)
        :param reg_type: the type of the registry value (int)
        :param reg_data: the data of the registry value (str)
    """

    def __init__(self, reg_value: str, reg_type: int, reg_data: bytes, from_str=False):
        self.reg_value = reg_value
        try:
            self.reg_type = RegType(reg_type)
        except ValueError:
            self.reg_type = RegType.UNK

        if from_str:
            self.reg_data = RegEntry.encode_data(self.reg_type, reg_data)
        else:
            self.reg_data = reg_data

    @staticmethod
    def encode_data(reg_type: RegType, data: str | list[str]) -> bytes:
        """
        Encode data based on the type.
        """

        match reg_type:
            case RegType.REG_MULTI_SZ | RegType.REG_SZ | RegType.REG_EXPAND_SZ:
                if reg_type == RegType.REG_MULTI_SZ:
                    # encode to multiple null terminated strings
                    if isinstance(data, str):
                        # if it was previously encoded, we remove the
                        # final \x00 and the final empty string
                        data = data.strip(b"\x00\x00\x00\x00")
                        encoded_data = (
                            b"\x00\x00".join(
                                [x.strip().encode("utf-16le") for x in data.split()]
                            )
                            + b"\x00\x00"  # final \x00
                            + b"\x00\x00"  # final empty string
                        )
                    elif isinstance(data, list):
                        # if it was previously encoded, we remove the
                        # final \x00 and the final empty string
                        if data[-1] == "":
                            data = data[:-1]
                        encoded_data = (
                            b"\x00\x00".join(
                                [
                                    x.strip().strip("\x00\x00").encode("utf-16le")
                                    for x in data
                                ]
                            )
                            + b"\x00\x00"  # final \x00
                            + b"\x00\x00"  # final empty string
                        )
                    else:
                        log_runtime.error(
                            "Expected str or list[str] instance for data, got %s",
                            type(data),
                        )
                        raise TypeError

                    return encoded_data

                else:
                    return data.encode("utf-16le")

            case RegType.REG_BINARY:
                if isinstance(data, bytes):
                    return data
                return data.encode("utf-8").decode("unicode_escape").encode("latin1")

            case RegType.REG_DWORD | RegType.REG_QWORD:
                # Use fixed sizes: 4 bytes for DWORD, 8 bytes for QWORD.
                bit_length = 4 if reg_type == RegType.REG_DWORD else 8
                return int(data).to_bytes(bit_length, byteorder="little")

            case RegType.REG_DWORD_BIG_ENDIAN:
                bit_length = 4
                return int(data).to_bytes(bit_length, byteorder="big")

            case RegType.REG_LINK:
                return data.encode("utf-16le")

            case _:
                return data.encode("utf-8").decode("unicode_escape").encode("latin1")

    @staticmethod
    def decode_data(reg_type: RegType, data: bytes) -> str:
        """
        Decode data based on the type.
        """
        match reg_type:
            case RegType.REG_MULTI_SZ | RegType.REG_SZ | RegType.REG_EXPAND_SZ:
                if reg_type == RegType.REG_MULTI_SZ:
                    # decode multiple null terminated strings
                    return data.decode("utf-16le")[:-1].split("\x00")
                else:
                    return data.decode("utf-16le")

            case RegType.REG_BINARY:
                return data

            case RegType.REG_DWORD | RegType.REG_QWORD:
                return int.from_bytes(data, byteorder="little")

            case RegType.REG_DWORD_BIG_ENDIAN:
                return int.from_bytes(data, byteorder="big")

            case RegType.REG_LINK:
                return data.decode("utf-16le")

            case _:
                return data

    def __str__(self) -> str:
        if self.reg_type == RegType.UNK:
            return f"{self.reg_value} ({self.reg_type.name}:{self.reg_type.real_value}) {self.reg_data}"
        return f"{self.reg_value} ({self.reg_type.name}:{self.reg_type.value}) {self.reg_data}"

    def __repr__(self) -> str:
        return f"RegEntry({self.reg_value}, {self.reg_type}, {self.reg_data})"

    def __eq__(self, value):
        return isinstance(value, RegEntry) and all(
            [
                self.reg_data == value.reg_data,
                self.reg_type == value.reg_type,
                self.reg_data == value.reg_data,
            ]
        )


class RegApi:
    """
    High level Windows Registry API functions.
    These functions use the low level RPC requests defined in ms_rrp to provide
    easy to use functions to manipulate the Windows registry.
    """

    @staticmethod
    def is_status_ok(status: int) -> Optional[bool]:
        """
        Check the error code and raise an exception if it is not successful.
        :param status: The error code to check.
        """

        try:
            err = ErrorCodes(status)
            if err not in [
                ErrorCodes.ERROR_SUCCESS,
                ErrorCodes.ERROR_NO_MORE_ITEMS,
                ErrorCodes.ERROR_MORE_DATA,
            ]:
                log_runtime.error(
                    "Error: %s - %s", hex(err.value), ErrorCodes(status).name
                )
                return False
            return True
        except ValueError as exc:
            log_runtime.error("Error: %s - Unknown error code", hex(status))
            raise ValueError(f"Error: {hex(status)} - Unknown error code") from exc

    @staticmethod
    def get_root_key_handle(
        client: DCERPC_Client,
        root_key_name: RootKeys,
        sam_desired: AccessRights | int = AccessRights.MAXIMUM_ALLOWED,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> Optional[NDRContextHandle]:
        """
        Get a handle to a root key.

        :param root_key_name: The name of the root key to open. Must be one of the RootKeys enum values.
        :param sam_desired: The desired access rights for the key.
        :param ndr64: Whether to use NDR64 encoding.
        :param ServerName: The server name. The ServerName SHOULD be sent as NULL, and MUST be ignored
                when it is received because binding to the server is already complete at this stage
        :return: The handle to the opened root key.
        """

        if root_key_name == RootKeys.HKEY_CLASSES_ROOT:
            return client.sr1_req(
                OpenClassesRoot_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        elif root_key_name == RootKeys.HKEY_CURRENT_USER:
            return client.sr1_req(
                OpenCurrentUser_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        elif root_key_name == RootKeys.HKEY_LOCAL_MACHINE:
            return client.sr1_req(
                OpenLocalMachine_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        elif root_key_name == RootKeys.HKEY_USERS:
            return client.sr1_req(
                OpenUsers_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        elif root_key_name == RootKeys.HKEY_CURRENT_CONFIG:
            return client.sr1_req(
                OpenCurrentConfig_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        elif root_key_name == RootKeys.HKEY_PERFORMANCE_DATA:
            return client.sr1_req(
                OpenPerformanceData_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        elif root_key_name == RootKeys.HKEY_PERFORMANCE_TEXT:
            return client.sr1_req(
                OpenPerformanceText_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        elif root_key_name == RootKeys.HKEY_PERFORMANCE_NLSTEXT:
            return client.sr1_req(
                OpenPerformanceNlsText_Request(
                    ServerName=None,
                    samDesired=sam_desired,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            ).phKey
        else:
            raise ValueError(f"Unknown root key: {root_key_name}")

    @staticmethod
    def get_subkey_handle(
        client: DCERPC_Client,
        root_key_handle: NDRContextHandle,
        subkey_path: str,
        desired_access_rights: AccessRights | int = AccessRights.MAXIMUM_ALLOWED,
        options: RegOptions = RegOptions.REG_OPTION_NON_VOLATILE,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> NDRContextHandle:
        """
        Get a handle to a subkey.

        :param client: The DCERPC client.
        :param root_key_handle: The handle to the root key.
        :param subkey_path: The name of the subkey to open.
        :param desired_access_rights: The desired access rights for the subkey.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: The handle to the opened subkey.
        """

        # Ensure it is null-terminated and handle the special case of "."
        if str(subkey_path) == ".":
            subkey_path = "\x00"
        elif not str(subkey_path).endswith("\x00"):
            subkey_path = str(subkey_path) + "\x00"

        response = client.sr1_req(
            BaseRegOpenKey_Request(
                hKey=root_key_handle,
                lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
                samDesired=desired_access_rights,
                dwOptions=options,
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while opening subkey %s",
                hex(response.status),
                subkey_path,
            )
            raise ValueError(response.status)

        return response.phkResult

    @staticmethod
    def get_version(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> Packet:
        """
        Get the version of the registry server.

        :param client: The DCERPC client.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: The response packet containing the version information.
        """

        response = client.sr1_req(
            BaseRegGetVersion_Request(
                hKey=key_handle,
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while getting version", hex(response.status)
            )

        return response

    @staticmethod
    def get_key_info(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> Optional[BaseRegQueryInfoKey_Response]:
        """
        Get information about a given registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: The response packet containing the key information.
        """

        response = client.sr1_req(
            BaseRegQueryInfoKey_Request(
                hKey=key_handle,
                lpClassIn=RPC_UNICODE_STRING(),
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while querying key info", hex(response.status)
            )
            raise ValueError(response.status)

        return response

    @staticmethod
    def get_key_security(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        security_information: int = None,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> SECURITY_DESCRIPTOR:
        """
        Get the security descriptor of a given registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param security_information: The security information to retrieve.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: The response packet containing the security descriptor.
        """

        if security_information is None:
            security_information = (
                0x00000001  # OWNER_SECURITY_INFORMATION
                | 0x00000002  # GROUP_SECURITY_INFORMATION
                | 0x00000004  # DACL_SECURITY_INFORMATION
            )

        # Build initial request
        req = BaseRegGetKeySecurity_Request(
            hKey=key_handle,
            SecurityInformation=security_information,
            pRpcSecurityDescriptorIn=PRPC_SECURITY_DESCRIPTOR(
                cbInSecurityDescriptor=512,  # Initial size of the buffer
            ),
            ndr64=ndr64,
        )

        # Send request
        response = client.sr1_req(req, timeout=timeout)
        if response.status == ErrorCodes.ERROR_INSUFFICIENT_BUFFER:
            # The buffer was too small, we need to retry with a larger one
            req.pRpcSecurityDescriptorIn.cbInSecurityDescriptor = (
                response.pRpcSecurityDescriptorOut.cbInSecurityDescriptor
            )
            response = client.sr1_req(req, timeout=timeout)

        # Check the response status
        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while getting security", hex(response.status)
            )
            return None

        sd = SECURITY_DESCRIPTOR(
            response.pRpcSecurityDescriptorOut.valueof("lpSecurityDescriptor")
        )

        return sd

    @staticmethod
    def enum_subkeys(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> Generator[Packet, None, None]:
        """
        Enumerate subkeys of a given registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: A generator yielding the responses for each enumerated subkey.
        """
        index = 0

        while True:
            response = client.sr1_req(
                BaseRegEnumKey_Request(
                    hKey=key_handle,
                    dwIndex=index,
                    lpNameIn=RPC_UNICODE_STRING(MaximumLength=1024),
                    lpClassIn=RPC_UNICODE_STRING(),
                    lpftLastWriteTime=None,
                    ndr64=ndr64,
                ),
                timeout=timeout,
            )

            # Send request
            if response.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break

            # Check the response status
            elif not RegApi.is_status_ok(response.status):
                log_runtime.error(
                    "Got status %s while enumerating keys", hex(response.status)
                )
                raise ValueError(response.status)

            index += 1
            yield response

    @staticmethod
    def enum_values(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> Generator[Packet, None, None]:
        """
        Enumerate values of a given registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: A generator yielding the responses for each enumerated value.
        """
        index = 0

        while True:
            # Get the name and value at index `index`
            response = client.sr1_req(
                BaseRegEnumValue_Request(
                    hKey=key_handle,
                    dwIndex=index,
                    lpValueNameIn=RPC_UNICODE_STRING(
                        MaximumLength=2048,
                        Buffer=NDRPointer(
                            value=NDRConformantArray(
                                max_count=1024, value=NDRVaryingArray(value=b"")
                            )
                        ),
                    ),
                    lpType=0,  # pointer to type, set to 0 for query
                    lpData=None,  # pointer to buffer
                    lpcbData=0,  # pointer to buffer size
                    lpcbLen=0,  # pointer to length
                    ndr64=ndr64,
                ),
                timeout=timeout,
            )

            if response.status == ErrorCodes.ERROR_NO_MORE_ITEMS:
                break

            elif not RegApi.is_status_ok(response.status):
                log_runtime.error(
                    "Got status %s while enumerating values", hex(response.status)
                )
                raise ValueError(response.status)

            # Get the value name and type
            # for the name we got earlier
            req = BaseRegQueryValue_Request(
                hKey=key_handle,
                lpValueName=response.valueof("lpValueNameOut"),
                lpType=0,
                lpcbData=1024,
                lpcbLen=0,
                lpData=NDRPointer(
                    value=NDRConformantArray(
                        max_count=1024, value=NDRVaryingArray(actual_count=0, value=b"")
                    )
                ),
                ndr64=ndr64,
            )

            # Send request
            response2 = client.sr1_req(req, timeout=timeout)
            if response2.status == ErrorCodes.ERROR_MORE_DATA:
                # The buffer was too small, we need to retry with a larger one
                req.lpcbData = response2.lpcbData
                req.lpData.value.max_count = response2.lpcbData.value
                response2 = client.sr1_req(req, timeout=timeout)

            # Check the response status
            if not RegApi.is_status_ok(response2.status):
                log_runtime.error(
                    "got status %s while querying value", hex(response2.status)
                )
                raise ValueError(response2.status)

            index += 1
            yield response, response2

    @staticmethod
    def get_value(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        value_name: str,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> Packet:
        """
        Get the value of a given registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param value_name: The name of the value to retrieve.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: The response packet containing the value data.
        """

        response = client.sr1_req(
            BaseRegQueryValue_Request(
                hKey=key_handle,
                lpValueName=value_name,
                lpType=0,
                lpcbData=1024,
                lpcbLen=0,
                lpData=NDRPointer(
                    value=NDRConformantArray(
                        max_count=1024, value=NDRVaryingArray(actual_count=0, value=b"")
                    )
                ),
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if response.status == ErrorCodes.ERROR_MORE_DATA:
            # The buffer was too small, we need to retry with a larger one
            response = client.sr1_req(
                BaseRegQueryValue_Request(
                    hKey=key_handle,
                    lpValueName=value_name,
                    lpType=0,
                    lpcbData=response.lpcbData,
                    lpcbLen=0,
                    lpData=NDRPointer(
                        value=NDRConformantArray(
                            max_count=response.lpcbData.value,
                            value=NDRVaryingArray(actual_count=0, value=b""),
                        )
                    ),
                    ndr64=ndr64,
                ),
                timeout=timeout,
            )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while querying value %s",
                hex(response.status),
                value_name,
            )

        return response

    @staticmethod
    def save_subkey(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        file_path: str,
        security_attributes: PRPC_SECURITY_ATTRIBUTES = None,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> bool:
        """
        Save a given registry key to a file.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param file_path: The path to the file where the key will be saved.
            Default path is %WINDIR%\\System32, which is readable by all users.
        :param security_attributes: Security attributes for the saved key.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: True if the key was saved successfully, False otherwise.
        """

        response = client.sr1_req(
            BaseRegSaveKey_Request(
                hKey=key_handle,
                lpFile=RPC_UNICODE_STRING(Buffer=file_path),
                pSecurityAttributes=security_attributes,
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error("Got status %s while saving key", hex(response.status))
            return False

        return True

    @staticmethod
    def set_value(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        value_name: str,
        value_type: RegType,
        value_data: str | bytes,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> bool:
        """
        Set a given value for a registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param value_name: The name of the value to set.
        :param value_type: The type of the value to set.
        :param value_data: The data of the value to set.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: True if the value was set successfully, False otherwise.
        """

        if not str(value_name).endswith("\x00"):
            value_name = str(value_name) + "\x00"

        if isinstance(value_data, bytes):
            data = value_data
        else:
            data = RegEntry.encode_data(value_type, value_data)

        response = client.sr1_req(
            BaseRegSetValue_Request(
                hKey=key_handle,
                lpValueName=RPC_UNICODE_STRING(Buffer=value_name),
                dwType=value_type.value,
                cbData=len(data),
                lpData=data,
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while setting value %s",
                hex(response.status),
                value_name,
            )
            raise ValueError(response.status)

        return True

    @staticmethod
    def create_subkey(
        client: DCERPC_Client,
        root_key_handle: NDRContextHandle,
        subkey_path: str,
        desired_access_rights: AccessRights | int = AccessRights.MAXIMUM_ALLOWED,
        options: RegOptions = RegOptions.REG_OPTION_NON_VOLATILE,
        security_attributes: PRPC_SECURITY_ATTRIBUTES = None,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> Packet:
        """
        Create a given subkey under a registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the root key.
        :param subkey_path: The name of the subkey to create.
        :param desired_access_rights: The desired access rights for the subkey.
        :param options: The options for the subkey.
        :param security_attributes: Security attributes for the created key.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: The handle to the created subkey.
        """

        if not str(subkey_path).endswith("\x00"):
            subkey_path = str(subkey_path) + "\x00"

        response = client.sr1_req(
            BaseRegCreateKey_Request(
                hKey=root_key_handle,
                lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
                samDesired=desired_access_rights,
                dwOptions=options,
                lpSecurityAttributes=security_attributes,
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while creating subkey %s",
                hex(response.status),
                subkey_path,
            )
            return None

        return response

    @staticmethod
    def delete_subkey(
        client: DCERPC_Client,
        root_key_handle: NDRContextHandle,
        subkey_path: str,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> bool:
        """
        Delete a given subkey from a registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the root key.
        :param subkey_path: The name of the subkey to remove.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: True if the subkey was deleted successfully, False otherwise.
        """

        if not str(subkey_path).endswith("\x00"):
            subkey_path = str(subkey_path) + "\x00"

        response = client.sr1_req(
            BaseRegDeleteKey_Request(
                hKey=root_key_handle,
                lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while deleting subkey %s",
                hex(response.status),
                subkey_path,
            )
            raise ValueError(response.status)

        return True

    @staticmethod
    def delete_value(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        value_name: str,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> bool:
        """
        Delete a given value from a registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the subkey to remove.
        :param value_name: The name of the value to delete.
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: True if the value was deleted successfully, False otherwise.
        """

        if not str(value_name).endswith("\x00"):
            value_name = str(value_name) + "\x00"

        response = client.sr1_req(
            BaseRegDeleteValue_Request(
                hKey=key_handle,
                lpValueName=RPC_UNICODE_STRING(Buffer=value_name),
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error(
                "Got status %s while deleting value %s",
                hex(response.status),
                value_name,
            )
            raise ValueError(response.status)

        return True

    @staticmethod
    def close_key(
        client: DCERPC_Client,
        key_handle: NDRContextHandle,
        ndr64: bool = True,
        timeout: int = 5,
    ) -> bool:
        """
        Close a given registry key handle.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param ndr64: Whether to use NDR64 encoding.
        :param timeout: The timeout for the request.
        :return: True if the key was closed successfully, False otherwise.
        """

        response = client.sr1_req(
            BaseRegCloseKey_Request(
                hKey=key_handle,
                ndr64=ndr64,
            ),
            timeout=timeout,
        )

        if not RegApi.is_status_ok(response.status):
            log_runtime.error("Got status %s while closing key", hex(response.status))
            raise ValueError(response.status)

        return True
