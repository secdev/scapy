# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) github.com/Ebrix

"""
Windows Registry RPCs

This file provides high-level wrapping over Windows Registry related RPCs.
(scapy.layers.msrpce.raw.ms_rrp)
"""

import struct

from enum import IntEnum, IntFlag
from typing import Optional, Union, List

from scapy.compat import StrEnum
from scapy.packet import Packet
from scapy.error import log_runtime

from scapy.layers.windows.security import (
    SECURITY_DESCRIPTOR,
)
from scapy.layers.msrpce.rpcclient import DCERPC_Client
from scapy.layers.dcerpc import (
    NDRConformantArray,
    NDRPointer,
    NDRVaryingArray,
    DCERPC_Transport,
    DCE_C_AUTHN_LEVEL,
    find_dcerpc_interface,
)

from scapy.layers.msrpce.raw.ms_rrp import (
    BaseRegCloseKey_Request,
    BaseRegCreateKey_Request,
    BaseRegDeleteKey_Request,
    BaseRegDeleteValue_Request,
    BaseRegEnumKey_Request,
    BaseRegEnumValue_Request,
    BaseRegGetKeySecurity_Request,
    BaseRegGetVersion_Request,
    BaseRegOpenKey_Request,
    BaseRegQueryInfoKey_Request,
    BaseRegQueryInfoKey_Response,
    BaseRegQueryValue_Request,
    BaseRegSaveKey_Request,
    BaseRegSetValue_Request,
    NDRContextHandle,
    OpenClassesRoot_Request,
    OpenCurrentConfig_Request,
    OpenCurrentUser_Request,
    OpenLocalMachine_Request,
    OpenPerformanceData_Request,
    OpenPerformanceNlsText_Request,
    OpenPerformanceText_Request,
    OpenUsers_Request,
    PRPC_SECURITY_ATTRIBUTES,
    PRPC_SECURITY_DESCRIPTOR,
    RPC_UNICODE_STRING,
)


class RootKeys(StrEnum):
    """
    Standard root keys for the Windows registry
    """

    HKEY_CLASSES_ROOT = "HKCR"
    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_CONFIG = "HKCC"
    HKEY_USERS = "HKU"
    HKEY_PERFORMANCE_DATA = "HKPD"
    HKEY_PERFORMANCE_TEXT = "HKPT"
    HKEY_PERFORMANCE_NLSTEXT = "HKPN"

    def __new__(cls, value):
        # 1. Strip and uppercase the raw input
        normalized = value.strip().upper()
        # 2. Create the enum member with the normalized value
        obj = str.__new__(cls, normalized)
        obj._value_ = normalized
        return obj


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

    REG_NONE = 0  # No defined value type
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
    def fromstr(cls, value: Union[str, int]) -> "RegType":
        """
        Convert a string to a RegType enum member.

        :param value: The string representation of the registry type.
        :return: The corresponding RegType enum member.
        """
        if isinstance(value, int):
            try:
                return cls(value)
            except ValueError:
                log_runtime.info(f"Unknown registry type: {value}, using UNK")
                return cls.UNK
        else:
            # we want to make sure that regdword, reg_dword, dword and upper
            # case equivalents are all properly parsed
            value = value.strip().upper()
            if "_" not in value:
                if value[:3] == "REG":
                    value = value[3:]
                value = "REG_" + value.replace("REG", "", 1)
            try:
                return cls[value]
            except (ValueError, KeyError):
                log_runtime.info(f"Unknown registry type: {value}, using UNK")
            return cls.UNK


class RegEntry:
    """
    RegEntry represents a Registry Value, inside a Registry Key.

    :param reg_name: the name of the registry value
    :param reg_type: the type of the registry value
    :param reg_data: the data of the registry value
    """

    def __init__(
        self,
        reg_name: str,
        reg_type: int,
        reg_data: Union[list, str, bytes, int],
    ):
        # Name
        self.reg_name = reg_name

        # Type
        try:
            self.reg_type = RegType(reg_type)
        except ValueError:
            self.reg_type = RegType.UNK

        # Check data type
        if reg_type == RegType.REG_MULTI_SZ:
            if not isinstance(reg_data, list):
                raise ValueError("Data must be a 'list' of 'str' for this type.")
        elif reg_type in [
            RegType.REG_SZ,
            RegType.REG_EXPAND_SZ,
            RegType.REG_LINK,
        ]:
            if not isinstance(reg_data, str):
                raise ValueError("Data must be a 'str' for this type.")
        elif reg_type in [RegType.REG_NONE, RegType.REG_BINARY]:
            if not isinstance(reg_data, bytes):
                raise ValueError("Data must be a 'bytes' for this type.")
        elif reg_type in [
            RegType.REG_DWORD,
            RegType.REG_QWORD,
            RegType.REG_DWORD_BIG_ENDIAN,
        ]:
            if not isinstance(reg_data, int):
                raise ValueError("Data must be a 'int' for this type.")
        else:
            if not isinstance(reg_data, bytes):
                raise ValueError("Data of this unknown type must be a 'bytes'.")

        self.reg_data = reg_data

    def encode(self) -> bytes:
        """
        Encode data based on the type.
        """
        if self.reg_type == RegType.REG_MULTI_SZ:
            # encode to multiple null terminated strings
            return (
                b"\x00\x00".join(x.strip().encode("utf-16le") for x in self.reg_data)
                + b"\x00\x00"  # final \x00
                + b"\x00\x00"  # final empty string
            )
        elif self.reg_type in [
            RegType.REG_SZ,
            RegType.REG_EXPAND_SZ,
            RegType.REG_LINK,
        ]:
            return self.reg_data.encode("utf-16le")
        elif self.reg_type in [RegType.REG_NONE, RegType.REG_BINARY]:
            return self.reg_data
        elif self.reg_type in [
            RegType.REG_DWORD,
            RegType.REG_QWORD,
            RegType.REG_DWORD_BIG_ENDIAN,
        ]:
            fmt = {
                RegType.REG_DWORD: "<I",
                RegType.REG_QWORD: "<Q",
                RegType.REG_DWORD_BIG_ENDIAN: ">I",
            }[self.reg_type]
            return struct.pack(fmt, self.reg_data)
        else:
            return self.reg_data

    @staticmethod
    def frombytes(reg_name: str, reg_type: RegType, data: bytes):
        """
        Create a RegEntry from bytes read on the network.
        """
        if reg_type == RegType.REG_MULTI_SZ:
            # encode to multiple null terminated strings
            reg_data = data.decode("utf-16le")[:-2].split("\x00")
        elif reg_type in [
            RegType.REG_SZ,
            RegType.REG_EXPAND_SZ,
            RegType.REG_LINK,
        ]:
            reg_data = data.decode("utf-16le")
        elif reg_type in [RegType.REG_NONE, RegType.REG_BINARY]:
            reg_data = data
        elif reg_type in [
            RegType.REG_DWORD,
            RegType.REG_QWORD,
            RegType.REG_DWORD_BIG_ENDIAN,
        ]:
            fmt = {
                RegType.REG_DWORD: "<I",
                RegType.REG_QWORD: "<Q",
                RegType.REG_DWORD_BIG_ENDIAN: ">I",
            }[reg_type]
            reg_data = struct.unpack(fmt, data)[0]
        else:
            reg_data = data

        return RegEntry(
            reg_name=reg_name,
            reg_type=reg_type,
            reg_data=reg_data,
        )

    @staticmethod
    def fromstr(reg_name: str, reg_type: RegType, data: str):
        """
        Create a RegEntry from user input.
        """
        if reg_type == RegType.REG_MULTI_SZ:
            reg_data = data.split(";")
        elif reg_type in [
            RegType.REG_SZ,
            RegType.REG_EXPAND_SZ,
            RegType.REG_LINK,
        ]:
            reg_data = data
        elif reg_type in [RegType.REG_NONE, RegType.REG_BINARY]:
            reg_data = bytes.fromhex(data)
        elif reg_type in [
            RegType.REG_DWORD,
            RegType.REG_QWORD,
            RegType.REG_DWORD_BIG_ENDIAN,
        ]:
            reg_data = int(data)
        else:
            reg_data = data

        return RegEntry(
            reg_name=reg_name,
            reg_type=reg_type,
            reg_data=reg_data,
        )

    def __str__(self) -> str:
        return (
            f"{self.reg_name} ({self.reg_type.name}: "
            + f"{self.reg_type.real_value if self.reg_type == RegType.UNK else self.reg_type.value}"  # noqa E501
            + f") {self.reg_data}"
        )

    def __repr__(self) -> str:
        return f"RegEntry({self.reg_name}, {self.reg_type}, {self.reg_data})"

    def __eq__(self, value):
        return isinstance(value, RegEntry) and all(
            [
                self.reg_data == value.reg_data,
                self.reg_type == value.reg_type,
                self.reg_data == value.reg_data,
            ]
        )


class RRP_Client(DCERPC_Client):
    """
    High level [MS-RRP] (Windows Registry) Client
    """

    def __init__(
        self,
        auth_level=DCE_C_AUTHN_LEVEL.PKT_INTEGRITY,
        verb=True,
        **kwargs,
    ):
        self.interface = find_dcerpc_interface("winreg")
        super(RRP_Client, self).__init__(
            DCERPC_Transport.NCACN_NP,
            auth_level=auth_level,
            verb=verb,
            **kwargs,
        )

    def connect(self, host, **kwargs):
        """
        This calls DCERPC_Client's connect
        """
        super(RRP_Client, self).connect(
            host=host,
            interface=self.interface,
            endpoint="winreg",
            **kwargs,
        )

    def bind(self):
        """
        This calls DCERPC_Client's bind
        """
        super(RRP_Client, self).bind(self.interface)

    def get_root_key_handle(
        self,
        root_key_name: RootKeys,
        sam_desired: int = 0x2000000,  # Maximum Allowed
        timeout: int = 5,
    ) -> Optional[NDRContextHandle]:
        """
        Get a handle to a root key.

        :param root_key_name: The name of the root key to open.
                              Must be one of the RootKeys enum values.
        :param sam_desired: The desired access rights for the key.
        :param ServerName: The server name. The ServerName SHOULD be
                           sent as NULL, and MUST be ignored
                           when it is received because binding to the server
                           is already complete at this stage
        :return: The handle to the opened root key.
        """

        cls_req = {
            RootKeys.HKEY_CLASSES_ROOT: OpenClassesRoot_Request,
            RootKeys.HKEY_CURRENT_USER: OpenCurrentUser_Request,
            RootKeys.HKEY_LOCAL_MACHINE: OpenLocalMachine_Request,
            RootKeys.HKEY_USERS: OpenUsers_Request,
            RootKeys.HKEY_CURRENT_CONFIG: OpenCurrentConfig_Request,
            RootKeys.HKEY_PERFORMANCE_DATA: OpenPerformanceData_Request,
            RootKeys.HKEY_PERFORMANCE_TEXT: OpenPerformanceText_Request,
            RootKeys.HKEY_PERFORMANCE_NLSTEXT: OpenPerformanceNlsText_Request,
        }

        if root_key_name not in cls_req:
            raise ValueError(f"Unknown root key: {root_key_name}")

        return self.sr1_req(
            cls_req[root_key_name](
                ServerName=None,
                samDesired=sam_desired,
            ),
            timeout=timeout,
        ).phKey

    def get_subkey_handle(
        self,
        root_key_handle: NDRContextHandle,
        subkey_path: str,
        desired_access_rights: int = 0x2000000,  # Maximum Allowed
        options: RegOptions = RegOptions.REG_OPTION_NON_VOLATILE,
        timeout: int = 5,
    ) -> NDRContextHandle:
        """
        Get a handle to a subkey.

        :param root_key_handle: The handle to the root key.
        :param subkey_path: The name of the subkey to open.
        :param desired_access_rights: The desired access rights for the subkey.
        :param timeout: The timeout for the request.
        :return: The handle to the opened subkey.
        """

        # Ensure it is null-terminated and handle the special case of "."
        if str(subkey_path) == ".":
            subkey_path = "\x00"
        elif not str(subkey_path).endswith("\x00"):
            subkey_path = str(subkey_path) + "\x00"

        response = self.sr1_req(
            BaseRegOpenKey_Request(
                hKey=root_key_handle,
                lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
                samDesired=desired_access_rights,
                dwOptions=options,
            ),
            timeout=timeout,
        )

        if response.status != 0:
            raise ValueError(response.status)

        return response.phkResult

    def get_version(
        self,
        key_handle: NDRContextHandle,
        timeout: int = 5,
    ) -> Packet:
        """
        Get the version of the registry server.

        :param client: The DCERPC client.
        :param timeout: The timeout for the request.
        :return: The response packet containing the version information.
        """

        response = self.sr1_req(
            BaseRegGetVersion_Request(
                hKey=key_handle,
            ),
            timeout=timeout,
        )

        if response.status != 0:
            log_runtime.error(
                "Got status %s while getting version", hex(response.status)
            )

        return response

    def get_key_info(
        self,
        key_handle: NDRContextHandle,
        timeout: int = 5,
    ) -> BaseRegQueryInfoKey_Response:
        """
        Get information about a given registry key.

        :param hKey: The handle to the registry key (root key or subkey).
        :param timeout: The timeout for the request.
        :return: The response packet containing the key information.
        """

        response = self.sr1_req(
            BaseRegQueryInfoKey_Request(
                hKey=key_handle,
                lpClassIn=RPC_UNICODE_STRING(),
            ),
            timeout=timeout,
        )

        if response.status != 0:
            log_runtime.error(
                "Got status %s while querying key info", hex(response.status)
            )
            raise ValueError(response.status)

        if response.lpClassOut.Length > 2:
            # There is a Class info stored. We need to
            # get it by specifying the proper MaximumLength.
            # By default the size is "2".
            response = self.sr1_req(
                BaseRegQueryInfoKey_Request(
                    hKey=key_handle,
                    lpClassIn=RPC_UNICODE_STRING(
                        MaximumLength=response.lpClassOut.Length
                    ),
                ),
                timeout=timeout,
            )

        if response.status != 0:
            log_runtime.error(
                "Got status %s while querying key info", hex(response.status)
            )
            raise ValueError(response.status)

        return response

    def get_key_security(
        self,
        key_handle: NDRContextHandle,
        security_information: int = None,
        timeout: int = 5,
    ) -> SECURITY_DESCRIPTOR:
        """
        Get the security descriptor of a given registry key.

        :param hKey: The handle to the registry key (root key or subkey).
        :param security_information: The security information to retrieve.
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
        )

        # Send request
        response = self.sr1_req(req, timeout=timeout)
        if response.status == 0x0000007A:  # ERROR_INSUFFICIENT_BUFFER
            # The buffer was too small, we need to retry with a larger one
            req.pRpcSecurityDescriptorIn.cbInSecurityDescriptor = (
                response.pRpcSecurityDescriptorOut.cbInSecurityDescriptor
            )
            response = self.sr1_req(req, timeout=timeout)

        # Check the response status
        if response.status != 0:
            log_runtime.error(
                "Got status %s while getting security", hex(response.status)
            )
            return None

        return SECURITY_DESCRIPTOR(
            response.pRpcSecurityDescriptorOut.valueof("lpSecurityDescriptor")
        )

    def enum_subkeys(
        self,
        key_handle: NDRContextHandle,
        timeout: int = 5,
    ) -> List[str]:
        """
        Enumerate subkeys of a given registry key.

        :param hKey: The handle to the registry key (root key or subkey).
        :param timeout: The timeout for the request.
        :return: A generator yielding the responses for each enumerated subkey.
        """
        index = 0
        results = []

        while True:
            response = self.sr1_req(
                BaseRegEnumKey_Request(
                    hKey=key_handle,
                    dwIndex=index,
                    lpNameIn=RPC_UNICODE_STRING(MaximumLength=1024),
                    lpClassIn=RPC_UNICODE_STRING(),
                    lpftLastWriteTime=None,
                ),
                timeout=timeout,
            )

            # Send request
            if response.status == 0x00000103:  # ERROR_NO_MORE_ITEMS
                break
            # Check the response status
            elif response.status != 0:
                raise ValueError(response.status)

            index += 1
            results.append(response.lpNameOut.valueof("Buffer")[:-1].decode())
        return results

    def enum_values(
        self,
        key_handle: NDRContextHandle,
        timeout: int = 5,
    ) -> List[RegEntry]:
        """
        Enumerate values of a given registry key.

        :param hKey: The handle to the registry key (root key or subkey).
        :param timeout: The timeout for the request.
        :return: A generator yielding the responses for each enumerated value.
        """
        index = 0
        results = []

        while True:
            # Get the name and value at index `index`
            response = self.sr1_req(
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
                ),
                timeout=timeout,
            )

            if response.status == 0x00000103:  # ERROR_NO_MORE_ITEMS
                break
            elif response.status != 0:
                raise ValueError(response.status)

            # Get the value name
            lpValueName = response.valueof("lpValueNameOut")

            # Get value content
            req = BaseRegQueryValue_Request(
                hKey=key_handle,
                lpValueName=lpValueName,
                lpType=0,
                lpcbData=1024,
                lpcbLen=0,
                lpData=NDRPointer(
                    value=NDRConformantArray(
                        max_count=1024,
                        value=NDRVaryingArray(actual_count=0, value=b""),
                    )
                ),
            )

            # Send request
            response = self.sr1_req(req, timeout=timeout)
            if response.status == 0x000000EA:  # ERROR_MORE_DATA
                # The buffer was too small, we need to retry with a larger one
                req.lpcbData = response.lpcbData
                req.lpData.value.max_count = response.lpcbData.value
                response = self.sr1_req(req, timeout=timeout)

            # Check the response status
            elif response.status != 0:
                raise ValueError(response.status)

            index += 1
            results.append(
                RegEntry.frombytes(
                    lpValueName.valueof("Buffer")[:-1].decode(),
                    response.valueof("lpType"),
                    response.valueof("lpData"),
                )
            )

        return results

    def get_value(
        self,
        key_handle: NDRContextHandle,
        value_name: str,
        timeout: int = 5,
    ) -> RegEntry:
        """
        Get the value of a given registry key.

        :param hKey: The handle to the registry key (root key or subkey).
        :param value_name: The name of the value to retrieve.
        :param timeout: The timeout for the request.
        :return: The response packet containing the value data.
        """

        pkt = BaseRegQueryValue_Request(
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
        )

        response = self.sr1_req(pkt, timeout=timeout)

        if response.status == 0x000000EA:  # ERROR_MORE_DATA
            # The buffer was too small, we need to retry with a larger one
            pkt.lpcbData = response.lpcbData
            pkt.lpData.value.max_count = response.lpcbData.value
            response = self.sr1_req(pkt, timeout=timeout)

        if response.status != 0:
            raise ValueError(response.status)

        return RegEntry.frombytes(
            value_name,
            response.valueof("lpType"),
            response.valueof("lpData"),
        )

    def save_subkey(
        self,
        key_handle: NDRContextHandle,
        file_path: str,
        security_attributes: PRPC_SECURITY_ATTRIBUTES = None,
        timeout: int = 5,
    ) -> None:
        """
        Save a given registry key to a file.

        :param hKey: The handle to the registry key (root key or subkey).
        :param file_path: The path to the file where the key will be saved.
            Default path is %WINDIR%\\System32, which is readable by all users.
        :param security_attributes: Security attributes for the saved key.
        :param timeout: The timeout for the request.
        """

        response = self.sr1_req(
            BaseRegSaveKey_Request(
                hKey=key_handle,
                lpFile=RPC_UNICODE_STRING(Buffer=file_path),
                pSecurityAttributes=security_attributes,
            ),
            timeout=timeout,
        )

        if response.status != 0:
            raise ValueError(response.status)

    def set_value(
        self,
        key_handle: NDRContextHandle,
        entry: RegEntry,
        timeout: int = 5,
    ) -> None:
        """
        Set a given value for a registry key.

        :param hKey: The handle to the registry key (root key or subkey).
        :param entry: The 'RegEntry' entry to set, containing the name, type and data
            of the value.
        :param timeout: The timeout for the request.
        """
        data = entry.encode()

        response = self.sr1_req(
            BaseRegSetValue_Request(
                hKey=key_handle,
                lpValueName=RPC_UNICODE_STRING(
                    Buffer=entry.reg_name.encode("utf-8") + b"\x00"
                ),
                dwType=entry.reg_type.value,
                cbData=len(data),
                lpData=data,
            ),
            timeout=timeout,
        )

        if response.status != 0:
            raise ValueError(response.status)

    def create_subkey(
        self,
        root_key_handle: NDRContextHandle,
        subkey_path: str,
        desired_access_rights: int = 0x2000000,  # Maximum allowed
        options: RegOptions = RegOptions.REG_OPTION_NON_VOLATILE,
        security_attributes: PRPC_SECURITY_ATTRIBUTES = None,
        timeout: int = 5,
    ) -> NDRContextHandle:
        """
        Create a given subkey under a registry key.

        :param client: The DCERPC client.
        :param root_key_handle: The handle to the root key.
        :param subkey_path: The name of the subkey to create.
        :param desired_access_rights: The desired access rights for the subkey.
        :param options: The options for the subkey.
        :param security_attributes: Security attributes for the created key.
        :param timeout: The timeout for the request.
        :return: The handle to the created subkey.
        """

        if not str(subkey_path).endswith("\x00"):
            subkey_path = str(subkey_path) + "\x00"

        response = self.sr1_req(
            BaseRegCreateKey_Request(
                hKey=root_key_handle,
                lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
                samDesired=desired_access_rights,
                dwOptions=options,
                lpSecurityAttributes=security_attributes,
            ),
            timeout=timeout,
        )

        if response.status != 0:
            raise ValueError(response.status)

        return response.phkResult

    def delete_subkey(
        self,
        root_key_handle: NDRContextHandle,
        subkey_path: str,
        timeout: int = 5,
    ) -> None:
        """
        Delete a given subkey from a registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the root key.
        :param subkey_path: The name of the subkey to remove.
        :param timeout: The timeout for the request.
        """

        if not str(subkey_path).endswith("\x00"):
            subkey_path = str(subkey_path) + "\x00"

        response = self.sr1_req(
            BaseRegDeleteKey_Request(
                hKey=root_key_handle,
                lpSubKey=RPC_UNICODE_STRING(Buffer=subkey_path),
            ),
            timeout=timeout,
        )

        if response.status != 0:
            raise ValueError(response.status)

    def delete_value(
        self,
        key_handle: NDRContextHandle,
        value_name: str,
        timeout: int = 5,
    ) -> None:
        """
        Delete a given value from a registry key.

        :param client: The DCERPC client.
        :param hKey: The handle to the subkey to remove.
        :param value_name: The name of the value to delete.
        :param timeout: The timeout for the request.
        """

        if not str(value_name).endswith("\x00"):
            value_name = str(value_name) + "\x00"

        response = self.sr1_req(
            BaseRegDeleteValue_Request(
                hKey=key_handle,
                lpValueName=RPC_UNICODE_STRING(Buffer=value_name),
            ),
            timeout=timeout,
        )

        if response.status != 0:
            raise ValueError(response.status)

    def close_key(
        self,
        key_handle: NDRContextHandle,
        timeout: int = 5,
    ) -> None:
        """
        Close a given registry key handle.

        :param client: The DCERPC client.
        :param hKey: The handle to the registry key (root key or subkey).
        :param timeout: The timeout for the request.
        """

        response = self.sr1_req(
            BaseRegCloseKey_Request(
                hKey=key_handle,
            ),
            timeout=timeout,
        )

        if response.status != 0:
            raise ValueError(response.status)
