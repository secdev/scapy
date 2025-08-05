# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
WiFi BPF Filter Builder for 802.11 packet filtering.

This module provides a structured, type-safe way to build BPF filter
expressions for WiFi/802.11 packet capture and filtering.
"""

from typing import Optional, Union, Sequence
from scapy.utils.bpf.base import BPFBuilder
from scapy.utils.bpf.constants import (
    FrameType, ManagementSubtype, ControlSubtype, DataSubtype,
    WiFiField, DSFlags, WiFiConstants,
    FRAME_TYPE_STRINGS, MANAGEMENT_SUBTYPE_STRINGS, 
    CONTROL_SUBTYPE_STRINGS, ADDR_FIELD_STRINGS
)


class WiFiBPFBuilder(BPFBuilder):
    """
    Builder for creating WiFi BPF filter expressions.
    
    Provides a fluent API for constructing 802.11 BPF filters with proper
    syntax validation and type safety.
    
    Example:
        Basic beacon filtering:
        >>> builder = WiFiBPFBuilder("aa:bb:cc:dd:ee:ff")
        >>> filter_str = builder.beacon_frames().build()
        
        Complex management frame filtering:
        >>> filter_str = (WiFiBPFBuilder("aa:bb:cc:dd:ee:ff")
        ...                .management_frames()
        ...                .multiple_subtypes([ManagementSubtype.BEACON,
        ...                                  ManagementSubtype.PROBE_RESPONSE])
        ...                .from_ap()
        ...                .build())
        
        Data frames with DS flags:
        >>> filter_str = (WiFiBPFBuilder("aa:bb:cc:dd:ee:ff")
        ...                .data_frames()
        ...                .ds_flags(to_ds=False, from_ds=True)
        ...                .build())
    """
    
    def __init__(self, target_bssid: str):
        """
        Initialize WiFi BPF builder with target BSSID.
        
        Args:
            target_bssid: MAC address of the target BSS (e.g., "aa:bb:cc:dd:ee:ff")
        """
        super().__init__()
        self.target_bssid = target_bssid.lower()
        self._base_filter_added = False
    
    def _ensure_base_filter(self) -> 'WiFiBPFBuilder':
        """Ensure the base BSSID filter is always present."""
        if not self._base_filter_added:
            self.current_condition.extend([
                'wlan', ADDR_FIELD_STRINGS[WiFiField.ADDR3], self.target_bssid
            ])
            self._base_filter_added = True
        return self
    
    def frame_type(self, frame_type: FrameType) -> 'WiFiBPFBuilder':
        """
        Add frame type filter.
        
        Args:
            frame_type: The 802.11 frame type to filter for
            
        Returns:
            Self for method chaining
        """
        self.current_condition.extend([
            'wlan', 'type', FRAME_TYPE_STRINGS[frame_type]
        ])
        return self
    
    def management_frames(self) -> 'WiFiBPFBuilder':
        """
        Add management frame type filter.
        
        Returns:
            Self for method chaining
        """
        return self.frame_type(FrameType.MANAGEMENT)
    
    def data_frames(self) -> 'WiFiBPFBuilder':
        """
        Add data frame type filter.
        
        Returns:
            Self for method chaining
        """
        return self.frame_type(FrameType.DATA)
    
    def control_frames(self) -> 'WiFiBPFBuilder':
        """
        Add control frame type filter.
        
        Returns:
            Self for method chaining
        """
        return self.frame_type(FrameType.CONTROL)
    
    def subtype(self, subtype: Union[ManagementSubtype, ControlSubtype, DataSubtype]) -> 'WiFiBPFBuilder':
        """
        Add subtype filter.
        
        Args:
            subtype: The frame subtype to filter for
            
        Returns:
            Self for method chaining
        """
        # Determine subtype string based on type
        if isinstance(subtype, ManagementSubtype):
            subtype_str = MANAGEMENT_SUBTYPE_STRINGS.get(subtype, str(subtype.value))
        elif isinstance(subtype, ControlSubtype):
            subtype_str = CONTROL_SUBTYPE_STRINGS.get(subtype, str(subtype.value))
        else:
            # DataSubtype or unknown - use numeric value
            subtype_str = str(subtype.value)
            
        self.current_condition.extend(['wlan', 'subtype', subtype_str])
        return self
    
    def beacon_frames(self) -> 'WiFiBPFBuilder':
        """
        Add beacon frame filter (management + beacon subtype).
        
        Returns:
            Self for method chaining
        """
        return self.management_frames().subtype(ManagementSubtype.BEACON)
    
    def probe_request_frames(self) -> 'WiFiBPFBuilder':
        """
        Add probe request frame filter.
        
        Returns:
            Self for method chaining
        """
        return self.management_frames().subtype(ManagementSubtype.PROBE_REQUEST)
    
    def probe_response_frames(self) -> 'WiFiBPFBuilder':
        """
        Add probe response frame filter.
        
        Returns:
            Self for method chaining
        """
        return self.management_frames().subtype(ManagementSubtype.PROBE_RESPONSE)
    
    def qos_data_frames(self) -> 'WiFiBPFBuilder':
        """
        Add QoS data frame filter.
        
        Returns:
            Self for method chaining
        """
        return self.data_frames().subtype(DataSubtype.QOS_DATA)
    
    def ack_frames(self) -> 'WiFiBPFBuilder':
        """
        Add ACK frame filter.
        
        Returns:
            Self for method chaining
        """
        return self.control_frames().subtype(ControlSubtype.ACK)
    
    def multiple_subtypes(self, subtypes: Sequence[Union[ManagementSubtype, ControlSubtype, DataSubtype]]) -> 'WiFiBPFBuilder':
        """
        Add multiple subtype filters with OR logic.
        
        Args:
            subtypes: List of subtypes to filter for
            
        Returns:
            Self for method chaining
        """
        if len(subtypes) == 1:
            return self.subtype(subtypes[0])
        
        subtype_conditions = []
        for i, subtype in enumerate(subtypes):
            # Get subtype string
            if isinstance(subtype, ManagementSubtype):
                subtype_str = MANAGEMENT_SUBTYPE_STRINGS.get(subtype, str(subtype.value))
            elif isinstance(subtype, ControlSubtype):
                subtype_str = CONTROL_SUBTYPE_STRINGS.get(subtype, str(subtype.value))
            else:
                subtype_str = str(subtype.value)
                
            subtype_conditions.extend(['wlan', 'subtype', subtype_str])
            if i < len(subtypes) - 1:
                subtype_conditions.append('or')
                
        self.current_condition.append(f"({' '.join(subtype_conditions)})")
        return self
    
    def from_ap(self) -> 'WiFiBPFBuilder':
        """
        Add source address filter (addr2 = target BSSID).
        
        Returns:
            Self for method chaining
        """
        self.current_condition.extend([
            'wlan', ADDR_FIELD_STRINGS[WiFiField.ADDR2], self.target_bssid
        ])
        return self
    
    def to_ap(self) -> 'WiFiBPFBuilder':
        """
        Add destination address filter (addr1 = target BSSID).
        
        Returns:
            Self for method chaining
        """
        self.current_condition.extend([
            'wlan', ADDR_FIELD_STRINGS[WiFiField.ADDR1], self.target_bssid
        ])
        return self
    
    def ds_flags(self, to_ds: Optional[bool] = None, from_ds: Optional[bool] = None) -> 'WiFiBPFBuilder':
        """
        Add DS flags filter using constants.
        
        Args:
            to_ds: To-DS flag value (None to ignore)
            from_ds: From-DS flag value (None to ignore)
            
        Returns:
            Self for method chaining
        """
        if to_ds is not None or from_ds is not None:
            if to_ds is False and from_ds is False:
                flag_value = DSFlags.TO_DS_0_FROM_DS_0
            elif to_ds is False and from_ds is True:
                flag_value = DSFlags.TO_DS_0_FROM_DS_1
            elif to_ds is True and from_ds is False:
                flag_value = DSFlags.TO_DS_1_FROM_DS_0
            elif to_ds is True and from_ds is True:
                flag_value = DSFlags.TO_DS_1_FROM_DS_1
            else:
                return self
                
            self.current_condition.extend([
                f'wlan[{WiFiConstants.FRAME_CONTROL_BYTE_1}]',
                '&',
                f'0x{WiFiConstants.DS_FLAGS_MASK:02x}',
                '=',
                f'0x{flag_value:02x}'
            ])
        return self
    
    def from_ds_flag(self, enabled: bool) -> 'WiFiBPFBuilder':
        """
        Add FromDS flag filter.
        
        Args:
            enabled: True if FromDS should be set, False otherwise
            
        Returns:
            Self for method chaining
        """
        operator = '!=' if enabled else '='
        
        self.current_condition.extend([
            f'wlan[{WiFiConstants.FRAME_CONTROL_BYTE_1}]',
            '&',
            f'0x{WiFiConstants.FROM_DS_MASK:02x}',
            operator,
            '0'
        ])
        return self
    
    def to_ds_flag(self, enabled: bool) -> 'WiFiBPFBuilder':
        """
        Add ToDS flag filter.
        
        Args:
            enabled: True if ToDS should be set, False otherwise
            
        Returns:
            Self for method chaining
        """
        operator = '!=' if enabled else '='
        
        self.current_condition.extend([
            f'wlan[{WiFiConstants.FRAME_CONTROL_BYTE_1}]',
            '&',
            f'0x{WiFiConstants.TO_DS_MASK:02x}',
            operator,
            '0'
        ])
        return self
    
    def retry_flag(self, enabled: bool) -> 'WiFiBPFBuilder':
        """
        Add retry flag filter.
        
        Args:
            enabled: True if retry flag should be set, False otherwise
            
        Returns:
            Self for method chaining
        """
        operator = '!=' if enabled else '='
        
        self.current_condition.extend([
            f'wlan[{WiFiConstants.FRAME_CONTROL_BYTE_1}]',
            '&',
            f'0x{WiFiConstants.RETRY_FLAG_MASK:02x}',
            operator,
            '0'
        ])
        return self
    
    def protected_frame(self, enabled: bool) -> 'WiFiBPFBuilder':
        """
        Add protected frame flag filter.
        
        Args:
            enabled: True if protected flag should be set, False otherwise
            
        Returns:
            Self for method chaining
        """
        operator = '!=' if enabled else '='
        
        self.current_condition.extend([
            f'wlan[{WiFiConstants.FRAME_CONTROL_BYTE_1}]',
            '&',
            f'0x{WiFiConstants.PROTECTED_MASK:02x}',
            operator,
            '0'
        ])
        return self
    
    def frame_control_raw(self, mask: int, value: int, operator: str = '=') -> 'WiFiBPFBuilder':
        """
        Add raw frame control filter with custom mask and value.
        
        Args:
            mask: Bitmask to apply
            value: Value to compare against
            operator: Comparison operator ('=', '!=', etc.)
            
        Returns:
            Self for method chaining
        """
        self.current_condition.extend([
            f'wlan[{WiFiConstants.FRAME_CONTROL_BYTE_0}]',
            '&',
            f'0x{mask:02x}',
            operator,
            f'0x{value:02x}'
        ])
        return self
    
    def beacon_frame_direct(self) -> 'WiFiBPFBuilder':
        """
        Direct beacon frame filter using frame control constants.
        
        Returns:
            Self for method chaining
        """
        return self.frame_control_raw(
            WiFiConstants.TYPE_SUBTYPE_MASK, 
            WiFiConstants.BEACON_FRAME
        )
    
    def or_(self) -> 'WiFiBPFBuilder':
        """
        Finish current condition group and prepare for OR with next group.
        
        Returns:
            Self for method chaining
        """
        if self.current_condition:
            self.conditions.append(self.current_condition.copy())
            self.current_condition.clear()
            self._base_filter_added = False
        return self
    
    def build(self) -> str:
        """
        Build the final BPF filter string.
        
        Returns:
            str: The constructed BPF filter expression
        """
        self._ensure_base_filter()
        
        if self.current_condition:
            self.conditions.append(self.current_condition.copy())
        
        if not self.conditions:
            return f'wlan {ADDR_FIELD_STRINGS[WiFiField.ADDR3]} {self.target_bssid}'
        
        # Build condition strings, filtering out redundant base BSSID filters
        condition_strings = []
        for condition_group in self.conditions:
            # Remove base BSSID filter from individual groups to avoid duplication
            filtered_group = []
            i = 0
            while i < len(condition_group):
                if (i + 2 < len(condition_group) and 
                    condition_group[i] == 'wlan' and
                    condition_group[i + 1] == ADDR_FIELD_STRINGS[WiFiField.ADDR3] and
                    condition_group[i + 2] == self.target_bssid):
                    # Skip the base BSSID filter
                    i += 3
                else:
                    filtered_group.append(condition_group[i])
                    i += 1
            
            if filtered_group:
                condition_strings.append(' '.join(filtered_group))
        
        if len(condition_strings) == 1:
            return f'wlan {ADDR_FIELD_STRINGS[WiFiField.ADDR3]} {self.target_bssid} and {condition_strings[0]}'
        else:
            or_conditions = ' or '.join(f'({cond})' for cond in condition_strings)
            return f'wlan {ADDR_FIELD_STRINGS[WiFiField.ADDR3]} {self.target_bssid} and ({or_conditions})'
