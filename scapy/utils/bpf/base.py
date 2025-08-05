# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Base classes for BPF filter builders.

This module provides the foundational classes that can be extended 
for protocol-specific BPF filter builders.
"""

from typing import List
from abc import ABC, abstractmethod


class BPFBuilder(ABC):
    """
    Abstract base class for BPF filter builders.
    
    This class provides the common interface and basic functionality
    that all BPF builders should implement.
    """
    
    def __init__(self):
        self.conditions: List[List[str]] = []
        self.current_condition: List[str] = []
    
    @abstractmethod
    def build(self) -> str:
        """
        Build the final BPF filter string.
        
        Returns:
            str: The constructed BPF filter expression.
        """
        pass
    
    def raw_condition(self, condition: str) -> 'BPFBuilder':
        """
        Add a raw BPF condition string (escape hatch).
        
        Args:
            condition: Raw BPF condition to add
            
        Returns:
            Self for method chaining
        """
        self.current_condition.append(f"({condition})")
        return self
    
    def and_(self) -> 'BPFBuilder':
        """
        Explicitly add AND operator.
        
        Returns:
            Self for method chaining
        """
        if self.current_condition:
            self.current_condition.append('and')
        return self
    
    def or_(self) -> 'BPFBuilder':
        """
        Finish current condition group and prepare for OR with next group.
        
        Returns:
            Self for method chaining
        """
        if self.current_condition:
            self.conditions.append(self.current_condition.copy())
            self.current_condition.clear()
        return self
