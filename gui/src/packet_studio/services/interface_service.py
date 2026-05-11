from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class InterfaceRecord:
    name: str
    description: str
    networkName: str
    mac: str
    ipv4: str
    ipv6: str
    provider: str
    isValid: bool
    flags: str
    index: int

    @property
    def isLoopback(self) -> bool:
        loweredName = self.name.lower()
        loweredDescription = self.description.lower()
        loweredNetworkName = self.networkName.lower()
        return (
            "loopback" in loweredName
            or "loopback" in loweredDescription
            or "loopback" in loweredNetworkName
        )

    @property
    def capabilityTags(self) -> list[str]:
        tags = []
        if self.isValid:
            tags.append("可用")
        else:
            tags.append("不可用")
        if self.isLoopback:
            tags.append("回环")
        if self.ipv4:
            tags.append("IPv4")
        if self.ipv6:
            tags.append("IPv6")
        if self.mac:
            tags.append("L2")
        if self.provider:
            tags.append(self.provider)
        return tags

    @property
    def capabilitySummary(self) -> str:
        return " / ".join(self.capabilityTags)


class InterfaceService:
    """封装 Scapy 接口发现流程。"""

    def loadInterfaces(self) -> List[InterfaceRecord]:
        import scapy.all as scapy  # noqa: F401
        from scapy.config import conf
        from scapy.interfaces import get_working_ifaces

        conf.ifaces.reload()
        interfaces = get_working_ifaces()
        records = []
        for interface in interfaces:
            ipv4 = interface.ip or ""
            ipv6 = ", ".join(interface.ips[6]) if interface.ips[6] else ""
            records.append(
                InterfaceRecord(
                    name=interface.name or interface.description or interface.network_name,
                    description=interface.description or interface.name,
                    networkName=interface.network_name,
                    mac=interface.mac or "",
                    ipv4=ipv4,
                    ipv6=ipv6,
                    provider=interface.provider.name,
                    isValid=interface.is_valid(),
                    flags=str(getattr(interface, "flags", "")),
                    index=int(interface.index),
                )
            )
        records.sort(key=lambda interfaceRecord: interfaceRecord.name.lower())
        return records