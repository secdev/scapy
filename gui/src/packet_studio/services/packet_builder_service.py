from __future__ import annotations

import ast
import importlib
import json
import pkgutil
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from packet_studio.adapters.scapy_packet_adapter import ScapyPacketAdapter


@dataclass(frozen=True)
class AvailableLayer:
    key: str
    label: str
    packetClassName: str
    category: str


@dataclass(frozen=True)
class LayerFieldRecord:
    name: str
    fieldType: str
    defaultValue: str
    currentValue: str
    editorKind: str
    choices: Tuple[Tuple[str, str], ...] = ()
    placeholderText: str = ""
    collectionKind: str = ""


@dataclass(frozen=True)
class LayerRecord:
    index: int
    name: str
    summary: str


class PacketBuilderService:
    """最小包构建器服务。"""

    CATEGORY_COMMON = "常用层"
    CATEGORY_WIRELESS = "无线与近场"
    CATEGORY_INDUSTRIAL = "工业与企业"
    CATEGORY_CONTRIB = "Contrib 扩展"
    CATEGORY_OTHER = "其他"
    CATEGORY_ORDER: Tuple[str, ...] = (
        CATEGORY_COMMON,
        CATEGORY_WIRELESS,
        CATEGORY_INDUSTRIAL,
        CATEGORY_CONTRIB,
        CATEGORY_OTHER,
    )

    _COMMON_MODULE_NAMES: Tuple[str, ...] = (
        "inet",
        "inet6",
        "l2",
        "dns",
        "dhcp",
        "dhcp6",
        "http",
        "tls",
        "quic",
        "sctp",
        "vxlan",
        "ntp",
        "rip",
        "ppp",
        "tftp",
        "radius",
        "l2tp",
        "isakmp",
    )
    _WIRELESS_MODULE_NAMES: Tuple[str, ...] = (
        "bluetooth",
        "dot11",
        "zigbee",
        "dot15d4",
        "sixlowpan",
        "nfc",
        "ubertooth",
    )
    _INDUSTRIAL_MODULE_NAMES: Tuple[str, ...] = (
        "netflow",
        "ldap",
        "kerberos",
        "smb",
        "smb2",
        "dcerpc",
        "gssapi",
        "ntlm",
        "msrpce",
        "pnio",
        "modbus",
        "tacacs",
    )

    _LEGACY_LAYER_DEFINITIONS: Tuple[Tuple[str, str, str], ...] = (
        ("ether", "Ethernet", "Ether"),
        ("arp", "ARP", "ARP"),
        ("ip", "IPv4", "IP"),
        ("ipv6", "IPv6", "IPv6"),
        ("tcp", "TCP", "TCP"),
        ("udp", "UDP", "UDP"),
        ("icmp", "ICMP", "ICMP"),
        ("dns", "DNS", "DNS"),
        ("dot1q", "802.1Q VLAN", "Dot1Q"),
        ("dot1ad", "802.1ad QinQ", "Dot1AD"),
        ("mac_pause", "802.3x Pause Frame", "MACControlPause"),
        ("mac_gate", "802.3 Gate Control", "MACControlGate"),
        ("mac_report", "802.3 Report Control", "MACControlReport"),
        ("mac_register_req", "802.3 Register Request", "MACControlRegisterReq"),
        ("mac_register", "802.3 Register", "MACControlRegister"),
        ("mac_register_ack", "802.3 Register Acknowledge", "MACControlRegisterAck"),
        (
            "mac_pfc",
            "802.1Qbb Priority Flow Control",
            "MACControlClassBasedFlowControl",
        ),
        ("raw", "Raw Payload", "Raw"),
    )

    _DISCOVERY_PACKAGE_NAMES: Tuple[str, ...] = ("scapy.layers", "scapy.contrib")
    _DISCOVERY_MODULE_PREFIXES: Tuple[str, ...] = ("scapy.layers.", "scapy.contrib.")
    _EXCLUDED_PACKET_CLASS_NAMES: Tuple[str, ...] = (
        "Packet",
        "NoPayload",
        "Padding",
        "ASN1_Packet",
        "MACControl",
    )

    _COMMON_ETHER_TYPE_CHOICES: Tuple[Tuple[int, str], ...] = (
        (0x0800, "IPv4"),
        (0x0806, "ARP"),
        (0x86DD, "IPv6"),
        (0x8100, "802.1Q VLAN"),
        (0x88A8, "802.1ad QinQ"),
        (0x8808, "Ethernet PAUSE"),
        (0x8809, "Slow Protocols"),
        (0x8847, "MPLS Unicast"),
        (0x8848, "MPLS Multicast"),
        (0x8863, "PPPoE Discovery"),
        (0x8864, "PPPoE Session"),
        (0x88CC, "LLDP"),
        (0x88E5, "MACsec"),
        (0x88F7, "PTP"),
    )

    def __init__(self) -> None:
        import scapy.all as scapy
        from scapy.packet import Packet
        from scapy.layers.inet import (
            IPOption_EOL,
            IPOption_LSRR,
            IPOption_NOP,
            IPOption_RR,
            IPOption_Router_Alert,
            IPOption_SSRR,
            IPOption_Security,
            IPOption_Timestamp,
        )
        from scapy.contrib.mac_control import (
            MACControlGate,
            MACControlClassBasedFlowControl,
            MACControlPause,
            MACControlRegister,
            MACControlRegisterAck,
            MACControlRegisterReq,
            MACControlReport,
        )

        self._scapy = scapy
        self._packetBaseClass = Packet
        self._availableLayerTypes: Dict[str, Callable[[], Any]] = {}
        self._availableLayerClasses: Dict[str, type[Any]] = {}
        self._availableLayers: List[AvailableLayer] = []
        self._layerKeysByClass: Dict[type[Any], str] = {}

        legacyLayerClasses: Dict[str, type[Any]] = {
            "Ether": scapy.Ether,
            "ARP": scapy.ARP,
            "IP": scapy.IP,
            "IPv6": scapy.IPv6,
            "TCP": scapy.TCP,
            "UDP": scapy.UDP,
            "ICMP": scapy.ICMP,
            "DNS": scapy.DNS,
            "Dot1Q": scapy.Dot1Q,
            "Dot1AD": scapy.Dot1AD,
            "MACControlPause": MACControlPause,
            "MACControlGate": MACControlGate,
            "MACControlReport": MACControlReport,
            "MACControlRegisterReq": MACControlRegisterReq,
            "MACControlRegister": MACControlRegister,
            "MACControlRegisterAck": MACControlRegisterAck,
            "MACControlClassBasedFlowControl": MACControlClassBasedFlowControl,
            "Raw": scapy.Raw,
        }

        for key, label, className in self._LEGACY_LAYER_DEFINITIONS:
            self._registerAvailableLayer(key, label, legacyLayerClasses[className])

        self._loadOptionalProtocolModules()
        self._registerDiscoveredLayers()
        self._layers: List[Any] = []
        self._ipOptionFactories: Dict[str, Callable[..., Any]] = {
            "NOP": IPOption_NOP,
            "EOL": IPOption_EOL,
            "RR": IPOption_RR,
            "LSRR": IPOption_LSRR,
            "SSRR": IPOption_SSRR,
            "Timestamp": IPOption_Timestamp,
            "RouterAlert": IPOption_Router_Alert,
            "Security": IPOption_Security,
        }
        self._packetAdapter = ScapyPacketAdapter()

    def listAvailableLayers(self) -> List[AvailableLayer]:
        return list(self._availableLayers)

    def listAvailableLayerCategories(self) -> List[str]:
        presentCategories = {layer.category for layer in self._availableLayers}
        return [category for category in self.CATEGORY_ORDER if category in presentCategories]

    def _registerAvailableLayer(
        self,
        key: str,
        label: str,
        packetType: type[Any],
    ) -> None:
        if packetType in self._layerKeysByClass:
            return

        self._availableLayerTypes[key] = packetType
        self._availableLayerClasses[key] = packetType
        category = self._categorizePacketType(packetType)
        self._availableLayers.append(AvailableLayer(key, label, packetType.__name__, category))
        self._layerKeysByClass[packetType] = key

    def _loadOptionalProtocolModules(self) -> None:
        for packageName in self._DISCOVERY_PACKAGE_NAMES:
            self._importProtocolModules(packageName)

    def _importProtocolModules(self, packageName: str) -> None:
        try:
            package = importlib.import_module(packageName)
        except Exception:
            return

        packagePath = getattr(package, "__path__", None)
        if packagePath is None:
            return

        moduleNames = sorted(
            moduleInfo.name
            for moduleInfo in pkgutil.walk_packages(packagePath, prefix=packageName + ".")
        )

        for moduleName in moduleNames:
            if moduleName.endswith(".__main__"):
                continue
            try:
                importlib.import_module(moduleName)
            except Exception:
                continue

    def _registerDiscoveredLayers(self) -> None:
        discoveredPacketTypes = sorted(
            self._iterDiscoveredPacketTypes(),
            key=lambda packetType: (packetType.__module__, packetType.__name__),
        )

        for packetType in discoveredPacketTypes:
            if not self._shouldExposePacketType(packetType):
                continue
            if packetType in self._layerKeysByClass:
                continue

            key = self._buildUniqueLayerKey(packetType)
            label = self._buildLayerLabel(packetType)
            self._registerAvailableLayer(key, label, packetType)

        legacyKeys = {key for key, _, _ in self._LEGACY_LAYER_DEFINITIONS}
        legacyLayers = [layer for layer in self._availableLayers if layer.key in legacyKeys]
        discoveredLayers = [layer for layer in self._availableLayers if layer.key not in legacyKeys]
        discoveredLayers.sort(key=lambda layer: (layer.label.casefold(), layer.packetClassName.casefold()))
        self._availableLayers = legacyLayers + discoveredLayers

    def _iterDiscoveredPacketTypes(self) -> List[type[Any]]:
        discoveredPacketTypes: Dict[str, type[Any]] = {}

        for module in list(sys.modules.values()):
            moduleName = getattr(module, "__name__", "")
            if not moduleName.startswith(self._DISCOVERY_MODULE_PREFIXES):
                continue

            moduleDictionary = getattr(module, "__dict__", None)
            if not isinstance(moduleDictionary, dict):
                continue

            for value in moduleDictionary.values():
                if not isinstance(value, type):
                    continue
                if not issubclass(value, self._packetBaseClass):
                    continue
                discoveredPacketTypes[f"{value.__module__}.{value.__name__}"] = value

        return list(discoveredPacketTypes.values())

    def _shouldExposePacketType(self, packetType: type[Any]) -> bool:
        if packetType.__name__ in self._EXCLUDED_PACKET_CLASS_NAMES:
            return False
        if packetType.__name__.startswith("_"):
            return False
        if packetType.__module__ == "scapy.packet":
            return packetType is self._scapy.Raw
        if not packetType.__module__.startswith(self._DISCOVERY_MODULE_PREFIXES):
            return False

        try:
            packetType()
        except Exception:
            return False

        return True

    def _buildUniqueLayerKey(self, packetType: type[Any]) -> str:
        baseKey = self._normalizeLayerKey(packetType.__name__)
        if baseKey not in self._availableLayerTypes:
            return baseKey

        moduleParts = [
            self._normalizeLayerKey(part)
            for part in packetType.__module__.split(".")
            if part and part not in {"scapy", "layers", "contrib"}
        ]
        for modulePart in reversed(moduleParts):
            candidate = f"{baseKey}_{modulePart}"
            if candidate not in self._availableLayerTypes:
                return candidate

        suffix = 2
        while True:
            candidate = f"{baseKey}_{suffix}"
            if candidate not in self._availableLayerTypes:
                return candidate
            suffix += 1

    def _buildLayerLabel(self, packetType: type[Any]) -> str:
        className = packetType.__name__
        rawDisplayName = getattr(packetType, "name", "")
        displayName = rawDisplayName.strip() if isinstance(rawDisplayName, str) else ""
        if not displayName or displayName == className:
            return className
        return f"{displayName} ({className})"

    def _categorizePacketType(self, packetType: type[Any]) -> str:
        if packetType in self._layerKeysByClass:
            existingKey = self._layerKeysByClass[packetType]
            legacyKeys = {key for key, _, _ in self._LEGACY_LAYER_DEFINITIONS}
            if existingKey in legacyKeys:
                return self.CATEGORY_COMMON

        moduleName = packetType.__module__
        moduleParts = moduleName.split(".")
        moduleLeaf = moduleParts[-1] if moduleParts else ""

        if moduleName.startswith("scapy.contrib."):
            return self.CATEGORY_CONTRIB
        if moduleLeaf in self._WIRELESS_MODULE_NAMES:
            return self.CATEGORY_WIRELESS
        if moduleLeaf in self._INDUSTRIAL_MODULE_NAMES:
            return self.CATEGORY_INDUSTRIAL
        if moduleLeaf in self._COMMON_MODULE_NAMES:
            return self.CATEGORY_COMMON
        return self.CATEGORY_OTHER

    def _normalizeLayerKey(self, value: str) -> str:
        normalizedValue = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
        normalizedValue = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalizedValue)
        normalizedValue = re.sub(r"[^0-9A-Za-z]+", "_", normalizedValue).strip("_").lower()
        if not normalizedValue:
            normalizedValue = "layer"
        if normalizedValue[0].isdigit():
            normalizedValue = f"layer_{normalizedValue}"
        return normalizedValue

    def reset(self) -> None:
        self._layers = []

    def addLayer(self, key: str) -> None:
        packetFactory = self._availableLayerTypes[key]
        self._layers.append(packetFactory())

    def removeLayer(self, index: int) -> None:
        del self._layers[index]

    def moveLayer(self, sourceIndex: int, targetIndex: int) -> None:
        layer = self._layers.pop(sourceIndex)
        self._layers.insert(targetIndex, layer)

    def reorderLayers(self, sourceIndexes: List[int]) -> None:
        self._layers = [self._layers[index] for index in sourceIndexes]

    def getLayerRecords(self) -> List[LayerRecord]:
        records = []
        for index, layer in enumerate(self._layers):
            records.append(
                LayerRecord(
                    index=index,
                    name=layer.name,
                    summary=layer.summary(),
                )
            )
        return records

    def getFieldRecords(self, layerIndex: int) -> List[LayerFieldRecord]:
        layer = self._layers[layerIndex]
        records = []
        for field in layer.fields_desc:
            currentValue = layer.getfieldval(field.name)
            editorKind, choices, placeholderText, collectionKind = self._describeFieldEditor(layer, field)
            records.append(
                LayerFieldRecord(
                    name=field.name,
                    fieldType=field.__class__.__name__,
                    defaultValue=self._formatFieldValue(layer, field, field.default),
                    currentValue=self._formatFieldValue(layer, field, currentValue),
                    editorKind=editorKind,
                    choices=choices,
                    placeholderText=placeholderText,
                    collectionKind=collectionKind,
                )
            )
        return records

    def getFieldValue(self, layerIndex: int, fieldName: str) -> str:
        layer = self._layers[layerIndex]
        field = layer.get_field(fieldName)
        return self._formatFieldValue(layer, field, layer.getfieldval(fieldName))

    def getFieldNativeValue(self, layerIndex: int, fieldName: str) -> Any:
        layer = self._layers[layerIndex]
        return layer.getfieldval(fieldName)

    def exportTemplate(self) -> Dict[str, Any]:
        layers = []
        for layer in self._layers:
            layerKey = self._resolveLayerKey(layer)
            serializedFields = {}
            for fieldName, currentValue in layer.fields.items():
                defaultValue = layer.default_fields.get(fieldName)
                serializedValue = self._serializeFieldValue(layer, fieldName, currentValue)
                defaultSerializedValue = self._serializeFieldValue(layer, fieldName, defaultValue)
                if serializedValue == defaultSerializedValue:
                    continue
                serializedFields[fieldName] = serializedValue
            layers.append(
                {
                    "key": layerKey,
                    "fields": serializedFields,
                }
            )
        return {
            "version": 1,
            "layers": layers,
        }

    def importTemplate(self, payload: Dict[str, Any]) -> None:
        layers = payload.get("layers", [])
        self.reset()
        for layerDefinition in layers:
            layerKey = layerDefinition["key"]
            self.addLayer(layerKey)
            layerIndex = len(self._layers) - 1
            for fieldName, rawValue in layerDefinition.get("fields", {}).items():
                self.setSerializedFieldValue(layerIndex, fieldName, rawValue)

    def saveTemplate(self, filePath: str) -> None:
        payload = self.exportTemplate()
        Path(filePath).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def loadTemplate(self, filePath: str) -> None:
        payload = json.loads(Path(filePath).read_text(encoding="utf-8"))
        self.importTemplate(payload)

    def importPacket(self, packet: Any) -> None:
        importedLayers: List[Any] = []

        currentLayer = packet.copy()
        while currentLayer is not None and currentLayer.__class__.__name__ != "NoPayload":
            nextLayer = getattr(currentLayer, "payload", None)

            if not self._shouldSkipImportedLayer(currentLayer):
                layerCopy = currentLayer.copy()
                layerCopy.remove_payload()
                self._appendImportedLayer(importedLayers, layerCopy)

            if nextLayer is None or nextLayer.__class__.__name__ == "NoPayload":
                break
            currentLayer = nextLayer

        self._layers = importedLayers

    def _appendImportedLayer(self, importedLayers: List[Any], layer: Any) -> None:
        self._resolveLayerKey(layer)
        importedLayers.append(layer)

    def _shouldSkipImportedLayer(self, layer: Any) -> bool:
        if self._canResolveLayerKey(layer):
            return False

        payload = getattr(layer, "payload", None)
        if payload is None or payload.__class__.__name__ == "NoPayload":
            return False

        publicFields = [field for field in layer.fields_desc if not field.name.startswith("_")]
        return len(publicFields) == 0

    def setFieldValue(self, layerIndex: int, fieldName: str, rawValue: str) -> None:
        layer = self._layers[layerIndex]
        if rawValue == "":
            layer.delfieldval(fieldName)
            return

        field = layer.get_field(fieldName)
        parsedValue = self._parseFieldValue(rawValue, field.default)
        parsedValue = self._coerceFieldValue(layer, fieldName, field, parsedValue)
        layer.setfieldval(fieldName, parsedValue)

    def setSerializedFieldValue(self, layerIndex: int, fieldName: str, rawValue: Any) -> None:
        if isinstance(rawValue, str):
            self.setFieldValue(layerIndex, fieldName, rawValue)
            return

        layer = self._layers[layerIndex]
        field = layer.get_field(fieldName)
        parsedValue = self._coerceFieldValue(layer, fieldName, field, rawValue)
        layer.setfieldval(fieldName, parsedValue)

    def buildSummary(self) -> str:
        packet = self.buildPacket()
        if packet is None:
            return "尚未添加任何协议层。"
        return self._packetAdapter.buildSummary(packet)

    def buildHexdump(self) -> str:
        packet = self.buildPacket()
        if packet is None:
            return ""
        return self._packetAdapter.buildHexdump(packet)

    def buildStructureDump(self) -> str:
        packet = self.buildPacket()
        if packet is None:
            return "尚未添加任何协议层。"
        return self._packetAdapter.buildStructureDump(packet)

    def buildPacket(self) -> Optional[Any]:
        if not self._layers:
            return None

        packet = self._layers[0].copy()
        for layer in self._layers[1:]:
            packet = packet / layer.copy()
        return packet

    def _parseFieldValue(self, rawValue: str, defaultValue: Any) -> Any:
        stripped = rawValue.strip()
        if isinstance(defaultValue, bytes):
            if stripped.startswith("b'") or stripped.startswith('b"'):
                return ast.literal_eval(stripped)
            return rawValue.encode("utf-8")

        if stripped.lower() in {"true", "false"}:
            return stripped.lower() == "true"

        try:
            return ast.literal_eval(stripped)
        except Exception:
            pass

        if isinstance(defaultValue, int):
            return int(stripped, 0)

        return rawValue

    def _coerceFieldValue(
        self,
        layer: Any,
        fieldName: str,
        field: Any,
        value: Any,
    ) -> Any:
        if layer.__class__ is self._scapy.IP and fieldName == "options":
            return self._coerceIpOptionList(value)

        if layer.__class__ is self._scapy.DNS and fieldName == "qd":
            return self._coerceDnsQuestionList(value)

        return value

    def _coerceDnsQuestionList(self, value: Any) -> Any:
        if not isinstance(value, list):
            return value

        questions = []
        for item in value:
            if isinstance(item, self._scapy.DNSQR):
                questions.append(item)
                continue

            if isinstance(item, dict):
                questions.append(
                    self._scapy.DNSQR(
                        qname=item.get("qname", ""),
                        qtype=item.get("qtype", "A"),
                        qclass=item.get("qclass", "IN"),
                    )
                )
                continue

            if isinstance(item, str):
                questions.append(
                    self._scapy.DNSQR(
                        qname=item,
                        qtype="A",
                        qclass="IN",
                    )
                )
                continue

            questions.append(item)

        return questions

    def _serializeDnsQuestionList(self, value: Any) -> Any:
        if not isinstance(value, list):
            return self._valueToEditorText(value)

        questions = []
        for item in value:
            if isinstance(item, self._scapy.DNSQR):
                qname = getattr(item, "qname", b"")
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                questions.append(
                    {
                        "qname": str(qname).rstrip("."),
                        "qtype": self._dnsQuestionFieldLabel(item, "qtype", "A"),
                        "qclass": self._dnsQuestionFieldLabel(item, "qclass", "IN"),
                    }
                )
                continue

            if isinstance(item, dict):
                questions.append(
                    {
                        "qname": str(item.get("qname", "")),
                        "qtype": str(item.get("qtype", "A")),
                        "qclass": str(item.get("qclass", "IN")),
                    }
                )
                continue

            if isinstance(item, str):
                questions.append(
                    {
                        "qname": item,
                        "qtype": "A",
                        "qclass": "IN",
                    }
                )
                continue

            questions.append(self._valueToEditorText(item))

        return questions

    def _dnsQuestionFieldLabel(self, packet: Any, fieldName: str, fallback: str) -> str:
        try:
            field = packet.get_field(fieldName)
        except Exception:
            return fallback

        fieldValue = getattr(packet, fieldName, fallback)
        label = field.i2repr(packet, fieldValue)
        if isinstance(label, str) and label:
            return label
        return self._valueToEditorText(fieldValue) or fallback

    def _coerceIpOptionList(self, value: Any) -> Any:
        if not isinstance(value, list):
            return value

        options = []
        for item in value:
            if item.__class__.__name__.startswith("IPOption"):
                options.append(item)
                continue

            if isinstance(item, str):
                factory = self._ipOptionFactories.get(item)
                if factory is not None:
                    options.append(factory())
                    continue

            if isinstance(item, dict):
                optionType = str(item.get("type", "")).strip()
                factory = self._ipOptionFactories.get(optionType)
                if factory is None:
                    options.append(item)
                    continue

                optionFields = self._extractIpOptionFields(item)
                options.append(factory(**optionFields))
                continue

            options.append(item)

        return options

    def _serializeIpOptionList(self, value: Any) -> Any:
        if not isinstance(value, list):
            return self._valueToEditorText(value)

        options = []
        for item in value:
            className = item.__class__.__name__
            if className == "IPOption_NOP":
                options.append({"type": "NOP"})
            elif className == "IPOption_EOL":
                options.append({"type": "EOL"})
            elif className in {"IPOption_RR", "IPOption_LSRR", "IPOption_SSRR"}:
                options.append(
                    {
                        "type": className.removeprefix("IPOption_"),
                        "routers": list(getattr(item, "routers", [])),
                    }
                )
            elif className == "IPOption_Timestamp":
                options.append(
                    {
                        "type": "Timestamp",
                        "flg": str(getattr(item, "flg", "timestamp_only")),
                        "internet_address": str(getattr(item, "internet_address", "0.0.0.0")),
                        "timestamp": int(getattr(item, "timestamp", 0)),
                    }
                )
            elif className == "IPOption_Router_Alert":
                options.append({"type": "RouterAlert"})
            elif className == "IPOption_Security":
                options.append(
                    {
                        "type": "Security",
                        "security": int(getattr(item, "security", 0)),
                        "compartment": int(getattr(item, "compartment", 0)),
                        "handling_restrictions": int(getattr(item, "handling_restrictions", 0)),
                        "transmission_control_code": str(getattr(item, "transmission_control_code", "xxx")),
                    }
                )
            elif isinstance(item, dict):
                options.append(dict(item))
            else:
                options.append(self._valueToEditorText(item))

        return options

    def _extractIpOptionFields(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        optionFields = dict(payload)
        optionFields.pop("type", None)

        routers = optionFields.get("routers")
        if isinstance(routers, str):
            optionFields["routers"] = [router.strip() for router in routers.split(",") if router.strip()]

        if "timestamp" in optionFields:
            optionFields["timestamp"] = int(optionFields["timestamp"])
        if "pointer" in optionFields:
            optionFields["pointer"] = int(optionFields["pointer"])
        if "flg" in optionFields:
            flgValue = optionFields["flg"]
            flgMap = {
                "timestamp_only": 0,
                "timestamp_and_ip_addr": 1,
                "prespecified_ip_addr": 3,
            }
            if isinstance(flgValue, str) and flgValue in flgMap:
                optionFields["flg"] = flgMap[flgValue]
        if "security" in optionFields:
            optionFields["security"] = int(optionFields["security"])
        if "compartment" in optionFields:
            optionFields["compartment"] = int(optionFields["compartment"])
        if "handling_restrictions" in optionFields:
            optionFields["handling_restrictions"] = int(optionFields["handling_restrictions"])

        return optionFields

    def _resolveLayerKey(self, layer: Any) -> str:
        exactMatch = self._findExactLayerKey(layer)
        if exactMatch is not None:
            return exactMatch

        for key, packetType in self._availableLayerClasses.items():
            if isinstance(layer, packetType):
                return key
        raise ValueError(f"Unsupported layer type: {layer.__class__.__name__}")

    def _canResolveLayerKey(self, layer: Any) -> bool:
        try:
            self._resolveLayerKey(layer)
            return True
        except ValueError:
            return False

    def _findExactLayerKey(self, layer: Any) -> Optional[str]:
        for key, packetType in self._availableLayerClasses.items():
            if layer.__class__ is packetType:
                return key
        return None

    def _serializeFieldValue(self, layer: Any, fieldName: str, value: Any) -> Any:
        if layer.__class__ is self._scapy.IP and fieldName == "options":
            return self._serializeIpOptionList(value)

        if layer.__class__ is self._scapy.DNS and fieldName == "qd":
            return self._serializeDnsQuestionList(value)

        return self._valueToEditorText(value)

    def _describeFieldEditor(
        self,
        layer: Any,
        field: Any,
    ) -> Tuple[str, Tuple[Tuple[str, str], ...], str, str]:
        if self._isMacField(field):
            return "mac", (), "示例: 00:11:22:33:44:55", ""

        if self._isIPv4Field(field):
            return "ipv4", (), "示例: 192.168.1.10", ""

        if self._isIPv6Field(field):
            return "ipv6", (), "示例: 2001:db8::10", ""

        if self._isCollectionField(field):
            collectionKind = self._describeCollectionKind(field)
            return (
                "collection",
                (),
                "支持 Python 字面量列表/元组，例如 []、['value']。复杂 PacketList 当前优先支持清空或保持默认值。",
                collectionKind,
            )

        choices = self._extractFieldChoices(layer, field)
        if choices:
            placeholderText = ""
            if self._isEtherTypeField(layer, field):
                placeholderText = "支持 0x0800、0x86DD、0x8808 等十六进制 Ethertype。"
            return "enum", choices, placeholderText, ""

        if self._isBooleanField(field):
            return "bool", (), "", ""

        if isinstance(field.default, bytes):
            return "bytes", (), "支持直接输入文本，或输入 b'\\x00\\x01' 形式的字节串。", ""

        return "text", (), "", ""

    def _extractFieldChoices(self, layer: Any, field: Any) -> Tuple[Tuple[str, str], ...]:
        unwrappedField = self._unwrapField(field)
        mapping = getattr(unwrappedField, "i2s", None)
        choices = []
        seenKeys: set[str] = set()

        if self._isEtherTypeField(layer, field):
            for key, label in self._COMMON_ETHER_TYPE_CHOICES:
                keyText = self._formatChoiceValue(layer, field, key)
                choices.append((keyText, f"{label} ({keyText})"))
                seenKeys.add(keyText)

        if mapping:
            for key, label in mapping.items():
                keyText = self._formatChoiceValue(layer, field, key)
                if keyText in seenKeys:
                    continue
                choices.append((keyText, f"{label} ({keyText})"))
                seenKeys.add(keyText)

        return tuple(choices)

    def _formatFieldValue(self, layer: Any, field: Any, value: Any) -> str:
        if self._isEtherTypeField(layer, field) and isinstance(value, int):
            return self._formatHexValue(value)
        return self._valueToEditorText(value)

    def _formatChoiceValue(self, layer: Any, field: Any, value: Any) -> str:
        if self._isEtherTypeField(layer, field) and isinstance(value, int):
            return self._formatHexValue(value)
        return self._valueToEditorText(value)

    def _formatHexValue(self, value: int) -> str:
        return f"0x{value:04X}"

    def _isBooleanField(self, field: Any) -> bool:
        unwrappedField = self._unwrapField(field)
        if type(unwrappedField.default) is bool:
            return True

        size = getattr(unwrappedField, "size", None)
        return (
            size == 1
            and unwrappedField.default in {0, 1}
            and not getattr(unwrappedField, "i2s", None)
        )

    def _isMacField(self, field: Any) -> bool:
        unwrappedField = self._unwrapField(field)
        return self._fieldInheritsFrom(unwrappedField, "MACField")

    def _isIPv4Field(self, field: Any) -> bool:
        unwrappedField = self._unwrapField(field)
        return (
            self._fieldInheritsFrom(unwrappedField, "IPField")
            or field.name in {"psrc", "pdst"}
        )

    def _isIPv6Field(self, field: Any) -> bool:
        unwrappedField = self._unwrapField(field)
        return self._fieldInheritsFrom(unwrappedField, "IP6Field")

    def _isCollectionField(self, field: Any) -> bool:
        unwrappedField = self._unwrapField(field)
        return (
            isinstance(unwrappedField.default, (list, tuple))
            or unwrappedField.__class__.__name__ in {
                "FieldListField",
                "PacketListField",
                "_DNSPacketListField",
            }
        )

    def _describeCollectionKind(self, field: Any) -> str:
        unwrappedField = self._unwrapField(field)
        if field.name == "options" and unwrappedField.__class__.__name__ == "PacketListField":
            return "ip_options"

        if unwrappedField.__class__.__name__ == "_DNSPacketListField" and field.name == "qd":
            return "dns_questions"

        if isinstance(unwrappedField.default, (list, tuple)):
            return "literal_list"

        return "raw"

    def _unwrapField(self, field: Any) -> Any:
        return getattr(field, "fld", field)

    def _isEtherTypeField(self, layer: Any, field: Any) -> bool:
        if field.name != "type":
            return False

        return layer.__class__ in {
            self._scapy.Ether,
            self._scapy.Dot1Q,
            self._scapy.Dot1AD,
        }

    def _fieldInheritsFrom(self, field: Any, className: str) -> bool:
        return any(base.__name__ == className for base in field.__class__.__mro__)

    def _valueToEditorText(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return repr(value)
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        return repr(value)