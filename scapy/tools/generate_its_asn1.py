#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Generate Scapy ASN1_Packet definitions for ETSI ITS messages.

Requires asn1tools (dev dependency only, not needed at runtime).

Usage:
    python scapy/tools/generate_its_asn1.py
"""

from __future__ import annotations

import argparse
import keyword
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from asn1tools import parse_files
except ImportError as exc:
    raise SystemExit(
        "asn1tools is required to regenerate ITS packets "
        "(pip install asn1tools)"
    ) from exc

ROOT_MESSAGES = ("CAM", "DENM", "IVIM", "SPATEM", "MAPEM")

PRIMITIVE_TYPES = {
    "INTEGER",
    "ENUMERATED",
    "BOOLEAN",
    "NULL",
    "BIT STRING",
    "OCTET STRING",
    "OBJECT IDENTIFIER",
    "IA5String",
    "UTF8String",
    "NumericString",
    "PrintableString",
    "GeneralizedTime",
    "UTCTime",
    "DATE",
    "EUI64",
    "VisibleString",
    "TeletexString",
    "GraphicString",
    "UniversalString",
    "BMPString",
    "ObjectDescriptor",
    "REAL",
}

STRING_TYPES = {
    "IA5String": "ASN1F_IA5_STRING",
    "UTF8String": "ASN1F_UTF8_STRING",
    "NumericString": "ASN1F_NUMERIC_STRING",
    "PrintableString": "ASN1F_PRINTABLE_STRING",
    "GeneralizedTime": "ASN1F_GENERALIZED_TIME",
    "UTCTime": "ASN1F_UTC_TIME",
}


def _asn_dir() -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "contrib" / "automotive" / "v2x" / "asn"
    )


def asn_file_list() -> List[Path]:
    asn = _asn_dir()
    return [
        asn / "ITS-Container.asn",
        asn / "CAM-PDU-Descriptions.asn",
        asn / "DENM-PDU-Descriptions.asn",
        asn / "SPATEM-PDU-Descriptions.asn",
        asn / "MAPEM-PDU-Descriptions.asn",
        asn / "IVIM-PDU-Descriptions.asn",
        asn / "iso-patched" / "ISO24534-3_ElectronicRegistrationIdentificationVehicleDataModule-patched.asn",
        asn / "iso-patched" / "ISO14823-missing.asn",
        asn / "iso-patched" / "ISO14906(2018)EfcDsrcGenericv7-patched.asn",
        asn / "iso-patched" / "ISO14906(2018)EfcDsrcApplicationv6-patched.asn",
        asn / "ISO-TS-19091-addgrp-C-2018-patched.asn",
        asn / "ISO14816_AVIAEINumberingAndDataStructures.asn",
        asn / "ISO19321IVIv2.asn",
        asn / "ISO_17419_1-1.asn",
    ]


PACKET_FIELD_RESERVED = frozenset({"name"})


def field_name(name: str) -> str:
    if name in PACKET_FIELD_RESERVED:
        return name + "_"
    return name


def sanitize_name(name: str) -> str:
    name = re.sub(r"[^0-9a-zA-Z_]", "_", name.replace("-", "_"))
    if not name or name[0].isdigit():
        name = "_" + name
    if keyword.iskeyword(name):
        name = name + "_"
    return name


def flatten_members(members: List[Any]) -> List[Dict[str, Any]]:
    flat: List[Dict[str, Any]] = []
    for member in members:
        if member is None:
            continue
        if isinstance(member, list):
            flat.extend(flatten_members(member))
        else:
            flat.append(member)
    return flat


def inline_type_name(parent: str, member_name: str) -> str:
    return f"ITS_Inline_{sanitize_name(parent)}_{member_name}"


def flatten_choice_members(members: List[Any]) -> List[Dict[str, Any]]:
    return flatten_members(members)


def is_extensible(members: List[Any]) -> bool:
    return any(m is None for m in members)


def py_literal(value: Any) -> str:
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, bytes):
        return repr(value)
    if isinstance(value, dict):
        items = ", ".join(f"{py_literal(k)}: {py_literal(v)}" for k, v in value.items())
        return "{" + items + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(py_literal(v) for v in value) + "]"
    return repr(value)


class ITSASN1Generator:
    def __init__(self, spec: Dict[str, Any], compiled_types: Optional[Set[str]] = None) -> None:
        self.spec = spec
        self.compiled_types = compiled_types
        self.class_names: Dict[Tuple[str, str], str] = {}
        self.used_py_names: Set[str] = set()
        self.import_fields: Set[str] = set()
        self.import_asn1: Set[str] = set()
        self._assign_class_names()

    def _assign_class_names(self) -> None:
        for module, data in self.spec.items():
            for type_name, desc in data.get("types", {}).items():
                if desc.get("parameters"):
                    continue
                if not self._needs_packet(module, type_name, desc):
                    continue
                py_name = sanitize_name(type_name)
                if py_name in self.used_py_names:
                    py_name = sanitize_name(module.split("-")[0]) + "_" + py_name
                while py_name in self.used_py_names:
                    py_name = py_name + "_"
                self.class_names[(module, type_name)] = py_name
                self.used_py_names.add(py_name)

    def _lookup_descriptor(self, module: str, type_name: str) -> Tuple[str, str, Dict[str, Any]]:
        data = self.spec.get(module, {})
        if type_name in data.get("types", {}):
            return module, type_name, data["types"][type_name]
        for imported_mod, imported_names in data.get("imports", {}).items():
            if type_name in imported_names:
                return self._lookup_descriptor(imported_mod, type_name)
        raise KeyError(f"type {type_name!r} not found from module {module!r}")

    def _resolve(self, module: str, type_name: str, seen: Optional[Set[Tuple[str, str]]] = None) -> Tuple[str, str, Dict[str, Any]]:
        key = (module, type_name)
        if seen is None:
            seen = set()
        if key in seen:
            return module, type_name, self.spec[module]["types"][type_name]
        seen.add(key)
        mod, name, desc = self._lookup_descriptor(module, type_name)
        base = desc.get("type")
        if base in PRIMITIVE_TYPES or base in ("SEQUENCE", "CHOICE", "SEQUENCE OF"):
            return mod, name, desc
        return self._resolve(mod, base, seen)

    def _needs_packet(self, module: str, type_name: str, desc: Optional[Dict[str, Any]] = None) -> bool:
        if desc is None:
            desc = self.spec[module]["types"][type_name]
        if desc.get("parameters"):
            return False
        base = desc.get("type")
        if base in ("SEQUENCE", "CHOICE"):
            return True
        if base in PRIMITIVE_TYPES:
            return False
        try:
            _, _, resolved = self._resolve(module, type_name)
        except KeyError:
            return False
        return resolved.get("type") in ("SEQUENCE", "CHOICE")

    def _class_for(self, module: str, type_name: str) -> str:
        mod, name, desc = self._resolve(module, type_name)
        if self._needs_packet(mod, name, desc):
            return self.class_names[(mod, name)]
        raise KeyError(type_name)

    def _size_args(self, desc: Dict[str, Any], field_cls: str = "") -> str:
        size = desc.get("size")
        if not size:
            return ""
        parts = []
        for item in size:
            if item is None:
                continue
            if isinstance(item, tuple):
                lo, hi = item
                if field_cls in ("ASN1F_BIT_STRING", "ASN1F_FLAGS"):
                    parts.append(f"uper_min={lo}")
                    parts.append(f"uper_max={hi}")
                elif lo == hi:
                    parts.append(f"size_len={lo}")
                else:
                    parts.append(f"uper_min={lo}")
                    parts.append(f"uper_max={hi}")
            elif isinstance(item, int):
                if field_cls in ("ASN1F_BIT_STRING", "ASN1F_FLAGS"):
                    parts.append(f"uper_min={item}")
                    parts.append(f"uper_max={item}")
                else:
                    parts.append(f"size_len={item}")
        return (", " + ", ".join(parts)) if parts else ""

    def _integer_args(self, desc: Dict[str, Any], enumerated: bool = False) -> str:
        args = []
        if enumerated:
            return ""
        restricted = desc.get("restricted-to")
        if restricted:
            lo, hi = restricted[0]
            args.append(f"uper_min={lo}")
            args.append(f"uper_max={hi}")
            if lo >= 0:
                args.append("oer_unsigned=True")
        return (", " + ", ".join(args)) if args else ""

    def _integer_default(self, desc: Dict[str, Any]) -> int:
        restricted = desc.get("restricted-to")
        if restricted:
            lo, hi = restricted[0]
            if lo <= 0 <= hi:
                return 0
            return lo
        return 0

    def _register_inline_packet(self, module: str, parent: str, member: Dict[str, Any]) -> str:
        member_name = sanitize_name(member.get("name") or "inline")
        type_name = inline_type_name(sanitize_name(parent), member_name)
        py_name = sanitize_name(type_name)
        while py_name in self.used_py_names:
            py_name = py_name + "_"
        key = (module, type_name)
        self.class_names[key] = py_name
        self.used_py_names.add(py_name)
        if module not in self.spec:
            self.spec[module] = {"types": {}}
        self.spec[module]["types"][type_name] = member
        return py_name

    def _is_forward_ref(self, mod: str, name: str, current_key: Optional[Tuple[str, str]], result_order: Optional[List[Tuple[str, str]]]) -> bool:
        if current_key is None or result_order is None:
            return False
        key = (mod, name)
        if key not in self.class_names:
            return True
        try:
            return result_order.index(key) > result_order.index(current_key)
        except ValueError:
            return False

    def _packet_ref(self, member_name: str, mod: str, name: str, tag_args: str, current_key: Optional[Tuple[str, str]], result_order: Optional[List[Tuple[str, str]]], optional: bool = False) -> str:
        if self._is_forward_ref(mod, name, current_key, result_order):
            self.import_fields.add("ASN1F_STRING")
            default = "None" if optional else 'b""'
            return f'ASN1F_STRING("{member_name}", {default}{tag_args})'
        cls = self.class_names[(mod, name)]
        self.import_fields.add("ASN1F_PACKET")
        default = "None" if optional else f"{cls}()"
        return f'ASN1F_PACKET("{member_name}", {default}, {cls}{tag_args})'

    def _discover_inline_types(self) -> None:
        pending = True
        while pending:
            pending = False
            for module, data in self.spec.items():
                for type_name, desc in list(data.get("types", {}).items()):
                    if desc.get("type") not in ("SEQUENCE", "CHOICE"):
                        continue
                    for member in flatten_members(desc.get("members", [])):
                        if member.get("type") in ("SEQUENCE", "CHOICE"):
                            _, inline_name = self._inline_key(
                                module, type_name, member,
                            )
                            if inline_name not in data.get("types", {}):
                                self._register_inline_packet(module, type_name, member)
                                pending = True

    def _field_for_member(
        self,
        module: str,
        member: Dict[str, Any],
        in_choice: bool = False,
        parent: str = "",
        current_key: Optional[Tuple[str, str]] = None,
        result_order: Optional[List[Tuple[str, str]]] = None,
    ) -> str:
        if member is None:
            return ""
        member_name = field_name(sanitize_name(member.get("name") or "extension"))
        type_name = member["type"]
        optional = member.get("optional")
        tag = member.get("tag")
        tag_args = ""
        if tag and not in_choice:
            tag_args = f", implicit_tag={tag['number']}"
        if type_name == "SEQUENCE OF":
            self.import_fields.add("ASN1F_SEQUENCE_OF")
            element = member.get("element", {})
            elem_type = element.get("type")
            if elem_type not in PRIMITIVE_TYPES:
                try:
                    emod, ename, edesc = self._resolve(module, elem_type)
                    if edesc.get("parameters"):
                        self.import_fields.add("ASN1F_STRING")
                        field = f'ASN1F_SEQUENCE_OF("{member_name}", None, ASN1F_STRING{tag_args})'
                        if optional:
                            self.import_fields.add("ASN1F_optional")
                            field = f"ASN1F_optional({field})"
                        return field
                except KeyError:
                    pass
            seq_default = self._sequence_of_default(
                module, element, member, optional, parent or member_name,
            )
            inner = self._sequence_of_element(module, element, parent=parent or member_name)
            size_args = self._sequence_of_size_args(member)
            field = f'ASN1F_SEQUENCE_OF("{member_name}", {seq_default}, {inner}{size_args}{tag_args})'
            if optional:
                self.import_fields.add("ASN1F_optional")
                field = f"ASN1F_optional({field})"
            return field
        if type_name in ("SEQUENCE", "CHOICE"):
            _, inline_name = self._inline_key(module, parent or member_name, member)
            field = self._packet_ref(
                member_name, module, inline_name, tag_args, current_key, result_order,
                optional=optional,
            )
            if optional:
                self.import_fields.add("ASN1F_optional")
                field = f"ASN1F_optional({field})"
            return field
        if type_name in PRIMITIVE_TYPES:
            desc = member
            mod = module
            name = member_name
            base = type_name
        else:
            try:
                mod, name, desc = self._resolve(module, type_name)
            except KeyError:
                self.import_fields.add("ASN1F_STRING")
                field = f'ASN1F_STRING("{member_name}", b""{tag_args})'
                if optional:
                    self.import_fields.add("ASN1F_optional")
                    field = f"ASN1F_optional({field})"
                return field
            base = desc.get("type")
        if desc.get("parameters") or (
            base in ("SEQUENCE", "CHOICE") and (mod, name) not in self.class_names
        ):
            self.import_fields.add("ASN1F_STRING")
            field = f'ASN1F_STRING("{member_name}", b""{tag_args})'
            if optional:
                self.import_fields.add("ASN1F_optional")
                field = f"ASN1F_optional({field})"
            return field

        if base == "SEQUENCE":
            field = self._packet_ref(
                member_name, mod, name, tag_args, current_key, result_order,
                optional=optional,
            )
        elif base == "CHOICE":
            field = self._packet_ref(
                member_name, mod, name, tag_args, current_key, result_order,
                optional=optional,
            )
        elif base == "SEQUENCE OF":
            element = desc.get("element", member)
            elem_type = element.get("type")
            if elem_type not in PRIMITIVE_TYPES:
                try:
                    emod, ename, edesc = self._resolve(mod, elem_type)
                    if edesc.get("parameters"):
                        self.import_fields.add("ASN1F_SEQUENCE_OF")
                        self.import_fields.add("ASN1F_STRING")
                        field = f'ASN1F_SEQUENCE_OF("{member_name}", None, ASN1F_STRING{tag_args})'
                        if optional:
                            self.import_fields.add("ASN1F_optional")
                            field = f"ASN1F_optional({field})"
                        return field
                except KeyError:
                    pass
            if elem_type in PRIMITIVE_TYPES:
                elem_desc = element
                elem_base = elem_type
            else:
                elem_mod, elem_name, elem_desc = self._resolve(mod, elem_type)
                elem_base = elem_desc.get("type")
            self.import_fields.add("ASN1F_SEQUENCE_OF")
            seq_default = self._sequence_of_default(
                mod, element, desc, optional, type_name,
            )
            size_args = self._sequence_of_size_args(desc)
            if elem_base == "SEQUENCE":
                if elem_type in PRIMITIVE_TYPES:
                    raise KeyError("unexpected inline SEQUENCE element")
                elem_mod, elem_name, _ = self._resolve(mod, elem_type)
                if self._is_forward_ref(elem_mod, elem_name, current_key, result_order):
                    inner = "ASN1F_STRING"
                    self.import_fields.add("ASN1F_STRING")
                else:
                    inner = self.class_names[(elem_mod, elem_name)]
                field = f'ASN1F_SEQUENCE_OF("{member_name}", {seq_default}, {inner}{size_args}{tag_args})'
            else:
                inner = self._sequence_of_element(mod, element, parent=type_name)
                field = f'ASN1F_SEQUENCE_OF("{member_name}", {seq_default}, {inner}{size_args}{tag_args})'
        else:
            field = self._primitive_field(member_name, desc, tag_args, in_choice, optional=optional)

        if optional:
            self.import_fields.add("ASN1F_optional")
            field = f"ASN1F_optional({field})"
        return field

    def _sequence_of_size_args(self, desc: Dict[str, Any]) -> str:
        parts = []
        extensible = False
        for item in desc.get("size") or []:
            if item is None:
                extensible = True
                continue
            if isinstance(item, tuple):
                parts.append(f"uper_min={item[0]}")
                parts.append(f"uper_max={item[1]}")
            elif isinstance(item, int):
                parts.append(f"uper_min={item}")
                parts.append(f"uper_max={item}")
        if extensible:
            parts.append("uper_extensible=True")
        return (", " + ", ".join(parts)) if parts else ""

    def _sequence_of_default(
        self,
        module: str,
        element: Dict[str, Any],
        desc: Dict[str, Any],
        optional: bool,
        parent: str,
    ) -> str:
        if optional:
            return "None"
        min_size = 0
        for item in desc.get("size") or []:
            if item is None:
                continue
            if isinstance(item, tuple):
                min_size = max(min_size, item[0])
            elif isinstance(item, int):
                min_size = max(min_size, item)
        if min_size <= 0:
            return "[]"
        inner = self._sequence_of_element(module, element, parent=parent)
        if inner.startswith("ASN1F_"):
            return "[]"
        return f"[{inner}()]"

    def _sequence_of_element(self, module: str, element: Dict[str, Any], parent: str = "seqof") -> str:
        elem_type = element.get("type")
        if elem_type in ("SEQUENCE", "CHOICE"):
            cls = self._register_inline_packet(module, parent, element)
            return cls
        if elem_type in PRIMITIVE_TYPES:
            cls = self._primitive_field_class(element)
            self.import_fields.add(cls)
            if cls in ("ASN1F_ENUMERATED", "ASN1F_FLAGS"):
                return self._primitive_field("item", element, "", False)
            return cls
        try:
            elem_mod, elem_name, elem_desc = self._resolve(module, elem_type)
        except KeyError:
            self.import_fields.add("ASN1F_STRING")
            return "ASN1F_STRING"
        if elem_desc.get("parameters"):
            self.import_fields.add("ASN1F_STRING")
            return "ASN1F_STRING"
        if self._needs_packet(elem_mod, elem_name, elem_desc):
            return self.class_names[(elem_mod, elem_name)]
        cls = self._primitive_field_class(elem_desc)
        self.import_fields.add(cls)
        if cls in ("ASN1F_ENUMERATED", "ASN1F_FLAGS"):
            return self._primitive_field("item", elem_desc, "", False)
        return cls

    def _primitive_field_class(self, desc: Dict[str, Any]) -> str:
        base = desc.get("type")
        if base == "INTEGER":
            return "ASN1F_INTEGER"
        if base == "ENUMERATED":
            return "ASN1F_ENUMERATED"
        if base == "BOOLEAN":
            return "ASN1F_BOOLEAN"
        if base == "NULL":
            return "ASN1F_NULL"
        if base == "BIT STRING":
            if desc.get("named-bits"):
                return "ASN1F_FLAGS"
            return "ASN1F_BIT_STRING"
        if base == "OCTET STRING":
            return "ASN1F_STRING"
        if base == "OBJECT IDENTIFIER":
            return "ASN1F_OID"
        if base in STRING_TYPES:
            return STRING_TYPES[base]
        return "ASN1F_STRING"

    def _enum_mapping(self, desc: Dict[str, Any]) -> Dict[str, int]:
        named = desc.get("named-numbers") or desc.get("values")
        if not named:
            return {}
        if isinstance(named, dict):
            return {k: v for k, v in named.items() if v is not None}
        mapping: Dict[str, int] = {}
        for item in named:
            if item is None:
                continue
            k, v = item
            if k is not None:
                mapping[k] = v
        return mapping

    def _enum_default(self, desc: Dict[str, Any]) -> int:
        mapping = self._enum_mapping(desc)
        if mapping:
            return min(mapping.values())
        values = [v for v in (desc.get("values") or []) if v is not None]
        if values:
            return values[0][1]
        restricted = desc.get("restricted-to")
        if restricted:
            return restricted[0][0]
        return 0

    def _primitive_field(self, member_name: str, desc: Dict[str, Any], tag_args: str, in_choice: bool, optional: bool = False) -> str:
        base = desc.get("type")
        cls = self._primitive_field_class(desc)
        self.import_fields.add(cls)
        default: Any
        if optional:
            default = None
        elif base == "BOOLEAN":
            default = False
        elif base == "NULL":
            default = None
        elif base in ("OCTET STRING", "IA5String", "UTF8String", "NumericString", "PrintableString"):
            default = b"" if base == "OCTET STRING" else ""
        elif base == "BIT STRING":
            default = b""
        elif base == "INTEGER":
            default = self._integer_default(desc)
        elif base == "ENUMERATED":
            default = self._enum_default(desc)
        else:
            default = 0

        extra = self._integer_args(desc, enumerated=(cls == "ASN1F_ENUMERATED")) + self._size_args(desc, cls)
        if cls == "ASN1F_ENUMERATED":
            mapping = self._enum_mapping(desc)
            if mapping:
                if default not in mapping.values():
                    default = min(mapping.values())
                scapy_enum = {v: k for k, v in mapping.items()}
                return f'{cls}("{member_name}", {py_literal(default)}, {py_literal(scapy_enum)}{extra}{tag_args})'
        if cls == "ASN1F_FLAGS" and desc.get("named-bits"):
            mapping = [bit[0] for bit in desc["named-bits"]]
            return f'{cls}("{member_name}", {py_literal(default)}, {py_literal(mapping)}{extra}{tag_args})'

        if in_choice and cls in ("ASN1F_INTEGER", "ASN1F_ENUMERATED", "ASN1F_BOOLEAN", "ASN1F_STRING", "ASN1F_BIT_STRING", "ASN1F_NULL", "ASN1F_OID"):
            if tag_args:
                tag_num = tag_args.split("=")[-1]
                extra += f", implicit_tag={tag_num}"
            return f'{cls}("{member_name}", {py_literal(default)}{extra})'
        return f'{cls}("{member_name}", {py_literal(default)}{extra}{tag_args})'

    def _choice_root(
        self,
        module: str,
        type_name: str,
        desc: Dict[str, Any],
        current_key: Optional[Tuple[str, str]] = None,
        result_order: Optional[List[Tuple[str, str]]] = None,
    ) -> str:
        self.import_fields.add("ASN1F_CHOICE")
        members = flatten_choice_members(desc.get("members", []))
        alts: List[str] = []
        for member in members:
            member_type = member["type"]
            if member_type in PRIMITIVE_TYPES:
                alts.append(self._primitive_field(
                    sanitize_name(member.get("name") or "alt"),
                    member,
                    "",
                    in_choice=True,
                ))
            else:
                try:
                    mod, name, member_desc = self._resolve(module, member_type)
                except KeyError:
                    continue
                if member_desc.get("parameters"):
                    continue
                base = member_desc.get("type")
                if base in ("SEQUENCE", "CHOICE"):
                    if (mod, name) not in self.class_names:
                        continue
                    if self._is_forward_ref(mod, name, current_key, result_order):
                        self.import_fields.add("ASN1F_STRING")
                        alts.append(
                            self._primitive_field(
                                sanitize_name(member.get("name") or "alt"),
                                {"type": "OCTET STRING"},
                                "",
                                in_choice=True,
                            )
                        )
                    else:
                        alts.append(self.class_names[(mod, name)])
                else:
                    alts.append(self._primitive_field(
                        sanitize_name(member.get("name") or "alt"),
                        member_desc,
                        "",
                        in_choice=True,
                    ))
        if not alts:
            self.import_fields.add("ASN1F_NULL")
            alts.append('ASN1F_NULL("unsupported", None)')
        default = "None"
        if alts:
            first = alts[0]
            if first[0].isupper() and not first.startswith("ASN1F_"):
                default = f"{first}()"
        ext_args = ", uper_extensible=True" if is_extensible(desc.get("members", [])) else ""
        return "ASN1F_CHOICE(\n        " + f'"root", {default},\n        ' + ",\n        ".join(alts) + ext_args + "\n    )"

    def _sequence_root(
        self,
        module: str,
        type_name: str,
        desc: Dict[str, Any],
        current_key: Optional[Tuple[str, str]] = None,
        result_order: Optional[List[Tuple[str, str]]] = None,
    ) -> str:
        self.import_fields.add("ASN1F_SEQUENCE")
        fields = []
        for member in flatten_members(desc.get("members", [])):
            field = self._field_for_member(
                module, member, parent=type_name,
                current_key=current_key, result_order=result_order,
            )
            if field:
                fields.append(field)
        if not fields:
            fields.append('ASN1F_NULL("placeholder", None)')
            self.import_fields.add("ASN1F_NULL")
        ext_args = ", uper_extensible=True" if is_extensible(desc.get("members", [])) else ""
        return "ASN1F_SEQUENCE(\n        " + ",\n        ".join(fields) + ext_args + "\n    )"

    def _packet_class(
        self,
        module: str,
        type_name: str,
        current_key: Optional[Tuple[str, str]] = None,
        result_order: Optional[List[Tuple[str, str]]] = None,
    ) -> str:
        desc = self.spec[module]["types"][type_name]
        py_name = self.class_names[(module, type_name)]
        key = current_key or (module, type_name)
        if desc["type"] == "CHOICE":
            root = self._choice_root(module, type_name, desc, key, result_order)
        else:
            root = self._sequence_root(module, type_name, desc, key, result_order)
        return (
            f"class {py_name}(ASN1_Packet):\n"
            f"    ASN1_codec = ASN1_Codecs.PER\n"
            f"    ASN1_root = {root}\n"
        )

    def _reachable_type_keys(self) -> Set[Tuple[str, str]]:
        roots: List[Tuple[str, str]] = []
        for root in ROOT_MESSAGES:
            for module, data in self.spec.items():
                if root in data.get("types", {}):
                    roots.append((module, root))
                    break
        seen: Set[Tuple[str, str]] = set()
        queue = list(roots)
        while queue:
            key = queue.pop(0)
            if key in seen or key not in self.class_names:
                continue
            seen.add(key)
            module, type_name = key
            desc = self.spec[module]["types"][type_name]
            for dep in self._collect_packet_refs(module, desc, type_name):
                if dep in self.class_names and dep not in seen:
                    queue.append(dep)
        return seen

    def generate(self) -> str:
        self._discover_inline_types()
        reachable = self._reachable_type_keys()
        self.class_names = {
            key: name for key, name in self.class_names.items()
            if key in reachable
        }
        self.used_py_names = set(self.class_names.values())
        ordered: List[Tuple[str, str]] = []
        for module, data in self.spec.items():
            for type_name, desc in data.get("types", {}).items():
                key = (module, type_name)
                if key in reachable and self._needs_packet(module, type_name, desc):
                    ordered.append(key)

        # Topological order: referenced packets before users
        deps: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {k: set() for k in ordered}
        for key in ordered:
            module, type_name = key
            desc = self.spec[module]["types"][type_name]
            refs = self._collect_packet_refs(module, desc, type_name)
            deps[key] = refs

        result_order: List[Tuple[str, str]] = []
        remaining = list(ordered)
        while remaining:
            progressed = False
            for key in list(remaining):
                if all(
                    dep not in remaining or dep in result_order
                    for dep in deps.get(key, ())
                ):
                    result_order.append(key)
                    remaining.remove(key)
                    progressed = True
            if not progressed:
                ready = [
                    k for k in remaining
                    if all(dep not in remaining for dep in deps.get(k, ()))
                ]
                if ready:
                    key = ready[0]
                else:
                    key = max(
                        remaining,
                        key=lambda k: (
                            sum(1 for dep in deps.get(k, ()) if dep in result_order),
                            -sum(1 for dep in deps.get(k, ()) if dep in remaining),
                        ),
                    )
                result_order.append(key)
                remaining.remove(key)

        root_keys: List[Tuple[str, str]] = []
        for root in ROOT_MESSAGES:
            for module, data in self.spec.items():
                if root in data.get("types", {}):
                    key = (module, root)
                    if key in result_order:
                        result_order.remove(key)
                        root_keys.append(key)
                    break
        result_order.extend(root_keys)

        class_lines: List[str] = []
        for module, type_name in result_order:
            class_lines.append(
                self._packet_class(module, type_name, (module, type_name), result_order)
            )
            class_lines.append("")

        lines = [
            "# SPDX-License-Identifier: GPL-2.0-only",
            "# This file is part of Scapy",
            "# See https://scapy.net/ for more information",
            "# AUTO-GENERATED by scapy/tools/generate_its_asn1.py - DO NOT EDIT",
            '"""',
            "ETSI ITS ASN.1 packets (UPER): CAM, DENM, IVIM, SPATEM, MAPEM.",
            '"""',
            "",
            "from scapy.asn1.asn1 import ASN1_Codecs",
        ]
        field_imports = sorted(self.import_fields)
        if field_imports:
            lines.append("from scapy.asn1fields import (")
            for name in field_imports:
                lines.append(f"    {name},")
            lines.append(")")
        lines.append("from scapy.asn1packet import ASN1_Packet")
        lines.append("")
        lines.extend(class_lines)

        for root in ROOT_MESSAGES:
            for module, data in self.spec.items():
                if root in data.get("types", {}):
                    cls = self.class_names[(module, root)]
                    lines.append(f"{root} = {cls}")
                    break
        lines.append("")
        lines.append("__all__ = [")
        for root in ROOT_MESSAGES:
            lines.append(f'    "{root}",')
        for module, type_name in result_order:
            lines.append(f'    "{self.class_names[(module, type_name)]}",')
        lines.append("]")
        lines.append("")
        return "\n".join(lines)

    def _inline_key(self, module: str, parent: str, member: Dict[str, Any]) -> Tuple[str, str]:
        member_name = sanitize_name(member.get("name") or "inline")
        type_name = inline_type_name(sanitize_name(parent), member_name)
        return module, type_name

    def _collect_packet_refs(
        self,
        module: str,
        desc: Dict[str, Any],
        parent_name: str = "",
    ) -> Set[Tuple[str, str]]:
        refs: Set[Tuple[str, str]] = set()

        def add_type_ref(mod: str, type_name: str) -> None:
            if type_name in PRIMITIVE_TYPES or type_name in ("SEQUENCE", "CHOICE", "SEQUENCE OF"):
                return
            try:
                rmod, rname, rdesc = self._resolve(mod, type_name)
            except KeyError:
                return
            if rdesc.get("type") == "SEQUENCE OF":
                element = rdesc.get("element", {})
                elem_type = element.get("type")
                if elem_type in ("SEQUENCE", "CHOICE"):
                    return
                add_type_ref(rmod, elem_type)
                return
            if self._needs_packet(rmod, rname, rdesc):
                refs.add((rmod, rname))

        def walk_members(members: List[Dict[str, Any]], mod: str, parent: str) -> None:
            for member in members:
                if not member:
                    continue
                mtype = member.get("type")
                if mtype in ("SEQUENCE", "CHOICE"):
                    key = self._inline_key(mod, parent, member)
                    if key in self.class_names:
                        refs.add(key)
                        inline_desc = self.spec[mod]["types"].get(key[1])
                        if inline_desc:
                            refs.update(self._collect_packet_refs(
                                mod, inline_desc, key[1],
                            ))
                    continue
                if mtype == "SEQUENCE OF":
                    element = member.get("element", {})
                    elem_type = element.get("type")
                    if elem_type in ("SEQUENCE", "CHOICE"):
                        continue
                    add_type_ref(mod, elem_type)
                elif mtype not in PRIMITIVE_TYPES:
                    add_type_ref(mod, mtype)

        base = desc.get("type")
        if base == "SEQUENCE":
            walk_members(
                flatten_members(desc.get("members", [])),
                module,
                parent_name,
            )
        elif base == "CHOICE":
            walk_members(
                flatten_choice_members(desc.get("members", [])),
                module,
                parent_name,
            )
        return refs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent.parent
        / "contrib" / "automotive" / "v2x" / "packets.py",
        help="Output Python file",
    )
    args = parser.parse_args()

    files = asn_file_list()
    missing = [str(f) for f in files if not f.exists()]
    if missing:
        raise SystemExit("Missing ASN.1 files:\n  " + "\n  ".join(missing))

    spec = parse_files([str(f) for f in files])
    import asn1tools
    compiled = asn1tools.compile_files([str(f) for f in files], codec="uper")
    generator = ITSASN1Generator(spec, compiled_types=set(compiled.types))
    output = generator.generate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print(f"Wrote {args.output} ({output.count(chr(10))} lines)")


if __name__ == "__main__":
    main()
