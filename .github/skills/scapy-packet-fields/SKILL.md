---
name: Scapy packet, field, and layer patterns
description: Use this when adding or modifying Scapy protocol layers, fields, payload binding logic, or UTScapy tests.
---

# Scapy packet, field, and layer patterns

Use this skill when working on protocol implementation in Scapy core/layers, especially around `Packet`, `Field`, `fields_desc`, layer binding, and regression tests via UTScapy.

## Core model

- A layer is a `Packet` subclass with a `fields_desc` list.
- Field values flow through human/internal/machine conversions (`h2i`, `i2h`, `i2m`, `m2i`, `any2i`).
- Building and dissecting are centralized in `Packet` (`do_build`, `post_build`, `do_dissect`, `guess_payload_class`, `extract_padding`).

## Packet and field usage patterns

### 1) Define layers as `Packet` subclasses with `fields_desc`

- Prefer explicit defaults in `fields_desc`.
- Use field types that encode semantics (e.g. `EnumField`, `FlagsField`, `PacketListField`) instead of generic numeric/string fields when possible.
- For optional/variant fields, use `ConditionalField` and `MultipleTypeField`.

Examples:
- `scapy/layers/inet.py` (`IP`, `TCP`, `UDP`, `ICMP`)
- `scapy/layers/l2.py` (`Ether`, `ARP`, `GRE`, `Dot1Q`)

### 2) Compute deferred values in `post_build`

- Keep `None` defaults for values that must be computed from final bytes (checksums, lengths, header offsets).
- Implement updates in `post_build(self, p, pay)` after payload is available.

Common examples:
- `IP.post_build`: IHL/len/checksum
- `TCP.post_build`: data offset + checksum
- `UDP.post_build`: len + checksum
- `GRE.post_build`: conditional checksum

### 3) Split payload/padding with `extract_padding` when length is explicit

- If a layer encodes payload length, override `extract_padding`.
- Return `(payload, padding)` correctly to keep dissection aligned.

Examples:
- `IP.extract_padding`
- `UDP.extract_padding`
- `Dot3.extract_padding`

### 4) Payload dispatch and layer binding (`guess_payload_class`, `bind_*`)

- `Packet.guess_payload_class(payload)` selects the next layer during dissection.
  - Default behavior iterates `payload_guess` entries and matches field constraints.
  - `payload_guess` is populated by `bind_bottom_up()` (and therefore by `bind_layers()`).
  - If no match applies, fallback is `Packet.default_payload_class()` (`conf.raw_layer`).
- Override `guess_payload_class` only when dispatch depends on dynamic logic that cannot be expressed as simple field equality.
- Base-class dispatch pattern: a base layer class can decode into a concrete sibling/subclass before normal dissection.
  - Commonly implemented with `dispatch_hook(cls, _pkt, ...)`.
  - Example: `Ether.dispatch_hook` can return `Dot3`, and `Dot3.dispatch_hook` can return `Ether`.
- Binding APIs:
  - `bind_bottom_up(lower, upper, ...)`: dissection-time binding only.
  - `bind_top_down(lower, upper, ...)`: build-time default field propagation only.
  - `bind_layers(lower, upper, ...)`: convenience helper that applies both directions.

Examples:
- `scapy/packet.py`: `guess_payload_class`, `bind_bottom_up`, `bind_top_down`, `bind_layers`
- `scapy/layers/l2.py`: `Ether.dispatch_hook` / `Dot3.dispatch_hook`
- `scapy/layers/inet.py`: protocol-specific `guess_payload_class` overrides

### 5) Request/response matching and stream reassembly hooks

- Implement `hashret()` when a protocol needs stable request/response correlation keys.
  - Base `Packet.hashret()` delegates to payload; many layers override it (e.g. IP/TCP/UDP) to include flow context.
- Implement `answers(other)` to express protocol-level "is response to" logic.
  - Base behavior matches same class then delegates to payload.
  - Typical checks include type/code pairs, id/seq tuples, and src/dst or sport/dport relationships.
- For stream-aware sniffing:
  - `IPSession` performs on-the-fly IPv4 defragmentation.
  - `TCPSession` reconstructs TCP byte streams and can call layer `tcp_reassemble(data, metadata, session)` when implemented.
  - `tcp_reassemble` should return a packet when enough bytes are present, else `None` and keep state in `metadata` / `session`.

References:
- `scapy/packet.py` (`hashret`, `answers`)
- `scapy/layers/inet.py` (`IP/TCP/UDP/ICMP` overrides)
- `scapy/sessions.py` (`IPSession`, `TCPSession`, `streamcls`)

### 6) Complete `scapy.fields` field-type catalog (and intended use)

This list covers field types defined in `scapy/fields.py` that are used when authoring packet layouts.

- **Base and wrappers (core composition/control)**
  - `Field`: base class for conversion and build/dissect behavior.
  - `Emph`: display emphasis wrapper.
  - `MayEnd`: allows legal early stop while dissecting optional tail fields.
  - `ActionField`: triggers side-effect callbacks during value assignment/build.
  - `ConditionalField`: include/exclude field based on runtime predicate.
  - `MultipleTypeField`: pick one of several field definitions from packet context.
  - `PadField`, `ReversePadField`: alignment/padding wrappers.
  - `TrailerField`, `FCSField`: model trailer fields appended after main payload.
- **Address/network identity fields**
  - `DestField`, `MACField`, `LEMACField`: MAC/address-like values.
  - `IPField`, `SourceIPField`: IPv4 values (including context-derived source behavior).
  - `IP6Field`, `SourceIP6Field`, `DestIP6Field`: IPv6 values.
  - `IPPrefixField`, `IP6PrefixField`: address + prefix-length encoding.
  - `OUIField`: 24-bit organization identifiers.
  - `UUIDField`, `UUIDEnumField`: UUID values (optionally enumerated).
- **Integer scalar fields**
  - Byte-sized: `ByteField`, `XByteField`, `OByteField`, `SignedByteField`, `YesNoByteField`
  - 3-byte and variable-width: `ThreeBytesField`, `X3BytesField`, `LEThreeBytesField`, `XLE3BytesField`, `NBytesField`, `XNBytesField`
  - 16-bit: `ShortField`, `SignedShortField`, `LEShortField`, `LESignedShortField`, `XShortField`, `XLEShortField`
  - 32-bit: `IntField`, `SignedIntField`, `LEIntField`, `LESignedIntField`, `XIntField`, `XLEIntField`
  - 64-bit: `LongField`, `SignedLongField`, `LELongField`, `LESignedLongField`, `XLongField`, `XLELongField`
- **Floating/scaled numeric fields**
  - `IEEEFloatField`, `IEEEDoubleField`: IEEE-754 float/double.
  - `BCDFloatField`: BCD-encoded decimal values.
  - `FixedPointField`: fixed-point values stored in bitfields.
  - `ScalingField`, `BitScalingField`: physical-unit scaling (offset/resolution) wrappers.
- **String/bytes fields**
  - Generic strings: `StrField`, `StrFieldUtf16`
  - Enumerated strings: `StrEnumField`
  - Fixed-length strings: `StrFixedLenField`, `StrFixedLenFieldUtf16`, `StrFixedLenEnumField`, `NetBIOSNameField`
  - Length-coupled strings: `StrLenField`, `StrLenFieldUtf16`, `StrLenEnumField`, `BoundStrLenField`
  - Hex-rendered byte strings: `XStrField`, `XStrLenField`, `XStrFixedLenField`, `XLEStrLenField`
  - Terminated strings: `StrNullField`, `StrNullFieldUtf16`, `StrStopField`
- **Packet/container and length-coupling fields**
  - Nested packets: `PacketField`, `PacketLenField`, `PacketListField`
  - Generic repeated values: `FieldListField`
  - Length/count references: `FieldLenField`, `LEFieldLenField`, `LenField`
- **Bit and varint-like fields**
  - `BitField`, `BitLenField`, `BitFieldLenField`, `XBitField`
  - `BitExtendedField`, `LSBExtendedField`, `MSBExtendedField`
- **Enum-capable fields**
  - Generic and char: `EnumField`, `CharEnumField`
  - Bit enums: `BitEnumField`, `BitLenEnumField`
  - Width/endianness-specific enums: `ShortEnumField`, `LEShortEnumField`, `LongEnumField`, `LELongEnumField`, `ByteEnumField`, `XByteEnumField`, `IntEnumField`, `SignedIntEnumField`, `LEIntEnumField`, `XLEIntEnumField`, `XShortEnumField`, `LE3BytesEnumField`, `XLE3BytesEnumField`
  - Contextual enums: `MultiEnumField`, `BitMultiEnumField`
  - Enum-key variants: `ByteEnumKeysField`, `ShortEnumKeysField`, `IntEnumKeysField`
- **Flags fields**
  - `FlagsField`: bitmask rendered as named flags.
  - `MultiFlagsField`: multi-set flag representation across grouped masks.
- **Time fields**
  - `UTCTimeField`: timestamps with human-readable UTC conversion support.
  - `SecondsIntField`: integer-seconds timestamp fields.
- **Raw override**
  - `RawVal` (from `scapy.packet`) is used with fields when you intentionally bypass normal conversion.

Examples:
- `scapy/layers/inet.py`: `IP.options` (`PacketListField`), ICMP conditional/enum usage
- `scapy/layers/l2.py`: ARP `MultipleTypeField` usage, GRE conditional/checksum fields

## UTScapy integration patterns

Use UTScapy for regression coverage of layer behavior.

### Campaign structure

- Campaign syntax in test files:
  - `%` campaign
  - `+` test set
  - `=` unit test
  - `~` keywords
  - `*` comments
- The last Python expression in a unit test determines pass/fail truthiness.

References:
- `doc/scapy/development.rst` (Testing with UTScapy)
- `scapy/tools/UTscapy.py` (`parse_campaign_file`, campaign execution/filtering)

### Useful UTScapy CLI patterns

- Run one or more campaigns: `-t`
- Include/exclude keyword groups: `-k` / `-K`
- Select tests by number: `-n`
- Load `.utsc` JSON config: `-c`
- Output formats: `-f text|ansi|HTML|LaTeX|xUnit|live`
- Generate docs from campaign comments/tests: `-R`
- Non-root mode keyword filtering: `-N`

Reference:
- `scapy/tools/UTscapy.py` (`usage()`, `main()`)

### Typical test workflow

1. Add/modify protocol layer fields and binding logic.
2. Add/adjust UTScapy tests in `test/` configs/campaign files with meaningful keywords.
3. Run through existing wrappers (`./test/run_tests` or tox environments using `scapy.tools.UTscapy`).
4. Keep tests focused on:
   - build/dissect roundtrips
   - computed fields (len/checksum/options)
   - payload dispatch and edge-case fallback

## Quick references

- Core packet behavior: `scapy/packet.py`
- Field internals: `scapy/fields.py`
- Common layer patterns: `scapy/layers/inet.py`, `scapy/layers/l2.py`
- Test runner internals: `scapy/tools/UTscapy.py`
- Design guidance: `doc/scapy/build_dissect.rst`
