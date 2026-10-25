# Scapy review checklist

This checklist combines recurring maintainer-review concerns with requirements in `CONTRIBUTING.md`, `AGENTS.md`, the existing `scapy-packet-fields` skill, and the Scapy custom-protocol documentation. It is a set of prompts, not a scorecard: apply items only when relevant, and do not create a finding merely because an item could not be tested.

## 1. Simplicity and consistency

- Match the file's existing conventions and analogous layers before introducing helpers, subclasses, abstractions, redundant fallback paths, or new state.
- Do not add a helper used once for a trivial condition. Prefer two straightforward statements over an opaque generic framework.
- If a function is only ever used once, it likely should be merged with it's caller. It's okay to have big functions as long as they are properly commented, in steps.
- Check if duplicate logic should instead live in an existing parent class or a built-in field.

## 2. Scapy-native packet representation

- Prefer `Packet.fields_desc` with `EnumField`, `FlagsField`, `ConditionalField`, `MultipleTypeField`, `PacketField`, `PacketListField`, etc.
- Prefer `bind_layers()` for the normal bidirectional binding contract. Know when `bind_bottom_up` or `bind_top_down` is intentionally one-sided.
- Override `guess_payload_class()` only for dispatch that bindings cannot express. Use `dispatch_hook()` for initial packet-class dispatch, if necessary.
- Before writing a custom field, examine existing fields and conversion hooks (`h2i`, `i2m`, `m2i`, `addfield`, `getfield`).
- If you see the use of the `struct` module to parse data (not within a `Packet`'s methods), wonder if a `Packet` could have been used instead.

## 3. Wire-format correctness

- Cross-check documented widths in **bytes and bits**, byte order, offsets, bit flags, conditional fields, alignment and reserved bits.
- For dependent length/count fields, check `FieldLenField(length_of=.../count_of=...)` against the target `length_from`/`count_from`, including `0`, `1`, minimum and maximum values.
- Compute checksums/lengths in `post_build()` where appropriate. A `None` default should request automatic computation; a caller-provided explicit value must not be clobbered without protocol-specific justification.
- Ensure `extract_padding()` returns correct `(payload, padding)` boundaries and never eats a following frame accidentally.
- Compare against independent packet captures or another dissector. `bytes(p) == bytes(Packet(bytes(p)))` cannot detect a symmetric serialization error.

## 4. Compatibility

- Check existing public field names, methods, parameters, defaults, repr, and decoding behavior.
- Avoid unintended default changes for existing users. Avoid needless aliases for names introduced only in the same PR.
- Test user-supplied atypical values: Scapy must support deliberately malformed packets, not normalize everything automatically.
- You can suggest using `deprecated_fields` (see `packet.py`) if one of the change is a simple field rename, as that option allows to redirect old names to a newer variant.

## 5. Untrusted input and robustness

- Bound reads and allocations before consuming lengths from network data or pcap record headers.
- Check empty/truncated inputs, malformed encodings, invalid length offsets, repeated nested structures, malformed compression, and parser fallback.
- Guard against huge allocations, infinite loops, and quadratic complexity for plausible attacker-controlled input.
- A dissector error falling back to `Raw` may be a correctness defect even when it is not a reportable security issue. Apply `SECURITY.md` classification.

## 6. State, reassembly and mutation

- Trace ownership of mutable packets and cached `bytes(pkt)`, length fields or lookup indices. Verify invalidation on mutations/removals.
- Check retries, partial reads, duplicate/out-of-order fragments, timeouts, session changes, close/drain, and stale state after reconnect.
- Prefer `hashret()` / `answers()` for request matching and `TCPSession` / `tcp_reassemble()` for appropriate TCP reassembly rather than parallel implementations.

## 7. Error handling and cleanup

- Do not catch all exceptions and silently continue. Catch expected errors and preserve diagnostic context.
- Initialize variables used by `finally` before failure can occur; avoid masking the root cause during teardown.
- Make re-entry/retry/close behavior predictable. Do not fix malformed input by catching every error at the top and returning a plausible but wrong packet.

## 8. Performance

- Inspect hot paths: `Packet.__init__`, field conversion, dissection, list parsing, socket I/O.
- Avoid copies of large buffers, unnecessary `bytes()` conversions, repeated walking of packet layers, and unbounded rescans.
- Use representative before/after measurements for changes to common paths; do not infer an optimization merely from shorter source code.

## 9. Regression tests and interoperability

- A bug-fix test should fail on the pre-fix code, pass with the fix, and assert the failing behavior directly.
- For protocol additions, cover independent incoming bytes, expected serialized bytes, bindings, computed values, and meaningful malformed/truncated cases.
- In UTScapy `.uts`, the final expression determines pass/fail; use explicit `assert` for conditions before it and never use the variable `_`.
- Tests should be added next to other tests that touch similar components, if possible.
- Add to the existing campaign. Keep tests deterministic; mock external services and hardware unless live interoperability is the behavior under test.
- If relevant and feasible, cross-check with Wireshark, a third-party dissector, or hardware captures.

## 10. Merge hygiene

- Match PEP 8, imports, naming, required commit `AI-Assisted` disclosure, relevant CI checks and documentation restrictions in upstream contribution guidance.
- Follow project direction not to generate human-facing material in `doc/` with AI.
- Keep review remarks neutral, small and grounded; verify AI-suggested defects manually.

## 11. Code placement and public architecture

- `scapy/layers/` for common protocols, `scapy/contrib/` for uncommon/specialized protocols; core layers must not import contrib.
- Protocol-related functionality belongs beside the layer when practical.
- Check the intended loader and import path: core layers load by default, while contrib modules are loaded with `load_contrib()`.
- Avoid importing underscored symbols across modules. Follow `<protocol>_` / `<PROTOCOL>_` / `<Protocol>` naming guidelines.
- Respect generated sources; change generators rather than outputs.

## 12. Quiet, useful logging

- Use `scapy.error.log_runtime` except for messages intended only for interactive mode (`log_interactive`).
- On ordinary packet dissection, stay at `INFO` or below unless a critical or security condition warrants warning/error.
- On explicit user-invoked actions or packet construction, warnings can be appropriate. Do not warn for every malformed packet in an untrusted capture.

## Evidence standard for review comments

Prefer a three-part explanation:

1. **Trigger:** exact packet bytes, user action, state or protocol condition.
2. **Consequence:** why the changed implementation violates a required invariant.
3. **Fix:** smallest change that resolves the issue without added abstractions.

If the issue is only suggested by AI or an older review comment, verify it still exists in the current head before reporting. Avoid over-counting duplicated bot comments. When assessing reviewer preferences, weight concrete human-reviewed and actually fixed behavior more heavily than verbose automated speculation.

## Upstream references

- `AGENTS.md` and `CONTRIBUTING.md` in the Scapy checkout
- `.github/skills/scapy-packet-fields/SKILL.md`
- `doc/scapy/build_dissect.rst` (published as https://scapy.readthedocs.io/en/latest/build_dissect.html)
- `doc/scapy/development.rst` and `SECURITY.md`
