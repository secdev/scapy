---
name: scapy-code-review
description: Review or re-review Scapy pull requests, branches, patches, and protocol implementations for correctness, simplicity, Scapy-likeness, backwards compatibility, robustness, performance, and tests. Compare old and new code, trace prior human review comments to their subsequent fixes, and return concise, evidence-backed, actionable findings rather than speculative suggestions.
---

# Scapy code review

Perform focused, maintainer-style code reviews of Scapy changes. Prioritize real bugs and unnecessary complexity. Use the repository's `AGENTS.md` and `CONTRIBUTING.md` as authoritative policy; use this skill to apply them to specific code changes.

## 1. Establish the review scope

1. Identify the exact PR, commits, base revision, and head revision. Report the actual revisions when known; never invent a base or claim to have inspected unavailable versions.
2. Read the changed files, relevant original/base code, related callers and subclasses, and existing `.uts` tests. Read neighboring layers before proposing a new abstraction or pattern.
3. For a GitHub PR, inspect the PR discussion, inline review comments, review summaries, and subsequent commits. Treat specific **human** maintainer comments as strong signals for what to investigate, but validate each against the code. Automated and AI-generated reviews are leads, not proof. Do not infer authorship from comment length.
4. In a re-review, trace each material existing comment through **original behavior -> comment -> committed fix -> current behavior**. Do not re-report an issue that has been fixed.

Use the available repository and GitHub interfaces to inspect PR metadata, diffs, discussion, review comments, and revisions. Do not claim to have read comments, compared revisions, or executed checks that were inaccessible.

## 2. Apply the review rules

Review the change in the following order. Open [references/review-checklist.md](references/review-checklist.md) for concrete checks and typical failure modes.

1. **Correctness and protocol fidelity:** Byte and bit widths, endianness, length/count semantics, alignment, checksums, padding, payload dispatch, and specification conformance. Verify against independent packet bytes or implementations where possible; a self round-trip alone is weak evidence.
2. **Simplest Scapy-native design:** Favor `Packet`/`fields_desc`, built-in `Field` variants, `FieldLenField`, `post_build`, `extract_padding`, and layer binding over manual byte parsing, redundant methods, extra state, or new mini-frameworks.
3. **Compatibility and packet crafting:** Preserve established behavior, public APIs, defaults, explicit field overrides, and the ability to build malformed packets intentionally. Avoid compatibility aliases for symbols introduced only within the same PR.
4. **Robustness and lifecycle:** Inspect truncated/malformed input, bounded reads/allocations, partial initialization, cleanup, explicit and recoverable errors, and dissection fallback. Look for state invalidation errors after mutation, reassembly, retries, duplicate/out-of-order segments, or session changes.
5. **Performance:** Examine per-packet allocations, repeated lookups or traversals, copies, and algorithmic complexity. Request benchmarks for plausible hot-path regressions, not for every minor change.
6. **Tests and integration:** Verify bug reproducer, expected-byte assertions, relevant boundary inputs, state transitions, packet binding, independent interoperability checks, and UTScapy behavior. Reuse the existing campaign. Distinguish missing essential tests from optional extra coverage.
7. **Repository requirements:** Enforce existing module placement, naming, logging, generated-file rules, imports, and contribution requirements only when applicable to the changed code.

For protocol-level details consult `.github/skills/scapy-packet-fields/SKILL.md`. If a review uncovers a possible security vulnerability, follow `SECURITY.md` and its private reporting process. Do not put suspected vulnerabilities in a public review comment. The security-audit skill is a separate, deeper workflow; use it only when the user requests a security audit or that investigation is necessary.

## 3. Verify and filter candidate findings

- Start from an observed discrepancy or a concrete execution path. Establish **input/precondition -> old or changed code path -> incorrect result -> expected result**.
- Try a minimal reproducer or focused UTScapy test when permitted. Compare against the base implementation if evaluating a regression. If execution is unavailable, label the finding **code-inspection only** and explain the decisive evidence.
- Trace lifecycle and surrounding context before suggesting a one-line fix. A valid fix must not create a new problem elsewhere or erase user-specified malformed values.
- Do not report hypothetical edge cases, subjective stylistic preferences, or redundant refactoring as bugs. Do not suggest replacing an existing Scapy primitive with an equivalent helper.
- Recommend the **smallest sufficient fix**. Provide code suggestions only when they clearly improve precision; avoid unsolicited broad rewrites.
- Distinguish newly introduced bugs from pre-existing problems. Mention relevant pre-existing issues separately if they materially affect the PR, but do not falsely attribute them to the diff.

## 4. Produce a concise review

Present actionable findings first, most serious first. Keep each finding focused on one issue and the changed lines that expose it. Do not post the checklist, a general review essay, or optional observations when the user asked for a narrower scope.

For each finding provide:

- **Priority:** Use `P1` / `P2` / `P3` only when the review format or user requests priorities. A style preference alone is not blocking.
- **Location:** path and changed-line range, with a permanent GitHub line link if available.
- **Why:** concrete failing behavior and the exact conditions that trigger it.
- **Evidence:** minimal bytes/code/reproducer, specification reference, or a precise cross-file trace; state if not reproduced.
- **Minimal fix:** the smallest safe correction, with an example when useful.

For a re-review, precede new findings with a short **Previous review resolution** section that identifies `fixed`, `partially fixed`, or `still open` comments, with links. Avoid repeating earlier review text.

If the user requests a review and no substantial problems remain, say **No actionable findings identified** and name any material coverage limitations. Do not claim exhaustive correctness from partial inspection. Keep unverified suggestions out of the findings list.

When drafting text intended for a Scapy GitHub PR, commit, issue, or advisory, follow `AGENTS.md` and `CONTRIBUTING.md`: neutral English, concise explanation, source links, human verification, and explicit AI-assistance disclosure. Do not include CI or coverage summaries in a GitHub review comment. Do not use AI to answer a maintainer's comment. For a local analysis, summarize test commands/results only when useful to the user.
