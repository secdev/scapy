---
name: Scapy security audit
description: Use this when conducting a long-running autonomous security audit of Scapy, validating a suspected vulnerability, or preparing a source-backed security report.
---

# Scapy security audit

Use this skill to run an autonomous, evidence-driven search for severe, non-obvious, exploitable vulnerabilities in Scapy. Prioritize remotely reachable flaws, meaningful trust-boundary violations, and combinations of primitives that form high-impact exploit chains. Continue after the first confirmed result while time remains for a more severe finding, an independent vulnerability family, or a stronger validated chain.

## 1) Prepare the campaign

- Use the scope and reporting policy in [`SECURITY.md`](../../../SECURITY.md); do not restate it in the audit artifacts.
- Read [`AGENTS.md`](../../../AGENTS.md) before preparing a fix or regression; it owns the project's test form and commands.
- Leave `conf.debug_dissector` at its default value while establishing caller-visible behavior.
- During discovery, keep tracked source unchanged and use scratch harnesses for experiments. Do not retrieve candidate answers from vulnerability disclosures, advisories, issue reports, exploit writeups, prior audits, security patches, release notes, or repository history. Ordinary technical references such as protocol specifications and runtime semantics are allowed when needed to understand the supplied source.
- State the realistic caller, configuration, input source, and attacker capability before tracing a path. A direct call to an internal parser is not automatically a supported or attacker-reachable entry point.
- Write the security invariant before testing the suspected operation. Examples of invariant shapes include bounded work per wire-representable input, continued processing after malformed input, reply only after the required state transition, and acceptance only after the required authentication check. Treat these as hypotheses, not repository guarantees.
- Assume that at least one severe vulnerability exists so the search does not stop at easy negatives, but never lower the finding threshold or manufacture a result.

At the first tool call, record the UTC start time in the campaign notes described below.

## 2) Derive the attack-surface inventory

Build the inventory from the code under audit: enumerate the real outer boundaries where untrusted bytes enter, then work inward through the transformations, validation, dispatch, state, and sensitive operations the implementation actually uses. Record each architecture-specific approach family in the coverage registry, including what was examined and how deeply, rather than beginning from a fixed component map.

## 3) Create the canonical artifacts

Use these default filenames throughout the campaign:

- `SECURITY_AUDIT_NOTES.md`: architecture, trust boundaries, attack surfaces, approach-family and coverage registries, hypotheses, experiments, failed routes with reasons, unexplored areas, elapsed time, and checkpoint entries.
- `SECURITY_PRIMITIVES.md`: established or suspected primitives, each primitive's source, attacker control, constraints, confidence, possible consumers, and composition relationships.
- `SECURITY_AUDIT_CANDIDATES.md`: every serious result classified as Confirmed, Strong / validation incomplete, Unresolved, or Rejected, with concrete rejection reasons or exact missing evidence.
- `SECURITY_AUDIT_REPORT.md`: the reconciled final report.

These names are defaults. The reader may rename or relocate them, but must choose all four canonical paths before spawning workers and use those paths consistently. Prefer an audit scratch directory outside the working tree's tracked files so the audit does not dirty the repository.

Only the root agent may update the canonical artifacts. Workers must return evidence to the root instead of editing those files. They may create uniquely named scratch harnesses or reproducers outside tracked source, preferably in the audit scratch directory or a temporary directory.

In the coverage registry, track each architecture-specific approach family as deeply examined, shallowly examined, or not examined. Use deeply examined only after tracing a realistic entry point through its defenses to the sensitive operation and checking important runtime assumptions. Reading a file or finding a suspicious operation is shallow coverage.

In the primitive registry, treat a primitive as a bounded capability, not automatically as a finding. When combining primitives, trace the output of one into the input of the next and validate representation, state, lifetime, ordering, and every intervening defense. Never treat a required but unproven primitive as established.

## 4) Orchestrate Codex workers

The root agent exclusively controls campaign-level delegation and the canonical artifacts. Use parallel discovery only where assignments can proceed independently.

Use the configured default subagent model and reasoning effort. Do not specify or override either setting in a spawn request. The current `spawn_agent` result and `list_agents` output do not report model or reasoning effort, so runtime confirmation is unavailable through these interfaces. If a future interface reports either value, stop the campaign and report a mismatch rather than continuing with a mixed worker pool.

Call Codex's `list_agents` before every `spawn_agent` request. If no slot is available, call `wait_agent` and wait for a worker to complete; do not attempt or repeatedly retry another spawn.

Discovery and redirected-discovery workers get no inherited root conversation or investigation history. In every Codex spawn request, set:

```yaml
fork_turns: "none"
```

`fork_turns: "none"` is the available control for passing no surrounding conversation to the worker. The interface has no separate context toggle; do not add an unsupported context field.

Do not include `model` or `reasoning_effort` in the request. Tell every worker that it must not spawn agents, and repeat that restriction in every new or follow-up assignment. Also tell workers not to edit canonical audit artifacts.

Give each discovery worker only:

- a bounded attack surface or vulnerability formulation;
- the repository-integrity and external-information constraints that apply to the run;
- the evidence standard and return contract below;
- instructions not to spawn agents or edit canonical audit artifacts.

Never tell a discovery worker the root's leading hypothesis, favored findings, or other workers' results. This isolation applies during independent and redirected discovery so workers do not converge prematurely.

Every worker must return all ten items:

1. scope examined and hypotheses attempted;
2. exact affected code paths;
3. attacker-controlled input or influence;
4. relevant validation and defenses;
5. the complete path to the claimed security impact;
6. experimental evidence or counterexample;
7. exploitability constraints and deployment assumptions;
8. classification as Confirmed, Strong / validation incomplete, Unresolved, or Rejected;
9. confidence;
10. recommended next action.

Vague status reports do not satisfy this contract.

For adversarial validation, send a compact candidate packet containing:

- the attacker model;
- the exact code path;
- the evidence;
- relevant defenses;
- exploitability constraints;
- open questions;
- an explicit task to falsify the candidate.

Do not include unrelated campaign history. Assign validation to a worker that did not develop the candidate when capacity permits.

## 5) Run three timed phases

Use a 75-minute active investigation budget by default. The reader may scale all of these times for a different run, but must preserve the phases, synthesis checkpoints, final-reconciliation window, and no-idling rule. With the default budget, perform root synthesis checkpoints at approximately minutes 20, 40, and 60. Do not begin final reconciliation before minute 70, do not terminate before minute 75, and aim to finish by minute 85.

### Phase 1: independent discovery

Start a genuinely diverse portfolio across attack surfaces, trust boundaries, components, and vulnerability families. Preserve several incompatible hypotheses through the early campaign. Do not use a fixed component allocation, and do not share results among discovery workers. If workers cluster on one attractive surface, redirect available capacity toward materially different components, boundaries, or security ideas.

### Phase 2: redirected discovery

Use the coverage and disposition registries to move capacity away from crowded surfaces and over-investigated approach families toward unexamined components, materially different hypotheses, unresolved exploit conditions, and gaps exposed by falsified routes. Redirect a blocked approach by changing the attack surface, abstraction level, component, or vulnerability family.

### Phase 3: adversarial validation and composition

Challenge serious candidates, test whether independently established primitives compose, and run a final independent search outside the leading finding cluster. Validate every required link in a proposed chain. A candidate does not become stronger merely because several workers repeat the same unsupported assumption.

At each checkpoint, perform this complete synthesis list:

- reconcile every completed worker result into the disposition ledger;
- identify over-investigated and under-investigated families;
- record rejected hypotheses and the evidence that falsified them;
- update primitive, candidate, and coverage registries;
- redirect free capacity to the highest-value coverage gap or unresolved exploit condition;
- stop assigning general exploration to a mature finding unless a specific missing condition remains;
- record elapsed time and the checkpoint in `SECURITY_AUDIT_NOTES.md`.

If the artifacts were renamed or relocated, record the checkpoint in the canonical campaign-notes file chosen at startup.

Every serious worker result must be promoted, rejected with a concrete reason, or retained as Strong / validation incomplete or Unresolved with its missing evidence identified. It must not disappear when focus changes or context is compacted.

Mark a route blocked when it depends on an unsupported assumption, unrealistic capability, unavailable primitive, or repeatedly unproven condition. Revisit it only when new code, evidence, or an established primitive can materially advance it.

An unsuccessful hypothesis, a well-defended component, or completion of the first worker wave is a signal to redirect, not to finish. Do not finish early because a hypothesis failed or the first worker wave completed. Continue while time remains for underexplored coverage, adversarial validation, or exploit composition. Never sleep or idle merely to consume time. If a hard system limit prevents completion, preserve the current state and label the campaign incomplete.

## 6) Apply a strict finding threshold

A finding requires a realistic attacker capability and a complete, source-backed path from attacker influence, through the applicable validation and defenses, to a violated security invariant and meaningful impact. Establish important runtime and deployment assumptions experimentally when practical.

Suspicious code alone is not a finding. Do not promote generic hardening, a dependency version concern without an applicable demonstrated vulnerability, unreachable unsafe behavior, an unvalidated parser anomaly, a speculative race, a crash without meaningful security consequence, or a claim requiring unrealistic attacker capability. Reject a path blocked by earlier authentication, authorization, validation, normalization, canonicalization, bounds checks, representation changes, or lack of attacker control. Do not treat an unproven primitive required by a proposed chain as established.

Prefer one completely established result over multiple speculative ones, but continue checking distinct surfaces and hypothesis families after confirming a result. Finding count is not a coverage measure. If no result meets the threshold, say so directly; do not promote unresolved leads to fill the report.

## 7) Prove behavior at the caller boundary

### 7.1) Account for the `Raw` fallback

Scapy deliberately catches dissector failures and may continue with `Raw`; [`SECURITY.md`](../../../SECURITY.md) states the policy and links to the implementation. With the default `conf.debug_dissector`, an inner failure that lands in `Raw` and remains contained is not a security finding. A finding must show that the security-relevant failure escapes the fallback and reaches the caller; a harness that calls only an inner parser has not established that.

For a candidate based on a dissector exception or stopped parsing:

1. exercise the normal outer entry point with the default configuration;
2. identify every applicable exception boundary between the failing operation and caller;
3. inspect the returned packet for `Raw` at the failed layer;
4. place a benign packet after the trigger and observe whether the same reader, receive loop, or sniffer continues;
5. promote only if the security-relevant failure escapes containment and is observable at the caller boundary.

The same principle applies to hangs and excessive work: measure the effect at the outer boundary rather than treating an expensive internal call as proof of reachable denial of service.

### 7.2) Require a negative control

Run the trigger and a negative control through the same outer entry point, configuration, initial state, and surrounding packet exchange. The negative control must remove or neutralize only the proposed trigger and show the claimed boundary holding. For stateful behavior, begin both runs from fresh equivalent state.

If the trigger and control both fail, both succeed, or never reach the claimed boundary, the experiment does not establish the defect. Record that result rather than interpreting the trigger run alone.

## 8) Establish and falsify every serious candidate

For each candidate, establish all applicable items:

1. attacker capability and exact controlled input, timing, ordering, or state;
2. concrete outer entry point and complete data- or control-flow path;
3. relevant authentication, authorization, validation, normalization, canonicalization, bounds, representation, and fallback defenses;
4. vulnerable operation and the violated security invariant;
5. resulting primitive and realistic confidentiality, integrity, or availability impact;
6. wire, runtime, configuration, deployment, mitigation, and exploitability constraints;
7. a minimal reproduction with deterministic observations and a negative control.

Use source inspection, existing tests, targeted harnesses, crafted inputs, tracing, debugging, instrumentation, fuzzing, and local instances where useful. Inspect the actual relevant third-party implementation when its behavior is security-critical and locally available. Unsupported statements that exploitation is likely, obvious, or straightforward do not close a missing link.

Then perform a separate falsification pass. Start from the claimed invariant and attempt to break the candidate with counterexamples: challenge reachability and attacker control, look for an earlier defense or alternate dispatch, verify default configuration, bound the input to a wire-representable form, check state, lifetime, integer, parser, cryptographic, privilege, and concurrency assumptions, and try to make the negative control indistinguishable from the trigger. Record the evidence whether the candidate survives or fails. Every High or Critical candidate must survive an independent attempt to falsify it.

## 9) Write the regression in Scapy's form

When the requested work includes fixing a confirmed defect, follow the project's regression form and verification commands in [`AGENTS.md`](../../../AGENTS.md).

The regression must drive the affected outer behavior when practical, include the triggering case and its negative control, and assert the security boundary rather than only the absence of an exception. Keep a smaller parser-level case only when it isolates the root cause in addition to the boundary-level regression.

## 10) Reconcile and report

Before returning, ensure no worker remains live, reconcile every worker result, and rerun representative reproducers when practical. `SECURITY_AUDIT_REPORT.md`, or the canonical report path chosen at startup, must include for every confirmed vulnerability:

1. title, severity, confidence, and attacker model;
2. affected code and root cause;
3. complete attack path from attacker influence to boundary violation;
4. precise exploit primitive and resulting security impact;
5. existing defenses and why they fail or constrain exploitation;
6. concrete reproduction, observations, and negative control;
7. deployment assumptions, mitigations, and exploitability limitations;
8. composition opportunities, without claiming unproven links.

Conclude with `Audit Coverage`, describing components, attack surfaces, approach families, depth of coverage, significant disproven hypotheses, and substantially unexplored areas. Then include `Highest-Value Unresolved Leads`, preserving the strongest hypotheses that still lack required evidence and naming the next experiment for each.

Operate autonomously. Preserve search diversity, resist premature convergence, falsify promising findings, redirect blocked work, and test whether modest primitives compose. Optimize for the most severe real vulnerability the source contains, not the number of report entries. Begin now.
