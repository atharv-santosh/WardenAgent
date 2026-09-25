# Threat model

## What this project is

A policy-enforcement and provenance-tracking layer that sits between an LLM
agent's decision loop and the tools it can call, plus a red-team harness
that measures whether the layer actually reduces attack success rate
without destroying the agent's ability to do its job.

## In scope: what this defends against

* **Indirect prompt injection via tool output.** Content fetched from a
  URL, an email, or a file that contains an embedded directive aimed at
  the agent. Defended by: quarantining untrusted content before the
  privileged decision loop sees it (`agent_sandbox/quarantine.py`), and by
  the taint flow rule refusing to let anything derived from that content
  reach a privileged sink without explicit declassification
  (`agent_sandbox/taint.py`).
* **Direct injection from an unauthenticated or semi-trusted channel.**
  Content that arrives as if it were a normal user message but actually
  originates from an untrusted source (a public form, a forwarded
  message). Defended the same way: provenance is about *where data
  entered*, not *which API parameter it arrived in*.
* **Confused-deputy privilege escalation.** Untrusted content trying to
  induce the agent to call a tool with more privilege than the operator's
  actual request warrants (e.g. `grant_admin`). Defended by: the taint
  flow rule (untrusted directive -> privileged sink is blocked
  structurally) and by human approval gates on high-privilege tools
  (`agent_sandbox/approval.py`).
* **Data exfiltration, including side-channel attempts.** Directives that
  try to move secrets or sensitive data out via an outbound tool call's
  arguments, including hiding data in a URL query string. Defended by:
  sink tagging + taint flow rule, network egress host/scheme allowlisting,
  and outbound secret-leakage scanning (`agent_sandbox/secrets.py`).
* **Tool-argument smuggling.** Extra or malformed values riding along in
  an otherwise-plausible tool call (path traversal, extra recipients,
  injected shell metacharacters). Defended by: per-argument shape
  validation, path jails, and regex patterns enforced by the policy engine
  regardless of taint status.
* **Policy-boundary probing.** Attempts to find a gap in an allowlist via
  subdomain confusion, scheme downgrade, or IP-literal hosts. Defended by:
  the network validator explicitly rejecting IP literals and
  suffix-only host matches, and the path-jail validator normalizing `..`
  before checking containment.
* **A declassification-bypass attempt.** Content that explicitly claims to
  be "pre-approved," "cleared," or "declassified for forwarding" in an
  effort to talk either a human approver or an automated pipeline into
  waving untrusted data through to a privileged sink. Defended by:
  declassification being content-blind by construction (see the next
  section's honest limitation for the one place this still depends on
  human judgment, not code).
* **Secret exposure in model context.** Credentials referenced by opaque
  handle, resolved only inside tool execution, with an outbound scan that
  catches a raw value that leaked into an argument by some other path.
* **Encoded/obfuscated payloads, up to the encodings this project's
  extractor understands.** Base64 is decoded and stripped like any other
  instruction-shaped text; zero-width-character obfuscation is stripped
  before pattern matching.

## Declassification is necessary, and it is the one place this project relies on judgment, not just code

Taint tracking with no way to ever clear untrusted-derived data for a
legitimate sink call is not a defense a real deployment could ship: it
blocks 33.3% of a modest benign-forwarding corpus (`MEASUREMENTS.md`).
This project ships two declassification paths, and is explicit about what
each one actually relies on:

* **Human approval** (`declassify_via="approval"`) is content-blind: the
  approval gate is shown a structured request -- tool, args, and the full
  provenance chain -- never the untrusted text itself, and never anything
  claiming to pre-authorize itself (`declassification_bypass_probe-01/02`
  in the corpus prove this: a directive that claims to be "pre-approved"
  is blocked identically to one that doesn't). **But this path's safety
  still depends on the human actually reading the provenance chain and
  exercising judgment.** A rubber-stamp approver -- someone who clicks
  "approve" on everything without reading the chain -- defeats this
  mechanism completely, and nothing in this codebase can detect or prevent
  that. `MEASUREMENTS.md`'s 0% approval-mode attack-success-rate holds
  because the measurement uses a conservative `auto_deny` callback for the
  attack corpus specifically to avoid resting the headline number on an
  optimistic assumption about approver diligence. A real deployment's
  actual safety margin is only as good as its actual approvers.
* **Quarantine-mode auto-declassification** (`declassify_via="quarantine"`)
  has no human-judgment dependency, but is deliberately narrow: it only
  clears the `entities` field (short, length-capped, pattern-constrained),
  never the freeform `summary` field, and only when the specific argument
  was named by the *operator's own trusted directive* -- never by anything
  a directive found in untrusted content itself proposes. This is why it
  only resolves 3 of the 10 new benign-forwarding false positives, not all
  10 (`MEASUREMENTS.md`). That's the intended trade: less human burden, at
  the cost of leaving most realistic forwarding tasks (which need the
  freeform summary, not just an extracted entity) still gated on a human.

  **The value it clears is still attacker-derived content.** The schema
  bounds an entity's length and character class; it says nothing about its
  meaning, and an attacker who controls the untrusted text controls every
  element of `entities` and their order. `adaptive_declassify_entity-02`
  exploits exactly that: the operator legitimately asks to forward an
  extracted reference, the attacker writes first so `entities[0]` is
  theirs, and the value is auto-cleared with no human step. It is the one
  adaptive case in this repository that gets past the taint layer, and the
  approval gate is the only thing left in front of it -- which means this
  configuration's safety collapses onto the approver-diligence dependency
  described above. It is measured and reported in `MEASUREMENTS.md` rather
  than removed, because the alternative is a 33.3% false-positive rate;
  a deployment that cannot rely on its approvers should run
  `declassify_via=None` and pay that rate.

## Explicitly out of scope: what this does NOT defend against

Overclaiming is the fastest way to lose credibility with a security-literate
reader, so this section is deliberately blunt:

* **Approver/reviewer judgment quality.** As stated above: human-approval
  declassification is only as strong as the human doing the approving.
  This project measures and enforces the *mechanism* (structured,
  content-blind requests; logged decisions) but cannot measure or enforce
  *diligence*. Treat the approval-mode 0% ASR figure as "the mechanism does
  not leak by itself," not as "a human can't be talked into approving
  something they shouldn't."

* **This started as a simulation, and now has a real-model measurement
  alongside it -- read `MEASUREMENTS.md` for which is which.** The
  original "LLM" in this repository is a deterministic, disclosed pattern
  matcher (`agent_sandbox/llm_sim.py`), not a real language model, and
  every number in `MEASUREMENTS.md` Part 1 is a statement about *this
  corpus against this architecture, simulated*, not a universal claim
  about prompt injection. Part 2 closes part of that gap: the exact same
  50-case attack corpus, the exact same policy/taint/quarantine
  enforcement code, run against real Gemini models
  (`gemini-2.5-flash-lite`, `gemini-2.5-flash`) over Google Vertex AI,
  with committed, replayable trajectory fixtures
  (`tests/fixtures/gemini/`). Three things came out of that comparison,
  and all three are reported honestly rather than smoothed over:
  1. **Naive susceptibility was lower than the simulator predicted, but
     still severe** -- 74.0% real ASR (`gemini-2.5-flash-lite`) vs. the
     simulator's 96.0%. A real model resists some straightforward
     injected directives the fixed-grammar brain always falls for
     (particularly bare-encoding and URL-exfiltration attempts), but a
     74% attack success rate against an undefended agent is not a result
     that should read as reassuring.
  2. **The sandboxed architecture's 0.0% ASR held identically against
     real models** -- the one result this project most wants to be true
     held up under the harder test. This is because the defense is
     structural (quarantine never lets the privileged loop see raw
     untrusted text; the taint flow rule blocks untrusted-tagged
     arguments at the sink regardless of what any brain, real or
     simulated, "decides"), not because a real model happens to behave
     the way the simulator assumed.
  3. **One defense mechanism that worked in simulation did not transfer to
     the real backend, was reported as measured, and has since been
     fixed**: quarantine-mode auto-declassification resolved 3/10 benign
     false positives in the simulator but resolved zero against the real
     model, because the live adapter's provenance-attribution heuristic
     (`gemini_adapter.py::attribute_provenance`, necessary because a real
     model has no placeholder mechanism to name its own argument's source)
     checked a digest's `summary` before its `entities`, and mis-tagged a
     value that appeared in both. Attribution now resolves by evidence
     strength rather than field order, and the real quarantine-mode
     false-positive rate is 23.3%, matching the simulator. Fixing it also
     exposed that attribution alone would hand the auto-clear to any
     argument a free-forming model happened to make equal to an entity, so
     `run_sandboxed` now requires the operator's own trusted directive to
     have named a digest entity -- the opt-in the simulator's placeholder
     provided implicitly and the live path never had. `MEASUREMENTS.md`
     keeps both the before and the after numbers.
  A real model's action space is still far larger and far less
  predictable than the fixed `call TOOL(args)` grammar the simulator's
  brain recognizes, and the live corpus run here is two model families on
  one disclosed corpus, not a general claim about all models or all
  attacks -- see "A fully adaptive, sandbox-aware attacker" below, which
  applies to the real-model measurement exactly as much as it applies to
  the simulator's.
* **Novel encodings the extractor doesn't decode.** This project's naive
  baseline decodes base64 but not ROT13, hex, or other encodings -- which
  is realistic (real models vary in what they'll decode unprompted) but
  means the corpus does not claim to enumerate every possible encoding. A
  sufficiently exotic encoding could sail past *both* the naive brain's
  decoder and a keyword-based instruction filter; the taint flow rule
  (which does not depend on recognizing the payload at all) is the layer
  that actually has to hold in that case, and it is the layer this project
  invests in most.
* **Compromise of an allowlisted host.** The network policy trusts a
  hostname, not the content that host serves. If `docs.trusted.example`
  is compromised or its content is attacker-controlled, this project's
  network allowlist provides no protection -- only the taint/quarantine
  layers do, and only against the injection patterns they recognize.
* **Semantic/social-engineering attacks that never touch a privileged
  tool.** An attacker convincing the agent to give bad advice, leak
  information through the *text* of a benign-looking response rather than
  a tool call, or waste budget on useless-but-allowed actions is not
  something a tool-call policy layer can see, let alone stop.
* **Side channels outside modeled tools.** Timing channels, cache
  side-channels, or exfiltration through a tool this project doesn't
  model are not covered. `http_post`'s URL-query-string exfil attempt is
  modeled explicitly because it is a well-known real pattern, but the
  corpus is not an exhaustive list of side channels.
* **A fully adaptive, sandbox-aware attacker.** The 50-case red-team
  corpus is static and disclosed (it ships in this repository), and static
  corpora measure resistance to *known* attack shapes: evidence of a
  floor, not a ceiling. `redteam/adaptive.py` narrows that gap without
  closing it -- twelve cases written after reading this codebase, aimed at
  the quarantine schema's bounds and character class, the entity
  extractor's instruction filter, the declassification placeholder
  mechanism, the approval gate's presentation, and the gap between
  per-argument provenance and decision provenance. One of the twelve gets
  past the taint layer (see the quarantine-mode bullet above). That set is
  written by the same people who wrote the defenses, which is a real
  limitation of its own: it probes the gaps its authors could think of.
* **Multi-agent and cross-session attacks.** This project models a single
  agent run in isolation. An attacker who can poison state that persists
  *across* runs (a shared memory store, a cached tool result reused by a
  later run) is not modeled here.

## Bottom line

This project demonstrates that provenance-based flow control plus
schema-constrained extraction plus deny-by-default policy enforcement is a
categorically stronger defense than "the model is asked nicely not to
follow injected instructions" -- which is the status quo in a naive tool-
calling agent, and which this project's own naive baseline shows failing
96% of the time against a simulated attack corpus, and 74.0% / 68.0% of
the time against real Gemini models (`gemini-2.5-flash-lite` /
`gemini-2.5-flash`) on the identical corpus (`MEASUREMENTS.md`). The
sandboxed architecture measured 0.0% attack success in every case --
simulated and real. It is not a claim that this specific implementation
is production-hardened, nor that provenance tracking is sufficient on its
own against a determined, sandbox-aware adversary, and it is not a claim
that generalizes beyond the two model families and one disclosed corpus
actually measured here.
