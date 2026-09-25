# Design decisions

## Why deny-by-default

An allowlist policy engine (`agent_sandbox/policy.py`) treats every tool
and every argument shape as forbidden until explicitly granted. The
alternative -- a denylist of known-bad tools/args -- fails the moment an
attacker finds a shape the denylist author didn't think of (a subdomain
that looks like the allowed host, an IP literal instead of a hostname, a
scheme downgrade from `https` to `http`). Deny-by-default converts "did we
think of every attack" into "did we enumerate every legitimate need,"
which is a much smaller and more stable set to get right, and which fails
*closed* rather than *open* when the policy author misses a case.

This project's `policies/default.yaml` demonstrates the pattern: `fetch_url`
is allowed only to four specific hostnames over `https`; everything else,
including a hostname that merely *contains* one of those four as a
substring (`docs.trusted.example.evil.example`), is rejected by
`_validate_network` in `agent_sandbox/policy.py`.

## Why provenance-based defense (taint tracking) beats input filtering

The obvious first instinct for prompt-injection defense is a filter: scan
incoming text for phrases like "ignore previous instructions" and strip or
block them. This project's quarantine step does exactly that as one layer
-- but a filter alone is not the primary defense, for two reasons visible
directly in this codebase:

1. **Filters are a moving target; flow rules are not.** `agent_sandbox/quarantine.py`'s
   instruction-pattern list will always be incomplete against a
   sufficiently creative attacker (that's exactly what
   `encoding_obfuscation` demonstrates: ROT13 and hex payloads sail past
   the naive brain's *decoder*, let alone a keyword filter). The taint
   flow rule in `agent_sandbox/taint.py` does not depend on recognizing
   *what* an attacker said -- only on *where the data came from* and
   *where it is trying to go*. `require_flow` blocks `untrusted -> sink`
   regardless of whether the untrusted payload used English, base64, or a
   language the filter author never anticipated.

2. **Filtering degrades data; provenance preserves it.** A keyword filter
   that just deletes suspicious substrings from tool output also destroys
   legitimate content that happens to contain those substrings (a
   changelog that legitimately says "this endpoint is now deprecated;
   ignore the old response format"). Provenance tracking doesn't need to
   decide up front whether content is malicious -- it just tracks where it
   came from and enforces the flow rule at the one place it matters: the
   sink. Benign untrusted content that never tries to reach a privileged
   sink is untouched.

Provenance is also *explainable* in a way filtering is not: when
`TaintViolation` fires, `agent_sandbox/taint.py`'s `Tainted.chain_description()`
reports the exact hop-by-hop path the data took -- which tool produced it,
which extraction step transformed it, and which sink it was headed for --
so an operator reviewing a blocked run sees a causal story, not a bare
"blocked."

## Why the quarantined-LLM pattern

Even with taint tracking, something still has to read untrusted content
and produce *something* useful from it (a summary, a list of names) for
the privileged agent to reason about -- otherwise the agent can never act
on anything it fetches. The risk is that the thing doing the reading is
itself an LLM that can be talked into disobeying its own extraction
instructions, exactly the class of vulnerability this project defends
against in the first place. Two structural choices address that:

* The extractor's *output space* is a fixed JSON Schema with exactly two
  fields (`summary`, `entities`) and `additionalProperties: false`
  (`agent_sandbox/quarantine.py`, `DIGEST_SCHEMA`). There is no field a
  tool call or a free-form directive could occupy, so even a fully
  compromised extractor cannot hand the privileged loop anything but text
  in those two shapes.
* This project's default extractor is not a model call at all -- it's a
  deterministic function that drops any sentence matching an
  instruction-shaped pattern before the summary is ever assembled
  (`_matches_instruction`). `agent_sandbox/anthropic_adapter.py` shows
  where a real model call would sit in this pipeline, and deliberately
  *discards* that model's own JSON response, re-deriving the digest with
  the deterministic extractor instead -- documented there as: "a model can
  be prompt-injected into violating its own instructions, but a JSON
  Schema validator cannot." A real deployment gets defense in depth by
  running both and requiring agreement, but the schema-validated
  deterministic path is the floor, not the ceiling.

## Why declassification has two paths, scoped differently

An earlier version of this project's benign corpus never presented
untrusted-derived data at a privileged sink at all, which made its 0%
false-positive rate close to tautological -- the taint flow rule was never
actually exercised against a legitimate task. Once the corpus grew to
include the real false-positive surface (forwarding a summary of an
untrusted email, posting a fetched page's digest to a webhook), naive
taint enforcement's cost became visible and ugly: a 33.3% false-positive
rate (`MEASUREMENTS.md`). That number is the reason this project has a
declassification design at all, and it shapes why there are two paths
instead of one, scoped very differently:

* **Human approval** clears *any* untrusted argument, because a human can
  apply judgment a fixed rule can't. The cost is that it needs a human in
  the loop for every such flow, and its safety margin is bounded by
  approver diligence (see `THREAT-MODEL.md`'s explicit callout of this).
* **Quarantine-mode auto-declassification** clears *only* the `entities`
  field, never `summary`, and only when that specific argument was named
  by the operator's own trusted directive. Three properties make this
  narrow scope load-bearing, not incidental:
  1. `entities` is schema-capped at 120 characters and validated against
     `DIGEST_SCHEMA`'s pattern -- it structurally cannot carry a long
     freeform payload.
  2. Every sentence contributing to `entities` already passed through the
     same instruction-stripping pass that `summary` did -- so an entity
     can't itself be an un-stripped directive.
  3. The eligibility check in `agent_sandbox.agent.run_sandboxed` requires
     both that the argument is tagged `"untrusted_digest_entity"` and that
     the operator's own trusted task contains the `{{DIGEST_ENTITY}}`
     placeholder. A directive found inside untrusted content (an
     attacker's own payload) is tagged plain `"untrusted"`, which the tag
     check excludes; a real model that free-forms an argument happening to
     equal an entity is excluded by the opt-in check, which nothing an
     attacker writes can satisfy. See
     `tests/test_redteam.py::test_declassification_bypass_probes_are_blocked_under_every_configuration`
     and
     `tests/test_agent.py::test_quarantine_autoclear_requires_the_operator_to_have_named_a_digest_entity`.

  What these three properties do **not** give is any guarantee about an
  entity's *meaning*. Every element of `entities` is derived from attacker-
  controlled text, and their order follows the order of that text, so an
  attacker who knows the operator will forward "the extracted reference"
  can decide what that reference is. `redteam/adaptive.py`'s
  `adaptive_declassify_entity-02` does exactly that and is the one adaptive
  case that reaches the approval gate. Keeping this path is a deliberate
  trade of one defense layer for a 10-point reduction in false positives;
  `THREAT-MODEL.md` says so, and a deployment that cannot rely on its
  approvers should run `declassify_via=None`.

`summary` is deliberately never eligible for automatic clearance: it is
long, freeform, and only capped in *length*, not in what kind of content
it can carry, so "schema-validated" is a much weaker guarantee for it than
for `entities`. That's why 7 of the 10 new benign false positives still
require a human even under `declassify_via="quarantine"`.

## What an adaptive attacker could still do

This project is honest about its scope in `THREAT-MODEL.md`; the short
version relevant to design decisions: the corpus tests *known* attack
categories against a *fixed* pattern-matching brain. An adaptive attacker
who can observe the sandbox's behavior could:

* Search for a directive grammar the pattern matcher doesn't recognize at
  all (this project's `_DIRECTIVE_RE` is a fixed, disclosed grammar -- a
  real deployment's actual LLM has a much larger and less predictable
  action space, and the corresponding real-world defense needs schema-
  constrained tool-calling, not regex matching, to close that gap).
* Attempt to poison the *quarantine* step's entity/summary output with
  content engineered to look benign to the extractor but meaningful to a
  downstream trusted-side process that re-parses it (a second-order
  injection). This project's flat, capped-length string schema resists
  this better than free text would, but is not a formal proof against it.
* Chip away at the network allowlist via legitimately-hosted redirects or
  compromised allowlisted infrastructure -- the allowlist trusts the
  hostname, not the content served, and this project does not model
  supply-chain compromise of an allowlisted host.

`redteam/adaptive.py` turns the first two of these from speculation into
measurement: twelve cases written against the quarantine schema, the entity
extractor's filter, the placeholder mechanism, the approval gate's
presentation, and the gap between per-argument and per-decision provenance.
One of the twelve succeeds. The rest of that list stays speculative, and
the set shares a weakness with the corpus it supplements: it was written by
the same people who wrote the defenses, so it probes the gaps its authors
could think of.

These gaps are why this project positions itself as *the policy layer*, not
*a guarantee of safety* -- see `THREAT-MODEL.md` for the full, explicit list
of what is and is not defended against.

## Addendum: adding a real Gemini backend without touching the defense

When a real Vertex AI Gemini backend (`agent_sandbox/gemini_adapter.py`)
was added alongside the simulator, the guiding constraint was that it
must not require touching `policy.py`, `taint.py`, or `quarantine.py`'s
enforcement logic at all -- only the "brain" (what decides which tool to
call) should be swappable. This was done by giving
`agent.py::run_naive`/`run_sandboxed` `decide_fn`/`extract_fn` parameters
that default to the existing simulator functions, so every existing call
site and every existing test is unaffected, and the live backend is
reached purely by passing different callables with identical signatures.

One real design problem surfaced by this exercise, not visible from the
simulator alone: the simulator's quarantine-mode auto-declassification
relies on a `{{DIGEST_ENTITY}}` placeholder mechanism that only the
*operator's own trusted directive* can write (see
`llm_sim.py::_apply_digest_placeholders`) -- a real model has no such
convention and simply free-forms its tool-call arguments. The live
adapter has to attribute provenance to each argument *after the fact*
(`gemini_adapter.py::attribute_provenance`), by checking whether the
value showed up in the trusted task text, the digest's `summary`, or the
digest's `entities`. This is a heuristic, not a structural guarantee, and
it measurably under-performed the simulator's mechanism in one specific
way: see `MEASUREMENTS.md` Part 2 for the `benign_forward_entity-01` case
where the original ordering (summary checked before entities) caused
quarantine-mode's one legitimate auto-clear rule to miss a value it should
have caught. That result was published before the fix was applied, because
this project's rule against tuning results after seeing them applies to
its own adapter code, not just to the red-team corpus.

The fix that followed is in two parts, and the second part is the one
worth reading. Reordering the attribution by evidence strength is
straightforward. But attribution is a statement about where a value came
from, and the auto-clear also needs a statement about whether the operator
asked for it -- which the simulator got for free, since only a trusted
directive can write `{{DIGEST_ENTITY}}`, and the live adapter had no
equivalent. Reordering alone moved one attack case from being blocked by
the taint rule to being blocked only by the approval gate, with no change
in attack success rate to signal it. The opt-in check in `run_sandboxed`
restores the missing half, and is enforced identically for both brains
rather than reimplemented per-adapter.
