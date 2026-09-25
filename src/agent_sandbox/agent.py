"""The agent loop, in two variants: naive (unprotected) and sandboxed."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from agent_sandbox.approval import ApprovalCallback, ApprovalGate, auto_deny
from agent_sandbox.events import EventLog
from agent_sandbox.llm_sim import DIGEST_ENTITY_PLACEHOLDER, ToolCallIntent, naive_decide, sandboxed_decide
from agent_sandbox.policy import PolicyEngine
from agent_sandbox.quarantine import Digest, QuarantineViolation, extract as quarantine_extract
from agent_sandbox.secrets import SecretLeakage, SecretStore
from agent_sandbox.taint import Tainted, TaintViolation
from agent_sandbox.tools import SimulatedWorld, execute_tool


@dataclass(slots=True)
class UntrustedInput:
    """One piece of untrusted content a scenario delivers to the agent."""

    text: str
    carrier_tool: str | None = None
    carrier_args: dict[str, Any] = field(default_factory=dict)
    origin_label: str = "external content"


@dataclass(slots=True)
class Scenario:
    """One red-team (or benign) test case."""

    id: str
    category: str
    trusted_task: str
    untrusted_inputs: list[UntrustedInput] = field(default_factory=list)
    is_benign: bool = False
    check_success: Callable[[SimulatedWorld], bool] | None = None
    notes: str = ""

    def build_world(self) -> SimulatedWorld:
        world = SimulatedWorld()
        for inp in self.untrusted_inputs:
            if inp.carrier_tool == "fetch_url":
                world.web_pages[inp.carrier_args["url"]] = inp.text
            elif inp.carrier_tool == "read_email":
                world.emails[inp.carrier_args["msg_id"]] = inp.text
            elif inp.carrier_tool == "read_file":
                world.files[inp.carrier_args["path"]] = inp.text
        return world


@dataclass(slots=True)
class RunResult:
    scenario_id: str
    category: str
    variant: str
    attack_succeeded: bool
    blocked_by: str | None
    intent: ToolCallIntent | None
    log: EventLog


def _digest_index_for(value: str, digests: list[Digest], tag: str) -> int:
    """Which digest a sink argument actually came from, so a multi-source run shows the approver the origin that produced the value rather than whichever source happened to be read first."""
    for index, digest in enumerate(digests):
        if tag == "untrusted_digest_entity" and any(value.strip() == e.strip() for e in digest.entities):
            return index
        if tag == "untrusted_digest_summary" and digest.summary and value in digest.summary:
            return index
    return 0


def run_naive(
    scenario: Scenario,
    secrets: SecretStore | None = None,
    decide_fn: Callable[[str], ToolCallIntent | None] = naive_decide,
    event_log: EventLog | None = None,
) -> RunResult:
    """Run a scenario against the undefended baseline agent."""
    secrets = secrets or SecretStore()
    world = scenario.build_world()
    log = event_log if event_log is not None else EventLog()
    log.emit("run_start", {"scenario": scenario.id, "variant": "naive"})

    context_parts = [scenario.trusted_task]
    for inp in scenario.untrusted_inputs:
        if inp.carrier_tool is not None:
            result = execute_tool(inp.carrier_tool, inp.carrier_args, world, secrets)
            log.emit("tool_call", {"tool": inp.carrier_tool, "args": inp.carrier_args})
            log.emit("tool_result", {"tool": inp.carrier_tool, "ok": result.ok, "output": result.output})
            context_parts.append(result.output)
        else:
            context_parts.append(inp.text)
    context_text = "\n".join(context_parts)

    log.emit("llm_call", {"context_chars": len(context_text)})
    intent = decide_fn(context_text)
    log.emit("llm_result", {"intent": intent.tool if intent else None})

    attack_succeeded = False
    if intent is not None:
        log.emit("tool_call", {"tool": intent.tool, "args": intent.args, "triggered_by": intent.triggered_by})
        result = execute_tool(intent.tool, intent.args, world, secrets)
        log.emit("tool_result", {"tool": intent.tool, "ok": result.ok, "output": result.output})
        if scenario.check_success is not None:
            attack_succeeded = scenario.check_success(world)

    log.emit("run_end", {"attack_succeeded": attack_succeeded})
    return RunResult(
        scenario_id=scenario.id,
        category=scenario.category,
        variant="naive",
        attack_succeeded=attack_succeeded,
        blocked_by=None,
        intent=intent,
        log=log,
    )


def run_sandboxed(
    scenario: Scenario,
    policy_engine: PolicyEngine,
    secrets: SecretStore | None = None,
    approval_callback: ApprovalCallback = auto_deny,
    declassify_via: str | None = None,
    decide_fn: Callable[[str, list[Digest]], ToolCallIntent | None] = sandboxed_decide,
    extract_fn: Callable[[str], Digest] = quarantine_extract,
    event_log: EventLog | None = None,
) -> RunResult:
    """Run a scenario against the sandboxed agent."""
    secrets = secrets or SecretStore()
    world = scenario.build_world()
    log = event_log if event_log is not None else EventLog()
    log.emit("run_start", {"scenario": scenario.id, "variant": "sandboxed", "declassify_via": declassify_via})
    gate = ApprovalGate(approval_callback, log)

    trusted = Tainted.trusted(scenario.trusted_task, origin="operator task instruction")
    digests: list[Digest] = []
    tainted_digests: list[Tainted] = []
    blocked_by: str | None = None

    for inp in scenario.untrusted_inputs:
        if blocked_by is not None:
            break
        if inp.carrier_tool is not None:
            decision = policy_engine.evaluate(inp.carrier_tool, inp.carrier_args)
            log.emit("decision", decision.to_dict())
            if not decision.allow:
                blocked_by = f"policy:{decision.rule}"
                continue
            result = execute_tool(inp.carrier_tool, inp.carrier_args, world, secrets)
            log.emit("tool_call", {"tool": inp.carrier_tool, "args": inp.carrier_args})
            log.emit("tool_result", {"tool": inp.carrier_tool, "ok": result.ok, "output": result.output})
            raw = result.output
            origin = f"{inp.carrier_tool}({inp.carrier_args})"
        else:
            raw = inp.text
            origin = inp.origin_label

        tainted_raw = Tainted.untrusted(raw, origin=origin)
        try:
            digest = extract_fn(tainted_raw.value)
        except QuarantineViolation as exc:
            log.emit("error", {"kind": "QuarantineViolation", "detail": str(exc)})
            blocked_by = "quarantine_violation"
            continue
        log.emit(
            "decision",
            {
                "allow": True,
                "rule": "quarantine:extract",
                "reason": "untrusted content routed through quarantined extraction",
                "tool": inp.carrier_tool or "direct_input",
            },
        )
        digests.append(digest)
        tainted_digests.append(tainted_raw.derive(digest, step="quarantine.extract (schema-validated)"))

    intent: ToolCallIntent | None = None
    if blocked_by is None:
        log.emit("llm_call", {"trusted_chars": len(trusted.value), "digests": len(digests)})
        intent = decide_fn(trusted.value, digests)
        log.emit("llm_result", {"intent": intent.tool if intent else None})

    attack_succeeded = False
    if blocked_by is None and intent is not None:
        decision = policy_engine.evaluate(intent.tool, intent.args)
        log.emit("decision", decision.to_dict())
        if not decision.allow:
            blocked_by = f"policy:{decision.rule}"
        else:
            if policy_engine.is_sink(intent.tool):
                tainted_args: dict[str, Tainted] = {}
                for name, value in intent.args.items():
                    tag = intent.source_of(name)
                    if tag == "trusted":
                        tainted_args[name] = trusted.derive(value, step=f"argument '{name}' from trusted directive")
                    elif tag in ("untrusted_digest_summary", "untrusted_digest_entity") and tainted_digests:
                        index = _digest_index_for(value, digests, tag)
                        tainted_args[name] = tainted_digests[index].derive(
                            value, step=f"substituted into '{name}' from quarantine digest ({tag})"
                        )
                    else:
                        tainted_args[name] = Tainted.untrusted(
                            value, origin=f"argument proposed from untrusted text ({intent.triggered_by!r})"
                        )

                if declassify_via == "approval":
                    for name, tainted in list(tainted_args.items()):
                        if tainted.label != "untrusted":
                            continue
                        approval = gate.request(
                            intent.tool,
                            {name: intent.args[name]},
                            "declassify:approval",
                            tainted_args={name: tainted},
                        )
                        if approval.approved:
                            tainted_args[name] = tainted.declassify(reason=approval.reason, approved_by=approval.decided_by)
                elif declassify_via == "quarantine":
                    operator_named_entity = DIGEST_ENTITY_PLACEHOLDER in trusted.value
                    for name, tainted in list(tainted_args.items()):
                        if not operator_named_entity:
                            continue
                        if intent.source_of(name) == "untrusted_digest_entity" and tainted.label == "untrusted":
                            tainted_args[name] = tainted.declassify(
                                reason="schema-validated entity field from the quarantined extractor, "
                                "named as an argument source by the operator's own trusted directive",
                                approved_by="quarantine:schema_validated",
                            )
                            log.emit(
                                "decision",
                                {
                                    "allow": True,
                                    "rule": "declassify:quarantine_entity",
                                    "reason": "auto-declassified schema-validated entity argument",
                                    "tool": intent.tool,
                                },
                            )
                try:
                    policy_engine.check_taint_flow(intent.tool, tainted_args)
                except TaintViolation as exc:
                    log.emit("decision", {"allow": False, "rule": "taint_flow", "reason": str(exc), "tool": intent.tool})
                    log.emit("error", {"kind": "TaintViolation", "detail": exc.report()})
                    blocked_by = "taint_flow"
            if blocked_by is None and decision.requires_approval:
                approval = gate.request(intent.tool, intent.args, decision.rule, tainted_args=None)
                if not approval.approved:
                    blocked_by = "approval_denied"
            if blocked_by is None:
                try:
                    log.emit("tool_call", {"tool": intent.tool, "args": intent.args})
                    result = execute_tool(intent.tool, intent.args, world, secrets)
                    log.emit("tool_result", {"tool": intent.tool, "ok": result.ok, "output": result.output})
                except SecretLeakage as exc:
                    log.emit("error", {"kind": "SecretLeakage", "detail": str(exc)})
                    blocked_by = "secret_leakage"
                else:
                    if scenario.check_success is not None:
                        attack_succeeded = scenario.check_success(world)
    elif blocked_by is None and intent is None:
        blocked_by = "quarantine:no_directive_reached_brain"

    log.emit("run_end", {"attack_succeeded": attack_succeeded, "blocked_by": blocked_by})
    return RunResult(
        scenario_id=scenario.id,
        category=scenario.category,
        variant="sandboxed",
        attack_succeeded=attack_succeeded,
        blocked_by=blocked_by,
        intent=intent,
        log=log,
    )
