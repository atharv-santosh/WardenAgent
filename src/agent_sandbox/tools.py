"""Simulated tool implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from agent_sandbox.secrets import SecretStore, scan_for_leakage


@dataclass(slots=True)
class ToolResult:
    ok: bool
    output: str
    error: str | None = None


@dataclass(slots=True)
class SimulatedWorld:
    """The fake external world tool calls read from and write to."""

    web_pages: dict[str, str] = field(default_factory=dict)
    emails: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    sent_emails: list[dict[str, str]] = field(default_factory=list)
    http_posts: list[dict[str, str]] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    admin_grants: list[str] = field(default_factory=list)
    shell_commands: list[str] = field(default_factory=list)
    call_log: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def called(self, tool_name: str, **expected: str) -> bool:
        """True if ``tool_name`` was actually executed with args containing every ``expected`` substring."""
        for name, args in self.call_log:
            if name != tool_name:
                continue
            if all(key in args and expected_val in str(args[key]) for key, expected_val in expected.items()):
                return True
        return False


ToolFn = Callable[[dict[str, Any], SimulatedWorld, SecretStore], ToolResult]


def fetch_url(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    url = args["url"]
    if url not in world.web_pages:
        return ToolResult(ok=False, output="", error=f"no such page: {url}")
    return ToolResult(ok=True, output=world.web_pages[url])


def read_email(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    msg_id = args["msg_id"]
    if msg_id not in world.emails:
        return ToolResult(ok=False, output="", error=f"no such message: {msg_id}")
    return ToolResult(ok=True, output=world.emails[msg_id])


def read_file(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    path = args["path"]
    if path not in world.files:
        return ToolResult(ok=False, output="", error=f"no such file: {path}")
    return ToolResult(ok=True, output=world.files[path])


def send_email(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    resolved_body = _resolve_secrets_and_scan("send_email", args, secrets)
    world.sent_emails.append({"to": args["to"], "subject": args.get("subject", ""), "body": resolved_body})
    return ToolResult(ok=True, output=f"email sent to {args['to']}")


def http_post(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    _resolve_secrets_and_scan("http_post", args, secrets)
    world.http_posts.append({"url": args["url"], "data": args.get("data", "")})
    return ToolResult(ok=True, output=f"posted to {args['url']}")


def delete_file(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    world.deleted_files.append(args["path"])
    return ToolResult(ok=True, output=f"deleted {args['path']}")


def grant_admin(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    world.admin_grants.append(args["user"])
    return ToolResult(ok=True, output=f"granted admin to {args['user']}")


def run_shell(args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    world.shell_commands.append(args["cmd"])
    return ToolResult(ok=True, output=f"ran: {args['cmd']}")


def _resolve_secrets_and_scan(tool_name: str, args: dict[str, Any], secrets: SecretStore) -> str:
    """Resolve any secret handles in string args, then scan for raw leakage."""
    body = args.get("body") or args.get("data") or ""
    resolved = body
    for name in list(secrets.raw_values()):
        handle = f"$SECRET:{name}"
        if handle in resolved:
            resolved = resolved.replace(handle, secrets.resolve(handle))
    scan_for_leakage(tool_name, {**args, "body": resolved}, secrets)
    return resolved


TOOL_REGISTRY: dict[str, ToolFn] = {
    "fetch_url": fetch_url,
    "read_email": read_email,
    "read_file": read_file,
    "send_email": send_email,
    "http_post": http_post,
    "delete_file": delete_file,
    "grant_admin": grant_admin,
    "run_shell": run_shell,
}


def execute_tool(tool_name: str, args: dict[str, Any], world: SimulatedWorld, secrets: SecretStore) -> ToolResult:
    fn = TOOL_REGISTRY.get(tool_name)
    if fn is None:
        return ToolResult(ok=False, output="", error=f"unknown tool: {tool_name}")
    world.call_log.append((tool_name, dict(args)))
    return fn(args, world, secrets)
