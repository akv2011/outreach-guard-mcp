"""The one enforcement point every tools/call passes through, plus the counters and audit log it keeps."""

import time
import uuid
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from typing import Any

import mcp_types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.context import Context
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import InputRequiredToolResult, ToolResult
from key_value.aio.protocols import AsyncKeyValue
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from outreach_guard.config import Settings
from outreach_guard.instantly import Instantly
from outreach_guard.policy import (
    Allow,
    Deny,
    Kind,
    NeedsApproval,
    Resolved,
    Rule,
    State,
    admit,
    approval_problem,
    approval_state,
    check,
    digest,
    effective_settings,
)

# Set by the web chat route from its signed session cookie. A remote MCP client cannot reach it.
WEB_USER: ContextVar[str | None] = ContextVar("web_user", default=None)

AUDIT_SIZE = 200
LINK_TTL_SECONDS = 600
DENIED = "Denied by guard: "
CONFIRM_SCHEMA = {
    "type": "object",
    "properties": {"confirm": {"type": "boolean", "title": "Send these emails", "default": False}},
    "required": ["confirm"],
}


def current_user() -> str | None:
    token = get_access_token()
    if token is None:
        return WEB_USER.get()
    email = token.claims.get("email")
    if isinstance(email, str) and token.claims.get("email_verified") in (True, "true"):
        return email.strip().lower()
    return None


async def bump(store: AsyncKeyValue, key: str, ttl: int, by: int = 1) -> int:
    # ponytail: get then put is not atomic, so concurrent calls can undercount. Move to Redis INCR if that matters.
    doc = await store.get(key, collection="counters")
    n = (doc or {}).get("n", 0) + by
    await store.put(key, {"n": n}, collection="counters", ttl=ttl)
    return n


async def count(store: AsyncKeyValue, key: str) -> int:
    doc = await store.get(key, collection="counters")
    return (doc or {}).get("n", 0)


async def record(store: AsyncKeyValue, entry: dict[str, Any]) -> None:
    # ponytail: read-modify-write on one document; concurrent writers can drop an entry. Use a Redis list if that matters.
    doc = await store.get("log", collection="audit")
    entries = [entry, *(doc or {}).get("entries", [])][:AUDIT_SIZE]
    await store.put("log", {"entries": entries}, collection="audit")


async def audit_entries(store: AsyncKeyValue, user: str, settings: Settings) -> list[dict[str, Any]]:
    doc = await store.get("log", collection="audit")
    entries = (doc or {}).get("entries", [])
    if user in settings.allowed_emails:
        return entries
    return [e for e in entries if e["user"] == user]


def rate_key(user: str | None, now: float) -> str:
    return f"rate:{user}:{int(now // 60)}"


def sends_key(user: str | None, now: float) -> str:
    return f"sends:{user}:{int(now // 86400)}"


async def policy_for(store: AsyncKeyValue, settings: Settings, user: str | None) -> Settings:
    overrides = await store.get(user, collection="policy") if user and settings.mode == "demo" else None
    return effective_settings(settings, user, overrides)


class Guard(Middleware):
    def __init__(
        self,
        rules: Mapping[str, Rule],
        settings: Settings,
        store: AsyncKeyValue,
        instantly: Instantly,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.rules = rules
        self.settings = settings
        self.store = store
        self.instantly = instantly
        self.clock = clock

    async def on_call_tool(
        self, context: MiddlewareContext[mt.CallToolRequestParams], call_next: CallNext[mt.CallToolRequestParams, ToolResult]
    ) -> ToolResult:
        name = context.message.name
        args = dict(context.message.arguments or {})
        user = current_user()
        now = self.clock()
        log = self._logger(user, name, args, now)

        rule = self.rules.get(name)
        if rule is None:
            raise await log("deny", "no guard rule for this tool")
        ctx = context.fastmcp_context
        responses = ctx.input_responses if ctx else None
        settings = await policy_for(self.store, self.settings, user)
        calls = await bump(self.store, rate_key(user, now), ttl=120) if user and responses is None else 0
        if denied := admit(rule, user, calls, settings):
            raise await log("deny", denied.reason)

        state, preview = State(calls_this_minute=calls), ""
        sends = sends_key(user, now)
        if rule.kind is not Kind.READ:
            try:
                resolved = await rule.resolve(self.instantly, args) if rule.resolve else Resolved()
                needs_block_list = bool(rule.recipient_fields or rule.resolve)
                blocked = await self.instantly.blocked() if needs_block_list else frozenset()
            except Exception as e:  # fail closed: a recipient we could not look up is a recipient we did not check
                raise await log("deny", f"could not check recipients: {e}")
            state = State(calls, await count(self.store, sends), blocked, resolved.recipients)
            preview = resolved.preview

        match check(rule, args, user, state, settings):
            case Deny(reason):
                raise await log("deny", reason)
            case Allow(recipients):
                await log("allow", f"approval is off in your demo policy, {len(recipients)} recipient(s)" if recipients else "")
                result = await call_next(context)
                if recipients:
                    await bump(self.store, sends, ttl=2 * 86400, by=len(recipients))
                return result
            case NeedsApproval(recipients):
                assert user is not None
                call_digest = digest(name, args, recipients)
                message = approval_message(name, recipients, preview)
                if not _modern(ctx):
                    if not await redeem_link_approval(self.store, user, call_digest, now):
                        approval_id = await open_link_approval(self.store, user, name, call_digest, message, now)
                        await log("hold", f"approval link sent for {len(recipients)} recipient(s)")
                        raise ToolError(
                            f"Needs your approval: open {self.settings.base_url}/?approve={approval_id}, "
                            "approve it, then ask me to run the same call again."
                        )
                    how = "on the web page"
                elif responses is None:
                    await log("hold", f"approval asked for {len(recipients)} recipient(s)")
                    return _ask(message, approval_state(user, call_digest, now))
                else:
                    problem = approval_problem(ctx.request_state if ctx else None, user, call_digest, now)
                    if problem is None and not _confirmed(responses.get("approval")):
                        problem = "declined by the user"
                    if problem:
                        raise await log("deny", problem)
                    how = "in the client"
                result = await call_next(context)
                await bump(self.store, sends, ttl=2 * 86400, by=len(recipients))
                await log("allow", f"approved {how} for {len(recipients)} recipient(s)")
                return result

    def _logger(self, user: str | None, tool: str, args: dict[str, Any], now: float):
        async def log(verdict: str, reason: str) -> ToolError:
            entry = {
                "ts": now,
                "user": user or "anonymous",
                "tool": tool,
                "verdict": verdict,
                "reason": reason,
                "args_digest": digest(tool, args, ())[:16],
            }
            await record(self.store, entry)
            return ToolError(DENIED + reason)

        return log


def _confirmed(answer: object) -> bool:
    return isinstance(answer, mt.ElicitResult) and answer.action == "accept" and (answer.content or {}).get("confirm") is True


def _modern(ctx: Context | None) -> bool:
    """2026-07-28 clients can answer an InputRequiredResult; older ones cannot, so they approve by link."""
    return bool(ctx and ctx.request_context and ctx.request_context.protocol_version in MODERN_PROTOCOL_VERSIONS)


def approval_message(tool: str, recipients: tuple[str, ...], preview: str) -> str:
    return f"Approve {tool}: email {len(recipients)} recipient(s)\nTo: {', '.join(recipients)}\n{preview}".strip()


def _ask(message: str, request_state: str) -> InputRequiredToolResult:
    ask = mt.ElicitRequest(params=mt.ElicitRequestFormParams(message=message, requested_schema=CONFIRM_SCHEMA))
    return InputRequiredToolResult(mt.InputRequiredResult(input_requests={"approval": ask}, request_state=request_state))


async def open_link_approval(store: AsyncKeyValue, user: str, tool: str, call_digest: str, message: str, now: float) -> str:
    link = await store.get(f"{user}:{call_digest}", collection="approval-links")
    doc = await store.get(link["id"], collection="approvals") if link else None
    if link and doc and doc["status"] == "pending" and doc["expires_at"] > now:
        return link["id"]
    approval_id = uuid.uuid4().hex
    doc = {"user": user, "status": "pending", "tool": tool, "message": message, "expires_at": now + LINK_TTL_SECONDS}
    await store.put(approval_id, doc, collection="approvals", ttl=2 * LINK_TTL_SECONDS)
    await store.put(f"{user}:{call_digest}", {"id": approval_id}, collection="approval-links", ttl=2 * LINK_TTL_SECONDS)
    inbox = await store.get(user, collection="approval-inbox") or {"ids": []}
    await store.put(user, {"ids": [approval_id, *inbox["ids"]][:20]}, collection="approval-inbox", ttl=2 * LINK_TTL_SECONDS)
    return approval_id


async def redeem_link_approval(store: AsyncKeyValue, user: str, call_digest: str, now: float) -> bool:
    # ponytail: read then mark used is not atomic, so two concurrent retries could both pass. Use Redis GETDEL if that matters.
    link = await store.get(f"{user}:{call_digest}", collection="approval-links")
    doc = await store.get(link["id"], collection="approvals") if link else None
    if not link or not doc or doc["status"] != "accept" or doc["expires_at"] <= now:
        return False
    await store.put(link["id"], doc | {"status": "used"}, collection="approvals", ttl=LINK_TTL_SECONDS)
    return True


async def pending_link_approvals(store: AsyncKeyValue, user: str, now: float) -> list[dict[str, Any]]:
    inbox = await store.get(user, collection="approval-inbox") or {"ids": []}
    pending = []
    for approval_id in inbox["ids"]:
        doc = await store.get(approval_id, collection="approvals")
        if doc and doc["user"] == user and doc["status"] == "pending" and doc["expires_at"] > now:
            pending.append({"approval_id": approval_id, "tool": doc["tool"], "message": doc["message"], "expires_at": doc["expires_at"]})
    return pending

