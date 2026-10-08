import hashlib
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from email.utils import getaddresses
from enum import StrEnum
from typing import Any

from outreach_guard.config import Settings

APPROVAL_TTL_SECONDS = 300
DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")


class Kind(StrEnum):
    READ = "read"
    WRITE = "write"
    SEND = "send"


@dataclass(frozen=True)
class Resolved:
    """Recipients and content the guard had to fetch, because the arguments alone do not name them."""

    recipients: tuple[str, ...] = ()
    preview: str = ""


Resolver = Callable[[Any, Mapping[str, Any]], Awaitable[Resolved]]


@dataclass(frozen=True)
class Rule:
    kind: Kind
    recipient_fields: tuple[str, ...] = ()
    resolve: Resolver | None = None
    idempotent: bool = False


@dataclass(frozen=True)
class State:
    calls_this_minute: int = 0
    sends_today: int = 0
    blocked: frozenset[str] = frozenset()
    resolved: tuple[str, ...] = ()


@dataclass(frozen=True)
class Allow:
    recipients: tuple[str, ...] = ()


@dataclass(frozen=True)
class Deny:
    reason: str


@dataclass(frozen=True)
class NeedsApproval:
    recipients: tuple[str, ...]


Verdict = Allow | Deny | NeedsApproval


def addresses(value: object) -> list[str]:
    """Normalize a recipient field: a comma-separated string, a list of strings, or a list of {"email": ...}.

    Raises ValueError for anything it cannot read, so an odd shape is denied rather than skipped.
    """
    if value is None:
        return []
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list):
        raise ValueError(f"unreadable recipient field {value!r}")
    found: list[str] = []
    for item in items:
        if isinstance(item, dict):
            item = item.get("email")
        if not isinstance(item, str):
            raise ValueError(f"unreadable recipient {item!r}")
        if not item.strip():
            continue
        for _, addr in getaddresses([item]):
            addr = addr.strip().lower()
            if addr.count("@") != 1 or addr.startswith("@") or addr.endswith("@") or any(c.isspace() for c in addr):
                raise ValueError(f"unreadable recipient {item!r}")
            found.append(addr)
    return found


def recipients_of(rule: Rule, args: Mapping[str, Any], state: State) -> tuple[str, ...]:
    found = {a for field in rule.recipient_fields for a in addresses(args.get(field))}
    found.update(addresses(list(state.resolved)))
    return tuple(sorted(found))


def admit(rule: Rule, user: str | None, calls_this_minute: int, settings: Settings) -> Deny | None:
    """The checks that need no lookups, so a caller who will be denied never triggers Instantly calls."""
    if not user:
        return Deny("sign in with Google first")
    if calls_this_minute > settings.rate_limit_per_min:
        return Deny(f"rate limit: {settings.rate_limit_per_min} tool calls per minute")
    if rule.kind is not Kind.READ and user not in settings.allowed_emails:
        return Deny(f"{user} is not in ALLOWED_EMAILS, so {rule.kind} tools are off")
    return None


def check(rule: Rule, args: Mapping[str, Any], user: str | None, state: State, settings: Settings) -> Verdict:
    if denied := admit(rule, user, state.calls_this_minute, settings):
        return denied
    if rule.kind is Kind.READ:
        return Allow()
    try:
        recipients = recipients_of(rule, args, state)
    except ValueError as e:
        return Deny(str(e))
    for r in recipients:
        domain = r.rpartition("@")[2]
        if r in state.blocked or domain in state.blocked or domain in settings.blocked_domains:
            return Deny(f"{r} is on the Instantly block list")
        if domain not in settings.recipient_domains:
            return Deny(f"{r} is outside RECIPIENT_DOMAINS")
    if rule.kind is Kind.WRITE:
        return Allow()
    if not recipients:
        return Deny("no recipients to check, refusing to send")
    if state.sends_today + len(recipients) > settings.daily_send_cap:
        return Deny(f"daily send cap: {state.sends_today} of {settings.daily_send_cap} recipients used today")
    return NeedsApproval(recipients) if settings.require_approval else Allow(recipients)


def parse_overrides(body: object) -> dict[str, Any]:
    """Validate a demo user's policy overrides. Raises ValueError with a message the page can show."""
    if not isinstance(body, dict):
        raise ValueError("send a JSON object")
    domains = {}
    for field in ("recipient_domains", "blocked_domains"):
        values = body.get(field)
        if not isinstance(values, list) or len(values) > 20 or not all(isinstance(v, str) for v in values):
            raise ValueError(f"{field} must be a list of at most 20 domains")
        cleaned = sorted({v.strip().lower() for v in values if v.strip()})
        if bad := [d for d in cleaned if not DOMAIN.fullmatch(d)]:
            raise ValueError(f"not a domain: {bad[0]}")
        domains[field] = cleaned
    cap = body.get("daily_send_cap")
    if not isinstance(cap, int) or isinstance(cap, bool) or not 1 <= cap <= 50:
        raise ValueError("daily_send_cap must be a whole number from 1 to 50")
    flags = {f: body.get(f) for f in ("write_access", "require_approval")}
    if not all(isinstance(v, bool) for v in flags.values()):
        raise ValueError("write_access and require_approval must be true or false")
    return domains | {"daily_send_cap": cap} | flags


def effective_settings(settings: Settings, user: str | None, overrides: Mapping[str, Any] | None) -> Settings:
    """Global settings with one user's demo overrides on top. Live mode ignores overrides."""
    if settings.mode != "demo" or not user or not overrides:
        return settings
    return replace(
        settings,
        recipient_domains=frozenset(overrides["recipient_domains"]),
        blocked_domains=settings.blocked_domains | frozenset(overrides["blocked_domains"]),
        daily_send_cap=overrides["daily_send_cap"],
        allowed_emails=settings.allowed_emails | {user} if overrides["write_access"] else settings.allowed_emails,
        require_approval=overrides["require_approval"],
    )


def digest(tool: str, args: Mapping[str, Any], recipients: tuple[str, ...]) -> str:
    canonical = json.dumps({"tool": tool, "args": args, "recipients": recipients}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def approval_state(user: str, call_digest: str, now: float) -> str:
    return json.dumps({"user": user, "digest": call_digest, "exp": now + APPROVAL_TTL_SECONDS})


def approval_problem(state: str | None, user: str, call_digest: str, now: float) -> str | None:
    """Why a retried approval does not cover this call, or None when it does."""
    try:
        claims = json.loads(state or "")
    except json.JSONDecodeError:
        return "approval state missing"
    if not isinstance(claims, dict):
        return "approval state missing"
    if claims.get("user") != user:
        return "approval was given to a different user"
    if claims.get("digest") != call_digest:
        return "arguments or recipients changed after approval"
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
        return "approval expired"
    return None
