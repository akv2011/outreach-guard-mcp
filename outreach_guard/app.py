"""The HTTP app: the MCP server at /mcp, its OAuth routes, and the web chat with its own Google sign-in."""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.server.auth import AuthProvider
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.memory import MemoryStore
from key_value.aio.stores.redis import RedisStore
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse

from outreach_guard import agent
from outreach_guard.config import Settings
from outreach_guard.fake_instantly import fake_transport
from outreach_guard.guard import (
    WEB_USER,
    audit_entries,
    bump,
    count,
    pending_link_approvals,
    policy_for,
    rate_key,
    record,
    sends_key,
)
from outreach_guard.instantly import Instantly
from outreach_guard.policy import parse_overrides
from outreach_guard.server import RULES, build_server, describe, google_auth, hints

SESSION_COOKIE = "og_session"
STATE_COOKIE = "og_oauth_state"
SESSION_SECONDS = 7 * 86400
APPROVAL_TIMEOUT_SECONDS = 120
POLL_SECONDS = 0.5
GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"


def make_store(settings: Settings) -> AsyncKeyValue:
    return RedisStore(url=settings.redis_url) if settings.redis_url else MemoryStore()


def connect_instantly(settings: Settings, store: AsyncKeyValue) -> Instantly:
    if settings.mode == "live":
        return Instantly(settings.instantly_api_key)
    return Instantly("demo", transport=fake_transport(store))


def session_cookie(settings: Settings, email: str, now: float) -> str:
    payload = f"{email}|{int(now + SESSION_SECONDS)}"
    mac = hmac.new(settings.derived_key("session"), payload.encode(), "sha256").hexdigest()
    return f"{payload}|{mac}"


def session_user(settings: Settings, request: Request, now: float) -> str | None:
    parts = request.cookies.get(SESSION_COOKIE, "").rsplit("|", 2)
    if len(parts) != 3:
        return None
    email, expires, mac = parts
    expected = hmac.new(settings.derived_key("session"), f"{email}|{expires}".encode(), "sha256").hexdigest()
    if hmac.compare_digest(mac, expected) and expires.isdigit() and int(expires) > now:
        return email
    return None


async def wait_for_decision(
    store: AsyncKeyValue, approval_id: str, clock: Callable[[], float], sleep: Callable[[float], Awaitable[Any]]
) -> str:
    deadline = clock() + APPROVAL_TIMEOUT_SECONDS
    while clock() < deadline:
        doc = await store.get(approval_id, collection="approvals")
        if doc and doc["status"] != "pending":
            return doc["status"]
        await sleep(POLL_SECONDS)
    doc = await store.get(approval_id, collection="approvals") or {}
    await store.put(approval_id, doc | {"status": "timeout"}, collection="approvals", ttl=600)
    return "timeout"


async def _json_body(request: Request) -> dict[str, Any] | None:
    # A cross-site form cannot send application/json without a CORS preflight, which this app never grants.
    if not request.headers.get("content-type", "").startswith("application/json"):
        return None
    try:
        body = await request.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def build_web(
    settings: Settings,
    store: AsyncKeyValue,
    instantly: Instantly,
    auth: AuthProvider | None,
    generate: agent.Generate,
    google_transport: httpx.AsyncBaseTransport | None = None,
    self_transport: httpx.AsyncBaseTransport | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
) -> FastMCP:
    """The MCP server with the web routes added, so one ASGI app serves both."""
    mcp = build_server(settings, store, instantly, auth, clock=clock)
    page = Path(__file__).with_name("index.html").read_text()
    secure = settings.base_url.startswith("https://")
    callback_url = f"{settings.base_url}/auth/web/callback"

    def user_of(request: Request) -> str | None:
        return session_user(settings, request, clock())

    def day() -> int:
        return int(clock() // 86400)

    @mcp.custom_route("/", methods=["GET"])
    async def index(request: Request) -> Response:
        return HTMLResponse(page)

    @mcp.custom_route("/auth/web/login", methods=["GET"])
    async def web_login(request: Request) -> Response:
        state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        back = request.query_params.get("next", "/")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query = urlencode(
            {
                "client_id": settings.google_client_id,
                "redirect_uri": callback_url,
                "response_type": "code",
                "scope": "openid email",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "prompt": "select_account",
            }
        )
        response = RedirectResponse(f"{GOOGLE_AUTHORIZE}?{query}", status_code=302)
        response.set_cookie(STATE_COOKIE, f"{state}.{verifier}.{back}", max_age=600, httponly=True, samesite="lax", secure=secure)
        return response

    @mcp.custom_route("/auth/web/callback", methods=["GET"])
    async def web_callback(request: Request) -> Response:
        state, verifier, back = (request.cookies.get(STATE_COOKIE, "").split(".", 2) + ["", "", ""])[:3]
        code = request.query_params.get("code")
        if not state or not code or not hmac.compare_digest(request.query_params.get("state", ""), state):
            return JSONResponse({"error": "sign-in state did not match, start again"}, status_code=400)
        async with httpx.AsyncClient(timeout=10, transport=google_transport) as http:
            token = await http.post(
                GOOGLE_TOKEN,
                data={
                    "code": code,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": callback_url,
                    "grant_type": "authorization_code",
                    "code_verifier": verifier,
                },
            )
            if token.is_error:
                return JSONResponse({"error": "Google rejected the sign-in code"}, status_code=401)
            info = await http.get(GOOGLE_USERINFO, headers={"authorization": f"Bearer {token.json()['access_token']}"})
        claims = info.json() if info.is_success else {}
        if not isinstance(claims.get("email"), str) or claims.get("email_verified") is not True:
            return JSONResponse({"error": "Google did not return a verified email"}, status_code=401)
        same_site = back.startswith("/") and not back.startswith("//") and "\\" not in back
        response = RedirectResponse(back if same_site else "/", status_code=302)
        response.set_cookie(
            SESSION_COOKIE,
            session_cookie(settings, claims["email"].lower(), clock()),
            max_age=SESSION_SECONDS,
            httponly=True,
            samesite="lax",
            secure=secure,
        )
        response.delete_cookie(STATE_COOKIE)
        return response

    @mcp.custom_route("/auth/web/logout", methods=["POST"])
    async def web_logout(request: Request) -> Response:
        response = Response(status_code=204)
        response.delete_cookie(SESSION_COOKIE)
        return response

    @mcp.custom_route("/api/me", methods=["GET"])
    async def me(request: Request) -> Response:
        user = user_of(request)
        if not user:
            return JSONResponse({"signed_in": False})
        used = await count(store, f"chat:{user}:{day()}")
        return JSONResponse(
            {
                "signed_in": True,
                "email": user,
                "chat_limit": settings.chat_limit_per_day,
                "chat_remaining": max(0, settings.chat_limit_per_day - used),
                "mcp_url": f"{settings.base_url}/mcp",
                "mode": settings.mode,
            }
        )

    @mcp.custom_route("/api/audit", methods=["GET"])
    async def audit(request: Request) -> Response:
        user = user_of(request)
        if not user:
            return JSONResponse({"error": "signed out"}, status_code=401)
        return JSONResponse({"entries": await audit_entries(store, user, settings)})

    async def policy_view(user: str) -> dict[str, Any]:
        now = clock()
        effective = await policy_for(store, settings, user)
        try:
            instantly_blocked = sorted(await instantly.blocked())[:50]
        except Exception as e:  # the panel still renders when Instantly is unreachable
            instantly_blocked = [f"unavailable: {e}"]

        def values(s: Settings) -> dict[str, Any]:
            return {
                "recipient_domains": sorted(s.recipient_domains),
                "blocked_domains": sorted(s.blocked_domains),
                "daily_send_cap": s.daily_send_cap,
                "write_access": user in s.allowed_emails,
                "require_approval": s.require_approval,
            }

        return {
            "mode": settings.mode,
            "editable": settings.mode == "demo",
            "rules": [
                {"tool": name, "kind": rule.kind, "checks": describe(rule), "annotations": hints(rule).model_dump(by_alias=True, exclude_none=True)}
                for name, rule in RULES.items()
            ],
            "effective": values(effective),
            "defaults": values(settings),
            "overridden": effective is not settings,
            "usage": {
                "sends_today": await count(store, sends_key(user, now)),
                "daily_send_cap": effective.daily_send_cap,
                "calls_this_minute": await count(store, rate_key(user, now)),
                "rate_limit_per_min": settings.rate_limit_per_min,
            },
            "instantly_block_list": instantly_blocked,
        }

    async def policy_event(user: str, reason: str) -> None:
        await record(store, {"ts": clock(), "user": user, "tool": "policy", "verdict": "policy", "reason": reason, "args_digest": ""})

    @mcp.custom_route("/api/policy", methods=["GET", "POST", "DELETE"])
    async def policy(request: Request) -> Response:
        user = user_of(request)
        if not user:
            return JSONResponse({"error": "signed out"}, status_code=401)
        if request.method == "GET":
            return JSONResponse(await policy_view(user))
        if settings.mode != "demo":
            return JSONResponse({"error": "live mode: rules come from server config"}, status_code=403)
        if request.method == "DELETE":
            await store.delete(user, collection="policy")
            await policy_event(user, "reset to defaults")
            return JSONResponse(await policy_view(user))
        try:
            overrides = parse_overrides(await _json_body(request))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        await store.put(user, overrides, collection="policy")
        changes = ", ".join(f"{k}={v}" for k, v in overrides.items())
        await policy_event(user, f"set {changes}")
        return JSONResponse(await policy_view(user))

    @mcp.custom_route("/api/approvals", methods=["GET"])
    async def approvals(request: Request) -> Response:
        user = user_of(request)
        if not user:
            return JSONResponse({"error": "signed out"}, status_code=401)
        return JSONResponse({"approvals": await pending_link_approvals(store, user, clock())})

    @mcp.custom_route("/api/selfcheck", methods=["GET"])
    async def selfcheck(request: Request) -> Response:
        if not user_of(request):
            return JSONResponse({"error": "signed out"}, status_code=401)
        return JSONResponse({"checks": await _selfcheck(mcp, settings.base_url, self_transport)})

    @mcp.custom_route("/api/approve/{approval_id}", methods=["POST"])
    async def approve(request: Request) -> Response:
        user = user_of(request)
        if not user:
            return JSONResponse({"error": "signed out"}, status_code=401)
        body = await _json_body(request)
        if not body or body.get("decision") not in ("accept", "decline"):
            return JSONResponse({"error": 'send {"decision": "accept" | "decline"}'}, status_code=400)
        approval_id = request.path_params["approval_id"]
        doc = await store.get(approval_id, collection="approvals")
        if doc is None:
            return JSONResponse({"error": "unknown approval"}, status_code=404)
        if doc["user"] != user:
            return JSONResponse({"error": "this approval belongs to another user"}, status_code=403)
        if doc["status"] != "pending":
            return JSONResponse({"error": f"already {doc['status']}"}, status_code=409)
        if doc.get("expires_at", float("inf")) <= clock():
            return JSONResponse({"error": "this approval expired"}, status_code=410)
        await store.put(approval_id, doc | {"status": body["decision"]}, collection="approvals", ttl=600)
        return Response(status_code=204)

    @mcp.custom_route("/api/chat", methods=["POST"])
    async def chat(request: Request) -> Response:
        user = user_of(request)
        if not user:
            return JSONResponse({"error": "signed out"}, status_code=401)
        body = await _json_body(request)
        prompt = str((body or {}).get("prompt", "")).strip()[:2000]
        if not prompt:
            return JSONResponse({"error": 'send {"prompt": "..."}'}, status_code=400)
        used = await bump(store, f"chat:{user}:{day()}", ttl=2 * 86400)
        remaining = settings.chat_limit_per_day - used
        if remaining < 0:
            return JSONResponse({"error": "daily chat limit reached", "remaining": 0}, status_code=429)

        events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        current: dict[str, Any] = {}

        async def emit(event: dict[str, Any]) -> None:
            if event["type"] == "tool_call":
                current.update(id=event["id"], name=event["name"])
            await events.put(event)

        async def ask_in_browser(message: str, response_type: Any, params: Any, context: Any) -> Any:
            approval_id = uuid.uuid4().hex
            await store.put(approval_id, {"user": user, "status": "pending"}, collection="approvals", ttl=600)
            await emit({"type": "verdict", "id": current.get("id"), "verdict": "hold", "reason": "waiting for your approval"})
            await emit(
                {"type": "approval_required", "id": current.get("id"), "approval_id": approval_id, "tool": current.get("name"), "message": message}
            )
            decision = await wait_for_decision(store, approval_id, clock, sleep)
            await emit({"type": "approval_resolved", "approval_id": approval_id, "decision": decision})
            return {"confirm": True} if decision == "accept" else ElicitResult(action="decline")

        async def work() -> None:
            WEB_USER.set(user)
            try:
                async with Client(mcp, elicitation_handler=ask_in_browser) as client:
                    await agent.run(prompt, client, generate, emit)
            except Exception:  # end the stream cleanly; provider errors can quote the API key, so details stay in the log
                logging.getLogger(__name__).exception("web agent failed")
                await emit({"type": "error", "message": "agent stopped: the model call failed, try again in a minute"})
            finally:
                await events.put({"type": "done", "remaining": remaining})

        task = asyncio.create_task(work())

        async def stream():
            try:
                while True:
                    event = await events.get()
                    yield f"data: {json.dumps(event)}\n\n"
                    if event["type"] == "done":
                        return
            finally:
                task.cancel()

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"cache-control": "no-cache"})

    return mcp


def create_app(*args: Any, **kwargs: Any) -> Starlette:
    return build_web(*args, **kwargs).http_app(path="/mcp", stateless_http=True)


async def _selfcheck(mcp: FastMCP, base: str, transport: httpx.AsyncBaseTransport | None) -> list[dict[str, Any]]:
    """What a connecting client would see, fetched from this server's public URL."""
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, value: str) -> None:
        checks.append({"name": name, "ok": ok, "value": value})

    async with httpx.AsyncClient(timeout=10, transport=transport) as http:
        try:
            prm_url = f"{base}/.well-known/oauth-protected-resource/mcp"
            prm = await http.get(prm_url)
            body = prm.json() if prm.is_success else {}
            add("Protected resource metadata", body.get("resource") == f"{base}/mcp", f"{prm.status_code}, resource {body.get('resource')}")
            call = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            anon = await http.post(f"{base}/mcp", json=call, headers={"accept": "application/json, text/event-stream"})
            challenge = anon.headers.get("www-authenticate", "")
            add("Calls without a token get 401", anon.status_code == 401 and f'resource_metadata="{prm_url}"' in challenge, f"{anon.status_code}, {challenge or 'no WWW-Authenticate'}")
            issuer = (body.get("authorization_servers") or [base])[0].rstrip("/")
            meta = (await http.get(f"{issuer}/.well-known/oauth-authorization-server")).json()
            pkce = meta.get("code_challenge_methods_supported", [])
            cimd = meta.get("client_id_metadata_document_supported") is True
            add("Sign-in offers PKCE S256 and CIMD", "S256" in pkce and cimd, f"PKCE {pkce}, CIMD {cimd}")
        except (httpx.HTTPError, ValueError) as e:
            add("Public URL reachable", False, f"{base}: {e}")
    async with Client(mcp) as client:
        tools = await client.list_tools()
        add("tools/list over MCP", len(tools) > 0, f"{len(tools)} tools, protocol {client.protocol_version}")
    return checks


def production_app() -> Starlette:
    settings = Settings.from_env()
    store = make_store(settings)
    return create_app(
        settings, store, connect_instantly(settings, store), google_auth(settings, store), agent.gemini(settings)
    )
