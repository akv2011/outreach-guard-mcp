import asyncio
import base64
import hashlib
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from google.genai import types
from key_value.aio.stores.memory import MemoryStore
from starlette.testclient import TestClient

from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.utilities.tests import asgi_server

from outreach_guard.app import SESSION_COOKIE, build_web, connect_instantly, create_app, session_cookie
from outreach_guard.fake_instantly import _id
from outreach_guard.guard import LINK_TTL_SECONDS, audit_entries
from outreach_guard.instantly import Instantly
from outreach_guard.policy import parse_overrides
from outreach_guard.server import RULES
from outreach_guard.server import google_auth
from tests.conftest import OWNER, STRANGER, InstantlyMock, make_settings

BASE = "http://localhost:8000"
SETTINGS = make_settings(BASE_URL=BASE, GOOGLE_CLIENT_ID="cid", GOOGLE_CLIENT_SECRET="csecret")


def model_turns(*turns: list[types.Part]):
    async def generate(contents, declarations):
        turn = turns[sum(c.role == "model" for c in contents)]

        async def chunks():
            for part in turn:
                yield types.GenerateContentResponse(candidates=[types.Candidate(content=types.Content(role="model", parts=[part]))])

        return chunks()

    return generate


def call(name: str, **args) -> list[types.Part]:
    return [types.Part(function_call=types.FunctionCall(name=name, args=args))]


def say(*words: str) -> list[types.Part]:
    return [types.Part.from_text(text=w) for w in words]


class Google:
    def __init__(self, email: str = "Viewer@Gmail.com", verified: bool = True) -> None:
        self.email, self.verified = email, verified
        self.token_requests: list[dict[str, list[str]]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            self.token_requests.append(parse_qs(request.content.decode()))
            return httpx.Response(200, json={"access_token": "google-at", "token_type": "Bearer", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer google-at"
        return httpx.Response(200, json={"sub": "1", "email": self.email, "email_verified": self.verified})


@pytest.fixture
def store():
    return MemoryStore()


def make_app(store, generate=None, google=None, sleep=None):
    async def no_sleep(_):
        return None

    return create_app(
        SETTINGS,
        store,
        connect_instantly(SETTINGS, store),
        None,
        generate or model_turns(say("hi")),
        google_transport=httpx.MockTransport((google or Google()).handle),
        sleep=sleep or no_sleep,
    )


def signed_in(app, email: str) -> TestClient:
    client = TestClient(app, base_url=BASE)
    client.cookies.set(SESSION_COOKIE, session_cookie(SETTINGS, email, 1_800_000_000))
    return client


def events(response: httpx.Response) -> list[dict]:
    return [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]


def test_chat_without_a_session_is_rejected(store):
    with TestClient(make_app(store), base_url=BASE) as client:
        assert client.post("/api/chat", json={"prompt": "hi"}).status_code == 401
        assert client.get("/api/me").json() == {"signed_in": False}


def test_a_cookie_signed_with_another_key_is_rejected(store):
    other = make_settings(SESSION_SECRET="another-secret-that-is-also-long-enough")
    with TestClient(make_app(store), base_url=BASE) as client:
        client.cookies.set(SESSION_COOKIE, session_cookie(other, OWNER, 1_800_000_000))
        assert client.post("/api/chat", json={"prompt": "hi"}).status_code == 401


def test_the_session_user_is_the_user_the_guard_sees(store):
    reply = call("reply_to_email", email_id="x", eaccount="outreach@example.net", subject="Re", body="hi")
    app = make_app(store, model_turns(call("list_campaigns"), reply, say("done")))
    with signed_in(app, STRANGER) as client:
        stream = events(client.post("/api/chat", json={"prompt": "list then reply"}))
    verdicts = [(e["id"], e["verdict"]) for e in stream if e["type"] == "verdict"]
    assert verdicts == [("c1", "allow"), ("c2", "deny")]
    assert "ALLOWED_EMAILS" in next(e["reason"] for e in stream if e["type"] == "verdict" and e["verdict"] == "deny")
    log = asyncio.run(audit_entries(store, OWNER, SETTINGS))
    assert {(e["user"], e["tool"]) for e in log} == {(STRANGER, "list_campaigns"), (STRANGER, "reply_to_email")}


def test_chat_limit_trips_on_the_eleventh_request_of_the_day(store):
    with signed_in(make_app(store), STRANGER) as client:
        remaining = [events(client.post("/api/chat", json={"prompt": "hi"}))[-1]["remaining"] for _ in range(10)]
        eleventh = client.post("/api/chat", json={"prompt": "hi"})
        me = client.get("/api/me").json()
    assert remaining == list(range(9, -1, -1))
    assert eleventh.status_code == 429 and eleventh.json()["remaining"] == 0
    assert me["chat_remaining"] == 0 and me["chat_limit"] == 10 and me["mode"] == "demo"


def test_model_text_streams_as_it_arrives(store):
    with signed_in(make_app(store, model_turns(say("Hel", "lo"))), STRANGER) as client:
        stream = events(client.post("/api/chat", json={"prompt": "hi"}))
    assert [e["text"] for e in stream if e["type"] == "text"] == ["Hel", "lo"]


def test_approve_endpoint_only_accepts_the_user_who_was_asked(store):
    asyncio.run(store.put("a1", {"user": OWNER, "status": "pending"}, collection="approvals"))
    app = make_app(store)
    with signed_in(app, STRANGER) as stranger:
        assert stranger.post("/api/approve/a1", json={"decision": "accept"}).status_code == 403
    with signed_in(app, OWNER) as owner:
        assert owner.post("/api/approve/a1", content="decision=accept", headers={"content-type": "application/x-www-form-urlencoded"}).status_code == 400
        assert owner.post("/api/approve/a1", json={"decision": "accept"}).status_code == 204
        assert owner.post("/api/approve/a1", json={"decision": "decline"}).status_code == 409
        assert owner.post("/api/approve/nope", json={"decision": "accept"}).status_code == 404


@pytest.mark.parametrize(("decision", "verdict"), [("accept", "allow"), ("decline", "deny")])
def test_web_approval_goes_through_the_approve_endpoint(store, decision, verdict):
    app_ref: list = []

    async def browser_clicks(_):
        for key in await store.keys(collection="approvals"):
            if (await store.get(key, collection="approvals"))["status"] != "pending":
                continue
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_ref[0]), base_url=BASE) as browser:
                browser.cookies.set(SESSION_COOKIE, session_cookie(SETTINGS, OWNER, 1_800_000_000))
                assert (await browser.post(f"/api/approve/{key}", json={"decision": decision})).status_code == 204

    reply = call("reply_to_email", email_id=_id("ana-reply"), eaccount="outreach@example.net", subject="Re: pricing", body="Pricing attached.")
    app = make_app(store, model_turns(reply, say("ok")), sleep=browser_clicks)
    app_ref.append(app)
    with signed_in(app, OWNER) as client:
        stream = events(client.post("/api/chat", json={"prompt": "reply to Ana"}))
    kinds = [(e["type"], e.get("verdict") or e.get("decision")) for e in stream if e["type"] in ("verdict", "approval_resolved")]
    assert kinds == [("verdict", "hold"), ("approval_resolved", decision), ("verdict", verdict)]
    ask = next(e for e in stream if e["type"] == "approval_required")
    assert ask["id"] == "c1" and ask["tool"] == "reply_to_email" and "To: ana@example.com" in ask["message"]
    workspace = asyncio.run(store.get("workspace", collection="demo")) or {"emails": []}
    sent = [e for e in workspace["emails"] if e["subject"] == "Re: pricing"]
    assert len(sent) == (1 if decision == "accept" else 0)


def test_google_sign_in_sets_a_session_for_the_verified_email(store):
    google = Google()
    with TestClient(make_app(store, google=google), base_url=BASE, follow_redirects=False) as client:
        login = client.get("/auth/web/login")
        query = parse_qs(urlparse(login.headers["location"]).query)
        assert query["redirect_uri"] == [f"{BASE}/auth/web/callback"] and query["code_challenge_method"] == ["S256"]
        callback = client.get("/auth/web/callback", params={"code": "c1", "state": query["state"][0]})
        me = client.get("/api/me").json()
    assert callback.status_code == 302 and me["email"] == "viewer@gmail.com"
    verifier = google.token_requests[0]["code_verifier"][0]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert query["code_challenge"] == [challenge]


def test_google_sign_in_rejects_a_mismatched_state_and_an_unverified_email(store):
    with TestClient(make_app(store, google=Google(verified=False)), base_url=BASE, follow_redirects=False) as client:
        state = parse_qs(urlparse(client.get("/auth/web/login").headers["location"]).query)["state"][0]
        assert client.get("/auth/web/callback", params={"code": "c1", "state": "forged"}).status_code == 400
        assert client.get("/auth/web/callback", params={"code": "c1", "state": state}).status_code == 401
        assert SESSION_COOKIE not in client.cookies


THIRD = "third@gmail.com"
TOKENS = {
    "owner-token": {"client_id": "test", "sub": "owner", "email": OWNER, "email_verified": True},
    "stranger-token": {"client_id": "test", "sub": "stranger", "email": STRANGER, "email_verified": True},
    "third-token": {"client_id": "test", "sub": "third", "email": THIRD, "email_verified": True},
}
ANA = {"email_id": _id("ana-reply"), "eaccount": "outreach@example.net", "subject": "Re: pricing", "body": "Pricing attached."}


@pytest.fixture
async def legacy_server(store, clock):
    mcp = build_web(SETTINGS, store, connect_instantly(SETTINGS, store), StaticTokenVerifier(tokens=TOKENS), model_turns(say("hi")), clock=clock)
    async with asgi_server(mcp, stateless_http=True) as server:
        yield server


def root(server) -> str:
    return server.url.removesuffix("/mcp")


async def decide(server, email: str, approval_id: str, decision: str) -> int:
    async with server.http_client() as http:
        http.cookies.set(SESSION_COOKIE, session_cookie(SETTINGS, email, 1_800_000_000))
        return (await http.post(f"{root(server)}/api/approve/{approval_id}", json={"decision": decision})).status_code


async def legacy_reply(server, args=ANA) -> tuple[bool, str]:
    async with server.client(auth="owner-token", mode="legacy") as client:
        assert client.protocol_version == "2025-11-25"
        result = await client.call_tool("reply_to_email", args, raise_on_error=False)
    return result.is_error, result.content[0].text


def link_id(text: str) -> str:
    assert text.startswith(f"Needs your approval: open {BASE}/?approve="), text
    return text.split("?approve=")[1].split(",")[0]


async def sent_replies(store) -> int:
    workspace = await store.get("workspace", collection="demo") or {"emails": []}
    return sum(e["subject"] == "Re: pricing" for e in workspace["emails"])


async def test_legacy_client_gets_an_approval_link_and_the_page_lists_it(legacy_server, store):
    failed, text = await legacy_reply(legacy_server)
    approval_id = link_id(text)
    async with legacy_server.http_client() as http:
        http.cookies.set(SESSION_COOKIE, session_cookie(SETTINGS, OWNER, 1_800_000_000))
        listed = (await http.get(f"{root(legacy_server)}/api/approvals")).json()["approvals"]
    assert failed and await sent_replies(store) == 0
    assert [a["approval_id"] for a in listed] == [approval_id]
    assert "To: ana@example.com" in listed[0]["message"]


async def test_link_approval_by_another_user_is_rejected(legacy_server, store):
    approval_id = link_id((await legacy_reply(legacy_server))[1])
    assert await decide(legacy_server, STRANGER, approval_id, "accept") == 403
    failed, text = await legacy_reply(legacy_server)
    assert failed and link_id(text) == approval_id and await sent_replies(store) == 0


async def test_approved_link_lets_the_same_call_run_exactly_once(legacy_server, store):
    approval_id = link_id((await legacy_reply(legacy_server))[1])
    assert await decide(legacy_server, OWNER, approval_id, "accept") == 204
    first = await legacy_reply(legacy_server)
    second = await legacy_reply(legacy_server)
    assert first[0] is False and await sent_replies(store) == 1
    assert link_id(second[1]) != approval_id


async def test_changed_arguments_need_a_new_approval(legacy_server, store):
    approval_id = link_id((await legacy_reply(legacy_server))[1])
    assert await decide(legacy_server, OWNER, approval_id, "accept") == 204
    changed = await legacy_reply(legacy_server, ANA | {"body": "Different words."})
    assert link_id(changed[1]) != approval_id and await sent_replies(store) == 0


async def test_an_expired_link_approval_asks_again(legacy_server, store, clock):
    approval_id = link_id((await legacy_reply(legacy_server))[1])
    assert await decide(legacy_server, OWNER, approval_id, "accept") == 204
    clock.now += LINK_TTL_SECONDS
    late = await legacy_reply(legacy_server)
    assert link_id(late[1]) != approval_id and await sent_replies(store) == 0
    clock.now += LINK_TTL_SECONDS
    assert await decide(legacy_server, OWNER, link_id(late[1]), "accept") == 410


class LateASGI(httpx.AsyncBaseTransport):
    app = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await httpx.ASGITransport(app=self.app).handle_async_request(request)


@pytest.mark.parametrize("with_auth", [True, False], ids=["google-auth", "no-auth"])
async def test_selfcheck_reports_what_a_connecting_client_sees(store, with_auth):
    settings = make_settings(BASE_URL=BASE, GOOGLE_CLIENT_ID="cid", GOOGLE_CLIENT_SECRET="csecret", JWT_SIGNING_KEY="k" * 48)
    loopback = LateASGI()
    auth = google_auth(settings, store) if with_auth else None
    mcp = build_web(settings, store, connect_instantly(settings, store), auth, model_turns(say("hi")), self_transport=loopback)
    async with asgi_server(mcp, stateless_http=True) as server:
        loopback.app = server.app
        async with server.http_client() as http:
            assert (await http.get(f"{root(server)}/api/selfcheck")).status_code == 401
            http.cookies.set(SESSION_COOKIE, session_cookie(settings, STRANGER, 1_800_000_000))
            checks = (await http.get(f"{root(server)}/api/selfcheck")).json()["checks"]
    by_name = {c["name"]: c for c in checks}
    assert by_name["tools/list over MCP"] == {"name": "tools/list over MCP", "ok": True, "value": "8 tools, protocol 2026-07-28"}
    assert [c["ok"] for c in checks[:3]] == ([True, True, True] if with_auth else [False, False, False])


@pytest.mark.parametrize(("requested", "landing"), [("/?approve=abc", "/?approve=abc"), ("//evil.example", "/"), ("/\\evil.example", "/"), ("https://evil.example", "/")])
def test_sign_in_returns_to_a_same_site_path_only(store, requested, landing):
    with TestClient(make_app(store), base_url=BASE, follow_redirects=False) as client:
        query = parse_qs(urlparse(client.get("/auth/web/login", params={"next": requested}).headers["location"]).query)
        callback = client.get("/auth/web/callback", params={"code": "c1", "state": query["state"][0]})
    assert callback.headers["location"] == landing


SANDBOX = {
    "recipient_domains": ["example.com", "outside.net"],
    "blocked_domains": ["example.org"],
    "daily_send_cap": 2,
    "write_access": True,
    "require_approval": False,
}
BCC_CAMPAIGN = {"name": "x", "subject": "s", "body": "b", "bcc_list": ["audit@outside.net"]}


async def web(server, email: str, method: str, path: str, body: dict | None = None) -> httpx.Response:
    async with server.http_client() as http:
        http.cookies.set(SESSION_COOKIE, session_cookie(SETTINGS, email, 1_800_000_000))
        return await http.request(method, f"{root(server)}{path}", json=body)


async def mcp_call(server, token: str, tool: str, args: dict) -> tuple[bool, str]:
    async with server.client(auth=token) as client:
        result = await client.call_tool(tool, args, raise_on_error=False)
    return result.is_error, result.content[0].text if result.is_error else ""


async def test_sandbox_overrides_apply_only_to_their_owner(legacy_server):
    assert (await web(legacy_server, STRANGER, "POST", "/api/policy", SANDBOX)).status_code == 200
    assert await mcp_call(legacy_server, "stranger-token", "create_campaign", BCC_CAMPAIGN) == (False, "")
    third = await mcp_call(legacy_server, "third-token", "create_campaign", BCC_CAMPAIGN)
    assert third[0] and "ALLOWED_EMAILS" in third[1]


async def test_turning_approval_off_still_enforces_domains_block_list_and_cap(legacy_server, store):
    assert (await web(legacy_server, STRANGER, "POST", "/api/policy", SANDBOX)).status_code == 200
    blocked = await mcp_call(legacy_server, "stranger-token", "reply_to_email", ANA | {"cc_address_email_list": ["dana@example.org"]})
    outside = await mcp_call(legacy_server, "stranger-token", "reply_to_email", ANA | {"cc_address_email_list": ["x@elsewhere.net"]})
    first = await mcp_call(legacy_server, "stranger-token", "reply_to_email", ANA)
    second = await mcp_call(legacy_server, "stranger-token", "reply_to_email", ANA)
    over_cap = await mcp_call(legacy_server, "stranger-token", "reply_to_email", ANA)
    assert "block list" in blocked[1] and "RECIPIENT_DOMAINS" in outside[1]
    assert first == second == (False, "") and await sent_replies(store) == 2
    assert "daily send cap" in over_cap[1]


@pytest.mark.parametrize("cap", [0, 51, True, "5"])
async def test_sandbox_cap_must_be_a_whole_number_from_1_to_50(legacy_server, cap):
    response = await web(legacy_server, STRANGER, "POST", "/api/policy", SANDBOX | {"daily_send_cap": cap})
    assert response.status_code == 400 and "daily_send_cap" in response.json()["error"]
    assert (await web(legacy_server, STRANGER, "POST", "/api/policy", SANDBOX | {"daily_send_cap": 50})).status_code == 200


async def test_reset_restores_defaults_and_both_changes_are_audited(legacy_server):
    changed = (await web(legacy_server, STRANGER, "POST", "/api/policy", SANDBOX)).json()
    reset = (await web(legacy_server, STRANGER, "DELETE", "/api/policy")).json()
    log = (await web(legacy_server, STRANGER, "GET", "/api/audit")).json()["entries"]
    assert changed["overridden"] and changed["effective"]["recipient_domains"] == ["example.com", "outside.net"]
    assert not reset["overridden"] and reset["effective"] == reset["defaults"]
    assert reset["effective"]["write_access"] is False and reset["effective"]["require_approval"] is True
    assert [(e["tool"], e["verdict"], e["reason"].split(" ")[0]) for e in log] == [("policy", "policy", "reset"), ("policy", "policy", "set")]


async def test_policy_panel_lists_every_rule_and_live_usage(legacy_server):
    await mcp_call(legacy_server, "stranger-token", "list_campaigns", {})
    view = (await web(legacy_server, STRANGER, "GET", "/api/policy")).json()
    assert {r["tool"] for r in view["rules"]} == set(RULES)
    reply = next(r for r in view["rules"] if r["tool"] == "reply_to_email")
    assert "bcc_address_email_list" in reply["checks"] and reply["annotations"]["destructiveHint"] is True
    assert view["usage"]["calls_this_minute"] == 1 and view["instantly_block_list"] == ["competitor.example", "do-not-contact@example.org"]


async def test_live_mode_ignores_overrides_and_refuses_edits(store, clock):
    live = make_settings(BASE_URL=BASE, INSTANTLY_API_KEY="live-key")
    await store.put(STRANGER, parse_overrides(SANDBOX), collection="policy")
    mcp = build_web(live, store, Instantly("live-key", transport=InstantlyMock().transport()), StaticTokenVerifier(tokens=TOKENS), model_turns(say("hi")), clock=clock)
    async with asgi_server(mcp, stateless_http=True) as server:
        async with server.http_client() as http:
            http.cookies.set(SESSION_COOKIE, session_cookie(live, STRANGER, 1_800_000_000))
            edit = await http.post(f"{root(server)}/api/policy", json=SANDBOX)
            view = (await http.get(f"{root(server)}/api/policy")).json()
        denied = await mcp_call(server, "stranger-token", "create_campaign", BCC_CAMPAIGN)
    assert edit.status_code == 403 and view["editable"] is False and view["overridden"] is False
    assert denied[0] and "ALLOWED_EMAILS" in denied[1]
