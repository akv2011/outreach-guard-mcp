import json

import mcp_types as mt
import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.utilities.tests import asgi_client
from key_value.aio.stores.memory import MemoryStore
from mcp.shared.exceptions import MCPError

from outreach_guard.guard import WEB_USER, audit_entries
from outreach_guard.instantly import Instantly
from outreach_guard.policy import APPROVAL_TTL_SECONDS
from outreach_guard.server import RULES, build_server
from tests.conftest import CAMPAIGN, INBOUND, OWNER, STRANGER, InstantlyMock, make_settings

TOKENS = {
    "owner-token": {"client_id": "test", "sub": "owner", "email": OWNER, "email_verified": True},
    "stranger-token": {"client_id": "test", "sub": "stranger", "email": STRANGER, "email_verified": True},
    "unverified-token": {"client_id": "test", "sub": "u", "email": OWNER, "email_verified": False},
}
REPLY_ARGS = {"email_id": INBOUND["id"], "eaccount": "outreach@example.net", "subject": "Re: pricing", "body": "Pricing attached."}
YES = {"approval": mt.ElicitResult(action="accept", content={"confirm": True})}


@pytest.fixture
def mock():
    return InstantlyMock()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def server(mock, store, clock):
    instantly = Instantly("test-key", transport=mock.transport())
    return build_server(make_settings(), store, instantly, StaticTokenVerifier(tokens=TOKENS), clock=clock)


class Approver:
    def __init__(self, answer):
        self.answer = answer
        self.messages: list[str] = []

    async def __call__(self, message, response_type, params, context):
        self.messages.append(message)
        return self.answer


def client(server, token, approver=None):
    return asgi_client(server, auth=token, elicitation_handler=approver or Approver({"confirm": True}))


async def test_tools_list_carries_annotations_and_output_schemas(server):
    async with client(server, "stranger-token") as c:
        tools = {t.name: t for t in await c.list_tools()}
    assert set(tools) == set(RULES)
    for name, tool in tools.items():
        assert tool.output_schema, name
        assert tool.annotations.open_world_hint is True, name
        assert tool.annotations.read_only_hint is (RULES[name].kind == "read"), name
    assert tools["reply_to_email"].annotations.destructive_hint is True
    assert tools["activate_campaign"].annotations.destructive_hint is True
    assert tools["create_campaign"].annotations.destructive_hint is False


async def test_any_signed_in_user_can_read_and_the_server_uses_its_own_key(server, mock):
    async with client(server, "stranger-token") as c:
        result = await c.call_tool("list_campaigns", {})
    assert result.structured_content["items"][0]["name"] == CAMPAIGN["name"]
    assert mock.calls("GET", "/api/v2/campaigns")[0].headers["authorization"] == "Bearer test-key"


async def test_an_unverified_email_is_treated_as_anonymous(server):
    async with client(server, "unverified-token") as c:
        result = await c.call_tool("list_campaigns", {}, raise_on_error=False)
    assert result.is_error and "sign in" in result.content[0].text


async def test_write_is_denied_for_a_user_outside_the_allowlist(server, mock):
    async with client(server, "stranger-token") as c:
        result = await c.call_tool("create_campaign", {"name": "x", "subject": "s", "body": "b"}, raise_on_error=False)
    assert result.is_error and "ALLOWED_EMAILS" in result.content[0].text
    assert mock.calls("POST", "/api/v2/campaigns") == []


async def test_send_asks_for_approval_and_runs_once_on_accept(server, mock):
    approver = Approver({"confirm": True})
    async with client(server, "owner-token", approver) as c:
        result = await c.call_tool("reply_to_email", REPLY_ARGS)
    assert len(approver.messages) == 1
    assert "To: lead@example.org" in approver.messages[0] and "Pricing attached." in approver.messages[0]
    sent = mock.calls("POST", "/api/v2/emails/reply")
    assert len(sent) == 1
    assert json.loads(sent[0].content)["reply_to_uuid"] == INBOUND["id"]
    assert result.structured_content["id"].endswith("e2")


@pytest.mark.parametrize("answer", [ElicitResult(action="decline"), ElicitResult(action="cancel"), {"confirm": False}])
async def test_a_declined_approval_never_reaches_instantly(server, mock, answer):
    async with client(server, "owner-token", Approver(answer)) as c:
        result = await c.call_tool("reply_to_email", REPLY_ARGS, raise_on_error=False)
    assert result.is_error and "declined" in result.content[0].text
    assert mock.calls("POST", "/api/v2/emails/reply") == []


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("reply_to_email", REPLY_ARGS | {"bcc_address_email_list": ["records@outside-example.net"]}),
        ("create_campaign", {"name": "x", "subject": "s", "body": "b", "bcc_list": ["records@outside-example.net"]}),
    ],
)
async def test_bcc_exfiltration_is_denied_before_any_approval_is_asked(server, mock, tool, args):
    approver = Approver({"confirm": True})
    async with client(server, "owner-token", approver) as c:
        result = await c.call_tool(tool, args, raise_on_error=False)
    assert result.is_error and "records@outside-example.net is outside RECIPIENT_DOMAINS" in result.content[0].text
    assert approver.messages == []
    assert [r for r in mock.requests if r.method == "POST"] == []


async def test_activate_checks_every_lead_and_the_campaign_bcc(server, mock):
    mock.leads = ["ana@example.com", "x@outside.net"]
    async with client(server, "owner-token") as c:
        leads = await c.call_tool("activate_campaign", {"campaign_id": CAMPAIGN["id"]}, raise_on_error=False)
        mock.leads = ["ana@example.com"]
        mock.campaign = CAMPAIGN | {"bcc_list": ["audit@outside.net"]}
        bcc = await c.call_tool("activate_campaign", {"campaign_id": CAMPAIGN["id"]}, raise_on_error=False)
    assert "x@outside.net" in leads.content[0].text
    assert "audit@outside.net" in bcc.content[0].text
    assert mock.calls("POST", f"/api/v2/campaigns/{CAMPAIGN['id']}/activate") == []


async def test_block_listed_recipient_is_denied(server, mock):
    async with client(server, "owner-token") as c:
        result = await c.call_tool("add_leads", {"campaign_id": CAMPAIGN["id"], "leads": [{"email": "a@competitor.example.com"}]}, raise_on_error=False)
    assert result.is_error and "block list" in result.content[0].text


async def test_rate_limit_trips_on_the_sixth_call_in_a_minute(server):
    async with client(server, "stranger-token") as c:
        for _ in range(5):
            assert not (await c.call_tool("list_campaigns", {}, raise_on_error=False)).is_error
        sixth = await c.call_tool("list_campaigns", {}, raise_on_error=False)
    assert sixth.is_error and "rate limit" in sixth.content[0].text


async def test_rate_limit_resets_the_next_minute(server, clock):
    async with client(server, "stranger-token") as c:
        for _ in range(6):
            await c.call_tool("list_campaigns", {}, raise_on_error=False)
        clock.now += 60
        assert not (await c.call_tool("list_campaigns", {}, raise_on_error=False)).is_error


async def test_audit_records_every_verdict_with_the_caller(server, store):
    async with client(server, "stranger-token") as c:
        await c.call_tool("list_campaigns", {})
        await c.call_tool("create_campaign", {"name": "x", "subject": "s", "body": "b"}, raise_on_error=False)
    async with client(server, "owner-token") as c:
        await c.call_tool("reply_to_email", REPLY_ARGS)
        resource = json.loads((await c.read_resource("audit://decisions"))[0].text)
    seen = [(e["user"], e["tool"], e["verdict"]) for e in reversed(resource["entries"])]
    assert seen == [
        (STRANGER, "list_campaigns", "allow"),
        (STRANGER, "create_campaign", "deny"),
        (OWNER, "reply_to_email", "hold"),
        (OWNER, "reply_to_email", "allow"),
    ]
    assert [e["tool"] for e in await audit_entries(store, STRANGER, make_settings())] == ["create_campaign", "list_campaigns"]


async def test_audit_keeps_only_the_last_200_decisions(server, store, clock):
    async with client(server, "stranger-token") as c:
        for i in range(205):
            clock.now += 61 if i % 5 == 0 else 0
            await c.call_tool("list_campaigns", {})
    assert len(await audit_entries(store, OWNER, make_settings())) == 200


async def test_daily_send_cap_counts_approved_recipients(server, clock):
    async with client(server, "owner-token") as c:
        for i in range(5):
            clock.now += 61
            await c.call_tool("reply_to_email", REPLY_ARGS)
        clock.now += 61
        sixth = await c.call_tool("reply_to_email", REPLY_ARGS, raise_on_error=False)
    assert sixth.is_error and "daily send cap" in sixth.content[0].text


async def test_approval_is_rejected_after_it_expires(server, mock, clock):
    async with client(server, "owner-token") as c:
        ask = await c.session.call_tool("reply_to_email", REPLY_ARGS, allow_input_required=True)
        clock.now += APPROVAL_TTL_SECONDS
        late = await c.session.call_tool("reply_to_email", REPLY_ARGS, input_responses=YES, request_state=ask.request_state)
    assert late.is_error and "approval expired" in late.content[0].text
    assert mock.calls("POST", "/api/v2/emails/reply") == []


async def test_approval_is_rejected_when_the_recipients_change_after_it(server, mock):
    async with client(server, "owner-token") as c:
        ask = await c.session.call_tool("reply_to_email", REPLY_ARGS, allow_input_required=True)
        mock.inbound = INBOUND | {"from_address_email": "other@example.org"}
        retry = await c.session.call_tool("reply_to_email", REPLY_ARGS, input_responses=YES, request_state=ask.request_state)
    assert retry.is_error and "recipients changed" in retry.content[0].text
    assert mock.calls("POST", "/api/v2/emails/reply") == []


async def test_approval_is_rejected_when_the_arguments_are_swapped(server, mock):
    async with client(server, "owner-token") as c:
        ask = await c.session.call_tool("reply_to_email", REPLY_ARGS, allow_input_required=True)
        with pytest.raises(MCPError, match="requestState"):
            await c.session.call_tool(
                "reply_to_email", REPLY_ARGS | {"body": "swapped"}, input_responses=YES, request_state=ask.request_state
            )
    assert mock.calls("POST", "/api/v2/emails/reply") == []


async def test_approval_is_rejected_for_a_different_user_on_the_web_path(mock, store, clock):
    settings = make_settings(ALLOWED_EMAILS=f"{OWNER},{STRANGER}")
    server = build_server(settings, store, Instantly("test-key", transport=mock.transport()), None, clock=clock)
    WEB_USER.set(OWNER)
    async with Client(server) as owner:
        ask = await owner.session.call_tool("reply_to_email", REPLY_ARGS, allow_input_required=True)
    WEB_USER.set(STRANGER)
    async with Client(server) as stranger:
        retry = await stranger.session.call_tool("reply_to_email", REPLY_ARGS, input_responses=YES, request_state=ask.request_state)
    assert retry.is_error and "different user" in retry.content[0].text
    assert mock.calls("POST", "/api/v2/emails/reply") == []


async def test_instantly_errors_reach_the_caller_and_a_missing_key_is_explained(store, clock):
    server = build_server(make_settings(), store, Instantly(""), None, clock=clock)
    WEB_USER.set(STRANGER)
    async with Client(server) as c:
        result = await c.call_tool("list_campaigns", {}, raise_on_error=False)
    assert result.is_error and "INSTANTLY_API_KEY is not set" in result.content[0].text


async def test_a_tool_added_after_startup_without_a_rule_is_refused(server):
    @server.tool
    def export_all_leads() -> str:
        return "every lead"

    async with client(server, "owner-token") as c:
        result = await c.call_tool("export_all_leads", {}, raise_on_error=False)
    assert result.is_error and "no guard rule" in result.content[0].text
