"""Checks the demo backend and the client against Instantly's own OpenAPI file (tests/fixtures/instantly_api_v2.json,
downloaded from https://api.instantly.ai/openapi/api_v2.json)."""

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl

import httpx
import pytest
from fastmcp import Client
from jsonschema import Draft202012Validator
from key_value.aio.stores.memory import MemoryStore

from outreach_guard import instantly as models
from outreach_guard.fake_instantly import fake_transport
from outreach_guard.guard import WEB_USER
from outreach_guard.instantly import Instantly
from outreach_guard.server import build_server
from tests.conftest import OWNER, make_settings

SPEC = json.loads((Path(__file__).parent / "fixtures" / "instantly_api_v2.json").read_text())
TEMPLATES = sorted(SPEC["paths"], key=lambda p: p.count("{"))


def operation(method: str, path: str) -> tuple[str, dict]:
    for template in TEMPLATES:
        if re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", template), path) and method.lower() in SPEC["paths"][template]:
            return template, SPEC["paths"][template][method.lower()]
    raise AssertionError(f"{method} {path} is not in Instantly's API")


def validate(pointer: str, instance: object) -> list[str]:
    schema = SPEC | {"$ref": pointer}
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in Draft202012Validator(schema).iter_errors(instance)]


def pointer(template: str, method: str, *rest: str) -> str:
    escaped = template.replace("~", "~0").replace("/", "~1")
    return "/".join(["#/paths", escaped, method.lower(), *[r.replace("/", "~1") for r in rest]])


class Recorder(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.exchanges: list[tuple[httpx.Request, httpx.Response]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        await response.aread()
        self.exchanges.append((request, response))
        return response


async def approve(message, response_type, params, context):
    return {"confirm": True}


@pytest.fixture
async def exchanges():
    store = MemoryStore()
    recorder = Recorder(fake_transport(store))
    settings = make_settings(DAILY_SEND_CAP="50", RATE_LIMIT_PER_MIN="50")
    server = build_server(settings, store, Instantly("demo", transport=recorder), None)
    WEB_USER.set(OWNER)
    async with Client(server, elicitation_handler=approve) as c:
        campaign = (await c.call_tool("list_campaigns", {"limit": 2})).structured_content["items"][0]
        await c.call_tool("list_campaigns", {"limit": 2, "starting_after": campaign["id"]})
        await c.call_tool("campaign_analytics", {})
        await c.call_tool("list_leads", {"campaign_id": campaign["id"]})
        inbox = (await c.call_tool("list_emails", {"email_type": "received"})).structured_content["items"]
        created = await c.call_tool(
            "create_campaign", {"name": "Contract", "subject": "Hi", "body": "<p>Hi</p>", "email_list": ["outreach@example.net"], "cc_list": ["ana@example.com"]}
        )
        new_id = created.structured_content["id"]
        await c.call_tool("add_leads", {"campaign_id": new_id, "leads": [{"email": "zoe@example.com", "first_name": "Zoe"}]})
        await c.call_tool("activate_campaign", {"campaign_id": new_id})
        await c.call_tool(
            "reply_to_email",
            {"email_id": inbox[0]["id"], "eaccount": "outreach@example.net", "subject": "Re", "body": "Thanks",
             "cc_address_email_list": ["ana@example.com"], "additional_recipients": ["chen@example.com"]},
        )
    return recorder.exchanges


async def test_every_demo_response_matches_instantlys_response_schema(exchanges):
    covered = set()
    for request, response in exchanges:
        assert response.status_code == 200, (request.method, request.url.path, response.text)
        template, _ = operation(request.method, request.url.path)
        covered.add((request.method, template))
        schema = pointer(template, request.method, "responses", "200", "content", "application/json", "schema")
        assert validate(schema, response.json()) == [], (request.method, template)
    assert len(covered) == 11


async def test_every_request_the_client_sends_matches_instantlys_request_schema(exchanges):
    for request, _ in exchanges:
        template, op = operation(request.method, request.url.path)
        known = {p["name"] for p in op.get("parameters", []) if p.get("in") == "query"}
        assert {k for k, _ in parse_qsl(request.url.query.decode())} <= known, (request.method, template)
        if request.content:
            schema = pointer(template, request.method, "requestBody", "content", "application/json", "schema")
            assert validate(schema, json.loads(request.content)) == [], (request.method, template)


def _properties(schema: dict) -> set[str]:
    while "$ref" in schema:
        schema = SPEC["components"]["schemas"][schema["$ref"].split("/")[-1]]
    return set(schema.get("properties", {}))


def _item(path: str, method: str) -> dict:
    schema = SPEC["paths"][path][method]["responses"]["200"]["content"]["application/json"]["schema"]
    while "$ref" in schema:
        schema = SPEC["components"]["schemas"][schema["$ref"].split("/")[-1]]
    if schema.get("type") == "array":
        return schema["items"]
    return schema["properties"]["items"]["items"] if "next_starting_after" in schema.get("properties", {}) else schema


@pytest.mark.parametrize(
    ("model", "path", "method"),
    [
        (models.Campaign, "/api/v2/campaigns", "get"),
        (models.CampaignDetail, "/api/v2/campaigns/{id}", "get"),
        (models.CampaignAnalytics, "/api/v2/campaigns/analytics", "get"),
        (models.Lead, "/api/v2/leads/list", "post"),
        (models.Email, "/api/v2/emails", "get"),
        (models.AddLeadsResult, "/api/v2/leads/add", "post"),
    ],
)
def test_client_models_only_read_fields_instantly_defines(model, path, method):
    assert set(model.model_fields) <= _properties(_item(path, method))
