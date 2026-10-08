import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from outreach_guard.config import Settings

OWNER = "owner@example.com"
STRANGER = "stranger@gmail.com"


def make_settings(**overrides: str) -> Settings:
    env = {
        "SESSION_SECRET": "test-session-secret-that-is-long-enough",
        "ALLOWED_EMAILS": OWNER,
        "RECIPIENT_DOMAINS": "example.com,example.org",
        "DAILY_SEND_CAP": "5",
        "RATE_LIMIT_PER_MIN": "5",
        "CHAT_LIMIT_PER_DAY": "10",
    }
    return Settings.from_env(env | overrides)


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


SCHEDULE = {
    "schedules": [
        {"name": "Weekdays", "timing": {"from": "09:00", "to": "17:00"}, "days": {"1": True}, "timezone": "America/Detroit"}
    ]
}
CAMPAIGN = {
    "id": "0199a1b2-0000-7000-8000-000000000001",
    "name": "Q4 founders",
    "status": 0,
    "campaign_schedule": SCHEDULE,
    "timestamp_created": "2026-10-01T10:00:00.000Z",
    "timestamp_updated": "2026-10-01T10:00:00.000Z",
}
INBOUND = {
    "id": "0199a1b2-0000-7000-8000-0000000000e1",
    "timestamp_created": "2026-10-07T16:20:00.000Z",
    "timestamp_email": "2026-10-07T16:20:00.000Z",
    "message_id": "<m1@example.org>",
    "subject": "Re: Quick question",
    "from_address_email": "lead@example.org",
    "to_address_email_list": "outreach@example.net",
    "body": {"text": "Interested, send pricing"},
    "organization_id": "0199a1b2-0000-7000-8000-0000000000aa",
    "eaccount": "outreach@example.net",
    "lead": "lead@example.org",
    "ue_type": 2,
}


class InstantlyMock:
    """Real Instantly field names, canned responses, and a record of every request."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.leads = ["ana@example.com"]
        self.campaign = dict(CAMPAIGN)
        self.inbound = dict(INBOUND)
        self.blocked = ["blocked@example.com", "competitor.example.com"]

    def calls(self, method: str, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path == path]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        routes: dict[tuple[str, str], Callable[[], Any]] = {
            ("GET", "/api/v2/campaigns"): lambda: {"items": [self.campaign], "next_starting_after": None},
            ("POST", "/api/v2/campaigns"): lambda: self.campaign | {"name": json.loads(request.content)["name"]},
            ("GET", f"/api/v2/campaigns/{CAMPAIGN['id']}"): lambda: self.campaign,
            ("POST", f"/api/v2/campaigns/{CAMPAIGN['id']}/activate"): lambda: self.campaign | {"status": 1},
            ("POST", "/api/v2/leads/list"): lambda: {
                "items": [{"id": f"lead-{i}", "email": e, "status": 1} for i, e in enumerate(self.leads)]
            },
            ("GET", f"/api/v2/emails/{INBOUND['id']}"): lambda: self.inbound,
            ("POST", "/api/v2/emails/reply"): lambda: INBOUND | {"id": "0199a1b2-0000-7000-8000-0000000000e2", "ue_type": 3},
            ("GET", "/api/v2/block-lists-entries"): lambda: {
                "items": [{"id": f"bl-{i}", "bl_value": v, "is_domain": "@" not in v} for i, v in enumerate(self.blocked)]
            },
        }
        route = routes.get((request.method, request.url.path))
        if route is None:
            return httpx.Response(404, json={"statusCode": 404, "error": "Not Found", "message": "no route"})
        return httpx.Response(200, json=route())
