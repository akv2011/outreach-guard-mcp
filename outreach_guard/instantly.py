"""Instantly API v2 client. Field names follow https://api.instantly.ai/openapi/api_v2.json."""

from collections.abc import Awaitable, Callable
from typing import Any, Literal

import httpx
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict

API_URL = "https://api.instantly.ai"
MAX_PAGES = 10


class InstantlyError(ToolError):
    pass


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Campaign(_Model):
    id: str
    name: str
    status: int


class CampaignDetail(Campaign):
    cc_list: list[str] | None = None
    bcc_list: list[str] | None = None
    sequences: list[dict[str, Any]] | None = None


class CampaignPage(_Model):
    items: list[Campaign]
    next_starting_after: str | None = None


class CampaignAnalytics(_Model):
    campaign_id: str
    campaign_name: str
    campaign_status: int
    leads_count: int
    contacted_count: int
    emails_sent_count: int
    open_count: int
    reply_count: int
    link_click_count: int
    bounced_count: int
    unsubscribed_count: int
    completed_count: int
    total_opportunities: int


class AnalyticsList(_Model):
    items: list[CampaignAnalytics]


class Lead(_Model):
    id: str
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    company_name: str | None = None
    status: int


class LeadPage(_Model):
    items: list[Lead]
    next_starting_after: str | None = None


class Email(_Model):
    id: str
    timestamp_email: str
    subject: str
    from_address_email: str | None = None
    to_address_email_list: str
    cc_address_email_list: str | None = None
    lead: str | None = None
    eaccount: str
    thread_id: str | None = None
    campaign_id: str | None = None
    content_preview: str | None = None


class EmailPage(_Model):
    items: list[Email]
    next_starting_after: str | None = None


class AddLeadsResult(_Model):
    status: str
    total_sent: int
    leads_uploaded: int
    in_blocklist: int
    duplicated_leads: int
    skipped_count: int
    invalid_email_count: int


class Instantly:
    def __init__(self, api_key: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.api_key = api_key
        self.http = httpx.AsyncClient(base_url=API_URL, timeout=20, transport=transport)

    async def _call(self, method: str, path: str, *, params: dict[str, Any] | None = None, json: Any = None) -> Any:
        if not self.api_key:
            raise InstantlyError("INSTANTLY_API_KEY is not set on the server")
        query = {k: v for k, v in (params or {}).items() if v is not None}
        r = await self.http.request(
            method, path, params=query, json=json, headers={"authorization": f"Bearer {self.api_key}"}
        )
        if r.is_error:
            try:
                message = r.json().get("message")
            except ValueError:
                message = r.text[:200]
            raise InstantlyError(f"Instantly returned {r.status_code}: {message}")
        return r.json()

    async def list_campaigns(self, search: str | None, limit: int, starting_after: str | None) -> CampaignPage:
        data = await self._call(
            "GET", "/api/v2/campaigns", params={"search": search, "limit": limit, "starting_after": starting_after}
        )
        return CampaignPage.model_validate(data)

    async def get_campaign(self, campaign_id: str) -> CampaignDetail:
        return CampaignDetail.model_validate(await self._call("GET", f"/api/v2/campaigns/{campaign_id}"))

    async def analytics(self, campaign_id: str | None, start_date: str | None, end_date: str | None) -> AnalyticsList:
        data = await self._call(
            "GET",
            "/api/v2/campaigns/analytics",
            params={"id": campaign_id, "start_date": start_date, "end_date": end_date},
        )
        return AnalyticsList(items=data)

    async def list_leads(self, campaign_id: str, limit: int, starting_after: str | None) -> LeadPage:
        body = {"campaign": campaign_id, "limit": limit, "starting_after": starting_after}
        data = await self._call("POST", "/api/v2/leads/list", json={k: v for k, v in body.items() if v is not None})
        return LeadPage.model_validate(data)

    async def all_lead_emails(self, campaign_id: str) -> list[str]:
        items = await self._all_pages(
            lambda cursor: self._call(
                "POST",
                "/api/v2/leads/list",
                json={"campaign": campaign_id, "limit": 100} | ({"starting_after": cursor} if cursor else {}),
            )
        )
        return [item["email"] for item in items if item.get("email")]

    async def list_emails(
        self, campaign_id: str | None, email_type: Literal["received", "sent", "manual"] | None, limit: int
    ) -> EmailPage:
        data = await self._call(
            "GET", "/api/v2/emails", params={"campaign_id": campaign_id, "email_type": email_type, "limit": limit}
        )
        return EmailPage.model_validate(data)

    async def get_email(self, email_id: str) -> Email:
        return Email.model_validate(await self._call("GET", f"/api/v2/emails/{email_id}"))

    async def create_campaign(self, body: dict[str, Any]) -> Campaign:
        return Campaign.model_validate(await self._call("POST", "/api/v2/campaigns", json=body))

    async def add_leads(self, campaign_id: str, leads: list[dict[str, Any]]) -> AddLeadsResult:
        data = await self._call("POST", "/api/v2/leads/add", json={"campaign_id": campaign_id, "leads": leads})
        return AddLeadsResult.model_validate(data)

    async def activate(self, campaign_id: str) -> Campaign:
        return Campaign.model_validate(await self._call("POST", f"/api/v2/campaigns/{campaign_id}/activate"))

    async def reply(self, body: dict[str, Any]) -> Email:
        return Email.model_validate(await self._call("POST", "/api/v2/emails/reply", json=body))

    async def blocked(self) -> frozenset[str]:
        items = await self._all_pages(
            lambda cursor: self._call(
                "GET", "/api/v2/block-lists-entries", params={"limit": 100, "starting_after": cursor}
            )
        )
        return frozenset(item["bl_value"].strip().lower() for item in items)

    async def _all_pages(self, fetch: Callable[[str | None], Awaitable[Any]]) -> list[dict[str, Any]]:
        # ponytail: stops at MAX_PAGES * 100 items and denies the call; search per recipient if lists grow past that.
        items: list[dict[str, Any]] = []
        cursor = None
        for _ in range(MAX_PAGES):
            page = await fetch(cursor)
            items += page["items"]
            cursor = page.get("next_starting_after")
            if not cursor or not page["items"]:
                return items
        raise ValueError(f"more than {MAX_PAGES * 100} entries to check, refusing to guess")
