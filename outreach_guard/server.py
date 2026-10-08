import html
import time
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AuthProvider
from fastmcp.server.auth.providers.google import GoogleProvider
from key_value.aio.protocols import AsyncKeyValue
from mcp.server.request_state import RequestStateSecurity
from mcp_types import ToolAnnotations
from pydantic import BaseModel, Field

from outreach_guard.config import Settings
from outreach_guard.guard import Guard, audit_entries, current_user
from outreach_guard.instantly import (
    AddLeadsResult,
    AnalyticsList,
    Campaign,
    CampaignPage,
    Email,
    EmailPage,
    Instantly,
    LeadPage,
)
from outreach_guard.policy import Kind, Resolved, Rule, addresses

INSTRUCTIONS = """\
Outreach Guard runs tools against one Instantly workspace, with a guard on every call.
Reads are open to any signed-in Google user. Writes need an allowlisted email.
Sends (activate_campaign, reply_to_email) also need every recipient, including cc and bcc,
inside the allowed domains and under the daily cap, and the user approves the exact recipients
and content before anything goes out. A blocked call fails with "Denied by guard: <reason>";
do not retry it with the same arguments."""

MODE_NOTE = {
    "demo": "Mode: demo data. A fake Instantly workspace; sends are recorded, never delivered.",
    "live": "Mode: live Instantly workspace. Approved sends are delivered.",
}

Limit = Annotated[int, Field(ge=1, le=100)]


class LeadIn(BaseModel):
    email: str
    first_name: str | None = None
    last_name: str | None = None
    company_name: str | None = None


def _excerpt(text: str, size: int = 1000) -> str:
    return text if len(text) <= size else text[:size] + "…"


async def campaign_recipients(instantly: Instantly, args: Mapping[str, Any]) -> Resolved:
    """every lead in the campaign plus its cc_list and bcc_list"""
    campaign = await instantly.get_campaign(str(args.get("campaign_id", "")))
    leads = await instantly.all_lead_emails(campaign.id)
    variant = ((campaign.sequences or [{}])[0].get("steps") or [{}])[0].get("variants") or [{}]
    preview = f"Campaign: {campaign.name}\nSubject: {variant[0].get('subject', '')}\nBody: {_excerpt(variant[0].get('body', ''))}"
    return Resolved(tuple(leads + (campaign.cc_list or []) + (campaign.bcc_list or [])), preview)


async def reply_recipients(instantly: Instantly, args: Mapping[str, Any]) -> Resolved:
    """the sender the reply goes back to"""
    original = await instantly.get_email(str(args.get("email_id", "")))
    to = tuple(a for a in (original.from_address_email, original.lead) if a)
    return Resolved(to, f"Subject: {args.get('subject', '')}\nBody: {_excerpt(str(args.get('body', '')))}")


RULES: dict[str, Rule] = {
    "list_campaigns": Rule(Kind.READ),
    "campaign_analytics": Rule(Kind.READ),
    "list_leads": Rule(Kind.READ),
    "list_emails": Rule(Kind.READ),
    "create_campaign": Rule(Kind.WRITE, recipient_fields=("cc_list", "bcc_list")),
    "add_leads": Rule(Kind.WRITE, recipient_fields=("leads",), idempotent=True),
    "activate_campaign": Rule(Kind.SEND, resolve=campaign_recipients, idempotent=True),
    "reply_to_email": Rule(
        Kind.SEND,
        recipient_fields=("additional_recipients", "cc_address_email_list", "bcc_address_email_list"),
        resolve=reply_recipients,
    ),
}


def hints(rule: Rule) -> ToolAnnotations:
    read = rule.kind is Kind.READ
    return ToolAnnotations(
        read_only_hint=read,
        destructive_hint=None if read else rule.kind is Kind.SEND,
        idempotent_hint=read or rule.idempotent,
        open_world_hint=True,
    )


def describe(rule: Rule) -> str:
    """What the guard checks for a rule, in words, for the Guardrails panel."""
    parts = ["signed-in Google user" if rule.kind is Kind.READ else "email in ALLOWED_EMAILS"]
    if rule.recipient_fields:
        parts.append("recipients in " + ", ".join(rule.recipient_fields))
    if rule.resolve:
        parts.append(f"recipients fetched from Instantly: {rule.resolve.__doc__}")
    if rule.recipient_fields or rule.resolve:
        parts.append("recipient domains and block list")
    if rule.kind is Kind.SEND:
        parts += ["daily send cap", "approval"]
    return "; ".join(parts) + "; rate limit"


def google_auth(settings: Settings, store: AsyncKeyValue) -> GoogleProvider:
    return GoogleProvider(
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        base_url=settings.base_url,
        required_scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
        client_storage=store,
        jwt_signing_key=settings.jwt_signing_key,
    )


def build_server(
    settings: Settings,
    store: AsyncKeyValue,
    instantly: Instantly,
    auth: AuthProvider | None,
    rules: Mapping[str, Rule] = RULES,
    clock: Callable[[], float] = time.time,
) -> FastMCP:
    mcp = FastMCP(
        "Outreach Guard",
        version="0.1.0",
        instructions=f"{INSTRUCTIONS}\n{MODE_NOTE[settings.mode]}",
        auth=auth,
        middleware=[Guard(rules, settings, store, instantly, clock)],
        # Every instance must unseal what another sealed, so the key comes from config, not the process.
        request_state_security=RequestStateSecurity(keys=[settings.derived_key("request-state")]),
    )

    async def list_campaigns(
        search: str | None = None, limit: Limit = 20, starting_after: str | None = None
    ) -> CampaignPage:
        """List campaigns by name. Status: 0 draft, 1 active, 2 paused, 3 completed. Page with next_starting_after."""
        return await instantly.list_campaigns(search, limit, starting_after)

    async def campaign_analytics(
        campaign_id: str | None = None, start_date: str | None = None, end_date: str | None = None
    ) -> AnalyticsList:
        """Sent, open, reply, bounce and opportunity counts per campaign. Omit campaign_id for all. Dates are YYYY-MM-DD."""
        return await instantly.analytics(campaign_id, start_date, end_date)

    async def list_leads(campaign_id: str, limit: Limit = 50, starting_after: str | None = None) -> LeadPage:
        """List the leads in one campaign."""
        return await instantly.list_leads(campaign_id, limit, starting_after)

    async def list_emails(
        campaign_id: str | None = None,
        email_type: Literal["received", "sent", "manual"] | None = None,
        limit: Limit = 10,
    ) -> EmailPage:
        """Recent emails from the unibox, newest first. email_type "received" shows replies from leads.
        Pass an email's id to reply_to_email."""
        return await instantly.list_emails(campaign_id, email_type, limit)

    async def create_campaign(
        name: str,
        subject: str,
        body: str,
        email_list: list[str] | None = None,
        timezone: str = "America/Detroit",
        send_from: str = "09:00",
        send_until: str = "17:00",
        daily_limit: int = 30,
        cc_list: list[str] | None = None,
        bcc_list: list[str] | None = None,
    ) -> Campaign:
        """Create a draft campaign with one email step, sending Monday to Friday between send_from and send_until.
        email_list holds the sending accounts. Nothing is sent until activate_campaign.
        cc_list and bcc_list are copied on every email, so the guard checks them as recipients.
        timezone must be one of Instantly's values (America/New_York is not one; use America/Detroit)."""
        weekdays = {str(d): 1 <= d <= 5 for d in range(7)}
        schedule = {"name": "Weekdays", "timing": {"from": send_from, "to": send_until}, "days": weekdays, "timezone": timezone}
        step = {"type": "email", "delay": 2, "variants": [{"subject": subject, "body": body}]}
        return await instantly.create_campaign(
            {
                "name": name,
                "campaign_schedule": {"schedules": [schedule]},
                "sequences": [{"steps": [step]}],
                "email_list": email_list or [],
                "daily_limit": daily_limit,
                "insert_unsubscribe_header": True,
                "cc_list": addresses(cc_list),
                "bcc_list": addresses(bcc_list),
            }
        )

    async def add_leads(campaign_id: str, leads: Annotated[list[LeadIn], Field(min_length=1, max_length=100)]) -> AddLeadsResult:
        """Add up to 100 leads to a campaign. Instantly skips leads already in it and leads on the block list."""
        payload = []
        for lead in leads:
            found = addresses(lead.email)
            if len(found) != 1:
                raise ToolError(f"each lead needs exactly one email address, got {lead.email!r}")
            payload.append(lead.model_dump(exclude_none=True) | {"email": found[0]})
        return await instantly.add_leads(campaign_id, payload)

    async def activate_campaign(campaign_id: str) -> Campaign:
        """Start or resume a campaign. It emails every lead in it plus its cc_list and bcc_list,
        so the guard checks all of them and asks the user to approve first."""
        return await instantly.activate(campaign_id)

    async def reply_to_email(
        email_id: str,
        eaccount: str,
        subject: str,
        body: str,
        additional_recipients: list[str] | None = None,
        cc_address_email_list: list[str] | None = None,
        bcc_address_email_list: list[str] | None = None,
    ) -> Email:
        """Reply to an email from list_emails. It goes to that email's sender plus any additional, cc and bcc
        addresses; eaccount is the connected inbox to send from. The user approves before it is sent."""
        request: dict[str, Any] = {
            "eaccount": eaccount,
            "reply_to_uuid": email_id,
            "subject": subject,
            "body": {"text": body, "html": html.escape(body).replace("\n", "<br/>")},
        }
        if extra := addresses(additional_recipients):
            request["additional_recipients"] = extra
        if cc := addresses(cc_address_email_list):
            request["cc_address_email_list"] = ",".join(cc)
        if bcc := addresses(bcc_address_email_list):
            request["bcc_address_email_list"] = ",".join(bcc)
        return await instantly.reply(request)

    for tool in (
        list_campaigns,
        campaign_analytics,
        list_leads,
        list_emails,
        create_campaign,
        add_leads,
        activate_campaign,
        reply_to_email,
    ):
        rule = rules.get(tool.__name__)
        if rule is None:
            raise RuntimeError(f"tool {tool.__name__!r} has no guard rule")
        mcp.tool(tool, annotations=hints(rule))

    @mcp.resource("audit://decisions", mime_type="application/json")
    async def decisions() -> dict[str, list[dict[str, Any]]]:
        """The last 200 guard decisions. Allowlisted users see everyone's; others see their own."""
        user = current_user()
        if not user:
            raise ToolError("sign in with Google first")
        return {"entries": await audit_entries(store, user, settings)}

    return mcp
