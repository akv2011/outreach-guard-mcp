import pytest
from key_value.aio.stores.memory import MemoryStore

from outreach_guard.config import Settings
from outreach_guard.instantly import Instantly
from outreach_guard.policy import (
    APPROVAL_TTL_SECONDS,
    Allow,
    Deny,
    Kind,
    NeedsApproval,
    Rule,
    State,
    approval_problem,
    approval_state,
    check,
    digest,
    effective_settings,
    parse_overrides,
)
from outreach_guard.server import RULES, build_server
from tests.conftest import OWNER, STRANGER, make_settings

S = make_settings()
READ = Rule(Kind.READ)
WRITE = Rule(Kind.WRITE)
REPLY = RULES["reply_to_email"]
ADD_LEADS = RULES["add_leads"]
CREATE = RULES["create_campaign"]
ACTIVATE = RULES["activate_campaign"]


def denied(verdict: object, *words: str) -> bool:
    return isinstance(verdict, Deny) and all(w in verdict.reason for w in words)


def test_read_is_open_to_any_signed_in_user():
    assert check(READ, {}, STRANGER, State(), S) == Allow()


def test_anonymous_caller_is_denied_even_for_reads():
    assert denied(check(READ, {}, None, State(), S), "sign in")


@pytest.mark.parametrize("rule", [WRITE, REPLY], ids=["write", "send"])
def test_write_and_send_need_an_allowlisted_email(rule):
    assert denied(check(rule, {}, STRANGER, State(), S), "ALLOWED_EMAILS")


def test_allowlisted_owner_can_write():
    assert check(WRITE, {}, OWNER, State(), S) == Allow()


def test_rate_limit_applies_after_the_fifth_call_in_a_minute():
    assert check(READ, {}, STRANGER, State(calls_this_minute=5), S) == Allow()
    assert denied(check(READ, {}, STRANGER, State(calls_this_minute=6), S), "rate limit")


@pytest.mark.parametrize(
    ("rule", "field", "value"),
    [
        (REPLY, "additional_recipients", ["x@outside.net"]),
        (REPLY, "cc_address_email_list", ["x@outside.net"]),
        (REPLY, "bcc_address_email_list", ["x@outside.net"]),
        (CREATE, "cc_list", ["x@outside.net"]),
        (CREATE, "bcc_list", ["x@outside.net"]),
        (ADD_LEADS, "leads", [{"email": "x@outside.net"}]),
    ],
)
def test_every_recipient_field_is_checked_against_the_domains(rule, field, value):
    assert denied(check(rule, {field: value}, OWNER, State(resolved=("lead@example.com",)), S), "x@outside.net", "RECIPIENT_DOMAINS")


def test_hidden_bcc_to_an_outside_domain_is_denied_even_when_the_to_is_fine():
    args = {"additional_recipients": ["ana@example.com"], "bcc_address_email_list": ["records@outside-example.net"]}
    assert denied(check(REPLY, args, OWNER, State(resolved=("lead@example.org",)), S), "records@outside-example.net")


def test_recipients_inside_the_domains_ask_for_approval():
    args = {"cc_address_email_list": ["ana@example.com"]}
    assert check(REPLY, args, OWNER, State(resolved=("ben@example.org",)), S) == NeedsApproval(
        ("ana@example.com", "ben@example.org")
    )


def test_display_names_and_case_are_normalized():
    args = {"cc_address_email_list": ["Ana Ruiz <ANA@Example.COM>", "  ana@example.com "]}
    assert check(REPLY, args, OWNER, State(), S) == NeedsApproval(("ana@example.com",))


def test_display_name_cannot_disguise_an_outside_address():
    args = {"bcc_address_email_list": ["ana@example.com <x@outside.net>"]}
    assert denied(check(REPLY, args, OWNER, State(), S), "x@outside.net")


def test_a_comma_separated_string_cannot_smuggle_a_second_address():
    args = {"cc_address_email_list": "ana@example.com, x@outside.net"}
    assert denied(check(REPLY, args, OWNER, State(), S), "x@outside.net")


@pytest.mark.parametrize("value", [42, ["no-at-sign"], [{"name": "no email"}], ["a@b@example.com"]])
def test_unreadable_recipients_are_denied_not_skipped(value):
    assert denied(check(REPLY, {"cc_address_email_list": value}, OWNER, State(), S), "unreadable")


@pytest.mark.parametrize("entry", ["ana@example.com", "example.com"], ids=["email", "domain"])
def test_block_list_entries_deny_by_email_and_by_domain(entry):
    state = State(blocked=frozenset({entry}))
    assert denied(check(ADD_LEADS, {"leads": [{"email": "ana@example.com"}]}, OWNER, state, S), "block list")


def test_recipients_fetched_from_instantly_are_checked_too():
    assert denied(check(ACTIVATE, {}, OWNER, State(resolved=("ana@example.com", "x@outside.net")), S), "x@outside.net")


def test_a_send_with_no_recipients_is_denied():
    assert denied(check(ACTIVATE, {}, OWNER, State(), S), "no recipients")


def test_daily_cap_counts_recipients():
    two = State(resolved=("ana@example.com", "ben@example.org"), sends_today=3)
    assert isinstance(check(ACTIVATE, {}, OWNER, two, S), NeedsApproval)
    assert denied(check(ACTIVATE, {}, OWNER, State(resolved=two.resolved, sends_today=4), S), "daily send cap")


def test_send_is_denied_when_no_recipient_domains_are_configured():
    assert denied(check(ACTIVATE, {}, OWNER, State(resolved=("ana@example.com",)), make_settings(RECIPIENT_DOMAINS="")), "RECIPIENT_DOMAINS")


def test_approval_state_binds_user_arguments_and_expiry():
    d = digest("reply_to_email", {"body": "hi"}, ("ana@example.com",))
    state = approval_state(OWNER, d, now=1000.0)
    assert approval_problem(state, OWNER, d, now=1000.0 + APPROVAL_TTL_SECONDS - 1) is None
    assert approval_problem(state, STRANGER, d, now=1000.0) == "approval was given to a different user"
    swapped = digest("reply_to_email", {"body": "swapped"}, ("ana@example.com",))
    assert approval_problem(state, OWNER, swapped, now=1000.0) == "arguments or recipients changed after approval"
    assert approval_problem(state, OWNER, d, now=1000.0 + APPROVAL_TTL_SECONDS) == "approval expired"
    assert approval_problem(None, OWNER, d, now=1000.0) == "approval state missing"


def test_a_tool_without_a_rule_fails_at_startup():
    rules = {name: rule for name, rule in RULES.items() if name != "reply_to_email"}
    with pytest.raises(RuntimeError, match="reply_to_email"):
        build_server(S, MemoryStore(), Instantly(""), None, rules=rules)


def test_demo_mode_opens_the_seeded_domains_and_live_mode_opens_none():
    assert Settings.from_env({}).recipient_domains == {"example.com", "example.org", "example.net"}
    assert Settings.from_env({"INSTANTLY_API_KEY": "k"}).recipient_domains == frozenset()
    assert Settings.from_env({"RECIPIENT_DOMAINS": ""}).recipient_domains == frozenset()


def test_approval_off_turns_a_send_into_allow_but_keeps_every_other_check():
    off = make_settings(DAILY_SEND_CAP="2")
    off = type(off)(**{**off.__dict__, "require_approval": False})
    inside = State(resolved=("ana@example.com",))
    assert check(ACTIVATE, {}, OWNER, inside, off) == Allow(("ana@example.com",))
    assert denied(check(ACTIVATE, {}, OWNER, State(resolved=("x@outside.net",)), off), "RECIPIENT_DOMAINS")
    assert denied(check(ACTIVATE, {}, OWNER, State(resolved=inside.resolved, sends_today=2), off), "daily send cap")


def test_overrides_are_ignored_in_live_mode_and_for_other_users():
    overrides = parse_overrides(
        {"recipient_domains": ["outside.net"], "blocked_domains": [], "daily_send_cap": 9, "write_access": True, "require_approval": False}
    )
    demo, live = make_settings(), make_settings(INSTANTLY_API_KEY="k")
    mine = effective_settings(demo, STRANGER, overrides)
    assert mine.recipient_domains == {"outside.net"} and STRANGER in mine.allowed_emails and not mine.require_approval
    assert effective_settings(live, STRANGER, overrides) is live
    assert effective_settings(demo, STRANGER, None) is demo


@pytest.mark.parametrize(
    "bad",
    [
        {"recipient_domains": ["not a domain"]},
        {"blocked_domains": ["x.com"] * 21},
        {"daily_send_cap": 51},
        {"write_access": "yes"},
    ],
)
def test_overrides_are_validated_before_they_are_stored(bad):
    good = {"recipient_domains": ["Example.COM "], "blocked_domains": [], "daily_send_cap": 3, "write_access": False, "require_approval": True}
    assert parse_overrides(good)["recipient_domains"] == ["example.com"]
    with pytest.raises(ValueError):
        parse_overrides(good | bad)
