# Outreach Guard

An MCP server for Instantly with a guard on every tool call. An agent can read campaigns, leads and the unibox, and create campaigns. It can also reply to leads and start campaigns, but only after the guard checks every recipient and a person approves the exact send. Every decision lands in an audit log.

Without `INSTANTLY_API_KEY` it runs on demo data: a fake Instantly workspace that answers with the field names from Instantly's OpenAPI file and records sends instead of delivering them. Set the key and the same code talks to a live workspace.

Two ways in:

1. Add `https://outreach-guard-mcp.vercel.app/mcp` as a custom connector in Claude (or any MCP client) and sign in with Google.
2. Open https://outreach-guard-mcp.vercel.app, sign in with Google, and chat with a Gemini agent that calls the same tools through the same guard.

## What it shows

| MCP 2026-07-28 feature | Where |
|---|---|
| `server/discover` with `supportedVersions`, `instructions`, capabilities | FastMCP 4.0.11, checked on the wire |
| No `initialize`, no `Mcp-Session-Id`, no GET stream (GET `/mcp` returns 405) | stateless Streamable HTTP at `/mcp` |
| 2025-11-25 clients still connect through `initialize` | legacy path, sends approve by link |
| Multi round-trip approval: `tools/call` returns `resultType: "input_required"` with a form elicitation | `outreach_guard/guard.py` |
| `requestState` sealed with AES-GCM under a shared key, bound to user, a digest of arguments and recipients, and a 5 minute expiry | `policy.approval_state`, `RequestStateSecurity` |
| `resultType`, `ttlMs` and `cacheScope` on results | FastMCP 4.0.11 |
| Output schemas and annotations on every tool, derived from the policy table | `server.hints`, `server.RULES` |
| OAuth: protected resource metadata, 401 with `resource_metadata`, PKCE S256, client ID metadata documents, DCR, `iss` in responses | `GoogleProvider` |
| Resource `audit://decisions` | `server.decisions` |

| Guardrail | Rule |
|---|---|
| Reads | any signed-in Google user with a verified email |
| Writes (`create_campaign`, `add_leads`) | email in `ALLOWED_EMAILS` |
| Sends (`activate_campaign`, `reply_to_email`) | allowlisted, every recipient passes, under `DAILY_SEND_CAP`, then a person approves |
| Recipients | `additional_recipients`, `cc_address_email_list`, `bcc_address_email_list`, campaign `cc_list` and `bcc_list`, lead emails, every lead of a campaign being started, and the sender a reply goes back to. Display names and case are normalized. Anything unreadable is denied. |
| Domains | each recipient domain must be in `RECIPIENT_DOMAINS` and not on Instantly's block list |
| Hidden BCC (the postmark-mcp backdoor) | an outside address in any BCC field is denied before any approval is asked |
| Rate limit | `RATE_LIMIT_PER_MIN` tool calls per user per minute, `CHAT_LIMIT_PER_DAY` web chats per user per day |
| Fail closed | a tool with no rule is refused, and a recipient lookup that fails denies the call |
| Credentials | the server calls Instantly with its own key; the client's token never leaves the server |
| Audit | user, tool, argument digest, verdict and reason for every decision, last 200 kept |
| Demo sandbox | in demo mode each user can change their own recipient domains, extra blocked domains, send cap (1 to 50), write access and whether sends need approval, from the Guardrails panel. Turning approval off keeps every other check. Changes apply only to that user's calls, land in the audit log, and live mode ignores them. |

The guard is one FastMCP middleware (`Guard.on_call_tool`), so a new tool cannot skip it. The decision itself is one pure function, `policy.check(rule, args, user, state, settings)`, fed by a table of rules: `RULES` maps each tool to `Rule(kind, recipient_fields, resolve)`. Registering a tool without a rule fails at startup.

## Verified live

Checked against https://outreach-guard-mcp.vercel.app on 2026-10-08, demo mode, Vercel with Upstash Redis.

- An MCP client (FastMCP `Client`, `auth="oauth"`) registered, passed the consent page and Google sign-in, got a token bound to `resource=/mcp`, negotiated `2026-07-28`, listed 8 tools, read campaigns, and was denied `create_campaign` with `bcc_list: ["phan@giftshop.club"]`.
- The protected resource metadata, the 401 with `resource_metadata`, and authorization server metadata with S256, CIMD and `iss` all answer as the spec requires.
- The web page signed in with Google, ran Gemini `gemini-3.8-flash` through the guard, denied a reply that BCC'd `phan@giftshop.club`, held a clean reply for approval, sent it once on approve, and sent nothing on reject.
- Saving and resetting demo rules works, a cap of 99 is refused with 400, and both changes land in the audit log.
- Not tested yet: Claude.ai custom connectors and Claude Code.

## Run locally

```bash
uv sync
cp .env.example .env    # then fill it in
uv run --env-file .env uvicorn index:app --port 8000
```

Google sign-in needs these redirect URIs on the OAuth client: `http://localhost:8000/auth/callback` (MCP clients) and `http://localhost:8000/auth/web/callback` (web page).

The agent also runs from a terminal and asks for approval there:

```bash
uv run --env-file .env python -m outreach_guard.agent "List my campaigns" --url http://localhost:8000/mcp
```

On Vercel, `index.py` exports the ASGI app and `vercel.json` selects the Python runtime. Set `REDIS_URL` there so counters, approvals, audit, OAuth clients and demo data are shared across instances.

## Connect a client

The page's Connect panel shows these with copy buttons and a live connection check (`GET /api/selfcheck`).

| Client | How | Source |
|---|---|---|
| Claude.ai, Claude Desktop | Settings > Connectors > Add custom connector, paste the URL, sign in with Google | |
| Claude Code | `claude mcp add --transport http outreach-guard https://<host>/mcp`, then `/mcp` to sign in | [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp) |
| Cursor | `cursor://anysphere.cursor-deeplink/mcp/install?name=outreach-guard&config=<base64 of {"url": ...}>` | [cursor.com/docs/context/mcp/install-links](https://cursor.com/docs/context/mcp/install-links) |
| VS Code | `vscode:mcp/install?<url-encoded {"name", "type": "http", "url"}>` | [code.visualstudio.com/api/extension-guides/ai/mcp](https://code.visualstudio.com/api/extension-guides/ai/mcp) |
| MCP Inspector | `npx @modelcontextprotocol/inspector --server-url https://<host>/mcp --transport http` | [modelcontextprotocol.io/docs/tools/inspector](https://modelcontextprotocol.io/docs/tools/inspector) |

To read this code from an MCP client, add `https://gitmcp.io/akv2011/outreach-guard-mcp`. GitMCP serves a public GitHub repo as a remote MCP server, so it works once the repo is public.

A 2026-07-28 client approves sends in its own UI. A 2025-11-25 client cannot answer `input_required`, so the call fails with a link to this page; approve there and ask the client to run the same call again. The approval covers that exact call once, for 10 minutes.

## Environment

| Name | Default | Meaning |
|---|---|---|
| `BASE_URL` | `http://localhost:8000` | public URL, used for OAuth metadata and approval links |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | | Google OAuth client for both sign-ins |
| `JWT_SIGNING_KEY` | | signs the tokens the OAuth proxy issues; same value on every instance |
| `SESSION_SECRET` | | 32+ characters; signs web session cookies and seals `requestState` |
| `INSTANTLY_API_KEY` | | unset means demo data |
| `REDIS_URL` | | unset means in-memory state, fine for one process |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | `gemini-3.8-flash` | web and terminal agent, thinking level low |
| `ALLOWED_EMAILS` | | comma-separated emails allowed to write and send |
| `RECIPIENT_DOMAINS` | demo: `example.com,example.org,example.net`; live: none | comma-separated domains sends may reach; an explicit value always wins |
| `DAILY_SEND_CAP` | `5` | recipients per user per UTC day |
| `RATE_LIMIT_PER_MIN` | `5` | tool calls per user per minute |
| `CHAT_LIMIT_PER_DAY` | `10` | web chat requests per user per UTC day |

## Tools and Instantly endpoints

Field names come from Instantly's OpenAPI file, [api.instantly.ai/openapi/api_v2.json](https://api.instantly.ai/openapi/api_v2.json), copied to `tests/fixtures/instantly_api_v2.json`.

| Tool | Kind | Endpoint | Docs |
|---|---|---|---|
| `list_campaigns` | read | GET `/api/v2/campaigns` | [List campaign](https://developer.instantly.ai/api-reference/campaign/list-campaign) |
| `campaign_analytics` | read | GET `/api/v2/campaigns/analytics` | [Get campaigns analytics](https://developer.instantly.ai/api-reference/campaign/get-campaigns-analytics) |
| `list_leads` | read | POST `/api/v2/leads/list` | [List leads](https://developer.instantly.ai/api-reference/lead/list-leads) |
| `list_emails` | read | GET `/api/v2/emails` | [List email](https://developer.instantly.ai/api-reference/email/list-email) |
| `create_campaign` | write | POST `/api/v2/campaigns` | [Create campaign](https://developer.instantly.ai/api-reference/campaign/create-campaign) |
| `add_leads` | write | POST `/api/v2/leads/add` | [Add leads in bulk](https://developer.instantly.ai/api-reference/lead/add-leads-in-bulk-to-a-campaign-or-list) |
| `activate_campaign` | send | POST `/api/v2/campaigns/{id}/activate`; the guard first reads GET `/api/v2/campaigns/{id}` and every page of POST `/api/v2/leads/list` | [Activate](https://developer.instantly.ai/api-reference/campaign/activatestart-or-resume-a-campaign), [Get campaign](https://developer.instantly.ai/api-reference/campaign/get-campaign) |
| `reply_to_email` | send | POST `/api/v2/emails/reply`; the guard first reads GET `/api/v2/emails/{id}` to find who the reply goes to | [Reply](https://developer.instantly.ai/api-reference/email/reply-to-an-email), [Get email](https://developer.instantly.ai/api-reference/email/get-email) |
| guard | | GET `/api/v2/block-lists-entries` | [List block list entry](https://developer.instantly.ai/api-reference/blocklistentry/list-block-list-entry) |

## Tests

```bash
uv run pytest
```

- `tests/test_policy.py` covers every branch of the pure decision function.
- `tests/test_server.py` runs the server over real HTTP in-process with bearer tokens and Instantly mocked at the HTTP layer: annotations and schemas, the approval round trip, BCC exfiltration, request state binding, rate limit, audit.
- `tests/test_web.py` covers web sign-in with PKCE, session cookies, the chat stream, browser approvals, the chat limit, 2025-11-25 clients approving by link, the connection check, and the demo sandbox.
- `tests/test_contract.py` validates every demo response and every request the client sends against Instantly's OpenAPI file, and checks that the client's models read only fields Instantly defines.

`tests/e2e_live.py` checks a running deployment and is not collected by pytest:

```bash
uv run python tests/e2e_live.py --base-url https://<host>            # metadata, 401, PKCE
uv run python tests/e2e_live.py --base-url https://<host> --oauth    # signs in, one real read, one send that must be denied
```

It only attempts a real send with `--allow-send`, and that send still waits for a `y` at the terminal.

## Known limits

- Counters, the audit log and approval redemption use read-then-write on the key-value store, so concurrent requests can race. Each spot carries a `ponytail:` comment naming the fix.
- The block list and campaign leads are read at most 1,000 entries deep; past that the guard denies the send rather than guess.
