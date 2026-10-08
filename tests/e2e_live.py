"""Checks a running deployment over real HTTP. Not collected by pytest.

uv run python tests/e2e_live.py --base-url https://outreach-guard-mcp.vercel.app
uv run python tests/e2e_live.py --base-url http://localhost:8000 --oauth             # signs in through the browser
uv run python tests/e2e_live.py --base-url http://localhost:8000 --oauth --allow-send
"""

import argparse
import asyncio
import json
import sys

import httpx
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult

OUTSIDE = "records@outside-example.invalid"
failures: list[str] = []


def report(ok: bool, label: str, detail: object = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    if not ok:
        failures.append(label)


def http_checks(base: str) -> None:
    with httpx.Client(timeout=15) as http:
        prm_url = f"{base}/.well-known/oauth-protected-resource/mcp"
        prm = http.get(prm_url).json()
        report(prm.get("resource") == f"{base}/mcp", "PRM names this server as the resource", prm.get("resource"))
        report(bool(prm.get("authorization_servers")), "PRM lists an authorization server", prm.get("authorization_servers"))

        call = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        anon = http.post(f"{base}/mcp", json=call, headers={"accept": "application/json, text/event-stream"})
        challenge = anon.headers.get("www-authenticate", "")
        report(anon.status_code == 401, "unauthenticated POST /mcp is 401", anon.status_code)
        report(f'resource_metadata="{prm_url}"' in challenge, "WWW-Authenticate points at the PRM", challenge)

        issuer = prm["authorization_servers"][0].rstrip("/")
        meta = http.get(f"{issuer}/.well-known/oauth-authorization-server").json()
        report("S256" in meta.get("code_challenge_methods_supported", []), "authorization server offers PKCE S256", meta.get("code_challenge_methods_supported"))
        report(meta.get("client_id_metadata_document_supported") is True, "authorization server accepts CIMD client ids")


async def ask_in_terminal(message, response_type, params, context):
    print(f"\n{message}\n")
    answer = await asyncio.to_thread(input, "Approve send? [y/N] ")
    return {"confirm": True} if answer.strip().lower() == "y" else ElicitResult(action="decline")


async def oauth_checks(base: str, allow_send: bool) -> None:
    async with Client(f"{base}/mcp", auth="oauth", elicitation_handler=ask_in_terminal) as client:
        tools = await client.list_tools()
        report(len(tools) == 8, "tools/list returns 8 tools", [t.name for t in tools])
        campaigns = await client.call_tool("list_campaigns", {"limit": 5}, raise_on_error=False)
        report(not campaigns.is_error, "real read: list_campaigns", json.dumps(campaigns.structured_content)[:300] if not campaigns.is_error else campaigns.content[0].text)

        inbox = await client.call_tool("list_emails", {"email_type": "received", "limit": 1}, raise_on_error=False)
        items = (inbox.structured_content or {}).get("items", []) if not inbox.is_error else []
        reply = {
            "email_id": items[0]["id"] if items else "none",
            "eaccount": items[0]["eaccount"] if items else "none",
            "subject": "Re: your note",
            "body": "Thanks, following up shortly.",
        }
        denied = await client.call_tool("reply_to_email", reply | {"bcc_address_email_list": [OUTSIDE]}, raise_on_error=False)
        text = denied.content[0].text if denied.content else ""
        report(denied.is_error and text.startswith("Denied by guard"), "send with an outside BCC is denied", text)

        if allow_send and items:
            sent = await client.call_tool("reply_to_email", reply, raise_on_error=False)
            report(True, "real send attempted (you approved or declined it)", sent.content[0].text[:300] if sent.content else "")
        audit = json.loads((await client.read_resource("audit://decisions"))[0].text)
        for entry in audit["entries"][:5]:
            print(f"      audit  {entry['verdict']:5}  {entry['tool']:18}  {entry['reason']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--oauth", action="store_true", help="sign in with Google and call tools")
    parser.add_argument("--allow-send", action="store_true", help="also try one real reply, still behind the approval prompt")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    http_checks(base)
    if args.oauth:
        asyncio.run(oauth_checks(base, args.allow_send))
    print(f"\n{len(failures)} failed" if failures else "\nall passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
