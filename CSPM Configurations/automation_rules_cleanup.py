#!/usr/bin/env python3
"""Fetch automation rules via UI session headers, filter by creator email, and optionally delete.

Calls:
  POST /api/webapp/get_data?type=grid&table_name=PLAYBOOK_SELECTION_RULES_TABLE
  POST /api/webapp/playbook/update_triggers/

Authentication model
--------------------
This is *not* a public Cortex API. It relies on an authenticated UI session:
- Cookies
- Anti-CSRF / request headers (for example x-csrf-token, x-xsrf-token)

Those values are expected to come from a session JSON captured with
`capture_headers_client.py capture ... --out cortex_ui_headers.json`.

Security
--------
The session JSON contains secrets. Do not commit it.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

import requests

DEFAULT_SESSION_PATH = Path("cortex_ui_headers.json")


def load_ui_session(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_cookie_value(cookie_header: str, names: Iterable[str]) -> Optional[str]:
    cookies: Dict[str, str] = {}
    for chunk in cookie_header.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        k, v = chunk.split("=", 1)
        cookies[k.strip()] = v.strip()

    for name in names:
        if name in cookies:
            return cookies[name]
    return None


def _maybe_add_anti_csrf_headers(headers: Dict[str, str]) -> None:
    cookie = headers.get("Cookie") or headers.get("cookie")
    if not cookie:
        return

    lower_keys = {k.lower() for k in headers.keys()}

    def set_if_missing(name: str, value: str) -> None:
        if name.lower() not in lower_keys:
            headers[name] = value
            lower_keys.add(name.lower())

    xsrf_val = _extract_cookie_value(cookie, names=("XSRF-TOKEN", "xsrf-token", "XSRF_TOKEN"))
    if xsrf_val:
        set_if_missing("x-xsrf-token", unquote(xsrf_val))

    csrf_val = _extract_cookie_value(
        cookie,
        names=("CSRF-TOKEN", "csrf-token", "csrftoken", "csrfToken", "csrf_token"),
    )
    if csrf_val:
        set_if_missing("x-csrf-token", unquote(csrf_val))


def build_headers(session: Dict[str, Any], *, base_url: str, referer: Optional[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}

    captured = session.get("headers")
    if isinstance(captured, dict):
        headers.update({str(k): str(v) for k, v in captured.items()})

    cookie = session.get("cookie")
    if cookie:
        headers["Cookie"] = str(cookie)

    headers["Accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers.setdefault("Origin", base_url)
    headers.setdefault("x-requested-with", "XMLHttpRequest")

    if referer:
        headers["Referer"] = referer

    _maybe_add_anti_csrf_headers(headers)
    return headers


def _refresh_request_token(headers: Dict[str, str]) -> None:
    headers["x-xdr-request-token"] = str(uuid.uuid4())


def item_matches_email(item: Any, email: str) -> bool:
    if not isinstance(item, dict):
        return False

    for key in (
        "CREATED_BY",
        "CREATED_BY_PRETTY",
        "created_by",
        "createdBy",
        "creator",
        "owner",
        "created_by_email",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.lower() == email.lower():
            return True

    target = email.lower()

    def search(obj: Any) -> bool:
        if isinstance(obj, str):
            return target in obj.lower()
        if isinstance(obj, dict):
            return any(search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(search(v) for v in obj)
        return False

    return search(item)


def fetch_rules_table(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    url = f"{base_url}/api/webapp/get_data?type=grid&table_name=PLAYBOOK_SELECTION_RULES_TABLE"
    payload = {"filter_data": {}}

    _refresh_request_token(headers)
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
    resp.raise_for_status()

    body = resp.json()

    rules_table: List[Dict[str, Any]] = []
    last_rules_hash: Optional[str] = None

    if isinstance(body, dict):
        # Look for rules table in common places.
        if "rules_table" in body and isinstance(body["rules_table"], list):
            rules_table = [r for r in body["rules_table"] if isinstance(r, dict)]
        elif "reply" in body and isinstance(body["reply"], dict):
            reply = body["reply"]
            if "rules_table" in reply and isinstance(reply["rules_table"], list):
                rules_table = [r for r in reply["rules_table"] if isinstance(r, dict)]

            # Response shape: reply.DATA is a list of rules
            if not rules_table and isinstance(reply.get("DATA"), list):
                rules_table = [r for r in reply["DATA"] if isinstance(r, dict)]

            # Response shape: reply.DATA is a dict containing rules_table
            if not rules_table and isinstance(reply.get("DATA"), dict):
                data = reply["DATA"]
                if "rules_table" in data and isinstance(data["rules_table"], list):
                    rules_table = [r for r in data["rules_table"] if isinstance(r, dict)]

        # Capture last_rules_hash if present (also accept RULES_HASH)
        last_rules_hash = body.get("last_rules_hash") if isinstance(body.get("last_rules_hash"), str) else None
        if not last_rules_hash and isinstance(body.get("reply"), dict):
            reply = body["reply"]
            last_rules_hash = reply.get("last_rules_hash") if isinstance(reply.get("last_rules_hash"), str) else None
            if not last_rules_hash:
                last_rules_hash = reply.get("RULES_HASH") if isinstance(reply.get("RULES_HASH"), str) else None
            if not last_rules_hash and isinstance(reply.get("DATA"), dict):
                data = reply["DATA"]
                last_rules_hash = data.get("last_rules_hash") if isinstance(data.get("last_rules_hash"), str) else None
                if not last_rules_hash:
                    last_rules_hash = data.get("RULES_HASH") if isinstance(data.get("RULES_HASH"), str) else None

    return rules_table, last_rules_hash


def update_triggers(
    *,
    base_url: str,
    headers: Dict[str, str],
    rules_table: List[Dict[str, Any]],
    last_rules_hash: Optional[str],
    timeout_s: int,
) -> requests.Response:
    url = f"{base_url}/api/webapp/playbook/update_triggers/"
    payload: Dict[str, Any] = {"rules_table": rules_table}
    if last_rules_hash:
        payload["last_rules_hash"] = last_rules_hash
        payload["RULES_HASH"] = last_rules_hash

    _refresh_request_token(headers)
    return requests.post(url, headers=headers, json=payload, timeout=timeout_s)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Fetch automation rules and remove those created by a user.",
    )
    p.add_argument("--session", type=Path, default=DEFAULT_SESSION_PATH, help="Path to cortex_ui_headers.json")
    p.add_argument("--fqdn", help="Override Cortex UI FQDN (host only, no https://)")
    p.add_argument("--email", required=True, help="Creator email to filter (matches CREATED_BY)")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--referer", help="Override Referer header (optional)")
    p.add_argument("--confirm", action="store_true", help="Actually update rules (delete matches)")

    args = p.parse_args()

    if not args.session.exists():
        print(f"Session file not found: {args.session}", file=sys.stderr)
        sys.exit(2)

    session = load_ui_session(args.session)
    if args.fqdn:
        base_url = f"https://{args.fqdn.strip().rstrip('/')}"
    else:
        base_url = str(session.get("base_url") or "").rstrip("/")
    if not base_url:
        print("Session JSON missing 'base_url'", file=sys.stderr)
        sys.exit(2)

    referer = args.referer
    if not referer:
        captured_headers = session.get("headers")
        if isinstance(captured_headers, dict):
            referer = captured_headers.get("referer") or captured_headers.get("Referer")

    headers = build_headers(session, base_url=base_url, referer=referer)

    try:
        rules_table, last_rules_hash = fetch_rules_table(
            base_url=base_url,
            headers=headers,
            timeout_s=args.timeout,
        )
    except requests.HTTPError as e:
        text = getattr(e.response, "text", "") if getattr(e, "response", None) is not None else ""
        print(f"HTTP error fetching automation rules: {e} {text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error fetching automation rules: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(rules_table)} automation rules from {base_url}")

    matched = [r for r in rules_table if item_matches_email(r, args.email)]
    remaining = [r for r in rules_table if not item_matches_email(r, args.email)]

    print(f"Matched {len(matched)} automation rules created by {args.email}")

    if not args.confirm:
        print("Dry run mode (no deletions). To actually delete automation rules, rerun with --confirm flag.")
        return

    try:
        resp = update_triggers(
            base_url=base_url,
            headers=headers,
            rules_table=remaining,
            last_rules_hash=last_rules_hash,
            timeout_s=args.timeout,
        )
        if 200 <= resp.status_code < 300:
            print("Deleted automation rules via update_triggers.")
        else:
            print(f"Update triggers failed: status={resp.status_code}")
            if resp.text:
                print(resp.text)
            sys.exit(1)
    except Exception as e:
        print(f"Error updating triggers: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
