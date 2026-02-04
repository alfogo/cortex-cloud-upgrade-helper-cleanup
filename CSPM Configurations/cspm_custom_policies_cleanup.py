#!/usr/bin/env python3
"""Fetch CloudSec policies via UI session headers and filter by creator email.

This script calls:
  POST /api/cloudsec/v1/policy/get_data?type=grid&table_name=CLOUDSEC_POLICIES

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
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

import requests

DEFAULT_EMAIL = None
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

    # Start with captured headers (if any)
    captured = session.get("headers")
    if isinstance(captured, dict):
        headers.update({str(k): str(v) for k, v in captured.items()})

    # Always attach cookies
    cookie = session.get("cookie")
    if cookie:
        headers["Cookie"] = str(cookie)

    # Make sure request looks like an XHR to JSON endpoint
    headers["Accept"] = "application/json"
    headers["Content-Type"] = "application/json"
    headers.setdefault("Origin", base_url)
    headers.setdefault("x-requested-with", "XMLHttpRequest")

    if referer:
        headers["Referer"] = referer
    else:
        # Use captured referer if present; otherwise keep unset.
        pass

    _maybe_add_anti_csrf_headers(headers)
    return headers


def extract_items_and_total(body: Any) -> Tuple[List[Any], Optional[int]]:
    if isinstance(body, list):
        return body, None

    if isinstance(body, dict):
        # Try to extract total counts from common keys.
        total_keys = (
            "total",
            "totalCount",
            "total_count",
            "totalRows",
            "total_rows",
            "count",
            "number_of_results",
        )

        def find_total(obj: Any) -> Optional[int]:
            if isinstance(obj, dict):
                for k in total_keys:
                    if k in obj and isinstance(obj[k], int):
                        return obj[k]
                for v in obj.values():
                    t = find_total(v)
                    if t is not None:
                        return t
            return None

        total = find_total(body)

        # Common shapes we’ve seen across UI and public APIs.
        for key in (
            "reply",
            "data",
            "items",
            "results",
            "rows",
            "policies",
        ):
            if key in body and isinstance(body[key], (list, dict)):
                val = body[key]
                if isinstance(val, list):
                    return val, total
                if isinstance(val, dict):
                    for subkey in (
                        "items",
                        "results",
                        "rows",
                        "data",
                        "rowsData",
                        "rowData",
                        "DATA",
                    ):
                        if subkey in val and isinstance(val[subkey], list):
                            return val[subkey], total

                    # Sometimes rows live under "data" -> "rows" / "data" -> "items".
                    for subkey in ("rows", "items", "results"):
                        nested = val.get("data") if isinstance(val.get("data"), dict) else None
                        if nested and subkey in nested and isinstance(nested[subkey], list):
                            return nested[subkey], total

                    # Uppercase DATA seen in this API.
                    nested_upper = val.get("DATA") if isinstance(val.get("DATA"), dict) else None
                    if nested_upper:
                        for subkey in ("rows", "items", "results"):
                            if subkey in nested_upper and isinstance(nested_upper[subkey], list):
                                return nested_upper[subkey], total

        # Fallback: return the dict as a single item.
        return [body], total

    return [], None


def item_matches_email(item: Any, email: str) -> bool:
    if not isinstance(item, dict):
        return False

    # Try common creator keys.
    for key in (
        "created_by",
        "createdBy",
        "created_by_email",
        "creator",
        "owner",
        "createdByEmail",
        "created_by_user",
    ):
        v = item.get(key)
        if isinstance(v, str) and v.lower() == email.lower():
            return True

    # Deep search for email substring.
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


def find_policy_id(item: Any) -> Optional[str]:
    if not isinstance(item, dict):
        return None

    for key in ("id", "policy_id", "policyId", "uuid"):
        v = item.get(key)
        if isinstance(v, (str, int)):
            return str(v)

    # Some responses nest the policy under a key.
    for key in ("policy", "policyInfo", "data"):
        nested = item.get(key)
        if isinstance(nested, dict):
            found = find_policy_id(nested)
            if found:
                return found

    return None


def build_payload(from_: int, to: int) -> Dict[str, Any]:
    return {
        "extraData": None,
        "filter_data": {
            "sort": [{"FIELD": "modification_time", "ORDER": "DESC"}],
            "filter": {},
            "free_text": "",
            "visible_columns": None,
            "locked": None,
            "paging": {"from": from_, "to": to},
        },
        "jsons": [],
    }


def fetch_all_policies(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
    page_size: int,
    max_pages: int,
) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/cloudsec/v1/policy/get_data?type=grid&table_name=CLOUDSEC_POLICIES"

    all_items: List[Dict[str, Any]] = []
    total_expected: Optional[int] = None

    for page in range(max_pages):
        from_ = page * page_size
        to = from_ + page_size
        payload = build_payload(from_=from_, to=to)

        resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
        resp.raise_for_status()

        body = resp.json()
        items, total = extract_items_and_total(body)

        if total is not None and total_expected is None:
            total_expected = total

        # Keep only dict items.
        dict_items = [x for x in items if isinstance(x, dict)]

        if not dict_items:
            break

        all_items.extend(dict_items)

        if total_expected is not None and len(all_items) >= total_expected:
            break

        # Heuristic: if we got fewer than a full page, we’re done.
        if len(dict_items) < page_size:
            break

    return all_items


def delete_policy(*, base_url: str, headers: Dict[str, str], policy_id: str, timeout_s: int) -> int:
    url = f"{base_url}/api/cloudsec/v1/policy/{policy_id}"
    resp = requests.delete(url, headers=headers, timeout=timeout_s)
    return resp.status_code


def main() -> None:
    p = argparse.ArgumentParser(
        description="Fetch CloudSec policies via UI session headers and filter by creator email.",
    )
    p.add_argument("--session", type=Path, default=DEFAULT_SESSION_PATH, help="Path to cortex_ui_headers.json")
    p.add_argument("--fqdn", help="Override Cortex UI FQDN (host only, no https://)")
    p.add_argument("--email", required=True, help="Creator email to filter")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--page-size", type=int, default=100, help="Page size (default 100)")
    p.add_argument("--max-pages", type=int, default=100, help="Max pages to fetch (default 100)")
    p.add_argument("--referer", help="Override Referer header (optional)")
    p.add_argument("--confirm", action="store_true", help="Actually delete matched policies")
    p.add_argument(
        "--out",
        type=Path,
        help="Write matched policies to this file (JSON). If omitted, prints counts only.",
    )

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
        policies = fetch_all_policies(
            base_url=base_url,
            headers=headers,
            timeout_s=args.timeout,
            page_size=args.page_size,
            max_pages=args.max_pages,
        )
    except requests.HTTPError as e:
        text = getattr(e.response, "text", "") if getattr(e, "response", None) is not None else ""
        print(f"HTTP error fetching policies: {e} {text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error fetching policies: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(policies)} cloud policies from {base_url}")

    matched = [p for p in policies if item_matches_email(p, args.email)]

    print(f"Matched {len(matched)} cloud policies created by {args.email}")

    if not args.confirm:
        print("Dry run mode (no deletions). To actually delete cloud policies, rerun with --confirm flag.")
        return

    # Delete matched policies.
    success = 0
    fail = 0
    total = len(matched)
    for idx, policy in enumerate(matched, start=1):
        policy_id = find_policy_id(policy)
        if not policy_id:
            fail += 1
            print(f"Policy delete progress: {idx}/{total} (missing id)")
            continue
        try:
            status = delete_policy(
                base_url=base_url,
                headers=headers,
                policy_id=policy_id,
                timeout_s=args.timeout,
            )
            if 200 <= status < 300:
                success += 1
            else:
                fail += 1
            print(f"Policy delete progress: {idx}/{total}")
        except Exception:
            fail += 1
            print(f"Policy delete progress: {idx}/{total} (error)")

    print(f"Deleted cloud policies: success={success} fail={fail}")

    if args.out:
        output_text = json.dumps(matched, indent=2, sort_keys=True) + "\n"
        args.out.write_text(output_text, encoding="utf-8")


if __name__ == "__main__":
    main()
