#!/usr/bin/env python3
"""Fetch CloudSec rules via UI session headers, filter by creator email, and optionally delete.

Calls:
  POST /api/cloudsec/v1/rules/get_data?type=grid&table_name=CLOUDSEC_RULES
  PATCH /api/cloudsec/v1/rule/{id}

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

DEFAULT_NAME = None
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


def extract_items_and_total(body: Any) -> Tuple[List[Any], Optional[int]]:
    if isinstance(body, list):
        return body, None

    if isinstance(body, dict):
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

        for key in (
            "reply",
            "data",
            "items",
            "results",
            "rows",
            "rules",
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

                    for subkey in ("rows", "items", "results"):
                        nested = val.get("data") if isinstance(val.get("data"), dict) else None
                        if nested and subkey in nested and isinstance(nested[subkey], list):
                            return nested[subkey], total

                    nested_upper = val.get("DATA") if isinstance(val.get("DATA"), dict) else None
                    if nested_upper:
                        for subkey in ("rows", "items", "results"):
                            if subkey in nested_upper and isinstance(nested_upper[subkey], list):
                                return nested_upper[subkey], total

        return [body], total

    return [], None


def item_matches_name(item: Any, name: str) -> bool:
    if not isinstance(item, dict):
        return False

    # Prefer explicit createdBy for rules.
    for key in ("createdBy", "created_by", "creator", "owner"):
        v = item.get(key)
        if isinstance(v, str) and v.lower() == name.lower():
            return True

    target = name.lower()

    def search(obj: Any) -> bool:
        if isinstance(obj, str):
            return target in obj.lower()
        if isinstance(obj, dict):
            return any(search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(search(v) for v in obj)
        return False

    return search(item)


def find_rule_id(item: Any) -> Optional[str]:
    if not isinstance(item, dict):
        return None

    for key in ("id", "rule_id", "ruleId", "uuid"):
        v = item.get(key)
        if isinstance(v, (str, int)):
            return str(v)

    for key in ("rule", "ruleInfo", "data"):
        nested = item.get(key)
        if isinstance(nested, dict):
            found = find_rule_id(nested)
            if found:
                return found

    return None


def build_payload(from_: int, to: int) -> Dict[str, Any]:
    return {
        "extraData": None,
        "filter_data": {
            "sort": [{"FIELD": "severity", "ORDER": "DESC"}],
            "filter": {},
            "free_text": "",
            "visible_columns": None,
            "locked": None,
            "paging": {"from": from_, "to": to},
        },
        "jsons": [],
    }


def fetch_all_rules(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
    page_size: int,
    max_pages: int,
) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/cloudsec/v1/rules/get_data?type=grid&table_name=CLOUDSEC_RULES"

    all_items: List[Dict[str, Any]] = []
    total_expected: Optional[int] = None

    for page in range(max_pages):
        from_ = page * page_size
        to = from_ + page_size
        payload = build_payload(from_=from_, to=to)

        _refresh_request_token(headers)
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
        resp.raise_for_status()

        body = resp.json()
        items, total = extract_items_and_total(body)

        if total is not None and total_expected is None:
            total_expected = total

        dict_items = [x for x in items if isinstance(x, dict)]
        if not dict_items:
            break

        all_items.extend(dict_items)

        if total_expected is not None and len(all_items) >= total_expected:
            break

        if len(dict_items) < page_size:
            break

    return all_items


def build_rule_disable_payload(*, name: str) -> Dict[str, Any]:
    return {
        "enabled": False,
        "endTs": 1770163148571,
        "lastModifiedBy": name,
    }


def delete_rule(*, base_url: str, headers: Dict[str, str], rule_id: str, timeout_s: int, name: str) -> int:
    url = f"{base_url}/api/cloudsec/v1/rule/{rule_id}"
    _refresh_request_token(headers)
    payload = build_rule_disable_payload(name=name)
    resp = requests.patch(url, headers=headers, json=payload, timeout=timeout_s)
    return resp.status_code


def main() -> None:
    p = argparse.ArgumentParser(
        description="Fetch CloudSec rules via UI session headers and filter by creator email.",
    )
    p.add_argument("--session", type=Path, default=DEFAULT_SESSION_PATH, help="Path to cortex_ui_headers.json")
    p.add_argument("--fqdn", help="Override Cortex UI FQDN (host only, no https://)")
    p.add_argument("--name", required=True, help="Creator name to filter (matches createdBy)")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--page-size", type=int, default=100, help="Page size (default 100)")
    p.add_argument("--max-pages", type=int, default=100, help="Max pages to fetch (default 100)")
    p.add_argument("--referer", help="Override Referer header (optional)")
    p.add_argument("--confirm", action="store_true", help="Actually delete matched rules")
    p.add_argument(
        "--out",
        type=Path,
        help="Write matched rules to this file (JSON). If omitted, prints counts only.",
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
        rules = fetch_all_rules(
            base_url=base_url,
            headers=headers,
            timeout_s=args.timeout,
            page_size=args.page_size,
            max_pages=args.max_pages,
        )
    except requests.HTTPError as e:
        text = getattr(e.response, "text", "") if getattr(e, "response", None) is not None else ""
        print(f"HTTP error fetching rules: {e} {text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error fetching rules: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(rules)} cloud rules from {base_url}")

    matched = [r for r in rules if item_matches_name(r, args.name)]

    print(f"Matched {len(matched)} cloud rules created by {args.name}")

    if not args.confirm:
        print("Dry run mode (no deletions). To actually delete cloud rules, rerun with --confirm flag.")
        return

    success = 0
    fail = 0
    total = len(matched)
    for idx, rule in enumerate(matched, start=1):
        rule_id = find_rule_id(rule)
        if not rule_id:
            fail += 1
            print(f"Rule delete progress: {idx}/{total} (missing id)")
            continue
        try:
            status = delete_rule(
                base_url=base_url,
                headers=headers,
                rule_id=rule_id,
                timeout_s=args.timeout,
                name=args.name,
            )
            if 200 <= status < 300:
                success += 1
            else:
                fail += 1
            print(f"Rule delete progress: {idx}/{total}")
        except Exception:
            fail += 1
            print(f"Rule delete progress: {idx}/{total} (error)")

    print(f"Deleted cloud rules: success={success} fail={fail}")

    if args.out:
        output_text = json.dumps(matched, indent=2, sort_keys=True) + "\n"
        args.out.write_text(output_text, encoding="utf-8")


if __name__ == "__main__":
    main()
