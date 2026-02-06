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
import re
import sys
import time
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
            "TOTAL_COUNT",
            "FILTER_COUNT",
        )

        def find_total(obj: Any) -> Optional[int]:
            if isinstance(obj, dict):
                for k in total_keys:
                    if k in obj:
                        v = obj[k]
                        if isinstance(v, int):
                            return v
                        if isinstance(v, str) and v.isdigit():
                            return int(v)
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


def _normalize_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return re.sub(r"\s+", " ", normalized)


def item_matches_name(item: Any, name: str) -> bool:
    if not isinstance(item, dict):
        return False

    target_norm = _normalize_name(name)
    target_tokens = [token for token in target_norm.split(" ") if token]

    def field_matches(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        value_norm = _normalize_name(value)
        if not value_norm:
            return False
        if value_norm == target_norm:
            return True
        if target_tokens and all(token in value_norm for token in target_tokens):
            return True
        return False

    # Prefer explicit created-by style fields for rules.
    for key in (
        "createdBy",
        "created_by",
        "creator",
        "owner",
        "createdByName",
        "created_by_name",
        "createdByDisplayName",
        "lastModifiedBy",
        "last_modified_by",
        "lastModifiedByName",
        "lastModifiedByDisplayName",
    ):
        if field_matches(item.get(key)):
            return True

    def search(obj: Any) -> bool:
        if isinstance(obj, str):
            return field_matches(obj)
        if isinstance(obj, dict):
            return any(search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(search(v) for v in obj)
        return False

    return search(item)


def _debug_rule_match(item: Dict[str, Any], name: str) -> None:
    fields = (
        "id",
        "name",
        "createdBy",
        "createdByName",
        "createdByDisplayName",
        "lastModifiedBy",
        "lastModifiedByName",
        "lastModifiedByDisplayName",
    )
    print("Debug rule fields:")
    for key in fields:
        value = item.get(key)
        if value is not None:
            print(f"  {key}: {value}")
    print(f"Match result for '{name}': {item_matches_name(item, name)}")


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
            "sort": [{"FIELD": "lastModifiedBy", "ORDER": "ASC"}],
            "filter": {},
            "free_text": "",
            "visible_columns": None,
            "locked": {},
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
        "endTs": int(time.time() * 1000),
        "lastModifiedBy": name,
    }


def _should_retry_response(resp: requests.Response) -> bool:
    if resp.status_code in {408, 409, 429, 500, 502, 503, 504}:
        return True

    try:
        body = resp.json()
    except ValueError:
        return False

    if isinstance(body, dict):
        reply = body.get("reply") if isinstance(body.get("reply"), dict) else None
        err_code = reply.get("err_code") if reply else None
        err_msg = reply.get("err_msg") if reply else None
        if err_code == 459:
            return True
        if isinstance(err_msg, str) and "duplicate request" in err_msg.lower():
            return True

    return False


def _retry_delay_s(base_delay_s: float, attempt: int) -> float:
    return base_delay_s * (2 ** attempt)


def _patch_with_retry(
    *,
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    timeout_s: int,
    retries: int,
    backoff_s: float,
) -> requests.Response:
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            _refresh_request_token(headers)
            resp = session.patch(url, headers=headers, json=payload, timeout=timeout_s)
            if _should_retry_response(resp) and attempt < retries:
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = float(retry_after)
                else:
                    delay = _retry_delay_s(backoff_s, attempt)
                time.sleep(delay)
                continue
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            if attempt >= retries:
                break
            time.sleep(_retry_delay_s(backoff_s, attempt))

    if last_exc:
        raise last_exc
    raise RuntimeError("Delete request failed after retries")


def delete_rule(
    *,
    session: requests.Session,
    base_url: str,
    headers: Dict[str, str],
    rule_id: str,
    timeout_s: int,
    name: str,
    retries: int,
    backoff_s: float,
) -> requests.Response:
    url = f"{base_url}/api/cloudsec/v1/rule/{rule_id}"
    payload = build_rule_disable_payload(name=name)
    return _patch_with_retry(
        session=session,
        url=url,
        headers=headers,
        payload=payload,
        timeout_s=timeout_s,
        retries=retries,
        backoff_s=backoff_s,
    )


def main() -> None:
    p = argparse.ArgumentParser(
        description="Fetch CloudSec rules via UI session headers and filter by creator email.",
    )
    p.add_argument("--session", type=Path, default=DEFAULT_SESSION_PATH, help="Path to cortex_ui_headers.json")
    p.add_argument("--fqdn", help="Override Cortex UI FQDN (host only, no https://)")
    p.add_argument("--name", required=True, help="Creator name to filter (matches createdBy)")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument(
        "--delete-timeout",
        type=int,
        help="HTTP timeout seconds for delete calls (defaults to --timeout)",
    )
    p.add_argument(
        "--first-pass-retries",
        type=int,
        default=0,
        help="Retries per delete on the first pass (default 0 to fail fast)",
    )
    p.add_argument("--page-size", type=int, default=100, help="Page size (default 100)")
    p.add_argument("--max-pages", type=int, default=100, help="Max pages to fetch (default 100)")
    p.add_argument("--referer", help="Override Referer header (optional)")
    p.add_argument("--delete-retries", type=int, default=5, help="Retries for delete calls")
    p.add_argument("--delete-backoff", type=float, default=1.5, help="Base backoff for delete retries")
    p.add_argument("--delete-delay", type=float, default=0.2, help="Delay between deletes in seconds")
    p.add_argument(
        "--max-consecutive-failures",
        type=int,
        default=0,
        help="Abort after N consecutive delete failures (0 disables)",
    )
    p.add_argument(
        "--retry-rounds",
        type=int,
        default=10,
        help="Extra immediate retry rounds for failed deletes (default 10)",
    )
    p.add_argument(
        "--retry-round-delay",
        type=float,
        default=10.0,
        help="Delay between retry rounds in seconds (default 10)",
    )
    p.add_argument("--confirm", action="store_true", help="Actually delete matched rules")
    p.add_argument(
        "--out",
        type=Path,
        help="Write matched rules to this file (JSON). If omitted, prints counts only.",
    )
    p.add_argument(
        "--debug-created-by",
        action="store_true",
        help="Print distinct createdBy/lastModifiedBy values from fetched rules.",
    )
    p.add_argument(
        "--debug-rule-id",
        help="Print key fields for a specific rule id and show match decision.",
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
    headers.setdefault("x-platform-module-name", "cspm")

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

    if args.debug_rule_id:
        debug_target = str(args.debug_rule_id).strip()
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if str(rule.get("id", "")).strip() == debug_target:
                _debug_rule_match(rule, args.name)
                break
        else:
            print(f"Rule id not found in response: {debug_target}")

    if args.debug_created_by:
        created_values = set()
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            for key in ("createdBy", "createdByName", "createdByDisplayName"):
                value = rule.get(key)
                if isinstance(value, str) and value.strip():
                    created_values.add(value.strip())
            for key in ("lastModifiedBy", "lastModifiedByName", "lastModifiedByDisplayName"):
                value = rule.get(key)
                if isinstance(value, str) and value.strip():
                    created_values.add(value.strip())

        print(f"Distinct creator/modifier values: {len(created_values)}")
        for value in sorted(created_values)[:50]:
            print(f"  {value}")

    matched = [r for r in rules if item_matches_name(r, args.name)]

    print(f"Matched {len(matched)} cloud rules created by {args.name}")

    if not args.confirm:
        print("Dry run mode (no deletions). To actually delete cloud rules, rerun with --confirm flag.")
        return

    delete_timeout_s = args.delete_timeout or args.timeout
    first_pass_timeout_s = min(delete_timeout_s, 3)

    success = 0
    fail = 0
    total = len(matched)
    session_client = requests.Session()
    failed_ids: List[str] = []
    consecutive_failures = 0
    for idx, rule in enumerate(matched, start=1):
        rule_id = find_rule_id(rule)
        if not rule_id:
            fail += 1
            consecutive_failures += 1
            print(f"Rule delete progress: {idx}/{total} (missing id)")
            continue
        try:
            resp = delete_rule(
                session=session_client,
                base_url=base_url,
                headers=headers,
                rule_id=rule_id,
                timeout_s=first_pass_timeout_s,
                name=args.name,
                retries=args.first_pass_retries,
                backoff_s=args.delete_backoff,
            )
            if 200 <= resp.status_code < 300:
                success += 1
                consecutive_failures = 0
            else:
                failed_ids.append(rule_id)
                consecutive_failures += 1
                err_snippet = ""
                try:
                    err_snippet = resp.text.strip()
                except Exception:
                    err_snippet = ""
                if err_snippet:
                    err_snippet = f" {err_snippet[:200]}"
                print(
                    f"Rule delete progress: {idx}/{total} (status={resp.status_code}){err_snippet}"
                )
                if args.delete_delay > 0:
                    time.sleep(args.delete_delay)
                continue
            print(f"Rule delete progress: {idx}/{total}")
        except Exception:
            failed_ids.append(rule_id)
            consecutive_failures += 1
            print(f"Rule delete progress: {idx}/{total} (error)")
        if args.delete_delay > 0:
            time.sleep(args.delete_delay)
        if args.max_consecutive_failures > 0 and consecutive_failures >= args.max_consecutive_failures:
            print(
                f"Aborting after {consecutive_failures} consecutive failures. "
                "Rerun to retry remaining rules.",
                file=sys.stderr,
            )
            break

    if failed_ids:
        remaining_failures = list(failed_ids)
        for round_idx in range(1, args.retry_rounds + 1):
            if not remaining_failures:
                break
            if round_idx == 1:
                print(f"Retrying failed deletes immediately: {len(remaining_failures)} rules")
            else:
                print(f"Retry round {round_idx}/{args.retry_rounds}: {len(remaining_failures)} rules")
            if args.retry_round_delay > 0:
                print(f"Waiting {args.retry_round_delay:.1f}s before retry round {round_idx}")
                time.sleep(args.retry_round_delay)

            next_failures: List[str] = []
            for idx, rule_id in enumerate(remaining_failures, start=1):
                try:
                    resp = delete_rule(
                        session=session_client,
                        base_url=base_url,
                        headers=headers,
                        rule_id=rule_id,
                        timeout_s=delete_timeout_s,
                        name=args.name,
                        retries=0,
                        backoff_s=0.0,
                    )
                    if 200 <= resp.status_code < 300:
                        success += 1
                    else:
                        next_failures.append(rule_id)
                        err_snippet = ""
                        try:
                            err_snippet = resp.text.strip()
                        except Exception:
                            err_snippet = ""
                        if err_snippet:
                            err_snippet = f" {err_snippet[:200]}"
                        print(
                            f"Rule retry progress: {idx}/{len(remaining_failures)} "
                            f"(status={resp.status_code}){err_snippet}"
                        )
                except Exception:
                    next_failures.append(rule_id)
                    print(f"Rule retry progress: {idx}/{len(remaining_failures)} (error)")

            remaining_failures = next_failures

        fail += len(remaining_failures)

    print(f"Deleted cloud rules: success={success} fail={fail}")

    if args.out:
        output_text = json.dumps(matched, indent=2, sort_keys=True) + "\n"
        args.out.write_text(output_text, encoding="utf-8")


if __name__ == "__main__":
    main()
