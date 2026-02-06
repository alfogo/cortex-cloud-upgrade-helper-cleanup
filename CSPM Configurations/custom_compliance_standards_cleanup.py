#!/usr/bin/env python3
"""Fetch custom compliance controls via UI session headers and filter by creator email.

Calls:
  POST /api/webapp/get_data?type=grid&table_name=COMPLIANCE_CONTROLS_CATALOG

Expected response shape:
  reply.DATA -> array of controls
  reply.FILTER_COUNT -> count of filtered controls (creator matches)
  reply.TOTAL_COUNT  -> total controls (unfiltered)
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

DEFAULT_SESSION_PATH = Path("cortex_ui_headers.json")


def _vprint(verbose: bool, msg: str) -> None:
    if verbose:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")


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


def build_payload(from_: int, to: int, email: str) -> Dict[str, Any]:
    return {
        "extraData": {"STATUS": "ACTIVE"},
        "filter_data": {
            "sort": [{"FIELD": "CREATED_BY", "ORDER": "ASC"}],
            "filter": {
                "AND": [
                    {
                        "SEARCH_FIELD": "CREATED_BY",
                        "SEARCH_TYPE": "CONTAINS",
                        "SEARCH_VALUE": email,
                    }
                ]
            },
            "free_text": "",
            "visible_columns": None,
            "locked": {},
            "paging": {"from": from_, "to": to},
        },
        "jsons": [],
    }


def parse_reply(body: Any) -> Tuple[List[Dict[str, Any]], Optional[int], Optional[int]]:
    if not isinstance(body, dict):
        return [], None, None

    reply = body.get("reply") if isinstance(body.get("reply"), dict) else None
    if not reply:
        return [], None, None

    data = reply.get("DATA") if isinstance(reply.get("DATA"), list) else []
    items = [r for r in data if isinstance(r, dict)]

    # Allow ints or numeric strings
    def as_int(v: Any) -> Optional[int]:
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
        return None

    filter_count = as_int(reply.get("FILTER_COUNT"))
    total_count = as_int(reply.get("TOTAL_COUNT"))

    return items, filter_count, total_count


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def find_control_id(item: Dict[str, Any]) -> Optional[str]:
    for key in (
        "CONTROL_ID",
        "control_id",
        "controlId",
        "ID",
        "id",
        "uuid",
        "CONTROL_UUID",
        "control_uuid",
    ):
        v = item.get(key)
        if isinstance(v, str) and _UUID_RE.match(v):
            return v
        if isinstance(v, (str, int)) and key in {"ID", "id"}:
            s = str(v)
            if _UUID_RE.match(s):
                return s

    # Heuristic: any *ID field that looks like a UUID
    for k, v in item.items():
        if not isinstance(k, str):
            continue
        if "id" not in k.lower():
            continue
        if isinstance(v, str) and _UUID_RE.match(v):
            return v

    return None


def item_matches_email(item: Any, email: str) -> bool:
    if not isinstance(item, dict):
        return False

    for key in (
        "created_by",
        "createdBy",
        "created_by_email",
        "creator",
        "owner",
        "CREATED_BY",
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


def fetch_page(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
    from_: int,
    to: int,
    email: str,
    verbose: bool,
) -> Tuple[List[Dict[str, Any]], Optional[int], Optional[int]]:
    url = f"{base_url}/api/webapp/get_data?type=grid&table_name=COMPLIANCE_CONTROLS_CATALOG"
    payload = build_payload(from_, to, email)

    _refresh_request_token(headers)

    _vprint(verbose, f"POST {url}")
    _vprint(verbose, f"paging from={from_} to={to} filter CREATED_BY contains '{email}'")

    t0 = time.perf_counter()
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
    dt = time.perf_counter() - t0

    _vprint(verbose, f"status={resp.status_code} elapsed={dt:.3f}s bytes={len(resp.content)}")
    resp.raise_for_status()

    t1 = time.perf_counter()
    body = resp.json()
    _vprint(verbose, f"json_parse_elapsed={(time.perf_counter() - t1):.3f}s")

    return parse_reply(body)


def build_standards_payload() -> Dict[str, Any]:
    return {"filter_data": {"filter": {}, "sort": [{"FIELD": "NAME", "ORDER": "ASC"}]}}


def parse_standards_reply(body: Any) -> List[Dict[str, Any]]:
    if not isinstance(body, dict):
        return []

    reply = body.get("reply") if isinstance(body.get("reply"), dict) else None
    if isinstance(reply, dict):
        for key in ("DATA", "data", "items", "rows", "results"):
            val = reply.get(key)
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]

    for key in ("data", "items", "rows", "results"):
        val = body.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]

    return []


def fetch_standards(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
    verbose: bool,
) -> List[Dict[str, Any]]:
    url = f"{base_url}/api/webapp/get_data?type=grid&table_name=COMPLIANCE_STANDARDS"
    payload = build_standards_payload()

    _refresh_request_token(headers)
    _vprint(verbose, f"POST {url}")

    resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
    resp.raise_for_status()

    return parse_standards_reply(resp.json())


def find_standard_id(item: Dict[str, Any]) -> Optional[str]:
    for key in (
        "standard_id",
        "STANDARD_ID",
        "id",
        "ID",
        "uuid",
        "STANDARD_UUID",
    ):
        v = item.get(key)
        if isinstance(v, str) and _UUID_RE.match(v):
            return v
        if isinstance(v, (str, int)) and key in {"id", "ID"}:
            s = str(v)
            if _UUID_RE.match(s):
                return s

    for k, v in item.items():
        if not isinstance(k, str):
            continue
        if "id" not in k.lower():
            continue
        if isinstance(v, str) and _UUID_RE.match(v):
            return v

    return None


def delete_standard(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
    standard_id: str,
    verbose: bool,
) -> requests.Response:
    url = f"{base_url}/api/webapp/platform/compliance/delete_standard/"
    payload = {"standard_id": standard_id}

    _refresh_request_token(headers)
    _vprint(verbose, f"POST {url} standard_id={standard_id}")
    return requests.post(url, headers=headers, json=payload, timeout=timeout_s)


def delete_control(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
    control_id: str,
    verbose: bool,
) -> requests.Response:
    url = f"{base_url}/api/webapp/platform/compliance/delete_control"
    payload = {"control_id": control_id}

    _refresh_request_token(headers)
    _vprint(verbose, f"POST {url} control_id={control_id}")
    return requests.post(url, headers=headers, json=payload, timeout=timeout_s)


def fetch_all_controls(
    *,
    base_url: str,
    headers: Dict[str, str],
    timeout_s: int,
    page_size: int,
    email: str,
    verbose: bool,
    max_pages: int,
) -> Tuple[List[Dict[str, Any]], Optional[int], Optional[int]]:
    all_items: List[Dict[str, Any]] = []

    page = 0
    filter_count: Optional[int] = None
    total_count: Optional[int] = None

    while True:
        if page >= max_pages:
            _vprint(verbose, f"Stopping: reached max_pages={max_pages}")
            break

        from_ = page * page_size
        to = from_ + page_size

        items, page_filter_count, page_total_count = fetch_page(
            base_url=base_url,
            headers=headers,
            timeout_s=timeout_s,
            from_=from_,
            to=to,
            email=email,
            verbose=verbose,
        )

        if filter_count is None:
            filter_count = page_filter_count
            _vprint(verbose, f"FILTER_COUNT={filter_count!r}")
        if total_count is None:
            total_count = page_total_count
            _vprint(verbose, f"TOTAL_COUNT={total_count!r}")

        if not items:
            _vprint(verbose, "Stopping: page returned 0 items")
            break

        all_items.extend(items)
        _vprint(verbose, f"page={page} items={len(items)} cumulative={len(all_items)}")

        if filter_count is not None and len(all_items) >= filter_count:
            _vprint(verbose, "Stopping: fetched >= FILTER_COUNT")
            break

        page += 1

    return all_items, filter_count, total_count


def main() -> None:
    p = argparse.ArgumentParser(
        description="Fetch compliance controls filtered by creator email.",
    )
    p.add_argument("--session", type=Path, default=DEFAULT_SESSION_PATH, help="Path to cortex_ui_headers.json")
    p.add_argument("--fqdn", help="Override Cortex UI FQDN (host only, no https://)")
    p.add_argument("--email", required=True, help="Creator email to filter (CREATED_BY contains)")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--page-size", type=int, default=100, help="Page size for get_data paging")
    p.add_argument("--referer", help="Override Referer header (optional)")
    p.add_argument("--max-pages", type=int, default=500, help="Safety cap to avoid endless paging")
    p.add_argument("--verbose", action="store_true", help="Print request/loop timing and progress")
    p.add_argument("--confirm", action="store_true", help="Actually delete matched controls")

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

    _vprint(args.verbose, f"base_url={base_url}")
    _vprint(args.verbose, f"session_file={args.session}")
    _vprint(args.verbose, f"page_size={args.page_size} timeout={args.timeout}s max_pages={args.max_pages}")

    print(f"Querying compliance controls (page size {args.page_size})...")

    t0 = time.perf_counter()
    try:
        # Always fetch the first page (fast) to get FILTER_COUNT/TOTAL_COUNT.
        first_items, filter_count, total_count = fetch_page(
            base_url=base_url,
            headers=headers,
            timeout_s=args.timeout,
            from_=0,
            to=args.page_size,
            email=args.email,
            verbose=args.verbose,
        )
    except requests.HTTPError as e:
        text = getattr(e.response, "text", "") if getattr(e, "response", None) is not None else ""
        print(f"HTTP error fetching compliance controls: {e} {text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error fetching compliance controls: {e}", file=sys.stderr)
        sys.exit(1)

    first_elapsed = time.perf_counter() - t0

    filter_msg = str(filter_count) if filter_count is not None else "unknown"
    total_msg = str(total_count) if total_count is not None else "unknown"

    print(f"Total controls (unfiltered): {total_msg}")
    print(f"Controls created by {args.email} (FILTER_COUNT): {filter_msg}")

    if not args.confirm:
        print(
            f"Dry run mode (no deletions). First page returned {len(first_items)} items in {first_elapsed:.3f}s."
        )
        print("To actually delete controls and standards, rerun with --confirm.")

    if args.confirm:
        # Confirm mode: page through the filtered result set to collect control IDs.
        if filter_count is not None:
            total_pages = (filter_count + args.page_size - 1) // args.page_size
        else:
            total_pages = None

        control_ids: List[str] = []

        # Include first page
        for item in first_items:
            cid = find_control_id(item)
            if cid:
                control_ids.append(cid)

        print(
            f"Fetched page 1{f'/{total_pages}' if total_pages is not None else ''}: "
            f"{len(first_items)} items (ids collected: {len(control_ids)})"
        )

        page = 1
        while True:
            if page >= args.max_pages:
                print(f"Stopping paging: reached max pages cap ({args.max_pages}).")
                break

            if filter_count is not None and len(control_ids) >= filter_count:
                break

            from_ = page * args.page_size
            to = from_ + args.page_size

            t_page = time.perf_counter()
            items, _, _ = fetch_page(
                base_url=base_url,
                headers=headers,
                timeout_s=args.timeout,
                from_=from_,
                to=to,
                email=args.email,
                verbose=args.verbose,
            )
            dt_page = time.perf_counter() - t_page

            if not items:
                break

            for item in items:
                cid = find_control_id(item)
                if cid:
                    control_ids.append(cid)

            human_page = page + 1
            denom = f"/{total_pages}" if total_pages is not None else ""
            print(
                f"Fetched page {human_page}{denom}: {len(items)} items "
                f"(ids collected: {len(control_ids)}) in {dt_page:.3f}s"
            )

            page += 1

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_ids: List[str] = []
        for cid in control_ids:
            if cid not in seen:
                seen.add(cid)
                unique_ids.append(cid)

        print(f"Deleting {len(unique_ids)} compliance controls...")

        deleted = 0
        failed = 0

        for idx, control_id in enumerate(unique_ids, start=1):
            try:
                resp = delete_control(
                    base_url=base_url,
                    headers=headers,
                    timeout_s=args.timeout,
                    control_id=control_id,
                    verbose=args.verbose,
                )
                if 200 <= resp.status_code < 300:
                    deleted += 1
                    print(f"[{idx}/{len(unique_ids)}] Deleted control {control_id}")
                else:
                    failed += 1
                    print(
                        f"[{idx}/{len(unique_ids)}] Delete failed for {control_id}: status={resp.status_code}"
                    )
                    if resp.text:
                        print(resp.text)
            except Exception as e:
                failed += 1
                print(f"[{idx}/{len(unique_ids)}] Error deleting {control_id}: {e}")

        print(f"Deleted {deleted} controls; failed {failed}.")

    print("Querying compliance standards catalog...")

    try:
        standards = fetch_standards(
            base_url=base_url,
            headers=headers,
            timeout_s=args.timeout,
            verbose=args.verbose,
        )
    except requests.HTTPError as e:
        text = getattr(e.response, "text", "") if getattr(e, "response", None) is not None else ""
        print(f"HTTP error fetching compliance standards: {e} {text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error fetching compliance standards: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Total compliance standards: {len(standards)}")

    matched_standards = [s for s in standards if item_matches_email(s, args.email)]
    print(f"Compliance standards created by {args.email}: {len(matched_standards)}")

    if not args.confirm:
        return

    standard_ids: List[str] = []
    for item in matched_standards:
        sid = find_standard_id(item)
        if sid:
            standard_ids.append(sid)

    # Deduplicate while preserving order
    seen_std: set[str] = set()
    unique_standard_ids: List[str] = []
    for sid in standard_ids:
        if sid not in seen_std:
            seen_std.add(sid)
            unique_standard_ids.append(sid)

    print(f"Deleting {len(unique_standard_ids)} compliance standards...")

    deleted_std = 0
    failed_std = 0

    for idx, standard_id in enumerate(unique_standard_ids, start=1):
        try:
            resp = delete_standard(
                base_url=base_url,
                headers=headers,
                timeout_s=args.timeout,
                standard_id=standard_id,
                verbose=args.verbose,
            )
            if 200 <= resp.status_code < 300:
                deleted_std += 1
                print(f"[{idx}/{len(unique_standard_ids)}] Deleted standard {standard_id}")
            else:
                failed_std += 1
                print(
                    f"[{idx}/{len(unique_standard_ids)}] Delete failed for {standard_id}: status={resp.status_code}"
                )
                if resp.text:
                    print(resp.text)
        except Exception as e:
            failed_std += 1
            print(f"[{idx}/{len(unique_standard_ids)}] Error deleting {standard_id}: {e}")

    print(f"Deleted {deleted_std} standards; failed {failed_std}.")


if __name__ == "__main__":
    main()
