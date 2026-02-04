#!/usr/bin/env python3
"""List AppSec policies via Cortex public API, filter by creator email, and optionally delete.

Endpoints
---------
- List:   GET    https://{fqdn}/public_api/appsec/v1/policies
- Delete: DELETE https://{fqdn}/public_api/appsec/v1/policies/{id}

Auth
----
Uses the same public API headers as the other API-key based scripts:
- Authorization: <api_key>
- x-xdr-auth-id: <api_key_id>

Provide via args or env vars:
- --fqdn / CORTEX_FQDN   (host only, no https://)
- --api-key / CORTEX_API_KEY
- --api-key-id / CORTEX_API_KEY_ID
- --email / CORTEX_CREATOR_EMAIL

Notes
-----
Response shapes vary by tenant/version. This script tries common wrappers like
`reply`, `data`, `items`, `results`, `policies`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests


def safe_json(resp: requests.Response, *, label: str) -> Any:
    try:
        return resp.json()
    except json.JSONDecodeError:
        ct = resp.headers.get("content-type", "")
        text = (resp.text or "").strip()
        snippet = text[:1000]
        print(
            f"{label}: non-JSON response (status={resp.status_code}, content-type={ct})",
            file=sys.stderr,
        )
        if snippet:
            print(snippet, file=sys.stderr)
        raise


def get_headers(api_key: str, api_key_id: str) -> Dict[str, str]:
    return {
        "Authorization": api_key,
        "x-xdr-auth-id": str(api_key_id),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def normalize_fqdn(host: str) -> str:
    host = (host or "").strip()
    host = host.replace("https://", "").replace("http://", "").strip().strip("/")
    return host


def api_fqdn_from_any(host: str) -> str:
    """Public API host is typically api-<ui-host>; accept either and normalize."""
    host = normalize_fqdn(host)
    if host.startswith("api-"):
        return host
    if not host:
        return host
    return f"api-{host}"


def extract_items_json(body: Any) -> List[Dict[str, Any]]:
    if isinstance(body, list):
        return [b for b in body if isinstance(b, dict)]

    if not isinstance(body, dict):
        return []

    for key in ("reply", "data", "items", "results", "policies"):
        val = body.get(key)
        if isinstance(val, list):
            items = [b for b in val if isinstance(b, dict)]
            if items:
                return items
        if isinstance(val, dict):
            nested = extract_items_json(val)
            if nested:
                return nested

    for val in body.values():
        if isinstance(val, list):
            items = [b for b in val if isinstance(b, dict)]
            if items:
                return items
        if isinstance(val, dict):
            nested = extract_items_json(val)
            if nested:
                return nested

    return []


def find_policy_id(policy: Dict[str, Any]) -> Optional[str]:
    for key in ("id", "policy_id", "policyId", "uuid"):
        v = policy.get(key)
        if isinstance(v, (str, int)):
            return str(v)
    return None


def policy_created_by_email(policy: Dict[str, Any]) -> Optional[str]:
    v = policy.get("createdBy")
    if isinstance(v, str) and v.strip():
        return v.strip()

    # Sometimes nested.
    reply = policy.get("policy")
    if isinstance(reply, dict):
        return policy_created_by_email(reply)

    return None


def list_policies(base_url: str, headers: Dict[str, str], timeout_s: int) -> List[Dict[str, Any]]:
    url = f"{base_url}/public_api/appsec/v1/policies"
    resp = requests.get(url, headers=headers, timeout=timeout_s)
    resp.raise_for_status()
    return extract_items_json(safe_json(resp, label="List AppSec policies"))


def delete_policy(base_url: str, headers: Dict[str, str], policy_id: str, timeout_s: int) -> Tuple[int, str]:
    url = f"{base_url}/public_api/appsec/v1/policies/{policy_id}"
    resp = requests.delete(url, headers=headers, timeout=timeout_s)
    return resp.status_code, resp.text


def main() -> None:
    p = argparse.ArgumentParser(
        description="List AppSec policies, filter by creator email (createdBy), and delete them.",
    )
    p.add_argument("--fqdn", help="Cortex UI or API FQDN (host only, no https://)")
    p.add_argument("--api-key", help="API key (Authorization header)")
    p.add_argument("--api-key-id", help="API key id (x-xdr-auth-id header)")
    p.add_argument("--email", help="Creator email to filter")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--confirm", action="store_true", help="Actually perform deletions")
    args = p.parse_args()

    fqdn = normalize_fqdn(args.fqdn or os.environ.get("CORTEX_FQDN", ""))
    api_key = (args.api_key or os.environ.get("CORTEX_API_KEY") or "").strip()
    api_key_id = (args.api_key_id or os.environ.get("CORTEX_API_KEY_ID") or "").strip()
    email = (args.email or os.environ.get("CORTEX_CREATOR_EMAIL") or "").strip()

    # Interactive fallback for direct execution
    if (not api_key or not api_key_id) and sys.stdin.isatty():
        if not api_key:
            api_key = input("CORTEX_API_KEY (Authorization): ").strip()
        if not api_key_id:
            api_key_id = input("CORTEX_API_KEY_ID (x-xdr-auth-id): ").strip()

    if not fqdn or not api_key or not api_key_id:
        print(
            "Error: supply --fqdn, --api-key, and --api-key-id or set CORTEX_FQDN, CORTEX_API_KEY, CORTEX_API_KEY_ID env vars.",
            file=sys.stderr,
        )
        sys.exit(2)

    if not email:
        print(
            "Error: supply --email or set CORTEX_CREATOR_EMAIL.",
            file=sys.stderr,
        )
        sys.exit(2)

    api_fqdn = api_fqdn_from_any(fqdn)
    base_url = f"https://{api_fqdn}"
    headers = get_headers(api_key, api_key_id)

    try:
        policies = list_policies(base_url, headers, timeout_s=args.timeout)
    except requests.HTTPError as e:
        print(
            f"Failed to list AppSec policies: {e} - {getattr(e.response, 'text', '')}",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(f"Error listing AppSec policies: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(policies)} AppSec policies from {base_url}")

    matches: List[str] = []
    for pol in policies:
        if not isinstance(pol, dict):
            continue
        created_by = policy_created_by_email(pol)
        if isinstance(created_by, str) and created_by.lower() == email.lower():
            pid = find_policy_id(pol)
            if pid:
                matches.append(pid)

    print(f"Matched {len(matches)} AppSec policies created by {email}")

    if not args.confirm:
        print("Dry run mode (no deletions). To actually delete, rerun with --confirm flag.")
        return

    success = 0
    fail = 0
    total = len(matches)

    for idx, pid in enumerate(matches, start=1):
        try:
            status, _text = delete_policy(base_url, headers, pid, timeout_s=args.timeout)
            if 200 <= status < 300:
                success += 1
            else:
                fail += 1
            print(f"AppSec policy delete progress: {idx}/{total}")
        except Exception:
            fail += 1
            print(f"AppSec policy delete progress: {idx}/{total} (error)")

    print(f"Deleted AppSec policies: success={success} fail={fail}")


if __name__ == "__main__":
    main()
