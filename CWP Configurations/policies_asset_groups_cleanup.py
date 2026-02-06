#!/usr/bin/env python3
"""List CWP policies and asset groups via Cortex public API and optionally delete.

This script handles two resource types:
- CWP Policies: filtered by creator display name (often stored in `createdBy`).
- Asset Groups: filtered by creator email stored in `XDM.ASSET_GROUP.CREATED_BY`.

Endpoints
---------
- List:   GET  https://{fqdn}/public_api/v1/cwp/policies
- Delete: DELETE https://{fqdn}/public_api/v1/cwp/policies/{id}

- List:   GET  https://{fqdn}/public_api/v1/asset-groups
- Delete: POST https://{fqdn}/public_api/v1/asset-groups/delete/{group_id}

Auth
----
Uses the same public API headers as the other API-key based scripts:
- Authorization: <api_key>
- x-xdr-auth-id: <api_key_id>

Provide via args or env vars:
- --fqdn / CORTEX_FQDN   (host only, no https://)
- --api-key / CORTEX_API_KEY
- --api-key-id / CORTEX_API_KEY_ID

Notes
-----
Response shapes vary by tenant/version. This script tries common wrappers like
`reply`, `data`, `items`, `results`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests


def safe_json(resp: requests.Response, *, label: str) -> Any:
    try:
        return resp.json()
    except json.JSONDecodeError:
        ct = resp.headers.get("content-type", "")
        text = (resp.text or "").strip()
        snippet = text[:1000]
        print(f"{label}: non-JSON response (status={resp.status_code}, content-type={ct})", file=sys.stderr)
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


def extract_items_json(body: Any) -> List[Dict[str, Any]]:
    # Cortex responses vary a lot. This helper tries common wrappers (reply/data/items)
    # and falls back to scanning for the first list of objects.
    if isinstance(body, list):
        return [b for b in body if isinstance(b, dict)]

    if not isinstance(body, dict):
        return []

    # 1) Fast path: known wrapper keys.
    for key in (
        "reply",
        "data",
        "items",
        "results",
        "policies",
        "asset_groups",
        "assetGroups",
    ):
        val = body.get(key)
        if isinstance(val, list):
            items = [b for b in val if isinstance(b, dict)]
            if items:
                return items
        if isinstance(val, dict):
            nested_items = extract_items_json(val)
            if nested_items:
                return nested_items

    # 2) Scan all values for a list of objects or nested wrapper.
    for val in body.values():
        if isinstance(val, list):
            items = [b for b in val if isinstance(b, dict)]
            if items:
                return items
        if isinstance(val, dict):
            nested_items = extract_items_json(val)
            if nested_items:
                return nested_items

    return []


def _dict_get_ci(d: Dict[str, Any], key: str) -> Any:
    """Case-insensitive dict get; returns None if not found."""
    if key in d:
        return d[key]
    key_l = key.lower()
    for k, v in d.items():
        if isinstance(k, str) and k.lower() == key_l:
            return v
    return None


def get_dotted(obj: Any, dotted_key: str) -> Any:
    """Get value by dotted path, supporting both literal dotted keys and nested dicts."""
    if not isinstance(obj, dict):
        return None

    # Literal dotted key.
    direct = _dict_get_ci(obj, dotted_key)
    if direct is not None:
        return direct

    cur: Any = obj
    for part in dotted_key.split("."):
        if not isinstance(cur, dict):
            return None
        cur = _dict_get_ci(cur, part)
        if cur is None:
            return None
    return cur


def policy_matches_creator(policy: Dict[str, Any], creator: str) -> bool:
    # Common creator keys. In many tenants `createdBy` is a display name.
    for key in (
        "created_by",
        "createdBy",
        "creator",
        "owner",
        "created_by_email",
        "createdByEmail",
        "created_by_name",
        "createdByName",
    ):
        v = policy.get(key)
        if isinstance(v, str) and v.strip().lower() == creator.strip().lower():
            return True

    target = creator.strip().lower()

    def search(obj: Any) -> bool:
        if isinstance(obj, str):
            return target in obj.lower()
        if isinstance(obj, dict):
            return any(search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(search(v) for v in obj)
        return False

    return search(policy)


def asset_group_matches_email(asset_group: Dict[str, Any], email: str) -> bool:
    target = (email or "").strip().lower()
    if not target:
        return False

    # Primary field called out by the user.
    direct = get_dotted(asset_group, "XDM.ASSET_GROUP.CREATED_BY")
    if isinstance(direct, str) and direct.strip().lower() == target:
        return True

    # Fallback: search for the email anywhere in the object.
    def search(obj: Any) -> bool:
        if isinstance(obj, str):
            return target in obj.lower()
        if isinstance(obj, dict):
            return any(search(v) for v in obj.values())
        if isinstance(obj, list):
            return any(search(v) for v in obj)
        return False

    return search(asset_group)


def find_policy_id(policy: Dict[str, Any]) -> Optional[str]:
    for key in ("id", "policy_id", "policyId", "uuid"):
        v = policy.get(key)
        if isinstance(v, (str, int)):
            return str(v)

    # Sometimes nested
    nested = policy.get("policy")
    if isinstance(nested, dict):
        return find_policy_id(nested)

    return None


def find_asset_group_id(asset_group: Dict[str, Any]) -> Optional[str]:
    for dotted in (
        "XDM.ASSET_GROUP.ID",
        "XDM.ASSET_GROUP.ASSET_GROUP_ID",
        "XDM.ASSET_GROUP.UUID",
    ):
        v = get_dotted(asset_group, dotted)
        if isinstance(v, (str, int)):
            return str(v)

    # Fallbacks if the tenant returns a flatter structure.
    for key in ("id", "asset_group_id", "assetGroupId", "asset_group_uuid", "uuid"):
        v = asset_group.get(key)
        if isinstance(v, (str, int)):
            return str(v)

    nested = asset_group.get("asset_group")
    if isinstance(nested, dict):
        return find_asset_group_id(nested)

    return None


def list_policies(base_url: str, headers: Dict[str, str], timeout_s: int) -> List[Dict[str, Any]]:
    url = f"{base_url}/public_api/v1/cwp/policies"

    resp = requests.get(url, headers=headers, timeout=timeout_s)
    if resp.status_code == 405:
        # Some public API endpoints are POST-only in certain deployments.
        resp = requests.post(url, headers=headers, json={}, timeout=timeout_s)

    resp.raise_for_status()
    return extract_items_json(safe_json(resp, label="List CWP policies"))


def list_asset_groups(base_url: str, headers: Dict[str, str], timeout_s: int) -> List[Dict[str, Any]]:
    url = f"{base_url}/public_api/v1/asset-groups"

    # This endpoint typically expects a POST body for paging.
    page_size = 100
    search_from = 0
    all_items: List[Dict[str, Any]] = []

    while True:
        payload = {
            "request_data": {
                "filters": [],
                "search_from": search_from,
                "search_to": search_from + page_size,
            }
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
        if resp.status_code == 405:
            # Some deployments may allow GET without a body.
            resp = requests.get(url, headers=headers, timeout=timeout_s)

        resp.raise_for_status()
        items = extract_items_json(safe_json(resp, label="List asset groups"))
        if not items:
            break

        all_items.extend(items)

        # Stop when we appear to have exhausted the page.
        if len(items) < page_size:
            break
        search_from += page_size

    return all_items


def delete_policy(base_url: str, headers: Dict[str, str], policy_id: str, timeout_s: int) -> Tuple[int, str]:
    url = f"{base_url}/public_api/v1/cwp/policies/{policy_id}"
    resp = requests.delete(url, headers=headers, timeout=timeout_s)
    return resp.status_code, resp.text


def delete_asset_group(base_url: str, headers: Dict[str, str], asset_group_id: str, timeout_s: int) -> Tuple[int, str]:
    # In many tenants asset group deletion is a POST endpoint.
    # We'll try the most common forms to be resilient across versions.
    candidates: List[Tuple[str, str, Optional[Dict[str, Any]]]] = [
        (
            "POST",
            f"{base_url}/public_api/v1/asset-groups/delete/{asset_group_id}",
            None,
        ),
        (
            "POST",
            f"{base_url}/public_api/v1/asset-groups/{asset_group_id}/delete",
            None,
        ),
        (
            "POST",
            f"{base_url}/public_api/v1/asset-groups/delete",
            {"request_data": {"group_id": asset_group_id}},
        ),
        (
            "POST",
            f"{base_url}/public_api/v1/asset-groups/delete",
            {"request_data": {"group_ids": [asset_group_id]}},
        ),
    ]

    last_status = 0
    last_text = ""
    for method, url, payload in candidates:
        try:
            if method == "POST":
                resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
            else:
                resp = requests.request(method, url, headers=headers, timeout=timeout_s)

            last_status = resp.status_code
            last_text = resp.text

            # Treat 2xx as success.
            if 200 <= resp.status_code < 300:
                return resp.status_code, resp.text

            # If it's clearly the wrong endpoint, try the next one.
            if resp.status_code in (404, 405):
                continue

            # For auth/validation errors, don't keep hammering other endpoints.
            if resp.status_code in (400, 401, 403):
                return resp.status_code, resp.text

        except Exception as e:
            last_text = f"{type(e).__name__}: {e}"

    return last_status, last_text


def main() -> None:
    p = argparse.ArgumentParser(
        description="List CWP policies, filter by creator name (createdBy), and delete them.",
    )
    p.add_argument("--fqdn", help="Cortex API FQDN (host only, no https://)")
    p.add_argument("--api-key", help="API key (Authorization header)")
    p.add_argument("--api-key-id", help="API key id (x-xdr-auth-id header)")
    p.add_argument("--name", help="Creator name (display name) used to match policy createdBy")
    p.add_argument("--email", help="Creator email used to match asset group createdBy")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    p.add_argument("--delete-delay", type=float, default=0.25, help="Delay between deletes (seconds)")
    p.add_argument("--confirm", action="store_true", help="Actually perform deletions")
    args = p.parse_args()

    fqdn = args.fqdn or os.environ.get("CORTEX_FQDN")
    api_key = args.api_key or os.environ.get("CORTEX_API_KEY")
    api_key_id = args.api_key_id or os.environ.get("CORTEX_API_KEY_ID")

    missing_params: List[str] = []
    if not fqdn:
        missing_params.append("--fqdn/CORTEX_FQDN")
    if not api_key:
        missing_params.append("--api-key/CORTEX_API_KEY")
    if not api_key_id:
        missing_params.append("--api-key-id/CORTEX_API_KEY_ID")

    if missing_params:
        print(
            "Error: missing required parameters: " + ", ".join(missing_params),
            file=sys.stderr,
        )
        print(
            "Supply --fqdn, --api-key, and --api-key-id or set the matching env vars.",
            file=sys.stderr,
        )
        sys.exit(2)

    creator_name = (args.name or os.environ.get("CORTEX_CREATOR_NAME") or "").strip()
    creator_email = (args.email or os.environ.get("CORTEX_CREATOR_EMAIL") or "").strip()
    missing_filters: List[str] = []
    if not creator_name:
        missing_filters.append("--name/CORTEX_CREATOR_NAME")
    if not creator_email:
        missing_filters.append("--email/CORTEX_CREATOR_EMAIL")
    if missing_filters:
        print(
            "Error: missing required parameters: " + ", ".join(missing_filters),
            file=sys.stderr,
        )
        print(
            "Supply --name and --email or set the matching env vars.",
            file=sys.stderr,
        )
        sys.exit(2)

    # Public API host is typically "api-" + UI FQDN.
    ui_fqdn = (fqdn or "").strip().rstrip("/")
    if ui_fqdn.startswith("https://"):
        ui_fqdn = ui_fqdn[len("https://") :]
    if ui_fqdn.startswith("http://"):
        ui_fqdn = ui_fqdn[len("http://") :]
    ui_fqdn = ui_fqdn.strip().strip("/")
    if ui_fqdn.startswith("api-"):
        ui_fqdn = ui_fqdn[len("api-") :]
    api_fqdn = f"api-{ui_fqdn}" if ui_fqdn else ui_fqdn

    base_url = f"https://{api_fqdn}"
    headers = get_headers(api_key, api_key_id)

    # 1) CWP policies cleanup (list -> match -> optional delete)
    policies: List[Dict[str, Any]] = []
    try:
        policies = list_policies(base_url, headers, timeout_s=args.timeout)
    except requests.HTTPError as e:
        print(f"Failed to list CWP policies: {e} - {getattr(e.response, 'text', '')}", file=sys.stderr)
    except Exception as e:
        print(f"Error listing CWP policies: {e}", file=sys.stderr)

    print(f"Found {len(policies)} CWP policies from {base_url}")

    matched_policies: List[Tuple[str, Dict[str, Any]]] = []
    if creator_name:
        for pol in policies:
            if not isinstance(pol, dict):
                continue
            if policy_matches_creator(pol, creator_name):
                pid = find_policy_id(pol)
                if pid:
                    matched_policies.append((pid, pol))
    else:
        print("No --name provided; skipping policy creator-name matching.")

    if creator_name:
        print(f"Matched {len(matched_policies)} CWP policies created by {creator_name}")

    if not args.confirm:
        print("Dry run mode (no deletions). To actually delete, rerun with --confirm flag.")
        print("No delete calls were made.")

    # 2) Asset groups cleanup (list -> match -> delete).
    asset_groups: List[Dict[str, Any]] = []

    try:
        asset_groups = list_asset_groups(base_url, headers, timeout_s=args.timeout)
    except requests.HTTPError as e:
        print(f"Failed to list asset groups: {e} - {getattr(e.response, 'text', '')}", file=sys.stderr)
        return
    except Exception as e:
        print(f"Error listing asset groups: {e}", file=sys.stderr)
        return

    print(f"Found {len(asset_groups)} asset groups from {base_url}")

    matched_asset_groups: List[Tuple[str, Dict[str, Any]]] = []
    for ag in asset_groups:
        if not isinstance(ag, dict):
            continue
        if asset_group_matches_email(ag, creator_email):
            agid = find_asset_group_id(ag)
            if agid:
                matched_asset_groups.append((agid, ag))

    print(f"Matched {len(matched_asset_groups)} asset groups created by {creator_email}")

    if not args.confirm:
        print(f"Dry run: would delete {len(matched_policies)} CWP policies.")
        print(f"Dry run: would delete {len(matched_asset_groups)} asset groups.")
        return

    pol_success = 0
    pol_fail = 0
    pol_total = len(matched_policies)

    if pol_total:
        for idx, (pid, _) in enumerate(matched_policies, start=1):
            try:
                status, _text = delete_policy(base_url, headers, pid, timeout_s=args.timeout)
                if 200 <= status < 300:
                    pol_success += 1
                else:
                    pol_fail += 1
                print(f"Policy delete progress: {idx}/{pol_total}")
            except Exception:
                pol_fail += 1
                print(f"Policy delete progress: {idx}/{pol_total} (error)")
            if args.delete_delay > 0 and idx < pol_total:
                time.sleep(args.delete_delay)

    if pol_total:
        print(f"Deleted CWP policies: success={pol_success} fail={pol_fail}")

    ag_success = 0
    ag_fail = 0
    ag_total = len(matched_asset_groups)

    if ag_total:
        for idx, (agid, _) in enumerate(matched_asset_groups, start=1):
            try:
                status, _text = delete_asset_group(base_url, headers, agid, timeout_s=args.timeout)
                if 200 <= status < 300:
                    ag_success += 1
                else:
                    ag_fail += 1
                print(f"Asset group delete progress: {idx}/{ag_total}")
            except Exception:
                ag_fail += 1
                print(f"Asset group delete progress: {idx}/{ag_total} (error)")
            if args.delete_delay > 0 and idx < ag_total:
                time.sleep(args.delete_delay)

    print(f"Deleted asset groups: success={ag_success} fail={ag_fail}")


if __name__ == "__main__":
    main()
