#!/usr/bin/env python3
import os
import sys
import argparse
import json
import requests

DEFAULT_EMAIL = None


def get_headers(api_key, api_key_id):
    return {
        "Authorization": api_key,
        "x-xdr-auth-id": str(api_key_id),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def safe_json(resp, *, label: str):
    try:
        return resp.json()
    except json.JSONDecodeError:
        ct = resp.headers.get("content-type", "")
        text = (resp.text or "").strip()
        snippet = text[:1000]
        print(f"{label}: non-JSON response (status={resp.status_code}, content-type={ct})")
        if snippet:
            print(snippet)
        raise


def extract_items_json(body):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("reply", "items", "data", "results", "roles", "groups", "user_groups", "userGroups"):
            if key in body and isinstance(body[key], (list, dict)):
                val = body[key]
                if isinstance(val, dict):
                    for subkey in ("items", "results", "roles", "groups", "user_groups", "userGroups"):
                        if subkey in val and isinstance(val[subkey], list):
                            return val[subkey]
                if isinstance(val, list):
                    return val
        return [body]
    return []


def extract_roles_json(body):
    return extract_items_json(body)


def find_role_id(role):
    for key in ("id", "role_id", "roleId", "uuid"):
        if key in role:
            return role[key]
    if "role" in role and isinstance(role["role"], dict):
        return find_role_id(role["role"])
    return None


def find_group_id(group):
    for key in ("id", "group_id", "groupId", "uuid"):
        if key in group:
            return group[key]
    if "group" in group and isinstance(group["group"], dict):
        return find_group_id(group["group"])
    return None


def role_matches_email(role, email):
    if not role:
        return False
    for key in ("created_by", "createdBy", "creator", "owner", "created_by_email"):
        v = role.get(key)
        if isinstance(v, str) and v.lower() == email.lower():
            return True
    def search(obj):
        if isinstance(obj, str):
            return email.lower() in obj.lower()
        if isinstance(obj, dict):
            for val in obj.values():
                if search(val):
                    return True
        if isinstance(obj, list):
            for item in obj:
                if search(item):
                    return True
        return False

    return search(role)


def list_user_groups(base_url, headers):
    url = f"{base_url}/platform/iam/v1/user-group"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return extract_items_json(safe_json(resp, label="List user groups"))


def delete_user_group(base_url, headers, group_id):
    url = f"{base_url}/platform/iam/v1/user-group/{group_id}"
    resp = requests.delete(url, headers=headers, timeout=30)
    return resp.status_code, resp.text


def list_roles(base_url, headers):
    url = f"{base_url}/platform/iam/v1/role"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return extract_roles_json(safe_json(resp, label="List roles"))


def delete_role(base_url, headers, role_id):
    url = f"{base_url}/platform/iam/v1/role/{role_id}"
    resp = requests.delete(url, headers=headers, timeout=30)
    return resp.status_code, resp.text


def main():
    p = argparse.ArgumentParser(description="List user groups and roles, filter by creator email, and delete them.")
    p.add_argument("--fqdn", help="Cortex API FQDN (example: api-company.us.com)")
    p.add_argument("--api-key", help="API key (Authorization header)")
    p.add_argument("--api-key-id", help="API key id (x-xdr-auth-id header)")
    p.add_argument("--email", required=True, help="Creator email to filter")
    p.add_argument("--dry-run", action="store_true", default=True, dest="dry_run", help="Do not perform deletions (default)")
    p.add_argument("--confirm", action="store_true", help="Actually perform deletions")
    args = p.parse_args()

    fqdn = args.fqdn or os.environ.get("CORTEX_FQDN")
    api_key = args.api_key or os.environ.get("CORTEX_API_KEY")
    api_key_id = args.api_key_id or os.environ.get("CORTEX_API_KEY_ID")

    # Interactive fallback for direct execution
    if (not api_key or not api_key_id) and sys.stdin.isatty():
        if not api_key:
            api_key = input("CORTEX_API_KEY (Authorization): ").strip()
        if not api_key_id:
            api_key_id = input("CORTEX_API_KEY_ID (x-xdr-auth-id): ").strip()

    if not fqdn or not api_key or not api_key_id:
        print("Error: supply --fqdn, --api-key, and --api-key-id or set CORTEX_FQDN, CORTEX_API_KEY, CORTEX_API_KEY_ID env vars.")
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

    try:
        groups = list_user_groups(base_url, headers)
    except requests.HTTPError as e:
        print(f"Failed to list user groups: {e} - {getattr(e.response, 'text', '')}")
        sys.exit(1)
    except Exception as e:
        print(f"Error listing user groups: {e}")
        sys.exit(1)

    print(f"Found {len(groups)} user groups from {base_url}")

    group_matches = []
    for g in groups:
        if role_matches_email(g, args.email):
            gid = find_group_id(g)
            group_matches.append((gid, g))

    print(f"Matched {len(group_matches)} user groups created by {args.email}")

    try:
        roles = list_roles(base_url, headers)
    except requests.HTTPError as e:
        print(f"Failed to list roles: {e} - {getattr(e.response, 'text', '')}")
        sys.exit(1)
    except Exception as e:
        print(f"Error listing roles: {e}")
        sys.exit(1)

    print(f"Found {len(roles)} roles from {base_url}")

    matches = []
    for r in roles:
        if role_matches_email(r, args.email):
            rid = find_role_id(r)
            matches.append((rid, r))

    print(f"Matched {len(matches)} roles created by {args.email}")

    if not args.confirm:
        print("Dry run mode (no deletions). To actually delete user groups and roles, rerun with --confirm flag.")
        return

    # Delete user groups first, then roles.
    group_success = 0
    group_fail = 0
    total_groups = len(group_matches)
    for idx, (gid, group) in enumerate(group_matches, start=1):
        if not gid:
            group_fail += 1
            print(f"Group delete progress: {idx}/{total_groups} (missing id)")
            continue
        try:
            status, _ = delete_user_group(base_url, headers, gid)
            if 200 <= status < 300:
                group_success += 1
            else:
                group_fail += 1
            print(f"Group delete progress: {idx}/{total_groups}")
        except Exception:
            group_fail += 1
            print(f"Group delete progress: {idx}/{total_groups} (error)")

    print(f"Deleted user groups: success={group_success} fail={group_fail}")

    role_success = 0
    role_fail = 0
    total_roles = len(matches)
    for idx, (rid, role) in enumerate(matches, start=1):
        if not rid:
            role_fail += 1
            print(f"Role delete progress: {idx}/{total_roles} (missing id)")
            continue
        try:
            status, _ = delete_role(base_url, headers, rid)
            if 200 <= status < 300:
                role_success += 1
            else:
                role_fail += 1
            print(f"Role delete progress: {idx}/{total_roles}")
        except Exception:
            role_fail += 1
            print(f"Role delete progress: {idx}/{total_roles} (error)")

    print(f"Deleted roles: success={role_success} fail={role_fail}")


if __name__ == "__main__":
    main()
