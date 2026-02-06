#!/usr/bin/env python3
"""Run both cleanup scripts after prompting for an email.

This wrapper calls:
- Global Configurations/roles_usergroups_cleanup.py
- CSPM Configurations/cspm_custom_policies_cleanup.py
- CSPM Configurations/cspm_rules_cleanup.py
- CSPM Configurations/automation_rules_cleanup.py
- CSPM Configurations/custom_compliance_standards_cleanup.py

It passes the chosen email to both scripts.
"""

from __future__ import annotations

import os
import sys
import subprocess
import getpass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

ROLES_SCRIPT = BASE_DIR / "Global Configurations" / "roles_usergroups_cleanup.py"
CUSTOM_POLICIES_SCRIPT = BASE_DIR / "CSPM Configurations" / "cspm_custom_policies_cleanup.py"
RULES_SCRIPT = BASE_DIR / "CSPM Configurations" / "cspm_rules_cleanup.py"
AUTOMATION_RULES_SCRIPT = (
    BASE_DIR / "CSPM Configurations" / "automation_rules_cleanup.py"
)
COMPLIANCE_CONTROLS_SCRIPT = (
    BASE_DIR / "CSPM Configurations" / "custom_compliance_standards_cleanup.py"
)
CWP_POLICIES_SCRIPT = (
    BASE_DIR / "CWP Configurations" / "policies_asset_groups_cleanup.py"
)
APPSEC_CUSTOM_RULES_SCRIPT = (
    BASE_DIR
    / "Application Security Configurations"
    / "appsec_custom_policies_cleanup.py"
)


def normalize_fqdn(host: str) -> str:
    host = (host or "").strip()
    host = host.replace("https://", "").replace("http://", "").strip().strip("/")
    return host


def ui_fqdn_from_any(host: str) -> str:
    host = normalize_fqdn(host)
    if host.startswith("api-"):
        return host[len("api-") :]
    return host


def api_fqdn_from_ui(ui_fqdn: str) -> str:
    ui_fqdn = normalize_fqdn(ui_fqdn)
    if not ui_fqdn:
        return ui_fqdn
    if ui_fqdn.startswith("api-"):
        return ui_fqdn
    return f"api-{ui_fqdn}"


def prompt_fqdn() -> str:
    existing = normalize_fqdn(os.environ.get("CORTEX_FQDN", ""))
    raw = input("CORTEX_FQDN (host only, no https://) [blank=use env]: ").strip()
    raw = normalize_fqdn(raw)
    if raw:
        return raw
    if existing:
        return existing
    print("CORTEX_FQDN is required (set it in .env/env or enter it at the prompt).")
    sys.exit(2)


def prompt_email() -> str:
    existing = os.environ.get("CORTEX_CREATOR_EMAIL", "").strip()
    email = input("Creator email to clean up [blank=use env]: ").strip()
    if email:
        return email
    if existing:
        return existing
    print("Creator email is required (set CORTEX_CREATOR_EMAIL or enter it at the prompt).")
    sys.exit(2)


def prompt_confirm() -> bool:
    val = input("Perform deletions? (y/N): ").strip().lower()
    return val in {"y", "yes"}


def prompt_name() -> str:
    existing = os.environ.get("CORTEX_CREATOR_NAME", "").strip()
    name = input("Creator name for rules cleanup [blank=use env]: ").strip()
    if name:
        return name
    if existing:
        return existing
    print("Creator name is required (set CORTEX_CREATOR_NAME or enter it at the prompt).")
    sys.exit(2)


def prompt_api_key() -> str:
    # Use getpass to avoid echoing secrets.
    val = getpass.getpass("CORTEX_API_KEY (leave blank to use env): ").strip()
    return val


def prompt_api_key_id() -> str:
    val = input("CORTEX_API_KEY_ID (leave blank to use env): ").strip()
    return val


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"").strip("'")
        if not key:
            continue
        # Don't override real environment variables.
        os.environ.setdefault(key, value)


def print_banner(title: str) -> None:
    line = "=" * max(10, len(title) + 10)
    print(f"\n{line}\n  {title}\n{line}")


def print_step(label: str, *, index: int, total: int) -> None:
    left = f"[{index}/{total}] {label}"
    line_len = max(40, len(left) + 10)
    print("\n" + "-" * line_len)
    print(f"  {left}")
    print("-" * line_len)


def run_script(cmd: list[str], *, env: dict[str, str]) -> None:
    print("\nRunning:", " ".join(cmd))
    result = subprocess.run(cmd, check=False, env=env)
    if result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")


def main() -> None:
    load_dotenv(BASE_DIR / ".env")
    raw_fqdn = prompt_fqdn()
    ui_fqdn = ui_fqdn_from_any(raw_fqdn)
    api_fqdn = api_fqdn_from_ui(ui_fqdn)
    email = prompt_email()
    name = prompt_name()
    api_key = prompt_api_key()
    api_key_id = prompt_api_key_id()
    confirm = prompt_confirm()

    python = sys.executable or "python3"

    roles_cmd = [python, str(ROLES_SCRIPT), "--fqdn", api_fqdn, "--email", email]
    custom_policies_cmd = [python, str(CUSTOM_POLICIES_SCRIPT), "--fqdn", ui_fqdn, "--email", email]
    rules_cmd = [python, str(RULES_SCRIPT), "--fqdn", ui_fqdn, "--name", name]
    automation_rules_cmd = [python, str(AUTOMATION_RULES_SCRIPT), "--fqdn", ui_fqdn, "--email", email]
    compliance_controls_cmd = [python, str(COMPLIANCE_CONTROLS_SCRIPT), "--fqdn", ui_fqdn, "--email", email]
    cwp_policies_cmd = [python, str(CWP_POLICIES_SCRIPT), "--fqdn", api_fqdn, "--name", name, "--email", email]
    appsec_policies_cmd = [python, str(APPSEC_CUSTOM_RULES_SCRIPT), "--fqdn", api_fqdn, "--email", email]

    if confirm:
        roles_cmd.append("--confirm")
        custom_policies_cmd.append("--confirm")
        rules_cmd.append("--confirm")
        automation_rules_cmd.append("--confirm")
        compliance_controls_cmd.append("--confirm")
        cwp_policies_cmd.append("--confirm")
        appsec_policies_cmd.append("--confirm")

    merged_env = dict(os.environ)
    # Keep env var as the user-provided (UI) fqdn so other tools/docs stay consistent.
    merged_env["CORTEX_FQDN"] = ui_fqdn
    merged_env["CORTEX_CREATOR_EMAIL"] = email
    merged_env["CORTEX_CREATOR_NAME"] = name
    if api_key:
        merged_env["CORTEX_API_KEY"] = api_key
    if api_key_id:
        merged_env["CORTEX_API_KEY_ID"] = api_key_id

    print_banner("GLOBAL CONFIGURATIONS CLEANUP")
    print_step(Path(roles_cmd[1]).name, index=1, total=1)
    run_script(roles_cmd, env=merged_env)

    print_banner("CSPM CONFIGURATIONS CLEANUP")
    cspm_steps: list[tuple[str, list[str]]] = [
        (Path(custom_policies_cmd[1]).name, custom_policies_cmd),
        (Path(rules_cmd[1]).name, rules_cmd),
        (Path(automation_rules_cmd[1]).name, automation_rules_cmd),
        (Path(compliance_controls_cmd[1]).name, compliance_controls_cmd),
    ]
    for idx, (label, cmd) in enumerate(cspm_steps, start=1):
        print_step(label, index=idx, total=len(cspm_steps))
        run_script(cmd, env=merged_env)

    print_banner("CWP CONFIGURATIONS CLEANUP")
    print_step(Path(cwp_policies_cmd[1]).name, index=1, total=1)
    run_script(cwp_policies_cmd, env=merged_env)

    print_banner("APPLICATION SECURITY CLEANUP")
    print_step(Path(appsec_policies_cmd[1]).name, index=1, total=1)
    run_script(appsec_policies_cmd, env=merged_env)


if __name__ == "__main__":
    main()
