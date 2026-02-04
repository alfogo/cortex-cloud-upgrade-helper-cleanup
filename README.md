# Cortex Cloud Upgrade Helper rollback
This project rolls back the objects migrated from Prisma Cloud to Cortex Cloud using the Upgrade Helper from the Cortex Cloud console.

Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies (if not already installed):

```bash
python3 -m pip install -r requirements.txt
```

Run the wrapper (dry-run by default):

```bash
python3 run_cleanup.py
```

The wrapper will prompt for:
- `CORTEX_FQDN` (UI host; enter the host without `https://`; the wrapper will infer the `api-` host automatically)
- `Creator email` (used for scripts that filter by email)
- `Creator name` (used for scripts that filter by display name)
- `CORTEX_API_KEY` and `CORTEX_API_KEY_ID` (you can leave blank to use env/.env values)
- `Perform deletions? (y/N)` — answer `y` to actually delete; default is dry-run.

You can set defaults in a `.env` file at the repo root with keys like:

```
CORTEX_FQDN=your-ui-host.example.com
CORTEX_API_KEY=YOUR_API_KEY
CORTEX_API_KEY_ID=YOUR_API_KEY_ID
CORTEX_CREATOR_EMAIL=user@example.com
CORTEX_CREATOR_NAME="First Last"
```

Secrets and session files (for UI replay) must never be committed. See notes below.

## Repository layout and script descriptions

- `run_cleanup.py`: wrapper that orchestrates all cleanup scripts. Prompts once, sets env, and runs each module with clear step banners.
- `capture_headers_client.py`: helper to capture UI session headers/cookies from a copied cURL or the clipboard and write a `cortex_ui_headers.json` session file.

- `Application Security Configurations/appsec_custom_policies_cleanup.py`: lists AppSec policies via the public API (`/public_api/appsec/v1/policies`), filters by `createdBy` email, and deletes matches (`/public_api/appsec/v1/policies/{id}`).

- `CSPM Configurations/`
	- `cspm_custom_policies_cleanup.py`: list and optionally delete custom Cloud Security policies via the UI-backed endpoints (uses captured UI session headers).
	- `cspm_rules_cleanup.py`: list and optionally delete CSPM rules created by a given user (UI-backed endpoints).
	- `automation_rules_cleanup.py`: list and update automation rules (UI-backed); deletion is implemented by updating the rules table.
	- `custom_compliance_standards_clenaup.py`: lists compliance controls (`COMPLIANCE_CONTROLS_CATALOG`) and optionally deletes controls created by a user.

- `CWP Configurations/policies_asset_groups_cleanup.py`: lists CWP policies and asset groups via the public API; filters policies by creator display name and asset groups by `XDM.ASSET_GROUP.CREATED_BY` (email). Supports deletions for both resource types and retries across common endpoint shapes.

- `Global Configurations/roles_usergroups_cleanup.py`: lists and deletes IAM user-groups and roles via the platform API (deletes groups first, then roles).

- Top-level utility files:
	- `requirements.txt`: Python dependencies
	- `cortex_ui_headers.json`: captured UI session headers (contains secrets; do not commit)

## Safety notes
- All scripts default to dry-run; use `--confirm` or answer `y` when prompted by the wrapper to perform deletions.