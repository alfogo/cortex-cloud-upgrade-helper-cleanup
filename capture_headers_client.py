#!/usr/bin/env python3
"""Cortex Cloud UI client: capture a session once, then reuse it for many calls.

Problem
-------
Some Cortex Cloud UI endpoints require browser session cookies plus anti-CSRF/request tokens.
If you cannot automate a browser (Playwright blocked) but you *can* copy one
"Copy as cURL" from DevTools, you can:

1) Capture a reusable session from that one cURL.
2) Use that session to call subsequent UI endpoints by path + payload.

Security
--------
The session file contains secrets (cookies/tokens). Do not commit it.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import requests


@dataclass
class ParsedRequest:
    method: str
    url: str
    headers: Dict[str, str]
    data: Optional[str]
    verify_tls: bool = True


_CURL_DATA_FLAGS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-ascii",
    "--data-urlencode",
}


def _normalize_curl_text(text: str) -> str:
    """Normalize a multi-line 'Copy as cURL' command into a single-line string."""

    if not text:
        return ""

    t = text.strip()

    # Strip Markdown code fences.
    t = re.sub(r"^\s*```(?:bash|sh|zsh)?\s*", "", t)
    t = re.sub(r"\s*```\s*$", "", t)

    # Strip a leading shell prompt.
    t = re.sub(r"^\s*\$\s+", "", t)

    # Join backslash-newline continuations.
    t = t.replace("\\\r\n", " ").replace("\\\n", " ").replace("\\\r", " ")
    # Collapse remaining newlines.
    t = re.sub(r"[\r\n]+", " ", t)

    return t.strip()


def _extract_cookie_value(cookie_header: str, names) -> Optional[str]:
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
    """If cookies contain CSRF/XSRF values, mirror them into headers when missing."""

    cookie = None
    for key in ("cookie", "Cookie"):
        if key in headers and headers.get(key):
            cookie = headers[key]
            break
    if not cookie:
        return

    lower_keys = {k.lower(): k for k in headers.keys()}

    def has(header_name: str) -> bool:
        return header_name.lower() in lower_keys

    def set_if_missing(header_name: str, value: str) -> None:
        if not has(header_name):
            headers[header_name] = value

    xsrf_val = _extract_cookie_value(cookie, names=("XSRF-TOKEN", "xsrf-token", "XSRF_TOKEN"))
    if xsrf_val:
        set_if_missing("x-xsrf-token", requests.utils.unquote(xsrf_val))

    csrf_val = _extract_cookie_value(
        cookie,
        names=(
            "CSRF-TOKEN",
            "csrf-token",
            "csrftoken",
            "csrfToken",
            "csrf_token",  # seen in Cortex UI cookies
        ),
    )
    if csrf_val:
        set_if_missing("x-csrf-token", requests.utils.unquote(csrf_val))


def _minimize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Keep a practical subset of headers for UI-backed API calls."""

    allow = {
        "accept",
        "content-type",
        "origin",
        "referer",
        "user-agent",
        "x-csrf-token",
        "x-requested-with",
        "x-xdr-request-token",
        "x-xsrf-token",
        "timeoffset",
        "timezone",
        "cookie",
    }

    out: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in allow:
            out[k] = v

    if not any(k.lower() == "accept" for k in out):
        out["Accept"] = "application/json"

    return out


def parse_curl_command(curl_text: str) -> ParsedRequest:
    text = _normalize_curl_text(curl_text)
    tokens = shlex.split(text)
    if not tokens:
        raise ValueError("Empty cURL input")

    # Some copy formats might include leading env vars; start at `curl` if present.
    if "curl" in tokens and tokens[0] != "curl":
        tokens = tokens[tokens.index("curl") :]

    if tokens and tokens[0] == "curl":
        tokens = tokens[1:]

    method: Optional[str] = None
    url: Optional[str] = None
    headers: Dict[str, str] = {}
    data: Optional[str] = None
    verify_tls = True

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok in ("-X", "--request"):
            i += 1
            if i >= len(tokens):
                raise ValueError("Expected method after -X/--request")
            method = tokens[i].upper()
        elif tok in ("-H", "--header"):
            i += 1
            if i >= len(tokens):
                raise ValueError("Expected header value after -H/--header")
            header_line = tokens[i]
            if ":" in header_line:
                name, value = header_line.split(":", 1)
                headers[name.strip()] = value.lstrip()
        elif tok in ("-b", "--cookie"):
            i += 1
            if i >= len(tokens):
                raise ValueError("Expected cookie string after -b/--cookie")
            headers.setdefault("Cookie", tokens[i])
        elif tok in _CURL_DATA_FLAGS:
            i += 1
            if i >= len(tokens):
                raise ValueError(f"Expected data after {tok}")
            data = tokens[i]
            if method is None:
                method = "POST"
        elif tok == "--url":
            i += 1
            if i >= len(tokens):
                raise ValueError("Expected URL after --url")
            url = tokens[i]
        elif tok in ("-k", "--insecure"):
            verify_tls = False
        elif tok.startswith("http://") or tok.startswith("https://"):
            url = tok

        i += 1

    if not url:
        # Fallback: find the first http(s) token anywhere.
        for tok in tokens:
            if tok.startswith("http://") or tok.startswith("https://"):
                url = tok
                break

    if not url:
        raise ValueError("Could not find URL in cURL command")

    final_method = (method or ("POST" if data is not None else "GET")).upper()

    if data is not None and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"

    _maybe_add_anti_csrf_headers(headers)

    return ParsedRequest(method=final_method, url=url, headers=headers, data=data, verify_tls=verify_tls)


@dataclass
class UISession:
    base_url: str
    headers: Dict[str, str]
    cookie: Optional[str]
    verify_tls: bool = True


def _read_clipboard_macos() -> str:
    if sys.platform != "darwin":
        raise RuntimeError("Clipboard capture is only supported on macOS")
    proc = subprocess.run(["pbpaste"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError("Failed to read clipboard via pbpaste")
    return proc.stdout or ""


def _base_url_from_url(url: str) -> str:
    s = urlsplit(url)
    if not s.scheme or not s.netloc:
        raise ValueError(f"Invalid URL: {url!r}")
    return f"{s.scheme}://{s.netloc}".rstrip("/")


def _normalize_session_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Keep session-level headers; per-request headers are added later."""

    allow = {
        "accept",
        "origin",
        "referer",
        "user-agent",
        "x-csrf-token",
        "x-requested-with",
        "x-xdr-request-token",
        "x-xsrf-token",
        "timeoffset",
        "timezone",
    }

    out: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in allow:
            out[k] = v

    # Reasonable defaults
    if not any(k.lower() == "accept" for k in out):
        out["Accept"] = "application/json"

    return out


def capture_session_from_curl(curl_text: str, *, minimal_headers: bool) -> UISession:
    req = parse_curl_command(curl_text)

    headers = dict(req.headers)
    if minimal_headers:
        headers = _minimize_headers(headers)

    # Ensure CSRF/XSRF headers exist if cookies include them
    _maybe_add_anti_csrf_headers(headers)

    cookie = None
    for k in ("Cookie", "cookie"):
        if k in headers and headers.get(k):
            cookie = headers[k]
            break

    session_headers = _normalize_session_headers(headers)
    return UISession(
        base_url=_base_url_from_url(req.url),
        headers=session_headers,
        cookie=cookie,
        verify_tls=req.verify_tls,
    )


def save_session(session: UISession, path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "base_url": session.base_url,
                "headers": session.headers,
                "cookie": session.cookie,
                "verify_tls": session.verify_tls,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def load_session(path: Path) -> UISession:
    obj = json.loads(path.read_text(encoding="utf-8"))
    return UISession(
        base_url=obj["base_url"],
        headers=dict(obj.get("headers") or {}),
        cookie=obj.get("cookie"),
        verify_tls=bool(obj.get("verify_tls", True)),
    )


def _build_headers_for_call(session: UISession, *, content_type: Optional[str], referer: Optional[str]) -> Dict[str, str]:
    headers = dict(session.headers)

    if session.cookie:
        # Always send Cookie header.
        headers.setdefault("Cookie", session.cookie)

    if referer:
        headers["Referer"] = referer

    if content_type:
        headers["Content-Type"] = content_type

    # If cookies contain tokens but headers don't, add them.
    _maybe_add_anti_csrf_headers(headers)

    return headers


def _read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def call_with_session(
    session: UISession,
    *,
    url: Optional[str],
    path: Optional[str],
    method: Optional[str],
    json_file: Optional[Path],
    data_raw: Optional[str],
    timeout_s: int,
    referer: Optional[str],
) -> requests.Response:
    if not url and not path:
        raise ValueError("Provide either --url or --path")

    target_url = url
    if not target_url:
        target_url = f"{session.base_url}{path}"  # path should start with '/'

    body_data: Optional[str] = None
    body_json: Optional[Any] = None

    if json_file is not None:
        body_json = _read_json_file(json_file)
    elif data_raw is not None:
        body_data = data_raw

    # Default method
    final_method = (method or ("POST" if (body_json is not None or body_data is not None) else "GET")).upper()

    content_type = None
    if body_json is not None:
        content_type = "application/json"
    elif body_data is not None:
        # Assume JSON if it looks like JSON.
        content_type = "application/json" if body_data.strip().startswith("{") else "text/plain"

    headers = _build_headers_for_call(session, content_type=content_type, referer=referer)

    resp = requests.request(
        final_method,
        target_url,
        headers=headers,
        json=body_json,
        data=body_data if body_json is None else None,
        timeout=timeout_s,
        verify=session.verify_tls,
    )

    return resp


def main() -> None:
    p = argparse.ArgumentParser(description="Capture a UI session once and reuse it for many calls.")
    sub = p.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture", help="Capture a session from a copied 'curl ...' command")
    cap_src = cap.add_mutually_exclusive_group(required=True)
    cap_src.add_argument("--from-clipboard", action="store_true", help="Read cURL from macOS clipboard")
    cap_src.add_argument("--curl-file", type=Path, help="Read cURL from a file")
    cap_src.add_argument("--curl", help="cURL as a single string")
    cap.add_argument("--minimal-headers", action="store_true", help="Minimize headers to the useful subset")
    cap.add_argument("--out", type=Path, required=True, help="Write session JSON here (contains secrets)")

    call = sub.add_parser("call", help="Call an endpoint using a previously captured session")
    call.add_argument("--session", type=Path, required=True, help="Session JSON created by 'capture'")
    target = call.add_mutually_exclusive_group(required=True)
    target.add_argument("--url", help="Full URL to call")
    target.add_argument("--path", help="Path to call (example: /api/cloudsec/v1/policy/get_data?...)")
    call.add_argument("--method", help="HTTP method (default GET or POST if body provided)")
    body = call.add_mutually_exclusive_group()
    body.add_argument("--json-file", type=Path, help="JSON request body file")
    body.add_argument("--data-raw", help="Raw request body string")
    call.add_argument("--referer", help="Override Referer header")
    call.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")
    call.add_argument("--out", type=Path, help="Write response to this file (defaults to stdout)")

    args = p.parse_args()

    if args.cmd == "capture":
        if args.from_clipboard:
            curl_text = _read_clipboard_macos()
        elif args.curl_file:
            curl_text = args.curl_file.read_text(encoding="utf-8")
        else:
            curl_text = args.curl

        if not curl_text:
            print("No cURL input provided", file=sys.stderr)
            sys.exit(2)

        try:
            session = capture_session_from_curl(curl_text, minimal_headers=args.minimal_headers)
        except Exception as e:
            print(f"Failed to capture session: {e}", file=sys.stderr)
            sys.exit(2)

        save_session(session, args.out)
        print(f"Saved session to: {args.out}")
        return

    if args.cmd == "call":
        session = load_session(args.session)
        resp = call_with_session(
            session,
            url=args.url,
            path=args.path,
            method=args.method,
            json_file=args.json_file,
            data_raw=args.data_raw,
            timeout_s=args.timeout,
            referer=args.referer,
        )

        output_text = resp.text
        try:
            parsed = resp.json()
            output_text = json.dumps(parsed, indent=2, sort_keys=True) + "\n"
        except Exception:
            if not output_text.endswith("\n"):
                output_text += "\n"

        if args.out:
            args.out.write_text(output_text, encoding="utf-8")
        else:
            sys.stdout.write(output_text)

        if resp.status_code < 200 or resp.status_code >= 300:
            print(f"Request failed with HTTP {resp.status_code}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
