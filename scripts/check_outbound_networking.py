#!/usr/bin/env python3
"""
Prohibited-outbound-networking guard (Phase 0).

Every integration must reach the internet through the approved,
SSRF-validated gateway in backend/app/utils/http_client.py
(request_with_retry / resolve_public_addresses) - never by
instantiating an HTTP client or raw socket directly. This script scans
the backend source tree for the patterns that would bypass that
policy and fails if any are found outside an explicit allowlist.

Limitation (documented, not hidden): this is a regex/text scan, not a
full AST/import-graph analysis. It cannot catch every possible
indirection (e.g. dynamically constructed client objects, or a
prohibited call reached through several layers of aliasing). It is
intended as a fast, deterministic tripwire for the common case - the
exact two call sites that caused the original SSRF findings would
both have been caught by this check - not a substitute for the actual
security regression test suite in tests/test_security_regressions.py,
which remains the authoritative behavioral check.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent / "backend" / "app"

# Files exempt from the "must use request_with_retry" rule, each with
# a specific reason - not a blanket escape hatch:
ALLOWLIST = {
    # This IS the approved gateway that request_with_retry lives in.
    BACKEND_ROOT / "utils" / "http_client.py",
    # Raw TLS socket inspection (cannot go through an HTTP client at
    # all) - independently calls resolve_public_addresses() before
    # connecting, verified by tests/test_security_regressions.py.
    BACKEND_ROOT / "integrations" / "domain" / "ssl_integration.py",
    # Dead code: the synchronous BaseIntegration class (with its own
    # httpx.Client) has zero live subclasses - every integration in
    # this codebase extends AsyncBaseIntegration instead. Left here
    # deliberately (not deleted) pending an explicit cleanup decision,
    # but excluded from this guard since nothing can actually reach
    # this code path. TODO(cleanup): remove BaseIntegration entirely.
    BACKEND_ROOT / "integrations" / "base.py",
}

_CLIENT_CONSTRUCTION = re.compile(r"\bhttpx\.(?:Async)?Client\s*\(")
_APPROVED_GATEWAY_USE = re.compile(r"\brequest_with_retry\s*\(")

_OTHER_PROHIBITED_PATTERNS = [
    (re.compile(r"^\s*import\s+requests\b", re.MULTILINE), "the 'requests' library is not permitted"),
    (re.compile(r"^\s*from\s+requests\b", re.MULTILINE), "the 'requests' library is not permitted"),
    (re.compile(r"^\s*import\s+aiohttp\b", re.MULTILINE), "aiohttp is not permitted - use the approved httpx-based gateway"),
    (re.compile(r"^\s*from\s+aiohttp\b", re.MULTILINE), "aiohttp is not permitted - use the approved httpx-based gateway"),
    (re.compile(r"\baiohttp\.ClientSession\s*\("), "aiohttp.ClientSession(...) is not permitted"),
    (re.compile(r"\burllib\.request\."), "urllib.request is not permitted"),
    (re.compile(r"\bsocket\.create_connection\s*\("), "raw socket.create_connection(...) outside the approved gateway"),
    (re.compile(r"\bloop\.create_connection\s*\("), "raw loop.create_connection(...) outside the approved gateway"),
    (re.compile(r"\bsocket\.socket\s*\("), "raw socket.socket(...) outside the approved gateway"),
]


def scan() -> list[str]:

    violations: list[str] = []

    for path in BACKEND_ROOT.rglob("*.py"):

        if path in ALLOWLIST or "__pycache__" in path.parts:
            continue

        text = path.read_text(encoding="utf-8", errors="ignore")
        relative = path.relative_to(BACKEND_ROOT.parent.parent)

        # Rule 1: a file that constructs an httpx client must also
        # route requests through request_with_retry() somewhere in
        # the same file - otherwise it can only be calling
        # client.get/post/request() directly, bypassing SSRF
        # validation and redirect revalidation entirely.
        if _CLIENT_CONSTRUCTION.search(text) and not _APPROVED_GATEWAY_USE.search(text):

            line_number = text.count(
                "\n", 0, _CLIENT_CONSTRUCTION.search(text).start()
            ) + 1
            violations.append(
                f"{relative}:{line_number}: constructs an httpx client "
                f"but never calls request_with_retry() in this file - "
                f"outbound requests here bypass the SSRF policy."
            )

        # Rule 2: other prohibited networking primitives, unconditional.
        for pattern, message in _OTHER_PROHIBITED_PATTERNS:

            for match in pattern.finditer(text):

                line_number = text.count("\n", 0, match.start()) + 1
                violations.append(f"{relative}:{line_number}: {message}")

    return violations


def main() -> int:

    violations = scan()

    if violations:
        print("Prohibited outbound-networking pattern(s) found:\n", file=sys.stderr)

        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)

        print(
            "\nAll outbound network access must go through "
            "backend/app/utils/http_client.py's request_with_retry() / "
            "resolve_public_addresses(), which validates every "
            "destination and redirect hop against the SSRF policy. "
            "If a new call site genuinely needs direct access (rare), "
            "add it to ALLOWLIST in this script with a comment "
            "explaining why it independently enforces the same policy.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: no prohibited outbound-networking patterns found ({BACKEND_ROOT}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
