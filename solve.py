#!/usr/bin/env python3
"""
DefCon CTF - "Phantom Headers" (Scooby Doo / 08_Logs) solver.

Reconstructs the exact request the phantom (UA "PH-Replay") used to trigger the
hidden audit response on GET /challenges/2026/08, reverse-engineered purely from
the three correlated logs (edge_access / header_capture / app_events), matched by
Request ID.

  Required request shape (GET /challenges/2026/08):
    Accept:          application/vnd.puzzledhackers.audit+json   (else 406 media_mismatch)
    If-None-Match:   "audit-a17f-2026"                           (else 412 precondition_failed)
    User-Agent:      PH-Replay/0.8                               (0.7 -> 426 upgrade_required)
    X-PH-Case:       08-alder-7f3c                               (the "c" vs "d" trapdoor selector)
    X-PH-Timestamp:  <unix seconds>
    X-PH-Replay:     md5( str(timestamp) + case )                (placeholder -> 400 bad_request)

Token algorithm was recovered from the two accepted requests in the logs:
    ts=1784174547 -> 9f4f5119b01a68bff0d5d70907aac2bc
    ts=1784176226 -> 569d1d314a68462efa1ea0c2f1b5fdd9
Both equal md5(str(ts) + "08-alder-7f3c"), so a fresh, valid token can be
generated for any timestamp (the live server wants a current one).

The live "haunted" server is the apex host https://puzzledhackers.org (NOT the
ctf. scoreboard subdomain, and NOT the puzzledhackers.com / puzzled-hacker.com
decoy). No auth cookie is needed against the apex.

Usage:
    # Just print the headers + an equivalent curl command (no network):
    python3 solve.py --print

    # Actually send it to the default target and show the response:
    python3 solve.py --send

    # Point at a different host / challenge (reusable for future puzzles):
    python3 solve.py --send --base-url https://example.org \\
        --path /challenges/2026/09 --case 09-birch-1a2b --etag '"audit-XXXX-2026"'

    # Pin a specific timestamp (e.g. to exactly replay a log entry):
    python3 solve.py --send --timestamp 1784176226
"""
import argparse
import hashlib
import time
import sys
import shlex

# Defaults for this puzzle (all overridable via CLI so the tool is reusable).
DEFAULT_BASE_URL = "https://puzzledhackers.org"
DEFAULT_PATH = "/challenges/2026/08"
DEFAULT_CASE = "08-alder-7f3c"
DEFAULT_ACCEPT = "application/vnd.puzzledhackers.audit+json"
DEFAULT_ETAG = '"audit-a17f-2026"'
DEFAULT_USER_AGENT = "PH-Replay/0.8"


def replay_token(timestamp: int, case: str) -> str:
    """x-ph-replay = md5( <timestamp> + <case> ), recovered from the logs."""
    return hashlib.md5(f"{timestamp}{case}".encode()).hexdigest()


def build_headers(timestamp, case, accept, etag, user_agent,
                  cookie=None, extra=None) -> dict:
    headers = {
        "Accept": accept,
        "If-None-Match": etag,
        "User-Agent": user_agent,
        "X-PH-Case": case,
        "X-PH-Timestamp": str(timestamp),
        "X-PH-Replay": replay_token(timestamp, case),
    }
    if cookie:
        headers["Cookie"] = cookie
    for kv in (extra or []):
        if ":" in kv:
            k, v = kv.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def curl_command(url: str, headers: dict, insecure: bool = False) -> str:
    parts = ["curl", "-sS", "-i"]
    if insecure:
        parts.append("-k")
    for k, v in headers.items():
        parts += ["-H", f"{k}: {v}"]
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


def send(url: str, headers: dict, insecure: bool = False):
    if insecure:
        print("# WARNING: TLS verification DISABLED (--insecure).")
    try:
        import requests
        if insecure:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = requests.get(url, headers=headers, timeout=15, verify=not insecure,
                         allow_redirects=False)
        print(f"HTTP {r.status_code}")
        for k, v in r.headers.items():
            print(f"{k}: {v}")
        print()
        print(r.text)
        if r.status_code in (301, 302, 303, 307, 308) and "login" in r.headers.get("location", ""):
            print("\n# NOTE: redirected to login -> wrong host (this is the scoreboard, "
                  "not the target) or a missing/expired --cookie.")
        return
    except ImportError:
        pass
    # urllib fallback (no 'requests' installed)
    import urllib.request
    import urllib.error
    import ssl
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            print(f"HTTP {resp.status}")
            print(resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}")
        print(e.read().decode(errors="replace"))


def main():
    ap = argparse.ArgumentParser(description="Phantom Headers solver")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL,
                    help=f"Target base URL (default: {DEFAULT_BASE_URL})")
    ap.add_argument("--path", default=DEFAULT_PATH,
                    help=f"Request path (default: {DEFAULT_PATH})")
    ap.add_argument("--case", default=DEFAULT_CASE,
                    help=f"X-PH-Case value (default: {DEFAULT_CASE})")
    ap.add_argument("--accept", default=DEFAULT_ACCEPT,
                    help="Accept header value")
    ap.add_argument("--etag", default=DEFAULT_ETAG,
                    help="If-None-Match value (include the quotes)")
    ap.add_argument("--user-agent", default=DEFAULT_USER_AGENT,
                    help="User-Agent value")
    ap.add_argument("--timestamp", type=int, default=None,
                    help="Unix timestamp to use (default: now)")
    ap.add_argument("--print", dest="do_print", action="store_true",
                    help="Print headers + curl command")
    ap.add_argument("--send", action="store_true", help="Send the request")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="Skip TLS verification (not needed for puzzledhackers.org)")
    ap.add_argument("--cookie", default=None,
                    help='Session cookie string, e.g. "session=abc123" '
                         "(only needed for authenticated hosts)")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help='Extra header "Key: Value" (repeatable)')
    args = ap.parse_args()

    ts = args.timestamp if args.timestamp is not None else int(time.time())
    headers = build_headers(ts, args.case, args.accept, args.etag,
                            args.user_agent, cookie=args.cookie, extra=args.header)
    url = args.base_url.rstrip("/") + args.path

    print(f"# Reconstructed phantom request  ->  GET {args.path}")
    print(f"# target    = {url}")
    print(f"# timestamp = {ts}")
    for k, v in headers.items():
        print(f"{k}: {v}")
    print()

    print("# Equivalent curl:")
    print(curl_command(url, headers, insecure=args.insecure))
    print()

    if args.send:
        print("# --- server response ---")
        send(url, headers, insecure=args.insecure)


if __name__ == "__main__":
    main()
