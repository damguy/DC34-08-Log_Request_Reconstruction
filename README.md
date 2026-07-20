# Phantom Headers — DefCon CTF (Puzzle 08 / "08_Logs")

A log-forensics / request-reconstruction challenge themed around a Scooby-Doo
"haunted web server." A phantom visitor hit the exact same URL everyone else
did, but by sending a very specific set of HTTP headers it triggered a hidden
"trapdoor" and walked away with a secret response. The goal is to **rebuild that
one request from the logs alone** — no scanning or brute forcing — and replay it
against the live server to reveal the flag.

## Files

| File | Description |
| --- | --- |
| `clue1.txt`, `clue2.txt` | Story clues ("Phantom Headers", "recreate their exact footsteps"). |
| `logs/README.txt` | In-universe case file: correlate the logs by Request ID. |
| `logs/edge_access.log` | Edge/proxy access log: method, path, status, content-type, UA, `req=` id. |
| `logs/header_capture.log` | Captured request headers per `req=` id. |
| `logs/app_events.log` | Application verdicts per `req=` id (`outcome`, `error`, `response`). |
| `solve.py` | The tool we built: reconstructs and (optionally) sends the request. |

## The key insight

All three logs share a common **Request ID** (`req=req_xxxxxxxx`). Joining on it
lets you reconstruct any single visit completely: what was requested (edge), what
headers were sent (header capture), and how the app judged it (app events).

The overwhelming majority of traffic is noise designed to mislead:

- Normal browsers/`curl` → `event=challenge_page outcome=public_html` (the "boring wall").
- A `gobuster` scanner → `event=path_probe outcome=ignored` (a deliberate nudge
  *away* from scanning — the hint explicitly says brute forcing/scanning is not needed).

The signal is a handful of requests from user-agent **`PH-Replay`** (the phantom).
One earlier request is the legitimate `system_audit` (`outcome=success`), and the
phantom then makes a series of `replay_check` attempts, fixing one header at a time
until the app returns `outcome=accepted response=alternate_archive`.

## How the request was reverse-engineered

Each rejected attempt maps a status code / error to exactly which header was wrong.
Diffing the failures against the single accepted request yields the full recipe:

| Symptom in logs | Meaning | Correct value |
| --- | --- | --- |
| `406 media_mismatch` | wrong `Accept` | `Accept: application/vnd.puzzledhackers.audit+json` |
| `412 precondition_failed` | wrong `If-None-Match` (had `...-2025`) | `If-None-Match: "audit-a17f-2026"` |
| `426 upgrade_required` | client too old (`PH-Replay/0.7`) | `User-Agent: PH-Replay/0.8` |
| `400 bad_request` | placeholder replay token | a **valid** `X-PH-Replay` token |
| `public_html` instead of secret | wrong case selector (`...-7f3d`) | `X-PH-Case: 08-alder-7f3c` |

### The one non-obvious part: the replay token

The two *accepted* requests use **different** timestamps and **different**
`X-PH-Replay` values, which means the token is derived from the timestamp rather
than being static. Recovering the algorithm from the two known-good pairs shows:

```
X-PH-Replay = md5( str(X-PH-Timestamp) + X-PH-Case )
```

Because it is deterministic, we can mint a fresh, valid token for the *current*
time — so the whole thing works in a **single** request, with no guessing and no
retry loop (which also stays clear of any replay/lockout monitoring).

## The other trap: which host is the real one

A big part of this puzzle was resolving host confusion. The logs contain the path
(`/challenges/2026/08`) but no hostname, and there are several look-alike hosts:

- **`puzzledhackers.com` → `puzzled-hacker.com`** — a decoy. Expired/mismatched
  TLS cert, unrelated app, 404s the path. A rabbit hole.
- **`ctf.puzzledhackers.org`** — the **scoreboard/platform** (SvelteKit, behind a
  login). This is where you *submit* the flag, but it ignores the `X-PH-*` headers
  and just serves the normal challenge page.
- **`puzzledhackers.org`** (apex) — the actual **"haunted" server** from the logs.
  A plain request there returns `406 application/json` with `Vary: Accept` — the
  exact `media_mismatch` behavior seen in the logs — and the fully reconstructed
  request returns `200` with the audit JSON containing the flag. No auth needed.

## The tool: `solve.py`

`solve.py` reconstructs the request, computes a fresh valid token, prints an
equivalent `curl` one-liner, and can send it and show the response. All the
challenge-specific values are CLI flags so it is reusable for similar puzzles.

```bash
# Print headers + curl only (no network):
python3 solve.py --print

# Send to the default target (puzzledhackers.org) and show the response:
python3 solve.py --send

# Reuse for a future/altered challenge:
python3 solve.py --send \
  --base-url https://example.org \
  --path /challenges/2026/09 \
  --case 09-birch-1a2b \
  --etag '"audit-XXXX-2026"'
```

Useful flags:

- `--timestamp N` — pin a specific unix timestamp (e.g. to replay an exact log entry).
- `--cookie "session=..."` — attach a session cookie for authenticated hosts.
- `-H "Key: Value"` — add arbitrary extra headers (repeatable).
- `-k/--insecure` — skip TLS verification (not needed for the apex host).

## Solution workflow (summary)

1. Join `edge_access.log`, `header_capture.log`, and `app_events.log` on `req=`.
2. Filter out the noise (`public_html`, `path_probe`); isolate the `PH-Replay` requests.
3. Diff the rejected `replay_check` attempts against the one accepted request to
   determine every required header.
4. Recover the token formula `md5(timestamp + case)` from the accepted pairs.
5. Identify the real target host (apex `puzzledhackers.org`, not the decoy `.com`
   and not the `ctf.` scoreboard).
6. Send the reconstructed request with a fresh timestamp/token → the response body
   contains the flag (format `PH{...}`).
7. Submit the flag via the form on the `ctf.puzzledhackers.org` challenge page.

*The flag itself is intentionally omitted from this document.*
