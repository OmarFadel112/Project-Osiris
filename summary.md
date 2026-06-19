"""
osiris.py  v2.1
USAGE
─────
  python3 password_strength.py -p <PASSWORD> [-v] [-o]

  -p / --password  PASSWORD   Password string to evaluate (required).
  -v / --verbose              Full per-criterion breakdown.
  -o / --offline              Skip HIBP; use only the bundled local corpus.

HOW THE HIBP K-ANONYMITY CHECK WORKS
─────────────────────────────────────
  The password is NEVER sent over the network. The privacy model works as follows:

    Step 1:  SHA-1 hash the password locally.
             sha1("Tr0ub4dor&3") → "35B9CDB8E3C3C22EB7FDB6F23D7B3B3A6D6E2F0A"  (example)

    Step 2:  Send only the first 5 hex characters (the "prefix") to the HIBP API.
             GET https://api.pwnedpasswords.com/range/35B9C

    Step 3:  The API returns every SHA-1 suffix (position 6–40) that starts with
             that prefix, along with breach record counts. Thousands of different
             passwords share the same 5-char prefix — your query is anonymous.

    Step 4:  Search the response locally for your suffix ("DB8E3C3C22...").
             The full hash — and the plaintext — never leave this process.

  This is the same model used by Firefox Monitor, 1Password, and browsers worldwide.

  Add-Padding header:
    The request includes "Add-Padding: true", which instructs the HIBP API to pad
    every response to a uniform size.  Without padding, response length could leak
    how "popular" a prefix bucket is, providing a weak statistical side-channel.

EXIT CODES  (SOC / Orchestration Contract)
──────────────────────────────────────────
  0   STRONG   — All criteria passed. Safe to allow.
  1   WEAK / MEDIUM — Rejected. Block and alert.

SCORING RUBRIC
──────────────
  ⚠ Gatekeeper Rule: length < 8 → Score 0, WEAK, immediate return.

  If length ≥ 8, each criterion awards +1 point (max 5):
    1. Uppercase letter  [Unicode Lu]
    2. Lowercase letter  [Unicode Ll]
    3. Digit             [Unicode Nd]
    4. Symbol            [non-alnum, non-whitespace]
    5. Length ≥ 16 chars [entropy bonus]

  Score 0–1 → WEAK   (exit 1)
  Score 2–3 → MEDIUM (exit 1)
  Score 4+  → STRONG (exit 0) — requires NOT in leaked corpus (HIBP or local)

DEPLOYMENT — COMPILING TO A STANDALONE EXECUTABLE (PyInstaller)
════════════════════════════════════════════════════════════════

  Prerequisites:
    pip install pyinstaller>=6.0

  Production-hardened build — Linux / macOS:
    pyinstaller \
        --onefile          \
        --name psc         \
        --clean            \
        --strip            \
        --log-level WARN   \
        password_strength.py

  Production-hardened build — Windows (PowerShell):
    pyinstaller `
        --onefile        `
        --name psc       `
        --clean          `
        --strip          `
        --log-level WARN `
        password_strength.py

  Output:  dist/psc  (Linux/macOS)  or  dist\\psc.exe  (Windows)

  Post-build smoke tests:
    ./dist/psc -p "Tr0ub4dor&3"       # → [STRONG]  exit 0
    ./dist/psc -p "password"           # → [WEAK]    exit 1  (HIBP: millions of hits)
    ./dist/psc -p "Tr0ub4dor&3" -v    # → [STRONG] + full breakdown + HIBP status
    ./dist/psc -p "Tr0ub4dor&3" -o    # → offline mode, local corpus only

  n8n / Wazuh integration: unchanged — key on exit code 0/1.

SECURITY NOTES
──────────────
  ⚠ CLI EXPOSURE: --password values appear in process listings (ps aux). For
    higher-assurance environments use an environment variable:
        PSC_PASSWORD="MyP@ss" ./psc -p "$PSC_PASSWORD"
  ⚠ NETWORK: HIBP requests go to api.pwnedpasswords.com (Cloudflare-hosted, TLS 1.3).
    Use --offline in air-gapped SOC environments.
  ⚠ MEMORY: Python strings are immutable but not securely zeroed. See class docstring.

Python Compatibility : 3.8+
External Dependencies: None  (stdlib only — hashlib, hmac, urllib, argparse, sys)
"""