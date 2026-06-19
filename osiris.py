

from __future__ import annotations  # PEP 563 — deferred annotation eval (Python 3.7+)

__version__ = "2.1.0"

import argparse
import hashlib
import hmac
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  § 1 — Data Contracts
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class StrengthLevel(str, Enum):
    """
    Ordered strength classification.
    Inherits from `str` for transparent JSON serialization (no custom encoder needed).
    """
    WEAK   = "Weak"
    MEDIUM = "Medium"
    STRONG = "Strong"


@dataclass(frozen=True)
class HIBPResult:
    """
    Result from a single HaveIBeenPwned k-anonymity API query.
    Kept separate from StrengthReport so callers can inspect network status
    independently of the final strength classification.
    """
    available:    bool   # True if the HIBP API responded (False = network error/timeout)
    is_leaked:    bool   # True if the password was found in the HIBP database
    breach_count: int    # Times seen across all breach records (0 if not found or unavailable)


@dataclass(frozen=True)
class StrengthReport:
    """
    Immutable, audit-ready result object.

    `frozen=True` — prevents post-creation mutation; safe to cache, log, or pass
    to message queues and SIEM ingest pipelines without defensive copying.

    `tuple` for check collections — immutable, consistent with the frozen contract.

    `breach_count` — populated from HIBP when online; 0 when offline or not found.
    A count > 0 gives operators precise threat context: a password seen 40M times
    is categorically more dangerous than one seen 12 times.

    `hibp_checked` — True if the HIBP API responded successfully for this check.
    Allows the verbose layer to label the leak source accurately without guessing.
      hibp_checked=True,  is_leaked=True   → found in HIBP (count in breach_count)
      hibp_checked=True,  is_leaked=False  → HIBP confirms clean (900 M+ records)
      hibp_checked=False, is_leaked=True   → found in local corpus (HIBP unavailable)
      hibp_checked=False, is_leaked=False  → local corpus clean; HIBP not queried
    """
    level:         StrengthLevel
    score:         int                # Range: [0, 5]
    passed_checks: tuple[str, ...]
    failed_checks: tuple[str, ...]
    is_leaked:     bool
    breach_count:  int  = 0           # HIBP breach record count; 0 = unknown / not found
    hibp_checked:  bool = False       # True only if HIBP API responded successfully

    def is_acceptable(self) -> bool:
        """
        Zero-Trust enforcement predicate.
        True ONLY for STRONG, non-leaked passwords.
        MEDIUM is intentionally rejected — partial compliance is not acceptable.
        Maps to: True → sys.exit(0),  False → sys.exit(1).
        """
        return self.level == StrengthLevel.STRONG

    def __str__(self) -> str:
        if self.is_leaked:
            if self.breach_count > 0:
                leak_tag = f"  ⚠ [LEAKED — {self.breach_count:,} breach records]"
            else:
                leak_tag = "  ⚠ [IN LEAKED CORPUS]"
        else:
            leak_tag = ""

        bar       = "█" * self.score + "░" * (5 - self.score)
        gate_text = "✅ PASS  (exit 0)" if self.is_acceptable() else "🚫 BLOCK (exit 1)"
        return (
            f"  Strength : {self.level.value.upper()}{leak_tag}\n"
            f"  Score    : [{bar}] {self.score}/5\n"
            f"  Gate     : {gate_text}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  § 2 — Local Leaked Corpus  (Offline Fallback)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Used as an automatic fallback when the HIBP API is unreachable, and as
# the sole source in --offline mode.
#
# frozenset properties:
#   • O(1) average-case lookup  •  Immutable at runtime  •  Thread-safe reads
_DEFAULT_LEAKED_CORPUS: frozenset[str] = frozenset({
    "password",  "123456",     "password123", "admin",      "letmein",
    "qwerty",    "abc123",     "monkey",      "1234567890", "trustno1",
    "iloveyou",  "adobe123",   "sunshine",    "princess",   "welcome",
    "shadow",    "superman",   "michael",     "master",     "dragon",
    "passw0rd",  "123456789",  "football",    "baseball",   "welcome1",
})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  § 3 — HaveIBeenPwned K-Anonymity Checker
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class HIBPChecker:


    _API_BASE: str = "https://api.pwnedpasswords.com/range/"
    _TIMEOUT:  int = 5   # seconds — balances responsiveness vs slow CDN pops

    def query(self, password: str) -> HIBPResult:

        # ── Step 1: Compute SHA-1 hash locally ───────────────────────────────
        # hexdigest().upper() produces the 40-char uppercase hex string that
        # HIBP uses as its canonical hash format.
        sha1_hex: str = hashlib.sha1(
            password.encode("utf-8"),
            usedforsecurity=False,   # SHA-1 here is identity lookup, not MAC/sig
        ).hexdigest().upper()

        prefix: str = sha1_hex[:5]   # transmitted to API (k-anonymity prefix)
        suffix: str = sha1_hex[5:]   # searched locally  (never leaves this process)

        # ── Step 2: Fetch the prefix range from HIBP ─────────────────────────
        range_body: str | None = self._fetch_range(prefix)
        if range_body is None:
            # API unavailable — caller will fall back to local corpus
            return HIBPResult(available=False, is_leaked=False, breach_count=0)

        # ── Step 3: Search response for target suffix (constant-time) ────────
        # Response format (one entry per line):
        #   <35-CHAR-SUFFIX-UPPERCASE>:<BREACH-COUNT>\r\n
        #   e.g.  "1E4C9B93F3F0682250B6CF8331B7EE68FD8:2161965\r\n"
        #
        # Padded entries have a count of 0 and are ignored for breach assessment
        # but still processed through hmac.compare_digest() — we must not skip
        # lines early based on count, as that reintroduces a timing side-channel.
        suffix_bytes: bytes = suffix.encode("utf-8")

        for line in range_body.splitlines():
            if ":" not in line:
                continue  # malformed line — skip safely

            response_suffix, _, count_str = line.partition(":")

            # Constant-time comparison — see class docstring for rationale
            if hmac.compare_digest(suffix_bytes, response_suffix.strip().encode("utf-8")):
                try:
                    count = int(count_str.strip())
                except ValueError:
                    count = 0   # malformed count field — still a confirmed match
                return HIBPResult(available=True, is_leaked=True, breach_count=count)

        # Suffix not found in response — password not in HIBP database
        return HIBPResult(available=True, is_leaked=False, breach_count=0)

    def _fetch_range(self, prefix: str) -> str | None:
        """
        HTTP GET the HIBP range endpoint for `prefix`.
        Returns the decoded response body, or None on any error.

        Security headers sent:
          Add-Padding: true  — uniform response size (prevents length side-channel)
          User-Agent         — identifies the tool to HIBP for rate-limit fairness

        TLS note: urllib.request uses Python's ssl module, which defaults to
        ssl.create_default_context() — verifies the server certificate against
        the system trust store and enforces TLS 1.2+ minimum.
        """
        url = f"{self._API_BASE}{prefix}"
        req = urllib.request.Request(
            url,
            headers={
                "Add-Padding": "true",
                "User-Agent":  f"password-strength-checker/{__version__}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._TIMEOUT) as response:
                return response.read().decode("utf-8")

        except urllib.error.HTTPError as exc:
            # 4xx/5xx from the API — treat as unavailable, not as "not found"
            _ = exc   # suppress unused-variable warning; error is swallowed by design
            return None

        except (urllib.error.URLError, OSError, TimeoutError):
            # DNS failure, connection refused, socket timeout, etc.
            return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  § 4 — Core Checker
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PasswordStrengthChecker:


    _MIN_LENGTH:       int = 8
    _BONUS_LENGTH:     int = 16
    _MAX_SCORE:        int = 5
    _STRONG_THRESHOLD: int = 4
    _MEDIUM_THRESHOLD: int = 2

    def __init__(
        self,
        leaked_corpus: frozenset[str]  = _DEFAULT_LEAKED_CORPUS,
        hibp_checker:  HIBPChecker | None = None,
    ) -> None:
        """
        Parameters
        ──────────
        leaked_corpus : frozenset[str]
            Local fallback corpus.  Pre-encoded to bytes at construction time
            so hmac.compare_digest() cost is paid once, not per check() call.
        hibp_checker : HIBPChecker | None
            When provided, HIBP is queried first; local corpus is the fallback.
            When None, only the local corpus is used (offline / library mode).
        """
        self._hibp: HIBPChecker | None = hibp_checker

        # Pre-encode local corpus to bytes — O(corpus) once at init
        self._leaked_corpus_bytes: frozenset[bytes] = frozenset(
            entry.encode("utf-8") for entry in leaked_corpus
        )

    # ─── Public API ──────────────────────────────────────────────────────

    def check(self, password: str) -> StrengthReport:
        """
        Evaluate `password` and return an immutable StrengthReport.

        MEMORY NOTE: We never call .upper() / .lower() or build sub-strings from
        `password`. All predicates iterate the original reference to minimise
        O(n) heap copies of cleartext.
        """

        # ── GATE: Minimum Length (Brute-Force Mitigation) ────────────────────
        # < 8 chars → keyspace ≤ 95^7 ≈ 69 B combinations — trivially GPU-exhausted.
        # Score 0, WEAK, immediate return.  No further evaluation performed.
        if len(password) < self._MIN_LENGTH:
            return StrengthReport(
                level         = StrengthLevel.WEAK,
                score         = 0,
                passed_checks = (),
                failed_checks = (
                    f"Length {len(password)} < {self._MIN_LENGTH} — "
                    "immediate fail (brute-force keyspace collapse)",
                ),
                is_leaked    = False,
                breach_count = 0,
            )

        passed: list[str] = []
        failed: list[str] = []

        # ── Leaked Credential Check ───────────────────────────────────────────
        # Delegates to HIBP (with local corpus fallback) or local corpus only.
        # See _check_leaked() for the full priority chain and security rationale.
        is_leaked, breach_count, hibp_checked = self._check_leaked(password)
        if is_leaked:
            bc_str = f" — {breach_count:,} breach records" if breach_count > 0 else ""
            failed.append(
                f"Found in leaked credentials corpus{bc_str} — "
                "reject regardless of compositional strength"
            )

        # ── Character Class Checks (Unicode-Aware, O(n), Short-Circuiting) ───
        #
        # any(predicate(c) for c in password):
        #   • Lazy generator — stops at first qualifying character (best-case O(1))
        #   • C-level Unicode predicate — no Python loop overhead
        #
        # Unicode coverage (UCD 15.1, 143,859 code points):
        #   .isupper()              → Lu  — A, Ñ, Ω, Д, ...
        #   .islower()              → Ll  — a, ñ, ω, д, ...
        #   .isdigit()              → Nd  — 0–9, ٣ (Arabic-Indic), ३ (Devanagari), ...
        #   ¬(.isalnum()|.isspace())→ Symbols — !, @, €, ★, 🔑, ¥, ∞, ...
        _char_checks: list[tuple[bool, str]] = [
            (
                any(c.isupper() for c in password),
                "Uppercase letter [Unicode Lu — A–Z and beyond]",
            ),
            (
                any(c.islower() for c in password),
                "Lowercase letter [Unicode Ll — a–z and beyond]",
            ),
            (
                any(c.isdigit() for c in password),
                "Digit [Unicode Nd — 0–9, Arabic-Indic, Devanagari numerals]",
            ),
            (
                any(not c.isalnum() and not c.isspace() for c in password),
                "Symbol / special character [Unicode-aware — punctuation, emoji, currency]",
            ),
            (
                len(password) >= self._BONUS_LENGTH,
                f"Length ≥ {self._BONUS_LENGTH} chars [entropy bonus]",
            ),
        ]

        for result, label in _char_checks:
            (passed if result else failed).append(label)

        score: int = len(passed)

        if is_leaked:
            level = StrengthLevel.WEAK
        elif score >= self._STRONG_THRESHOLD:
            level = StrengthLevel.STRONG
        elif score >= self._MEDIUM_THRESHOLD:
            level = StrengthLevel.MEDIUM
        else:
            level = StrengthLevel.WEAK

        return StrengthReport(
            level         = level,
            score         = score,
            passed_checks = tuple(passed),
            failed_checks = tuple(failed),
            is_leaked     = is_leaked,
            breach_count  = breach_count,
            hibp_checked  = hibp_checked,
        )

    # ─── Private Helpers ─────────────────────────────────────────────────

    def _check_leaked(self, password: str) -> tuple[bool, int, bool]:
        """
        Tiered leak detection with automatic fallback.

        Priority chain:
          1. HIBPChecker (online, 900 M+ records) — if hibp_checker is set
             └─ If HIBP API available  → return its result (authoritative)
             └─ If HIBP unavailable    → fall through to local corpus
          2. Local corpus (offline, ~25 sample records)

        Returns:
          (is_leaked: bool, breach_count: int, hibp_checked: bool)
          hibp_checked is True only when HIBP responded — False means local corpus
          was the actual source of truth (either offline mode or network failure).
          breach_count is 0 for local corpus matches (count data unavailable).
        """
        if self._hibp is not None:
            result: HIBPResult = self._hibp.query(password)
            if result.available:
                # HIBP responded — its result is authoritative; skip local corpus.
                return result.is_leaked, result.breach_count, True
            # HIBP unreachable — fall through to local corpus (fail-open)

        return self._check_local_corpus(password), 0, False

    def _check_local_corpus(self, password: str) -> bool:

        password_bytes: bytes = password.encode("utf-8")
        return any(
            hmac.compare_digest(password_bytes, leaked_bytes)
            for leaked_bytes in self._leaked_corpus_bytes
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  § 5 — Convenience Functional API
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Offline singleton for library-mode imports — no network calls, no side effects.
# CLI mode creates its own checker instance with HIBPChecker attached.
_offline_checker: PasswordStrengthChecker = PasswordStrengthChecker()


def check_password(password: str) -> StrengthReport:
  
    return _offline_checker.check(password)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  § 6 — CLI Entry Point  (argparse + sys.exit)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psc",
        description=(
            f"Password Strength Checker v{__version__} — Zero-Trust & SOC Pipeline Edition\n"
            "Exits 0 for STRONG, 1 for WEAK or MEDIUM."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "EXIT CODES\n"
            "----------\n"
            "  0  STRONG       — All criteria passed. Allow.\n"
            "  1  WEAK/MEDIUM  — Criteria failed. Block / alert.\n"
            "\n"
            "EXAMPLES\n"
            "--------\n"
            '  psc -p "Tr0ub4dor&3"\n'
            '  psc -p "Tr0ub4dor&3" -v\n'
            '  psc -p "Tr0ub4dor&3" --offline\n'
            '  psc -p "$USER_PW" && create_account || reject_with_alert\n'
        ),
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        metavar="PASSWORD",
        help="Password string to evaluate. (required)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Print a full per-criterion breakdown of passed and failed checks.",
    )
    parser.add_argument(
        "-o", "--offline",
        action="store_true",
        default=False,
        help=(
            "Skip HIBP API; use only the bundled local corpus. "
            "Recommended for air-gapped SOC environments."
        ),
    )
    return parser


def _format_verbose_report(report: StrengthReport) -> str:
    """
    Render the human-readable verbose breakdown.
    Uses report.hibp_checked (ground truth) to label the leak source accurately.
    """
    lines: list[str] = ["\n  Criteria Breakdown:"]

    for check in report.passed_checks:
        lines.append(f"    ✅  {check}")
    for check in report.failed_checks:
        lines.append(f"    ❌  {check}")

    lines.append("")

    # ── Leak source — four deterministic cases from hibp_checked × is_leaked ──
    if report.is_leaked and report.hibp_checked:
        # HIBP API responded and confirmed this password is in its database
        lines.append(
            f"  ⚠  SOURCE  : HaveIBeenPwned API — "
            f"{report.breach_count:,} breach records (k-anonymity verified)"
        )
    elif report.is_leaked and not report.hibp_checked:
        # HIBP was unavailable or --offline; local corpus caught it instead
        lines.append(
            "  ⚠  SOURCE  : Local corpus (HIBP unavailable or --offline mode)"
        )
    elif not report.is_leaked and report.hibp_checked:
        # HIBP responded and found no match — strongest possible clean signal
        lines.append(
            "  ✅  HIBP    : Not found in 900 M+ breach records (k-anonymity checked)"
        )
    else:
        # --offline or HIBP unreachable; local corpus found no match
        lines.append(
            "  ✅  LOCAL   : Not found in local corpus "
            "(HIBP not queried — use online mode for full coverage)"
        )

    lines.append(f"  Score    : {report.score}/5")
    lines.append(f"  Strength : {report.level.value.upper()}")
    lines.append(
        f"  Action   : {'ALLOW  →  exit 0' if report.is_acceptable() else 'BLOCK  →  exit 1'}"
    )
    return "\n".join(lines)


def _run_cli() -> None:
    """
    CLI entry point.

    Output contract (primary line — always emitted, machine-parseable):
        [STRONG]                                  Score: 4/5
        [WEAK]    ⚠ LEAKED — 3,730,471 records    Score: 2/5
        [WEAK]    ⚠ IN LEAKED CORPUS              Score: 1/5

    Exit code is the authoritative machine-readable signal.
    Console output is supplementary — orchestration tools should key on
    exit code only, not stdout parsing.
    """
    parser = _build_parser()
    args   = parser.parse_args()

    # Build checker: HIBP-enabled by default; local-only when --offline
    hibp    = None if args.offline else HIBPChecker()
    checker = PasswordStrengthChecker(hibp_checker=hibp)
    report  = checker.check(args.password)

    # ── Primary output line (always emitted) ─────────────────────────────
    if report.is_leaked and report.breach_count > 0:
        leak_flag = f"  ⚠ LEAKED — {report.breach_count:,} records"
    elif report.is_leaked:
        leak_flag = "  ⚠ LEAKED"
    else:
        leak_flag = ""
    print(f"[{report.level.value.upper()}]{leak_flag}  Score: {report.score}/5")

    # ── Verbose breakdown (--verbose / -v only) ───────────────────────────
    if args.verbose:
        print(_format_verbose_report(report))

    # ── SOC Pipeline Exit Codes ───────────────────────────────────────────
    # 0 → STRONG  — allow downstream pipeline to continue
    # 1 → WEAK / MEDIUM — halt pipeline, trigger alert
    sys.exit(0 if report.is_acceptable() else 1)


if __name__ == "__main__":
    _run_cli()
