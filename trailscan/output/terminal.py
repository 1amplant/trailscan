from __future__ import annotations

import sys

from trailscan.engine.models import Finding, Status, Severity

# ── ANSI colour codes ──────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"

BG_RED   = "\033[41m"
BG_GREEN = "\033[42m"

# ── Safe print (handles Windows cp1252 terminals) ──────────────────────────────

def _print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


# ── Helpers ────────────────────────────────────────────────────────────────────

def _status_color(status: str) -> str:
    return {
        Status.PASS:  GREEN,
        Status.FAIL:  RED,
        Status.WARN:  YELLOW,
        Status.ERROR: MAGENTA,
    }.get(status, WHITE)


def _severity_color(severity: str) -> str:
    return {
        Severity.CRITICAL: RED + BOLD,
        Severity.HIGH:     RED,
        Severity.MEDIUM:   YELLOW,
        Severity.LOW:      CYAN,
        Severity.INFO:     DIM,
    }.get(severity, WHITE)


def _status_icon(status: str) -> str:
    return {
        Status.PASS:  "PASS",
        Status.FAIL:  "FAIL",
        Status.WARN:  "WARN",
        Status.ERROR: "ERR ",
    }.get(status, "?   ")


# ── Public API ─────────────────────────────────────────────────────────────────

def print_findings(findings: list[Finding], verbose: bool = False) -> None:
    """Print all findings grouped by service, coloured by status."""
    if not findings:
        _print(f"{DIM}No findings to display.{RESET}")
        return

    # Group by service prefix (e.g. "iam", "s3", "cloudtrail")
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        service = f.check_id.split(".")[0].upper()
        groups.setdefault(service, []).append(f)

    for service, svc_findings in sorted(groups.items()):
        _print(f"\n{BOLD}{CYAN}-- {service} {'-' * (50 - len(service))}{RESET}")
        for f in svc_findings:
            sc = _status_color(f.status)
            icon = _status_icon(f.status)
            sev_c = _severity_color(f.severity)
            sev_label = f"[{f.severity.upper()}]"

            _print(f"  {sc}{BOLD}[{icon}]{RESET}  {f.title}")
            _print(f"         {DIM}check:{RESET} {f.check_id}   "
                   f"{DIM}control:{RESET} {f.control_id}   "
                   f"{sev_c}{sev_label}{RESET}")
            _print(f"         {DIM}resource:{RESET} {f.resource_arn}")

            if f.status == Status.FAIL and f.remediation:
                _print(f"         {YELLOW}>> {f.remediation}{RESET}")

            if verbose and f.evidence:
                _print(f"         {DIM}evidence: {f.evidence}{RESET}")

            _print("")


def print_score(score: dict) -> None:
    """Print the readiness score banner."""
    pct = score["score_pct"]
    passed  = score["passed"]
    failed  = score["failed"]
    warned  = score["warned"]
    errored = score["errored"]
    total   = score["total"]

    if pct >= 80:
        bar_color = GREEN
        label = "READY"
    elif pct >= 50:
        bar_color = YELLOW
        label = "PARTIAL"
    else:
        bar_color = RED
        label = "AT RISK"

    bar_len = 40
    filled  = round(bar_len * pct / 100)
    bar     = "#" * filled + "." * (bar_len - filled)

    _print("")
    _print(f"{BOLD}{'=' * 56}{RESET}")
    _print(f"{BOLD}  SOC 2 AWS Readiness Score{RESET}")
    _print(f"{'-' * 56}")
    _print(f"  {bar_color}{BOLD}{bar}  {pct}%  {label}{RESET}")
    _print(f"{'-' * 56}")
    _print(f"  {GREEN}PASS: {passed:<4}{RESET}  "
           f"{RED}FAIL: {failed:<4}{RESET}  "
           f"{YELLOW}WARN: {warned:<4}{RESET}  "
           f"{MAGENTA}ERR: {errored}{RESET}")
    _print(f"  {DIM}Total checks evaluated: {total}{RESET}")
    _print(f"{BOLD}{'=' * 56}{RESET}")
    _print("")

    if errored > 0 and passed == 0 and failed == 0:
        _print(f"{MAGENTA}All checks returned errors -- likely a permissions issue.{RESET}")
        _print(f"{DIM}Ensure the IAM user has ReadOnlyAccess or the trailscan minimum policy.{RESET}")
        _print(f"{DIM}Run with --verbose to see error details per check.{RESET}")
    elif failed > 0:
        _print(f"{YELLOW}Run with --verbose to see full remediation steps.{RESET}")
        _print("")
        _print(f"{BOLD}  Fix these findings faster with TrailProof:{RESET}")
        _print(f"  {CYAN}-> Continuous monitoring    {RESET}never miss a new misconfiguration")
        _print(f"  {CYAN}-> Audit-ready PDF reports  {RESET}hand to your auditor in one click")
        _print(f"  {CYAN}-> Multi-source evidence    {RESET}AWS, GitHub, Okta, Google Workspace")
        _print(f"  {CYAN}-> Policy templates         {RESET}access control, incident response & more")
        _print("")
        _print(f"  {BOLD}{CYAN}https://trailproof.app{RESET}  {DIM}-- free trial, no credit card{RESET}")
    else:
        _print(f"{GREEN}{BOLD}All checks passed!{RESET}")
        _print("")
        _print(f"{BOLD}  Keep it that way with TrailProof:{RESET}")
        _print(f"  {CYAN}-> Get alerted the moment something regresses{RESET}")
        _print(f"  {CYAN}-> Historical evidence for your auditor{RESET}")
        _print(f"  {CYAN}-> Covers GitHub, Okta, Google Workspace too{RESET}")
        _print("")
        _print(f"  {BOLD}{CYAN}https://trailproof.app{RESET}  {DIM}-- free trial, no credit card{RESET}")
    _print("")


def print_header(profile: str | None, region: str | None) -> None:
    """Print the scan header."""
    from trailscan import __version__
    profile_str = profile or "default"
    region_str  = region  or "session default"
    _print(f"\n{BOLD}{CYAN}trailscan v{__version__}{RESET}  {DIM}-- SOC 2 AWS readiness scanner{RESET}")
    _print(f"{DIM}Profile: {profile_str}   Region: {region_str}{RESET}")
    _print(f"{DIM}Continuous monitoring + audit reports -> {RESET}{CYAN}https://trailproof.app{RESET}")
    _print(f"{DIM}{'-' * 56}{RESET}\n")
