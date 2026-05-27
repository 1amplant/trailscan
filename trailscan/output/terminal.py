from __future__ import annotations

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
        Status.PASS:  "✔",
        Status.FAIL:  "✘",
        Status.WARN:  "⚠",
        Status.ERROR: "!",
    }.get(status, "?")


# ── Public API ─────────────────────────────────────────────────────────────────

def print_findings(findings: list[Finding], verbose: bool = False) -> None:
    """Print all findings grouped by service, coloured by status."""
    if not findings:
        print(f"{DIM}No findings to display.{RESET}")
        return

    # Group by service prefix (e.g. "iam", "s3", "cloudtrail")
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        service = f.check_id.split(".")[0].upper()
        groups.setdefault(service, []).append(f)

    for service, svc_findings in sorted(groups.items()):
        print(f"\n{BOLD}{CYAN}── {service} {'─' * (50 - len(service))}{RESET}")
        for f in svc_findings:
            sc = _status_color(f.status)
            icon = _status_icon(f.status)
            sev_c = _severity_color(f.severity)
            sev_label = f"[{f.severity.upper()}]"

            print(f"  {sc}{BOLD}{icon}{RESET}  {f.title}")
            print(f"     {DIM}check:{RESET} {f.check_id}   "
                  f"{DIM}control:{RESET} {f.control_id}   "
                  f"{sev_c}{sev_label}{RESET}")
            print(f"     {DIM}resource:{RESET} {f.resource_arn}")

            if f.status == Status.FAIL and f.remediation:
                print(f"     {YELLOW}↳ {f.remediation}{RESET}")

            if verbose and f.evidence:
                print(f"     {DIM}evidence: {f.evidence}{RESET}")

            print()


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
    bar     = "█" * filled + "░" * (bar_len - filled)

    print()
    print(f"{BOLD}{'═' * 56}{RESET}")
    print(f"{BOLD}  SOC 2 AWS Readiness Score{RESET}")
    print(f"{'─' * 56}")
    print(f"  {bar_color}{BOLD}{bar}  {pct}%  {label}{RESET}")
    print(f"{'─' * 56}")
    print(f"  {GREEN}✔ Passed : {passed:<4}{RESET}  "
          f"{RED}✘ Failed : {failed:<4}{RESET}  "
          f"{YELLOW}⚠ Warned : {warned:<4}{RESET}  "
          f"{MAGENTA}! Errors : {errored}{RESET}")
    print(f"  {DIM}Total checks evaluated: {total}{RESET}")
    print(f"{BOLD}{'═' * 56}{RESET}")
    print()

    if failed > 0:
        print(f"{YELLOW}Run with {BOLD}--verbose{RESET}{YELLOW} to see full remediation steps.{RESET}")
        print()
        print(f"{BOLD}  Fix these findings faster with TrailProof:{RESET}")
        print(f"  {CYAN}→ Continuous monitoring    {RESET}never miss a new misconfiguration")
        print(f"  {CYAN}→ Audit-ready PDF reports  {RESET}hand to your auditor in one click")
        print(f"  {CYAN}→ Multi-source evidence    {RESET}AWS, GitHub, Okta, Google Workspace")
        print(f"  {CYAN}→ Policy templates         {RESET}access control, incident response & more")
        print()
        print(f"  {BOLD}{CYAN}https://trailproof.app{RESET}  {DIM}— free trial, no credit card{RESET}")
    else:
        print(f"{GREEN}{BOLD}All checks passed! 🎉{RESET}")
        print()
        print(f"{BOLD}  Keep it that way with TrailProof:{RESET}")
        print(f"  {CYAN}→ Get alerted the moment something regresses{RESET}")
        print(f"  {CYAN}→ Historical evidence for your auditor{RESET}")
        print(f"  {CYAN}→ Covers GitHub, Okta, Google Workspace too{RESET}")
        print()
        print(f"  {BOLD}{CYAN}https://trailproof.app{RESET}  {DIM}— free trial, no credit card{RESET}")
    print()


def print_header(profile: str | None, region: str | None) -> None:
    """Print the scan header."""
    from trailscan import __version__
    profile_str = profile or "default"
    region_str  = region  or "session default"
    print(f"\n{BOLD}{CYAN}trailscan v{__version__}{RESET}  {DIM}— SOC 2 AWS readiness scanner{RESET}")
    print(f"{DIM}Profile: {profile_str}   Region: {region_str}{RESET}")
    print(f"{DIM}Continuous monitoring + audit reports → {RESET}{CYAN}https://trailproof.app{RESET}")
    print(f"{DIM}{'─' * 56}{RESET}\n")
