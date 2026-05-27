from __future__ import annotations

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError

from trailscan.engine.models import Finding, Status
from trailscan.checks import ALL_CHECKS


def _get_account_id(session: boto3.Session) -> str:
    try:
        sts = session.client("sts")
        return sts.get_caller_identity()["Account"]
    except (ClientError, Exception):
        return "unknown"


def run_checks(
    session: boto3.Session,
    check_ids: list[str] | None = None,
) -> list[Finding]:
    """
    Run all (or a filtered subset of) checks against the given boto3 session.

    Args:
        session:   A boto3.Session already configured with credentials/region.
        check_ids: Optional list of check IDs to run. If None, all checks run.

    Returns:
        A flat list of Finding objects.
    """
    account_id = _get_account_id(session)

    checks_to_run = ALL_CHECKS
    if check_ids:
        id_set = set(check_ids)
        checks_to_run = [c for c in ALL_CHECKS if c.check_id in id_set]

    findings: list[Finding] = []
    for check_cls in checks_to_run:
        check = check_cls()
        try:
            results = check.run(session, account_id)
            findings.extend(results)
        except (NoCredentialsError, NoRegionError) as exc:
            # Surface credential/region problems immediately
            raise
        except Exception:
            # Individual check failures should never crash the whole scan
            pass

    return findings


def score(findings: list[Finding]) -> dict:
    """
    Compute a readiness score from a list of findings.

    Returns a dict with:
      total, passed, failed, warned, errored, score_pct
    """
    total = len(findings)
    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    warned = sum(1 for f in findings if f.status == Status.WARN)
    errored = sum(1 for f in findings if f.status == Status.ERROR)

    # Score: passed / (passed + failed); warnings are neutral, errors excluded
    denominator = passed + failed
    score_pct = round((passed / denominator) * 100) if denominator > 0 else 0

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "warned": warned,
        "errored": errored,
        "score_pct": score_pct,
    }
