import csv
import io
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status

INACTIVE_THRESHOLD_DAYS = 90
_NEVER = "N/A"
_NO_INFO = "no_information"


class UnusedCredentials(BaseCheck):
    check_id = "iam.unused_credentials"
    control_id = "CC6.1"
    title = "IAM credentials inactive for 90+ days are disabled"
    remediation = (
        "Disable or delete IAM credentials that have not been used in 90+ days. "
        "For console passwords: IAM Console → Users → select user → Security credentials "
        "→ Console password → Disable. "
        "For access keys: deactivate via aws iam update-access-key --status Inactive, "
        "then delete after confirming no impact."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        findings: list[Finding] = []

        try:
            report = _fetch_credential_report(iam)
        except ClientError as e:
            return [self._error(f"arn:aws:iam::{account_id}:user/*", "global", e)]

        now = datetime.now(timezone.utc)

        for row in report:
            if row["user"] == "<root_account>":
                continue

            resource_arn = row["arn"]
            stale_items: list[str] = []

            if row.get("password_enabled") == "true":
                last_used = row.get("password_last_used", _NEVER)
                if _is_stale(last_used, now):
                    stale_items.append(f"password unused since {last_used}")

            if row.get("access_key_1_active") == "true":
                last_used = row.get("access_key_1_last_used_date", _NEVER)
                if _is_stale(last_used, now):
                    stale_items.append(f"access_key_1 unused since {last_used}")

            if row.get("access_key_2_active") == "true":
                last_used = row.get("access_key_2_last_used_date", _NEVER)
                if _is_stale(last_used, now):
                    stale_items.append(f"access_key_2 unused since {last_used}")

            if stale_items:
                findings.append(Finding(
                    check_id=self.check_id,
                    control_id=self.control_id,
                    title=self.title,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_arn=resource_arn,
                    region="global",
                    evidence={
                        "UserName": row["user"],
                        "StaleItems": stale_items,
                        "ThresholdDays": INACTIVE_THRESHOLD_DAYS,
                    },
                    remediation=self.remediation,
                ))

        return findings


def _fetch_credential_report(iam_client) -> list[dict]:
    for _ in range(10):
        resp = iam_client.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(2)
    content = iam_client.get_credential_report()["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def _is_stale(last_used_str: str, now: datetime) -> bool:
    if last_used_str in (_NEVER, _NO_INFO, ""):
        return True
    try:
        last_used = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
        return (now - last_used).days > INACTIVE_THRESHOLD_DAYS
    except ValueError:
        return False
