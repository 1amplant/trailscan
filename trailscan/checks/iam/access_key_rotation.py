from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status

MAX_KEY_AGE_DAYS = 90


class AccessKeyRotation(BaseCheck):
    check_id = "iam.access_key_rotation"
    control_id = "CC6.1"
    title = "IAM access keys rotated within 90 days"
    remediation = (
        "Rotate stale access keys: go to IAM Console → Users → select user "
        "→ Security credentials → create a new access key, update your application "
        "or CI/CD pipeline to use the new key, then deactivate and delete the old key. "
        "Or via CLI: aws iam create-access-key --user-name <user>, update credentials, "
        "then aws iam delete-access-key --user-name <user> --access-key-id <old-key-id>"
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        findings: list[Finding] = []

        try:
            users = _paginate(iam, "list_users", "Users")
        except ClientError as e:
            return [self._error(f"arn:aws:iam::{account_id}:user/*", "global", e)]

        now = datetime.now(timezone.utc)

        for user in users:
            username = user["UserName"]
            resource_arn = user["Arn"]

            try:
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            except ClientError as e:
                findings.append(self._error(resource_arn, "global", e))
                continue

            active_keys = [k for k in keys if k["Status"] == "Active"]

            for key in active_keys:
                age_days = (now - key["CreateDate"]).days
                stale = age_days > MAX_KEY_AGE_DAYS

                findings.append(Finding(
                    check_id=self.check_id,
                    control_id=self.control_id,
                    title=self.title,
                    status=Status.FAIL if stale else Status.PASS,
                    severity=Severity.HIGH,
                    resource_arn=resource_arn,
                    region="global",
                    evidence={
                        "UserName": username,
                        "AccessKeyId": key["AccessKeyId"],
                        "Status": key["Status"],
                        "CreateDate": key["CreateDate"].isoformat(),
                        "AgeInDays": age_days,
                        "MaxAllowedDays": MAX_KEY_AGE_DAYS,
                    },
                    remediation=self.remediation,
                ))

        return findings


def _paginate(client, method: str, key: str) -> list:
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate():
        results.extend(page[key])
    return results
