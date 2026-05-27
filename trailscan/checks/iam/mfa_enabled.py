import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class RootMFAEnabled(BaseCheck):
    check_id = "iam.root_mfa_enabled"
    control_id = "CC6.1"
    title = "Root account MFA is enabled"
    remediation = (
        "Enable MFA on the root account: sign in to the AWS Console as root, "
        "go to My Security Credentials, and enable a virtual or hardware MFA device. "
        "After enabling, never use the root account for day-to-day operations."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        resource_arn = f"arn:aws:iam::{account_id}:root"

        try:
            summary = iam.get_account_summary()["SummaryMap"]
        except ClientError as e:
            return [self._error(resource_arn, "global", e)]

        mfa_on = summary.get("AccountMFAEnabled", 0) == 1

        return [Finding(
            check_id=self.check_id,
            control_id=self.control_id,
            title=self.title,
            status=Status.PASS if mfa_on else Status.FAIL,
            severity=Severity.CRITICAL,
            resource_arn=resource_arn,
            region="global",
            evidence={
                "AccountMFAEnabled": summary.get("AccountMFAEnabled"),
                "AccountAccessKeysPresent": summary.get("AccountAccessKeysPresent"),
            },
            remediation=self.remediation,
        )]


class UsersMFAEnabled(BaseCheck):
    check_id = "iam.users_mfa_enabled"
    control_id = "CC6.1"
    title = "IAM users with console access have MFA enabled"
    remediation = (
        "For each IAM user without MFA: go to IAM Console → Users → select the user "
        "→ Security credentials tab → Assigned MFA device → Manage. "
        "Assign a virtual MFA app (Google Authenticator, Authy) or hardware token. "
        "Consider enforcing MFA via an IAM policy that denies all actions unless MFA is present."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        findings: list[Finding] = []

        try:
            users = _paginate(iam, "list_users", "Users")
        except ClientError as e:
            return [self._error(f"arn:aws:iam::{account_id}:user/*", "global", e)]

        for user in users:
            username = user["UserName"]
            resource_arn = user["Arn"]

            try:
                iam.get_login_profile(UserName=username)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    continue
                findings.append(self._error(resource_arn, "global", e))
                continue

            try:
                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            except ClientError as e:
                findings.append(self._error(resource_arn, "global", e))
                continue

            has_mfa = len(mfa_devices) > 0

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if has_mfa else Status.FAIL,
                severity=Severity.HIGH,
                resource_arn=resource_arn,
                region="global",
                evidence={
                    "UserName": username,
                    "MFADevices": mfa_devices,
                    "HasConsoleAccess": True,
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
