import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class RootAccessKeys(BaseCheck):
    check_id = "iam.root_access_keys"
    control_id = "CC6.1"
    title = "Root account has no active access keys"
    remediation = (
        "Delete root account access keys immediately: sign in as root, go to "
        "My Security Credentials → Access keys, and delete all active keys. "
        "Root access keys cannot be scoped to least privilege and cannot be rotated safely. "
        "Use IAM users or roles with appropriate permissions instead."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        resource_arn = f"arn:aws:iam::{account_id}:root"

        try:
            summary = iam.get_account_summary()["SummaryMap"]
        except ClientError as e:
            return [self._error(resource_arn, "global", e)]

        keys_present = summary.get("AccountAccessKeysPresent", 0)

        return [Finding(
            check_id=self.check_id,
            control_id=self.control_id,
            title=self.title,
            status=Status.PASS if keys_present == 0 else Status.FAIL,
            severity=Severity.CRITICAL,
            resource_arn=resource_arn,
            region="global",
            evidence={"AccountAccessKeysPresent": keys_present},
            remediation=self.remediation,
        )]
