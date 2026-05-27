import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class CloudTrailKMSEncryption(BaseCheck):
    check_id = "cloudtrail.kms_encryption"
    control_id = "CC6.6"
    title = "CloudTrail log files are encrypted with KMS"
    remediation = (
        "Encrypt CloudTrail logs with a KMS key: CloudTrail Console → Trails → select trail "
        "→ Edit → SSE-KMS encryption → enable and select or create a KMS key. "
        "Or via CLI: aws cloudtrail update-trail --name <trail-name> --kms-key-id <key-arn>. "
        "Ensure the KMS key policy allows CloudTrail to use the key for encryption."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ct = session.client("cloudtrail")
        findings: list[Finding] = []

        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        except ClientError as e:
            return [self._error("arn:aws:cloudtrail:::trail/*", "global", e)]

        for trail in trails:
            trail_arn = trail["TrailARN"]
            region = trail.get("HomeRegion", "unknown")
            kms_key_id = trail.get("KMSKeyId")
            encrypted = bool(kms_key_id)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if encrypted else Status.WARN,
                severity=Severity.LOW,
                resource_arn=trail_arn,
                region=region,
                evidence={"TrailName": trail.get("Name"), "KMSKeyId": kms_key_id, "Encrypted": encrypted},
                remediation=self.remediation,
            ))

        return findings
