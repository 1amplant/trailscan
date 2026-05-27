import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class BucketVersioning(BaseCheck):
    check_id = "s3.bucket_versioning"
    control_id = "CC6.6"
    title = "S3 bucket versioning is enabled"
    remediation = (
        "Enable versioning: S3 Console → select bucket → Properties → Bucket Versioning "
        "→ Edit → Enable. "
        "Or via CLI: aws s3api put-bucket-versioning --bucket <bucket-name> "
        "--versioning-configuration Status=Enabled. "
        "Prioritise buckets containing customer data, database backups, or audit logs."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        s3 = session.client("s3")
        findings: list[Finding] = []

        try:
            buckets = s3.list_buckets()["Buckets"]
        except ClientError as e:
            return [self._error("arn:aws:s3:::*", "global", e)]

        for bucket in buckets:
            name = bucket["Name"]
            resource_arn = f"arn:aws:s3:::{name}"
            region = _get_bucket_region(s3, name)

            try:
                resp = s3.get_bucket_versioning(Bucket=name)
                status = resp.get("Status", "")
                versioning_on = status == "Enabled"
            except ClientError as e:
                findings.append(self._error(resource_arn, region, e))
                continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if versioning_on else Status.WARN,
                severity=Severity.LOW,
                resource_arn=resource_arn,
                region=region,
                evidence={"BucketName": name, "VersioningStatus": status or "Not enabled"},
                remediation=self.remediation,
            ))

        return findings


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    try:
        loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError:
        return "unknown"
