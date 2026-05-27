import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class BucketEncryption(BaseCheck):
    check_id = "s3.bucket_encryption"
    control_id = "CC6.6"
    title = "S3 bucket has server-side encryption enabled"
    remediation = (
        "Enable server-side encryption: S3 Console → select bucket → Properties "
        "→ Default encryption → Edit → select SSE-S3 (AES-256) or SSE-KMS. "
        "Or via CLI: aws s3api put-bucket-encryption --bucket <bucket-name> "
        "--server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
        "{\"SSEAlgorithm\":\"AES256\"}}]}'. "
        "For stronger protection use SSE-KMS with a customer-managed key."
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
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                algorithm = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                encrypted = True
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    algorithm = None
                    encrypted = False
                else:
                    findings.append(self._error(resource_arn, region, e))
                    continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if encrypted else Status.FAIL,
                severity=Severity.MEDIUM,
                resource_arn=resource_arn,
                region=region,
                evidence={"BucketName": name, "Encrypted": encrypted, "Algorithm": algorithm},
                remediation=self.remediation,
            ))

        return findings


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    try:
        loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError:
        return "unknown"
