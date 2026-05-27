import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class BucketLogging(BaseCheck):
    check_id = "s3.bucket_logging"
    control_id = "CC7.2"
    title = "S3 bucket access logging is enabled"
    remediation = (
        "Enable S3 server access logging: S3 Console → select bucket → Properties "
        "→ Server access logging → Edit → Enable → specify a target bucket for logs. "
        "Or via CLI: aws s3api put-bucket-logging --bucket <bucket-name> "
        "--bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"<prefix>/\"}}'. "
        "Create a dedicated logging bucket in the same region if one doesn't exist."
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
                resp = s3.get_bucket_logging(Bucket=name)
                logging_config = resp.get("LoggingEnabled")
            except ClientError as e:
                findings.append(self._error(resource_arn, region, e))
                continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if logging_config else Status.FAIL,
                severity=Severity.LOW,
                resource_arn=resource_arn,
                region=region,
                evidence={"BucketName": name, "LoggingEnabled": bool(logging_config)},
                remediation=self.remediation,
            ))

        return findings


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    try:
        loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError:
        return "unknown"
