import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class CloudTrailS3BucketLogging(BaseCheck):
    check_id = "cloudtrail.s3_bucket_logging"
    control_id = "CC7.2"
    title = "S3 bucket used by CloudTrail has access logging enabled"
    remediation = (
        "Enable access logging on the S3 bucket that receives CloudTrail logs: "
        "S3 Console → select the CloudTrail bucket → Properties → Server access logging → Enable. "
        "Deliver logs to a separate logging bucket. "
        "This creates an audit trail of who accessed the audit logs themselves."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ct = session.client("cloudtrail")
        s3 = session.client("s3")
        findings: list[Finding] = []

        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        except ClientError as e:
            return [self._error("arn:aws:cloudtrail:::trail/*", "global", e)]

        seen_buckets: set[str] = set()

        for trail in trails:
            bucket_name = trail.get("S3BucketName")
            if not bucket_name or bucket_name in seen_buckets:
                continue
            seen_buckets.add(bucket_name)

            resource_arn = f"arn:aws:s3:::{bucket_name}"
            region = trail.get("HomeRegion", "unknown")

            try:
                resp = s3.get_bucket_logging(Bucket=bucket_name)
                logging_config = resp.get("LoggingEnabled")
            except ClientError as e:
                findings.append(self._error(resource_arn, region, e))
                continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if logging_config else Status.FAIL,
                severity=Severity.MEDIUM,
                resource_arn=resource_arn,
                region=region,
                evidence={"TrailName": trail.get("Name"), "S3BucketName": bucket_name, "LoggingEnabled": bool(logging_config)},
                remediation=self.remediation,
            ))

        return findings
