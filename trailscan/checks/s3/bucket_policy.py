import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class BucketPolicyPublic(BaseCheck):
    check_id = "s3.bucket_policy_public"
    control_id = "CC6.6"
    title = "S3 bucket policy does not allow public access"
    remediation = (
        "Review and tighten the bucket policy: S3 Console → select bucket → Permissions "
        "→ Bucket policy → Edit. Remove any statements with Principal: '*' and Effect: Allow "
        "that grant public read/write access. "
        "If the bucket must serve public content (e.g. static website), use CloudFront with "
        "an Origin Access Control instead of a public bucket policy."
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
                status = s3.get_bucket_policy_status(Bucket=name)
                is_public = status["PolicyStatus"]["IsPublic"]
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration"):
                    is_public = False
                else:
                    findings.append(self._error(resource_arn, region, e))
                    continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL if is_public else Status.PASS,
                severity=Severity.CRITICAL,
                resource_arn=resource_arn,
                region=region,
                evidence={"BucketName": name, "IsPublic": is_public},
                remediation=self.remediation,
            ))

        return findings


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    try:
        loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError:
        return "unknown"
