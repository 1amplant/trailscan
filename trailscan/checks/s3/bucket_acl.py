import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status

_PUBLIC_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


class BucketACL(BaseCheck):
    check_id = "s3.bucket_acl"
    control_id = "CC6.6"
    title = "S3 bucket ACL does not grant public access"
    remediation = (
        "Remove public ACL grants: S3 Console → select bucket → Permissions → Access control list "
        "→ Edit → remove any grants to 'Everyone (public access)' or 'Authenticated users group'. "
        "Or via CLI: aws s3api put-bucket-acl --bucket <bucket-name> --acl private. "
        "If the bucket needs to serve public content, use a bucket policy with CloudFront instead of a public ACL."
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
                acl = s3.get_bucket_acl(Bucket=name)
            except ClientError as e:
                findings.append(self._error(resource_arn, region, e))
                continue

            public_grants = [
                g for g in acl.get("Grants", [])
                if g.get("Grantee", {}).get("URI") in _PUBLIC_URIS
            ]

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL if public_grants else Status.PASS,
                severity=Severity.CRITICAL,
                resource_arn=resource_arn,
                region=region,
                evidence={"BucketName": name, "PublicGrants": public_grants},
                remediation=self.remediation,
            ))

        return findings


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    try:
        loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError:
        return "unknown"
