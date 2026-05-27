import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status

_BLOCK_FIELDS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]


class AccountPublicAccessBlock(BaseCheck):
    check_id = "s3.account_public_access_block"
    control_id = "CC6.6"
    title = "S3 account-level public access block is fully enabled"
    remediation = (
        "Enable account-level S3 public access block — this protects all current and future buckets. "
        "Via CLI: aws s3control put-public-access-block --account-id <account-id> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true. "
        "Or in S3 Console → Block Public Access settings for this account → Edit → enable all four settings."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        s3control = session.client("s3control")
        resource_arn = f"arn:aws:s3:::{account_id}"

        try:
            config = s3control.get_public_access_block(AccountId=account_id)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return [Finding(
                    check_id=self.check_id,
                    control_id=self.control_id,
                    title=self.title,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_arn=resource_arn,
                    region="global",
                    evidence={"error": "No account-level public access block configuration found"},
                    remediation=self.remediation,
                )]
            return [self._error(resource_arn, "global", e)]

        disabled = [f for f in _BLOCK_FIELDS if not config.get(f, False)]

        return [Finding(
            check_id=self.check_id,
            control_id=self.control_id,
            title=self.title,
            status=Status.PASS if not disabled else Status.FAIL,
            severity=Severity.HIGH,
            resource_arn=resource_arn,
            region="global",
            evidence={"PublicAccessBlockConfiguration": config, "DisabledSettings": disabled},
            remediation=self.remediation,
        )]


class BucketPublicAccessBlock(BaseCheck):
    check_id = "s3.bucket_public_access_block"
    control_id = "CC6.6"
    title = "S3 bucket-level public access block is fully enabled"
    remediation = (
        "Enable public access block on each bucket: S3 Console → select bucket "
        "→ Permissions → Block public access → Edit → enable all four settings. "
        "Or via CLI: aws s3api put-public-access-block --bucket <bucket-name> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true. "
        "Better: enable the account-level block (s3.account_public_access_block) to cover all buckets automatically."
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
                config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                disabled = [f for f in _BLOCK_FIELDS if not config.get(f, False)]
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    config = {}
                    disabled = _BLOCK_FIELDS[:]
                else:
                    findings.append(self._error(resource_arn, region, e))
                    continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if not disabled else Status.FAIL,
                severity=Severity.HIGH,
                resource_arn=resource_arn,
                region=region,
                evidence={"BucketName": name, "DisabledSettings": disabled},
                remediation=self.remediation,
            ))

        return findings


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    try:
        loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError:
        return "unknown"
